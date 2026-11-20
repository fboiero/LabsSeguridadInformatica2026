"""Reglas de engagement locales para el checkpoint con adaptador inerte."""
from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from .types import Phase, ScopeToken

_FIELDS = {"engagement_id", "window_start", "window_end", "domains", "cidrs", "phases"}
_PRIVATE = tuple(ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_TTL_SECONDS = 300


class RoEError(ValueError):
    """Entrada o emisión de token rechazada."""


@dataclass(frozen=True)
class RoE:
    engagement_id: str
    window_start: float
    window_end: float
    domains: tuple[str, ...]
    cidrs: tuple[str, ...]
    phases: tuple[Phase, ...]


def _scalar(node: Node) -> str:
    if not isinstance(node, ScalarNode) or not isinstance(node.value, str):
        raise RoEError("roe_scalar_required")
    return node.value


def _sequence(node: Node) -> tuple[str, ...]:
    if not isinstance(node, SequenceNode) or len(node.value) > 32:
        raise RoEError("roe_bounded_sequence_required")
    values = tuple(_scalar(item) for item in node.value)
    if len(values) != len(set(values)):
        raise RoEError("roe_duplicate_value")
    return values


def _utc(node: Node) -> float:
    value = _scalar(node)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise RoEError("roe_utc_required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except (ValueError, OSError, OverflowError):
        raise RoEError("roe_invalid_time") from None


def parse_roe(text: str) -> RoE:
    if len(text) > 4096:
        raise RoEError("roe_document_too_large")
    try:
        if any(isinstance(token, (AnchorToken, AliasToken, TagToken)) for token in yaml.scan(text)):
            raise RoEError("roe_yaml_feature_not_allowed")
        root = yaml.compose(text, Loader=yaml.BaseLoader)
    except (yaml.YAMLError, RecursionError):
        raise RoEError("roe_invalid_yaml") from None
    if not isinstance(root, MappingNode):
        raise RoEError("roe_mapping_required")
    fields: dict[str, Node] = {}
    for key, value in root.value:
        name = _scalar(key)
        if name in fields or name not in _FIELDS:
            raise RoEError("roe_unexpected_or_duplicate_field")
        fields[name] = value
    if fields.keys() != _FIELDS:
        raise RoEError("roe_required_fields_missing")
    engagement = _scalar(fields["engagement_id"])
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", engagement):
        raise RoEError("roe_invalid_engagement")
    start, end = _utc(fields["window_start"]), _utc(fields["window_end"])
    if end <= start:
        raise RoEError("roe_invalid_window")
    domains, cidrs = _sequence(fields["domains"]), _sequence(fields["cidrs"])
    if not (domains or cidrs):
        raise RoEError("roe_empty_scope")
    if any(len(domain) > 253 or (domain != "phantomcorp.test" and
                                not re.fullmatch(rf"(?:{_LABEL}\.)+lab\.test", domain)) for domain in domains):
        raise RoEError("roe_lab_domain_required")
    try:
        networks = tuple(ipaddress.IPv4Network(cidr, strict=True) for cidr in cidrs)
        phases = tuple(Phase(value) for value in _sequence(fields["phases"]))
    except ValueError:
        raise RoEError("roe_invalid_cidr_or_phase") from None
    if not phases:
        raise RoEError("roe_empty_phases")
    if any(str(net) != raw or not any(net.subnet_of(private) for private in _PRIVATE)
           for raw, net in zip(cidrs, networks, strict=True)):
        raise RoEError("roe_canonical_private_ipv4_required")
    return RoE(engagement, start, end, domains, cidrs, phases)


def fixture_roe_yaml() -> str:
    now = datetime.now(UTC).replace(microsecond=0)
    return (
        f"engagement_id: fixture-{uuid4().hex}\n"
        f"window_start: {now:%Y-%m-%dT%H:%M:%SZ}\n"
        f"window_end: {now + timedelta(minutes=10):%Y-%m-%dT%H:%M:%SZ}\n"
        "domains: [dvwa.lab.test, phantomcorp.test]\ncidrs: []\nphases: [recon, analyze]\n"
    )


class TokenIssuer:
    """Credenciales locales efímeras; solo llamadas del coordinador de confianza."""

    def __init__(self, roe: RoE, *, approved_fixture: bool, clock: Callable[[], float] = time.time):
        self._roe = roe
        self._approved_fixture = approved_fixture
        self._clock = clock
        self._issued: dict[Phase, ScopeToken] = {}

    def issue(self, phase: Phase) -> ScopeToken:
        now, roe = self._clock(), self._roe
        if self._approved_fixture is not True or phase not in roe.phases or not roe.window_start <= now < roe.window_end:
            raise RoEError("roe_issue_not_authorized")
        token = ScopeToken(roe.engagement_id, roe.cidrs, roe.domains, now, min(roe.window_end, now + _TTL_SECONDS), phase)
        self._issued[phase] = token
        return token

    def accepts(self, token: ScopeToken) -> bool:
        return self._issued.get(token.phase) is token and token.is_live(self._clock())
