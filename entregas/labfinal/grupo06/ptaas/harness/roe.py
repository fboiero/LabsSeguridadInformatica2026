"""Parser y modelo del RoE (change 003).

Un RoE se valida **antes** de que exista cualquier token. Todas las reglas son
deterministas y se apoyan en el alcance máximo del laboratorio declarado en
`harness/profiles.yaml` (`targets.lab_only_cidrs` / `lab_only_domains`).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from harness.contracts import Phase
from harness.policy_loader import load_policy

_DIR = Path(__file__).resolve().parent
_PROFILES = _DIR / "profiles.yaml"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_MIN_PREFIX = {4: 24, 6: 64}
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _network(value: str, *, strict: bool = True) -> Network:
    return ipaddress.ip_network(value, strict=strict)


class RoEValidationError(ValueError):
    """El RoE es incompleto, peligroso o inconsistente. No se emite token."""


@dataclass(frozen=True)
class RoE:
    engagement_id: str
    approver: str
    approval_ref: str
    signed_at: float
    window_start: float
    window_end: float
    scope_cidrs: tuple[str, ...]
    scope_domains: tuple[str, ...]
    excluded_cidrs: tuple[str, ...]
    excluded_domains: tuple[str, ...]
    emergency_contacts: tuple[str, ...]
    authorized_phases: tuple[Phase, ...]
    revoked_at: float | None = None
    approval_hash: str = ""

    def scope_networks(self) -> tuple[Network, ...]:
        return tuple(_network(c) for c in self.scope_cidrs)

    def excluded_networks(self) -> tuple[Network, ...]:
        return tuple(_network(c) for c in self.excluded_cidrs)


def _lab_limits() -> tuple[tuple[Network, ...], tuple[str, ...]]:
    perfiles = yaml.safe_load(_PROFILES.read_text(encoding="utf-8"))
    targets = perfiles["targets"]
    return (tuple(_network(c) for c in targets["lab_only_cidrs"]),
            tuple(d.lower().rstrip(".") for d in targets["lab_only_domains"]))


def _texto(data: Mapping[str, Any], campo: str) -> str:
    valor = data.get(campo)
    if not isinstance(valor, str) or not valor.strip():
        raise RoEValidationError(f"falta {campo} no vacío en el RoE")
    return valor.strip()


def _epoch(valor: Any, campo: str) -> float:
    if not isinstance(valor, str) or not valor.strip():
        raise RoEValidationError(f"falta {campo} en el RoE")
    try:
        fecha = datetime.fromisoformat(valor.strip())
    except ValueError as exc:
        raise RoEValidationError(f"{campo} no es ISO 8601 con zona horaria: {valor!r}") from exc
    if fecha.tzinfo is None:
        raise RoEValidationError(f"{campo} debe incluir zona horaria (UTC o offset)")
    return fecha.timestamp()


def _dominio(valor: Any, campo: str) -> str:
    if not isinstance(valor, str):
        raise RoEValidationError(f"{campo} debe ser un dominio")
    dominio = valor.strip().lower().rstrip(".")
    if "*" in dominio or not _DOMAIN_RE.match(dominio):
        raise RoEValidationError(f"dominio inválido en {campo}: {valor!r}")
    return dominio


def _red(valor: Any, campo: str, lab_cidrs: Iterable[Network]) -> str:
    if not isinstance(valor, str):
        raise RoEValidationError(f"CIDR inválido en {campo}: {valor!r}")
    try:
        red = _network(valor.strip(), strict=False)
    except ValueError as exc:
        raise RoEValidationError(f"CIDR inválido en {campo}: {valor!r}") from exc
    minimo = _MIN_PREFIX[red.version]
    if red.prefixlen < minimo:
        raise RoEValidationError(
            f"CIDR demasiado amplio en {campo}: {red} (prefijo mínimo /{minimo})")
    pertenece_al_lab = False
    for permitida in lab_cidrs:
        if isinstance(red, ipaddress.IPv4Network) and isinstance(permitida, ipaddress.IPv4Network):  # noqa: SIM114
            pertenece_al_lab = red.subnet_of(permitida)
        elif isinstance(red, ipaddress.IPv6Network) and isinstance(permitida, ipaddress.IPv6Network):
            pertenece_al_lab = red.subnet_of(permitida)
        if pertenece_al_lab:
            break
    if not pertenece_al_lab:
        raise RoEValidationError(f"CIDR fuera del laboratorio autorizado: {red}")
    return str(red)


def _dominio_autorizado(dominio: str, lab_domains: Iterable[str]) -> bool:
    return any(dominio == lab or dominio.endswith("." + lab) for lab in lab_domains)


def _restar_redes(redes: Iterable[Network],
                  exclusiones: Iterable[Network]) -> list[Network]:
    resultado = list(redes)
    for exclusion in exclusiones:
        siguiente: list[Network] = []
        for red in resultado:
            if isinstance(red, ipaddress.IPv4Network) and isinstance(exclusion, ipaddress.IPv4Network):  # noqa: SIM114
                if not red.overlaps(exclusion):
                    siguiente.append(red)
                elif red.subnet_of(exclusion):
                    continue
                else:
                    siguiente.extend(red.address_exclude(exclusion))
            elif isinstance(red, ipaddress.IPv6Network) and isinstance(exclusion, ipaddress.IPv6Network):
                if not red.overlaps(exclusion):
                    siguiente.append(red)
                elif red.subnet_of(exclusion):
                    continue
                else:
                    siguiente.extend(red.address_exclude(exclusion))
            else:
                siguiente.append(red)
        resultado = siguiente
    return sorted(set(resultado), key=lambda r: (r.version, int(r.network_address), r.prefixlen))


def _dominio_excluido(dominio: str, exclusiones: Iterable[str]) -> bool:
    return any(dominio == ex or dominio.endswith("." + ex) for ex in exclusiones)


def _hash_aprobacion(partes: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(partes, sort_keys=True, default=str).encode()).hexdigest()


def parse(data: Mapping[str, Any], *,
          lab_cidrs: Iterable[str] | None = None,
          lab_domains: Iterable[str] | None = None) -> RoE:
    """Valida un RoE ya cargado como mapping. ``load`` hace YAML → mapping."""
    if not isinstance(data, Mapping):
        raise RoEValidationError("el RoE debe ser un mapping YAML")

    limites_cidrs, limites_dominios = _lab_limits()
    permitidas = (tuple(_network(c) for c in lab_cidrs)
                  if lab_cidrs is not None else limites_cidrs)
    dominios_lab = (tuple(d.lower().rstrip(".") for d in lab_domains)
                    if lab_domains is not None else limites_dominios)

    engagement_id = _texto(data, "engagement_id")
    approver = _texto(data, "approver")
    approval_ref = _texto(data, "approval_ref")
    signed_at = _epoch(data.get("signed_at"), "signed_at")

    window = data.get("window")
    if not isinstance(window, Mapping):
        raise RoEValidationError("falta window en el RoE")
    window_start = _epoch(window.get("start"), "window.start")
    window_end = _epoch(window.get("end"), "window.end")
    if window_start >= window_end:
        raise RoEValidationError("ventana invertida o vacía: window.start debe ser anterior a window.end")

    scope = data.get("scope")
    if not isinstance(scope, Mapping):
        raise RoEValidationError("RoE sin alcance: falta scope")
    cidrs_entrada = scope.get("cidrs") or []
    dominios_entrada = scope.get("domains") or []
    if not isinstance(cidrs_entrada, list) or not isinstance(dominios_entrada, list):
        raise RoEValidationError("scope.cidrs y scope.domains deben ser listas")
    if not cidrs_entrada and not dominios_entrada:
        raise RoEValidationError("RoE sin alcance: scope vacío")

    scope_cidrs = tuple(_red(c, "scope.cidrs", permitidas) for c in cidrs_entrada)
    scope_domains = tuple(_dominio(d, "scope.domains") for d in dominios_entrada)
    for dominio in scope_domains:
        if not _dominio_autorizado(dominio, dominios_lab):
            raise RoEValidationError(f"dominio fuera del laboratorio autorizado: {dominio}")

    exclusions = data.get("exclusions") or {}
    if not isinstance(exclusions, Mapping):
        raise RoEValidationError("exclusions debe ser un mapping")
    excluded_cidrs = tuple(_red(c, "exclusions.cidrs", permitidas)
                           for c in (exclusions.get("cidrs") or []))
    excluded_domains = tuple(_dominio(d, "exclusions.domains")
                             for d in (exclusions.get("domains") or []))

    restantes_cidrs = _restar_redes(
        tuple(_network(c) for c in scope_cidrs),
        tuple(_network(c) for c in excluded_cidrs),
    )
    restantes_dominios = tuple(
        d for d in scope_domains if not _dominio_excluido(d, excluded_domains)
    )
    if not restantes_cidrs and not restantes_dominios:
        raise RoEValidationError("la exclusión deja el alcance vacío")

    contactos = data.get("emergency_contacts")
    if (not isinstance(contactos, list) or not contactos
            or any(not isinstance(c, str) or not c.strip() for c in contactos)):
        raise RoEValidationError(
            "emergency_contacts debe contener al menos un contacto de texto no vacío"
        )

    if "authorized_phases" in data:
        fases_entrada = data["authorized_phases"]
        if not isinstance(fases_entrada, list) or not fases_entrada:
            raise RoEValidationError("authorized_phases debe ser una lista no vacía")
    else:
        try:
            fases_entrada = list(load_policy()["phases"])
        except (KeyError, TypeError) as exc:
            raise RoEValidationError("policy.yaml no define fases autorizables") from exc
    try:
        authorized_phases = tuple(Phase(f) for f in fases_entrada)
    except (TypeError, ValueError) as exc:
        raise RoEValidationError("authorized_phases contiene una fase desconocida") from exc

    revocado = data.get("revoked_at")
    revoked_at = _epoch(revocado, "revoked_at") if revocado is not None else None

    aprobacion = {
        "engagement_id": engagement_id, "approver": approver,
        "approval_ref": approval_ref, "signed_at": signed_at,
        "window_start": window_start, "window_end": window_end,
        "scope_cidrs": sorted(scope_cidrs), "scope_domains": sorted(scope_domains),
        "excluded_cidrs": sorted(excluded_cidrs),
        "excluded_domains": sorted(excluded_domains),
        "emergency_contacts": sorted(c.strip() for c in contactos),
        "authorized_phases": sorted(p.value for p in authorized_phases),
        "revoked_at": revoked_at,
    }
    return RoE(
        engagement_id=engagement_id, approver=approver, approval_ref=approval_ref,
        signed_at=signed_at, window_start=window_start, window_end=window_end,
        scope_cidrs=scope_cidrs, scope_domains=scope_domains,
        excluded_cidrs=excluded_cidrs, excluded_domains=excluded_domains,
        emergency_contacts=tuple(c.strip() for c in contactos),
        authorized_phases=authorized_phases, revoked_at=revoked_at,
        approval_hash=_hash_aprobacion(aprobacion),
    )


def load(path: str | Path, *, lab_cidrs: Iterable[str] | None = None,
         lab_domains: Iterable[str] | None = None) -> RoE:
    """Carga un RoE YAML. Un archivo ausente o inválido nunca produce token."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise RoEValidationError(f"no se pudo leer el RoE: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RoEValidationError(f"YAML inválido en el RoE: {exc}") from exc
    return parse(data, lab_cidrs=lab_cidrs, lab_domains=lab_domains)
