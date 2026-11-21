"""Contratos del harness PTaaS (esqueleto). El contrato, no el exploit.

Invariantes:
  I1. Toda acción que toca un activo pasa por Harness.invoke.
  I2. El Guard es determinista (sin LLM).
  I3. Toda decisión (OK, BLOCKED, PENDING_HITL, ABORTED) queda en bitácora.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class Phase(str, Enum):
    RECON = "recon"
    CORRELATE = "correlate"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    REPORT = "report"


class Result(str, Enum):
    OK = "OK"
    BLOCKED = "BLOCKED"
    PENDING_HITL = "PENDING_HITL"
    ABORTED = "ABORTED"


class ScopeViolation(Exception): ...
class KillSwitchEngaged(Exception): ...


@dataclass(frozen=True)
class ScopeToken:
    engagement_id: str
    allowed_cidrs: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    window_start: float
    window_end: float
    phase: Phase
    excluded_domains: tuple[str, ...] = ()

    def is_live(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.window_start <= now < self.window_end


@dataclass(frozen=True)
class Action:
    name: str                      # capability declarada, p.ej. "httpx.probe"
    phase: Phase
    destructive: bool = False
    requires_human_approval: bool = False


class ToolAdapter(Protocol):
    name: str
    allowed_phases: tuple[Phase, ...]
    destructive: bool

    def run(self, action: Action, target: str, token: ScopeToken) -> dict:
        """Debe devolver JSON parseable. Nunca ejecuta fuera de `target`."""
        ...


class Guard:
    """Autorización determinista. Sin LLM, sin heurísticas."""

    def __init__(self, phase_allowlist: dict[Phase, set[str]], approvals: set[str] | None = None,
                 engagement_id: str | None = None,
                 resolver: Callable[[str], Iterable[str]] | None = None):
        self.phase_allowlist = phase_allowlist
        self._approvals = approvals or set()
        self.engagement_id = engagement_id
        self.resolver = resolver

    def approve(self, action_name: str, target: str) -> None:
        self._approvals.add(f"{action_name}@{target}")

    def approved(self, action: Action, target: str) -> bool:
        return f"{action.name}@{target}" in self._approvals

    def is_allowed(self, action: Action, target: str, token: ScopeToken) -> bool:
        if action.destructive:        # acciones destructivas prohibidas en el MVP
            return False
        if action.phase != token.phase:
            return False
        if action.name not in self.phase_allowlist.get(token.phase, set()):
            return False
        if self.engagement_id is not None and token.engagement_id != self.engagement_id:
            return False
        if not self._in_scope(target, token):
            return False
        return self._resolves_in_scope(target, token)

    @staticmethod
    def _normalize(target: str) -> str:
        return target.strip().lower().rstrip(".")

    @staticmethod
    def _as_ip(value: str):
        ip = ipaddress.ip_address(value)
        return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped is not None else ip

    @classmethod
    def _in_scope(cls, target: str, token: ScopeToken) -> bool:
        host = cls._normalize(target)
        try:
            ip = cls._as_ip(host)
            return any(ip in ipaddress.ip_network(c) for c in token.allowed_cidrs)
        except ValueError:
            if any(host == ex or host.endswith("." + ex) for ex in token.excluded_domains):
                return False
            return any(
                host == d or host.endswith("." + d) for d in token.allowed_domains
            )

    def _resolves_in_scope(self, target: str, token: ScopeToken) -> bool:
        """A4: si hay resolver, todas las direcciones del host deben estar en alcance."""
        if self.resolver is None:
            return True
        host = self._normalize(target)
        try:
            self._as_ip(host)
            return True
        except ValueError:
            pass
        try:
            direcciones = list(self.resolver(host))
        except OSError:
            return False
        if not direcciones:
            return False
        redes = tuple(ipaddress.ip_network(c) for c in token.allowed_cidrs)
        for direccion in direcciones:
            try:
                ip = self._as_ip(str(direccion).strip())
            except ValueError:
                return False
            if not any(ip in red for red in redes):
                return False
        return True


@dataclass
class AuditLog:
    """Append-only con hash encadenado (detecta manipulación y escrituras concurrentes)."""

    entries: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def record_decision(self, agent: str, action_name: str, target: str,
                        engagement_id: str, phase: str, result: Result) -> dict:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
            body = {
                "ts": time.time(), "engagement": engagement_id, "agent": agent,
                "action": action_name, "target": target, "phase": phase,
                "result": result.value, "prev": prev,
            }
            body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
            self.entries.append(body)
            return body

    def record(self, agent: str, action: Action, target: str,
               token: ScopeToken, result: Result) -> dict:
        return self.record_decision(agent, action.name, target, token.engagement_id,
                                    token.phase.value, result)


class KillSwitch:
    engaged: bool = False


class Harness:
    def __init__(self, guard: Guard, audit: AuditLog,
                 tools: dict[str, ToolAdapter], killswitch: KillSwitch):
        self.guard, self.audit, self.tools, self.killswitch = guard, audit, tools, killswitch

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken) -> dict:
        if self.killswitch.engaged:
            self.audit.record(agent, action, target, token, Result.ABORTED)
            raise KillSwitchEngaged()
        if not token.is_live() or not self.guard.is_allowed(action, target, token):
            self.audit.record(agent, action, target, token, Result.BLOCKED)
            raise ScopeViolation(f"{action.name} sobre {target} fuera de RoE/ventana/fase")
        if action.requires_human_approval and not self.guard.approved(action, target):
            self.audit.record(agent, action, target, token, Result.PENDING_HITL)
            return {"status": "PENDING_HITL"}
        adapter = self.tools.get(action.name)
        if adapter is None:
            self.audit.record(agent, action, target, token, Result.BLOCKED)
            raise ScopeViolation(f"capability sin adaptador registrado: {action.name}")
        if token.phase not in adapter.allowed_phases:
            self.audit.record(agent, action, target, token, Result.BLOCKED)
            raise ScopeViolation(f"adaptador {adapter.name} no habilitado en {token.phase}")
        out = adapter.run(action, target, token)
        self.audit.record(agent, action, target, token, Result.OK)
        return out
