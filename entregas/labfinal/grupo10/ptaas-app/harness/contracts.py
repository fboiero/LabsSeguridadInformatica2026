"""Guard y Harness derivados del kit docente a1abb79; integración fail-closed del grupo."""
from __future__ import annotations

import ipaddress
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from .audit import AuditLog, AuditUnavailable, safe_target
from .types import Action, Phase, Result, ScopeToken, ToolAdapter

__all__ = [
    "Action", "AuditLog", "Guard", "Harness", "KillSwitch", "KillSwitchEngaged",
    "Phase", "Result", "ScopeToken", "ScopeViolation", "ToolAdapter", "ToolExecutionError",
]


class ScopeViolation(Exception):
    pass


class KillSwitchEngaged(Exception):
    pass


class ToolExecutionError(Exception):
    pass


class Guard:
    """El control de autorización no usa ningún modelo."""

    def __init__(self, phase_allowlist: dict[Phase, set[str]], approvals: set[str] | None = None, *,
                 issued_by: Callable[[ScopeToken], bool] | None = None):
        self.phase_allowlist = phase_allowlist
        self._approvals = set() if approvals is None else approvals
        self._issued_by = issued_by

    def approve(self, action_name: str, target: str) -> None:
        self._approvals.add(f"{action_name}@{target}")

    def approved(self, action: Action, target: str) -> bool:
        return f"{action.name}@{target}" in self._approvals

    def is_allowed(self, action: Action, target: str, token: ScopeToken) -> bool:
        if (
            action.destructive or action.phase != token.phase
            or action.name not in self.phase_allowlist.get(token.phase, set())
            or safe_target(target).startswith("invalid:")
            or (self._issued_by is not None and not self._issued_by(token))
        ):
            return False
        return self._in_scope(target, token)

    def _in_scope(self, target: str, token: ScopeToken) -> bool:
        try:
            address = ipaddress.ip_address(target)
            return any(address in ipaddress.ip_network(cidr) for cidr in token.allowed_cidrs)
        except ValueError:
            host = target.lower().rstrip(".")
            if self._issued_by is not None:
                return host in token.allowed_domains
            return any(
                host == domain.lower().rstrip(".") or host.endswith("." + domain.lower().rstrip("."))
                for domain in token.allowed_domains
            )


class KillSwitch:
    engaged: bool = False


class Harness:
    def __init__(self, guard: Guard, audit: AuditLog,
                 tools: dict[str, ToolAdapter], killswitch: KillSwitch):
        audit.assert_resumable()
        self.guard, self.audit, self.tools, self.killswitch = guard, audit, tools, killswitch
        self._halted = False

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if self.killswitch.engaged:
            self.audit.record(agent, action, target, token, Result.ABORTED)
            raise KillSwitchEngaged("kill_switch_engaged")
        if self._halted:
            raise AuditUnavailable("execution_suspended")
        if not token.is_live() or not self.guard.is_allowed(action, target, token):
            self.audit.record(agent, action, target, token, Result.BLOCKED)
            raise ScopeViolation("action_not_authorized")
        if action.requires_human_approval and not self.guard.approved(action, target):
            self.audit.record(agent, action, target, token, Result.PENDING_HITL)
            return {"status": "PENDING_HITL"}
        adapter = self.tools.get(action.name)
        if adapter is None or token.phase not in adapter.allowed_phases or adapter.destructive:
            self.audit.record(agent, action, target, token, Result.BLOCKED)
            raise ScopeViolation("adapter_not_authorized")
        invocation = "invoke-" + uuid4().hex
        try:
            self.audit.record_event(agent, action, target, token, "ATTEMPT", invocation)
            try:
                output = adapter.run(action, target, token)
            except Exception:  # noqa: BLE001 -- frontera: registrar y sanear cualquier fallo de adaptador
                failure = getattr(adapter, "last_error", None)
                self.audit.record_event(
                    agent, action, target, token, "TOOL_ERROR", invocation, error_code="adapter_failure",
                )
                raise ToolExecutionError(failure if isinstance(failure, str) else "adapter_failure") from None
            self.audit.record_event(agent, action, target, token, "DECISION", invocation, result=Result.OK)
            return output
        except AuditUnavailable:
            self._halted = True
            raise
