"""Emisor de scope tokens a partir de un RoE validado (change 003).

Es el ÚNICO lugar del código de producción que construye `ScopeToken`
(lo verifica `tests/test_roe_tokens.py::test_solo_el_emisor_crea_scope_tokens`).

Reglas:
  * Un token por fase pedida; solo si el RoE autoriza esa fase.
  * Vida = min(TTL de la fase en policy.yaml, fin de la ventana del RoE).
  * Las exclusiones del RoE se descuentan del alcance del token: el Guard
    nunca ve una dirección excluida como autorizada.
  * No hay renovación automática: un token vencido sigue vencido; para seguir
    hay que pedir otro, y el pedido vuelve a validarse contra el RoE.
  * Cada emisión y cada rechazo quedan en la bitácora.
  * Revocar el RoE impide nuevas emisiones y activa el kill switch, lo que
    detiene también los tokens ya emitidos.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Callable

from harness.contracts import (Action, AuditLog, Guard, KillSwitch, Phase, Result,
                               ScopeToken)
from harness.policy_loader import load_policy
from harness.roe import RoE

ISSUE_ACTION = "token.issue"


class TokenRejected(Exception):
    """El pedido de token no cumple el RoE o la política. Queda registrado."""


def _effective_cidrs(roe: RoE) -> tuple[str, ...]:
    """Alcance del RoE menos sus exclusiones, expresado como lista de CIDR."""
    remaining = [ipaddress.ip_network(c) for c in roe.scope_cidrs]
    for exc in (ipaddress.ip_network(e) for e in roe.excluded_cidrs):
        nxt = []
        for net in remaining:
            if net.version != exc.version or not net.overlaps(exc):
                nxt.append(net)
            elif net.subnet_of(exc):
                continue                         # la exclusión cubre toda la red
            else:
                nxt.extend(net.address_exclude(exc))
        remaining = nxt
    return tuple(str(n) for n in sorted(remaining, key=lambda n: (n.version, n)))


class TokenIssuer:
    def __init__(self, roe: RoE, audit: AuditLog, policy: dict | None = None,
                 killswitch: KillSwitch | None = None,
                 clock: Callable[[], float] = time.time):
        self.roe, self.audit, self.killswitch, self.clock = roe, audit, killswitch, clock
        self.policy = policy or load_policy()
        self.revoked = False

    # -- API pública ---------------------------------------------------------------
    def issue(self, phase: Phase | str, agent: str = "orchestrator") -> ScopeToken:
        phase = Phase(phase)
        now = self.clock()
        if self.revoked:
            self._reject(agent, phase, "el RoE fue revocado")
        if not self.roe.authorizes(phase):
            self._reject(agent, phase, f"el RoE no autoriza la fase '{phase.value}'")
        if not (self.roe.window_start <= now < self.roe.window_end):
            self._reject(agent, phase, "fuera de la ventana del RoE")
        ttl_min = self.policy["phases"][phase.value]["token_ttl_minutes"]
        token = ScopeToken(
            engagement_id=self.roe.engagement_id,
            allowed_cidrs=_effective_cidrs(self.roe),
            allowed_domains=tuple(d for d in self.roe.scope_domains
                                  if d not in self.roe.excluded_domains),
            window_start=now,
            window_end=min(now + ttl_min * 60, self.roe.window_end),
            phase=phase,
        )
        self.audit.record(agent, Action(ISSUE_ACTION, phase), self.roe.engagement_id,
                          token, Result.OK)
        return token

    def revoke(self, agent: str = "reviewer") -> None:
        """Revoca el RoE: no se emiten más tokens y se detiene el engagement."""
        self.revoked = True
        if self.killswitch is not None:
            self.killswitch.engaged = True
        self.audit.record(agent, Action("roe.revoke", Phase.RECON), self.roe.engagement_id,
                          self._null_token(Phase.RECON), Result.ABORTED)

    # -- internos ---------------------------------------------------------------
    def _null_token(self, phase: Phase) -> ScopeToken:
        """Token sin alcance ni vigencia: solo identifica el registro de un rechazo."""
        return ScopeToken(self.roe.engagement_id, (), (), 0.0, 0.0, phase)

    def _reject(self, agent: str, phase: Phase, reason: str):
        self.audit.record(agent, Action(ISSUE_ACTION, phase), self.roe.engagement_id,
                          self._null_token(phase), Result.BLOCKED)
        raise TokenRejected(f"token de fase '{phase.value}' rechazado: {reason}")


class EngagementGuard(Guard):
    """Guard atado a un engagement: un token de otro engagement no habilita nada (A6).

    Extiende el Guard sin cambiar el contrato de `Harness`.
    """

    def __init__(self, engagement_id: str, phase_allowlist: dict[Phase, set[str]],
                 approvals: set[str] | None = None):
        super().__init__(phase_allowlist, approvals)
        self.engagement_id = engagement_id

    def is_allowed(self, action: Action, target: str, token: ScopeToken) -> bool:
        if token.engagement_id != self.engagement_id:
            return False
        return super().is_allowed(action, target, token)
