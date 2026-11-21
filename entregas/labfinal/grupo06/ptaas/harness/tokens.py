"""Emisor de scope tokens por fase (change 003).

Única ruta del harness que construye un `ScopeToken`. El TTL sale de
`harness/policy.yaml`; la ventana nunca excede la del RoE.
"""
from __future__ import annotations

import time
from typing import Any

from harness.contracts import Phase, Result, ScopeToken
from harness.policy_loader import load_policy
from harness.roe import RoE, _dominio_excluido, _restar_redes

_ACCION_EMISION = "scope.issue_token"


class TokenIssuanceError(ValueError):
    """La fase, la ventana o el estado del RoE no permiten emitir el token."""


def _registrar(audit: Any, agent: str, phase: Phase | str, engagement_id: str,
               result: Result) -> None:
    if audit is None:
        raise TypeError("audit es obligatorio para emitir o rechazar un token")
    phase_name = phase.value if isinstance(phase, Phase) else str(phase)
    if hasattr(audit, "record_decision"):
        audit.record_decision(agent=agent, action_name=_ACCION_EMISION,
                              target=phase_name, engagement_id=engagement_id,
                              phase=phase_name, result=result)
        return
    if hasattr(audit, "append"):
        audit.append({"engagement": engagement_id, "agent": agent,
                      "action": _ACCION_EMISION, "target": phase_name,
                      "phase": phase_name, "result": result.value})
        return
    raise TypeError("audit debe exponer record_decision(...) o append(...)")


def _rechazar(motivo: str, *, audit: Any, agent: str, phase: Phase,
              engagement_id: str) -> TokenIssuanceError:
    _registrar(audit, agent, phase, engagement_id, Result.BLOCKED)
    return TokenIssuanceError(motivo)


def _dominios_restantes(roe: RoE) -> tuple[str, ...]:
    return tuple(d for d in roe.scope_domains if not _dominio_excluido(d, roe.excluded_domains))


def issue(roe: RoE, phase: Phase | str, *, audit: Any,
          now: float | None = None, agent: str = "scope-guard",
          policy: dict[str, Any] | None = None) -> ScopeToken:
    """Emite un token auditado solo para ``phase``, dentro de la ventana y con TTL."""
    if audit is None:
        raise TypeError("audit es obligatorio para emitir o rechazar un token")
    try:
        phase = Phase(phase)
    except (TypeError, ValueError) as exc:
        _registrar(audit, agent, str(phase), roe.engagement_id, Result.BLOCKED)
        raise TokenIssuanceError(f"fase desconocida: {phase!r}") from exc
    now = time.time() if now is None else float(now)

    if phase not in roe.authorized_phases:
        raise _rechazar(f"fase no autorizada por el RoE: {phase.value}",
                        audit=audit, agent=agent, phase=phase,
                        engagement_id=roe.engagement_id)

    if roe.revoked_at is not None and now >= roe.revoked_at:
        raise _rechazar(f"RoE revocado para el engagement {roe.engagement_id}",
                        audit=audit, agent=agent, phase=phase,
                        engagement_id=roe.engagement_id)

    if now < roe.window_start or now >= roe.window_end:
        raise _rechazar("fuera de la ventana del RoE: no se emite token",
                        audit=audit, agent=agent, phase=phase,
                        engagement_id=roe.engagement_id)

    policy = policy or load_policy()
    try:
        minutos = int(policy["phases"][phase.value]["token_ttl_minutes"])
    except (KeyError, TypeError, ValueError):
        raise _rechazar(f"policy.yaml no define TTL para la fase {phase.value}",
                        audit=audit, agent=agent, phase=phase,
                        engagement_id=roe.engagement_id)

    window_end = min(now + minutos * 60, roe.window_end)
    if window_end <= now:
        raise _rechazar("la ventana del RoE no deja tiempo de vida al token",
                        audit=audit, agent=agent, phase=phase,
                        engagement_id=roe.engagement_id)

    redes = _restar_redes(roe.scope_networks(), roe.excluded_networks())
    token = ScopeToken(
        engagement_id=roe.engagement_id,
        allowed_cidrs=tuple(str(red) for red in redes),
        allowed_domains=_dominios_restantes(roe),
        window_start=now,
        window_end=window_end,
        phase=phase,
        excluded_domains=roe.excluded_domains,
    )
    _registrar(audit, agent, phase, roe.engagement_id, Result.OK)
    return token
