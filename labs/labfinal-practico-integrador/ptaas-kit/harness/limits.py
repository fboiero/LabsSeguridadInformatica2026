"""Aplicación de topes operativos declarados en `policy.yaml`.

Hallazgo del red-team (grupo 14): `policy.yaml` declara
`limits.rate_limit_rps_per_target` y `limits.max_loop_iterations`, pero
`Harness.invoke` NO los hace cumplir — un agente (o un loop con bug) puede
golpear el mismo objetivo sin tope. Esto contradice el invariante de "contención"
y el límite de iteraciones de los loops.

Corrección: `GuardedHarness` envuelve un `Harness` y aplica un tope determinista
de invocaciones por (acción, objetivo) ANTES de delegar en `Harness.invoke`.
Cumple las reglas del proyecto: no ejecuta herramientas directamente (delega en
invoke), es determinista (sin LLM) y registra el bloqueo en la misma bitácora.
"""
from __future__ import annotations

from collections import defaultdict

from harness.contracts import Action, Harness, Result, ScopeToken, ScopeViolation


class LimitExceeded(ScopeViolation):
    """Se superó el tope de invocaciones permitido para (acción, objetivo)."""


class GuardedHarness:
    """Decorador de `Harness` que impone un tope de iteraciones por objetivo."""

    def __init__(self, harness: Harness, max_iterations_per_target: int):
        if max_iterations_per_target < 1:
            raise ValueError("max_iterations_per_target debe ser >= 1")
        self._h = harness
        self._max = max_iterations_per_target
        self._counts: dict[tuple[str, str], int] = defaultdict(int)

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken) -> dict:
        key = (action.name, target)
        if self._counts[key] >= self._max:
            # Igual que el harness: la decisión de bloqueo queda en bitácora (I3).
            self._h.audit.record(agent, action, target, token, Result.BLOCKED)
            raise LimitExceeded(
                f"tope de {self._max} iteraciones excedido para {action.name}@{target}"
            )
        self._counts[key] += 1
        return self._h.invoke(agent, action, target, token)
