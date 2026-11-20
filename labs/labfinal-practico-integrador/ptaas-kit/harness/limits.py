"""Enforcement determinista de los topes declarados en `policy.yaml`.

Hallazgo del red-team (grupo 14): las decisiones de parada de los loops viven en
`harness/loops.py` (`decide_recon`, etc.), pero son **consultivas** — el LLM puede
ignorarlas. A nivel de `Harness.invoke` no hay ningún tope que las haga cumplir, de
modo que un agente desobediente o un loop con bug puede iterar sin freno. El delta
de `asset-discovery` ("Scenario: tope alcanzado") exige que **el harness rechace**
la iteración, no solo que el agente decida parar.

`GuardedHarness` cierra esa brecha con dos controles deterministas:

1. **Tope de iteraciones de loop por fase** (`begin_iteration`), tomado de
   `policy['limits']['max_loop_iterations']` (recon/detection/validation). Cumple
   literalmente el requisito de spec.
2. **Tope de invocaciones por `(acción, objetivo)`** como defensa en profundidad
   (opcional, no proviene de la spec), con el bloqueo registrado en bitácora.

Respeta las reglas del proyecto: no ejecuta herramientas (delega en `invoke`), es
determinista (sin LLM) y usa la misma bitácora.
"""
from __future__ import annotations

from collections import defaultdict

from harness.contracts import Action, Harness, Result, ScopeToken, ScopeViolation


class LimitExceeded(ScopeViolation):
    """Base: se superó un tope operativo."""


class LoopIterationLimit(LimitExceeded):
    """Se alcanzó `max_loop_iterations[<loop>]`."""


class InvocationLimit(LimitExceeded):
    """Se superó el tope de invocaciones por (acción, objetivo)."""


class GuardedHarness:
    def __init__(self, harness: Harness, policy: dict, *,
                 max_invocations_per_target: int | None = None):
        if max_invocations_per_target is not None and max_invocations_per_target < 1:
            raise ValueError("max_invocations_per_target debe ser >= 1")
        self._h = harness
        self._iter_caps: dict[str, int] = dict(policy["limits"]["max_loop_iterations"])
        self._iters: dict[str, int] = defaultdict(int)
        self._max_inv = max_invocations_per_target
        self._inv: dict[tuple[str, str], int] = defaultdict(int)

    @property
    def audit(self):
        return self._h.audit

    def begin_iteration(self, loop: str) -> int:
        """Registra el inicio de una iteración del loop; rechaza al llegar al tope."""
        cap = self._iter_caps.get(loop)
        if cap is not None and self._iters[loop] >= cap:
            raise LoopIterationLimit(f"loop '{loop}' alcanzó el tope de {cap} iteraciones")
        self._iters[loop] += 1
        return self._iters[loop]

    def invoke(self, agent: str, action: Action, target: str, token: ScopeToken) -> dict:
        if self._max_inv is not None:
            key = (action.name, target)
            if self._inv[key] >= self._max_inv:
                self._h.audit.record(agent, action, target, token, Result.BLOCKED)
                raise InvocationLimit(
                    f"tope de {self._max_inv} invocaciones para {action.name}@{target}"
                )
            self._inv[key] += 1
        return self._h.invoke(agent, action, target, token)
