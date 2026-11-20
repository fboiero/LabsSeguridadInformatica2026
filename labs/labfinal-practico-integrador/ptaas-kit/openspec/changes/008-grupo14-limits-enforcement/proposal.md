# Change 008 — Aplicación de topes de iteración (grupo 14)

## Por qué
El red-team del grupo encontró una brecha entre la spec y la implementación:

- El delta de `asset-discovery` exige **"Loop de relevamiento acotado"** (Scenario
  "tope alcanzado": al llegar a `max_loop_iterations.recon` **el harness** rechaza
  otra iteración).
- Pero las decisiones de parada viven en `harness/loops.py` (`decide_recon`, etc.)
  y son **consultivas**: el LLM puede ignorarlas y `Harness.invoke` no impone
  ningún tope. El requisito dice que *el harness* rechaza, no solo que el agente
  decida; ese enforcement no existía.
- Además, `policy.yaml` declara `rate_limit_rps_per_target`, que tampoco se aplica.

## Qué cambia
Nuevo módulo `harness/limits.py` con `GuardedHarness` (decorador determinista,
aditivo, no cambia el contrato público del harness):

1. **Tope de iteraciones de loop por fase** (`begin_iteration(loop)`), leído de
   `policy['limits']['max_loop_iterations']`. Cumple literalmente el requisito.
2. **Tope de invocaciones por `(acción, objetivo)`** como defensa en profundidad
   (opcional, no proviene de la spec), con el bloqueo registrado en bitácora
   (`Result.BLOCKED`, invariante I3).

## Criterios de aceptación
1. Al llegar a `max_loop_iterations[<loop>]`, `begin_iteration` rechaza con
   `LoopIterationLimit`.
2. Con `GuardedHarness(..., max_invocations_per_target=k)`, la invocación `k+1`
   sobre el mismo objetivo se bloquea con `InvocationLimit` y queda en bitácora.
3. El contador de invocaciones es por `(acción, objetivo)`.
4. Se mantiene un test de caracterización que muestra que, sin `GuardedHarness`,
   los loops no tienen enforcement (documenta el hallazgo).

## Alcance / límites
- El tope es por conteo (determinista, sin reloj). El rate limit por segundo
  (`rps_per_target`) requiere ventana temporal y queda para un change siguiente.
- `begin_iteration` existe para que el driver del loop lo invoque; en la demo se
  usa en el loop de recon. Integrarlo en los loops B/C queda anotado en tasks.

## Evidencia
- `harness/limits.py`
- `tests/test_grupo14_redteam.py` (hallazgo + corrección + conteo por objetivo)
