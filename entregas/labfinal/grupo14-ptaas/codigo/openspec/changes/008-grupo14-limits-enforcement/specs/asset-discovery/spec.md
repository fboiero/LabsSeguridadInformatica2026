# Delta — asset-discovery (change 008)

## Requirement: Enforcement del tope de iteraciones a nivel de harness
El sistema DEBE rechazar una nueva iteración de loop cuando se alcanzó
`max_loop_iterations[<loop>]` de `policy.yaml`, de forma determinista y fuera del
control del agente. La decisión de parada de `decide_*` (en `harness/loops.py`) es
**consultiva**; el enforcement NO DEBE depender de que el agente la respete.

### Scenario: tope de iteraciones alcanzado
- GIVEN un loop que llegó a `max_loop_iterations.validation`
- WHEN se intenta iniciar otra iteración con `begin_iteration("validation")`
- THEN el harness la rechaza con `LoopIterationLimit`

## Requirement: Tope de invocaciones por objetivo (defensa en profundidad)
El sistema DEBERÍA acotar la cantidad de invocaciones de una misma acción sobre un
mismo objetivo, y registrar el bloqueo en la bitácora.

### Scenario: exceso de invocaciones por objetivo
- GIVEN un `GuardedHarness` con tope de k invocaciones por (acción, objetivo)
- WHEN se invoca la acción k+1 veces sobre el mismo objetivo
- THEN la invocación k+1 se bloquea con `InvocationLimit` y queda en bitácora

### Scenario: el tope es por objetivo
- GIVEN un tope de 1 invocación por (acción, objetivo)
- WHEN se invoca la misma acción sobre dos objetivos distintos
- THEN ambas pasan; recién la segunda invocación al primer objetivo se bloquea
