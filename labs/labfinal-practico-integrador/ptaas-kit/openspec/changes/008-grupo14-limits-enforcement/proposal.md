# Change 008 — Aplicación de topes de iteración (grupo 14)

## Por qué
El red-team del grupo encontró una brecha entre la spec y la implementación:

- `policy.yaml` declara `limits.rate_limit_rps_per_target` y
  `limits.max_loop_iterations`.
- El delta de `asset-discovery` ya exige **"Loop de relevamiento acotado"** y
  **"Respeto del rate limit"** (Scenario "tope alcanzado": al llegar a
  `max_loop_iterations.recon` el harness DEBE rechazar otra iteración).
- Pero `Harness.invoke` **no aplica ningún tope**: un agente o un loop con bug
  puede invocar la misma acción contra el mismo objetivo sin límite.

Es un requisito ya especificado y no implementado. Sin él, el invariante de
contención no se cumple y un loop desbocado puede saturar un objetivo.

## Qué cambia
- Nuevo módulo `harness/limits.py` con `GuardedHarness`: decorador determinista
  que impone un tope de invocaciones por `(acción, objetivo)` **antes** de delegar
  en `Harness.invoke`.
- El bloqueo por tope se registra en la misma bitácora (`Result.BLOCKED`), igual
  que cualquier otra decisión (invariante I3).
- No cambia el contrato público de `Harness` (es aditivo, por composición).

## Criterios de aceptación
1. Con el harness MVP, N invocaciones repetidas pasan sin tope (test que
   documenta el hallazgo).
2. Con `GuardedHarness(max_iterations_per_target=k)`, la invocación `k+1` sobre el
   mismo objetivo se bloquea con `LimitExceeded` y queda en bitácora.
3. El contador es por `(acción, objetivo)`: objetivos distintos no se interfieren.

## Alcance / límites
- MVP: tope por conteo de iteraciones (determinista, sin reloj). El rate limit por
  segundo (`rps`) queda propuesto para un change siguiente (requiere ventana
  temporal); se deja anotado para no sobre-diseñar hoy.

## Evidencia
- `harness/limits.py`
- `tests/test_grupo14_redteam.py` (hallazgo + corrección + conteo por objetivo)
