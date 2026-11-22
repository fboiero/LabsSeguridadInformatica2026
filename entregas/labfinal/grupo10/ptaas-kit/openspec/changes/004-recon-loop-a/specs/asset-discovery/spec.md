# Delta — asset-discovery (Change 004: Loop A integrado)

Tests: `tests/asset_discovery/test_loop_a.py`

## Requirement: Orquestación integrada del Loop A
El sistema DEBE ejecutar el Loop A mediante `Harness.invoke`, respetando el orden pasivo → activo, deduplicando activos entre iteraciones, aplicando rate limit y deteniéndose cuando `decide_recon` indica grafo estabilizado o tope de iteraciones.

### Scenario: loop A termina por grafo estabilizado
- GIVEN un alcance autorizado y adaptadores de recon pasivo y activo registrados en el harness
- WHEN una iteración posterior no descubre activos nuevos respecto al `AssetGraph` vigente
- THEN el Loop A se detiene con motivo `"grafo estabilizado"` sin re-sondear activos ya inventariados

### Scenario: loop A termina por tope de iteraciones
- GIVEN un generador de activos que sigue aportando descubrimientos en cada ronda y un `max_iterations` acotado
- WHEN se alcanza el tope configurado en `policy.yaml`
- THEN el Loop A se detiene con motivo `"tope de iteraciones alcanzado"`

### Scenario: descubrimiento fuera de alcance registrado y bloqueado en Loop A
- GIVEN un resultado de `subfinder.enum` que incluye un dominio fuera del `ScopeToken`
- WHEN el Loop A procesa los candidatos para sondeo activo
- THEN el dominio fuera de alcance queda registrado en `AssetGraph.out_of_scope` con evento `BLOCKED` en la bitácora y nunca llega al adaptador activo
