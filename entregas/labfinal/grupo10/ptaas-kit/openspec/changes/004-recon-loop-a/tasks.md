# Tasks — Change 004

## Spec y diseño
- [x] 1.1 `design.md`: schemas de salida, versionado del grafo, manejo de errores
- [x] 1.2 Deltas de `asset-discovery` y `tool-adapters`
- [x] 1.3 Revisión cruzada (`openspec/reviews/20261120-juan-turno3.md`)

## Implementación
- [x] 2.1 Grabar fixtures de salida de subfinder y httpx (`fixtures/recon/`)
- [x] 2.2 `harness/adapters/subfinder_adapter.py` con tests de argv y de salida
- [x] 2.3 `harness/adapters/httpx_adapter.py` con tests de argv y de salida
- [x] 2.4 Modelo `AssetGraph` y persistencia/versionado (`harness/loop_a.py`)
- [x] 2.5 Orquestación del loop A usando `decide_recon`
- [x] 2.6 Descubrimientos fuera de alcance: registrar y no sondear

## Verificación
- [x] 3.1 Test: loop A termina por grafo estabilizado
- [x] 3.2 Test: loop A termina por tope
- [x] 3.3 Test: un activo fuera de alcance nunca llega a un adaptador
- [x] 3.4 Test: el adaptador respeta el rate limit
- [x] 3.5 Corrida real contra el lab y bitácora verificada con `audit verify` *(corrida ejecutada desde el contenedor `runner` contra `dvwa.lab.test` y `juiceshop.lab.test` en red interna `internal: true`, con evidencia y bitácora verificada en `entregas/labfinal/grupo10/evidencia/ptaas/`; adicionalmente se conservó la corrida `--mode fixture` en `evidencia/ptaas/fixture/`)*
- [ ] 3.6 Archivar deltas en `openspec/specs/` *(pendiente de cierre/merge del PR del equipo)*
