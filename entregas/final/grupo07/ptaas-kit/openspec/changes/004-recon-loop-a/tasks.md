# Tasks — Change 004

## Spec y diseño
- [x] 1.1 `design.md`: schemas de salida, versionado del grafo, manejo de errores
- [x] 1.2 Deltas de `asset-discovery` y `tool-adapters`
- [x] 1.3 Revisión documental asistida por Codex, validada a pedido de Lorenzo (docs/revisiones-cierre.md)

## Implementación
- [x] 2.1 Grabar fixtures sintéticas de salida de subfinder y httpx
- [x] 2.2 `harness/adapters/subfinder_adapter.py` con tests de argv y de salida
- [x] 2.3 `harness/adapters/httpx_adapter.py` con tests de argv y de salida
- [x] 2.4 Modelo `AssetGraph` y persistencia
- [x] 2.5 Orquestación del loop A usando `decide_recon`
- [x] 2.6 Descubrimientos fuera de alcance: registrar y no sondear

## Verificación
- [x] 3.1 Test: loop A termina por grafo estabilizado
- [x] 3.2 Test: loop A termina por tope
- [x] 3.3 Test: un activo fuera de alcance nunca llega a un adaptador
- [x] 3.4 Test: el adaptador respeta el rate limit
- [ ] 3.5 Corrida real contra el lab y bitácora verificada con `audit verify` (pendiente: Docker apagado y change 002)
- [x] 3.6 Archivar deltas en `openspec/specs/`
