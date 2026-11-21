# Tasks — Change 004

## Spec y diseño
- [x] 1.1 `design.md`: schemas de salida, versionado del grafo, manejo de errores
- [x] 1.2 Deltas de `asset-discovery` y `tool-adapters`
- [x] 1.3 Revisión cruzada

## Implementación
- [x] 2.1 Grabar fixtures de salida de subfinder y httpx (contra el lab o sintéticas)
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
- [x] 3.5 Corrida real contra el lab y bitácora verificada con `audit verify`
- [x] 3.6 Archivar deltas en `openspec/specs/`


Evidencia 3.5: `entrega/evidencia/salidas/P3-real-04/` y `P3-real-verificacion.txt`.
Loop A real: 2 activos, 2 iteraciones, grafo estabilizado. Subfinder nativo
registra UNAVAILABLE por ausencia de fuentes locales; httpx sondea las semillas
autorizadas. `python -m harness.recon_lab audit verify` delega la verificación
del snapshot exportado en `harness.audit.verificar_cadena` de P1; no implementa
ni modifica su almacenamiento SQLite.

Revisión cruzada de P2: aceptada.

Archivado 3.6: deltas consolidados en `openspec/specs/asset-discovery/spec.md` y
`openspec/specs/tool-adapters/spec.md`. Registro de verificación: `archive.md`.
