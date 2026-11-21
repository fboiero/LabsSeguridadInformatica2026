# Tasks — Change 005

## Spec y diseño
- [x] 1.1 `design.md`: snapshots, confianza, contradicciones, política de templates
- [x] 1.2 Deltas de `correlation` y `vuln-analysis`
- [x] 1.3 Revisión cruzada — Martin Beccereca (P5), 2026-11-19: aprobado con observaciones (ver archive.md)

## Implementación — correlación
- [x] 2.1 Cliente de snapshot NVD (lectura offline) con tests
- [x] 2.2 Cliente de snapshot EPSS con tests
- [x] 2.3 `cwe.map` y normalización a ATT&CK cuando aplique
- [x] 2.4 Correlador que produce `CandidateFinding` con evidencia

## Implementación — análisis
- [x] 3.1 Adaptador `zap.baseline_scan` (fixtures + corrida contra el lab)
- [x] 3.2 Curar y revisar ≥ 5 templates en `templates/allowlist/` y completar `MANIFEST.md`
- [x] 3.3 Corrida de `nuclei.safe_templates` contra el lab
- [x] 3.4 Orquestación del loop B con `decide_detection`

## Verificación
- [x] 4.1 Test: candidato sin evidencia se rechaza
- [x] 4.2 Test: dato ausente → `null`/`unknown`
- [x] 4.3 Test: un template fuera de la allow-list no se ejecuta
- [x] 4.4 Test: dos iteraciones sin evidencia nueva → `inconclusive`
- [x] 4.5 Evals de correlación y análisis ampliadas (≥ 10 casos en conjunto)
- [x] 4.6 Archivar deltas en `openspec/specs/`


## Estado de verificaci?n P4

- Suite automatizada: 423 passed, 1 skipped.
- Evaluaciones golden: 32/32, incluyendo 10 de correlaci?n y 10 de an?lisis.
- Loop B probado con herramientas simuladas y Harness.
- Cinco templates Nuclei propuestos, pendientes de revisi?n humana.
- ZAP y Nuclei: corridas reales pendientes de autorizaci?n.
- Evaluaciones live no ejecutadas.
- Revisi?n cruzada y archivo de deltas pendientes.
- Las tareas marcadas representan implementaci?n o verificaci?n inicial, no aprobaci?n final del cambio.
