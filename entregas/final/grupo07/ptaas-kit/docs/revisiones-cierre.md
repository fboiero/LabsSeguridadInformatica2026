# Revisión documental de cierre — 20/11/2026

Pedido de Lorenzo: leer las revisiones pendientes y darlas como válidas si son
documentales. Revisión realizada por Codex sobre la rama actualizada desde
85e2660; no se atribuye a Fernando, Lautaro ni Guadalupe una lectura que no hicieron.
Se validan las tareas 1.3 como revisión documental asistida a pedido del usuario.

| Change | Documentos y contraste | Resultado |
|---|---|---|
| 002 | design.md, audit-log/spec.md, audit.py y tests de persistencia | Válido para un archivo por engagement, hilos de una instancia y detección de alteración/borrado intermedio. |
| 003 | design.md, delta authorization, roe.py y tokens.py | Válido: exclusiones, TTL por fase, UTC y revocación. La huella identifica el RoE; no es firma criptográfica. |
| 004 | design.md, deltas asset-discovery/tool-adapters y loops/adaptadores | Válido: scope antes del probe, grafo versionado y paradas deterministas. |
| 005 | design.md, deltas correlation/vuln-analysis y adaptadores | Válido: snapshots offline, ausencia de datos explícita, cinco templates GET con hash y parada inconclusa. |
| 006 | design.md, deltas validation/poc-catalog, validation.py y sandbox.py | Válido: aprobación ligada al contenido, catálogo, restricciones y cleanup del worker. |
| 007 | design.md, delta reporting, run.py y report_bundle.py | Válido: evidencia del mismo engagement, informe versionado y gate separado de entrega. |

Límites conservados: concurrencia 002 de hilos de la misma instancia, sin garantía
multi-proceso ni ancla externa que detecte truncado final con hashes recalculados.
DefectDojo sigue siendo exportación JSON local. El candidato CSP de integración
sigue manual: las alertas de herramientas no confirman automáticamente una CVE.
Las decisiones de gates para las pruebas automatizadas se identifican como pruebas,
no como aprobaciones académicas de los compañeros.

El modo Docker añadido a 007 usa los mismos módulos de A/B, distingue procedencia,
no hace fallback a fixtures y mantiene SQLite y gates. Su evidencia de ejecución
se guarda por separado; marcar 1.3 no equivale a declarar una corrida realizada.
