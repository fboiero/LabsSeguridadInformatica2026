# Revisión técnica previa al archivo

## Alcance

Esta revisión automatizada cubre los cambios locales 004, 005, 006, 007 y 015.
No se presenta como aprobación independiente de un Reviewer: esa firma debe
hacerla otra persona del grupo o la cátedra.

## Controles ejecutados

- `pytest -q`: suite completa.
- Ruff y mypy estricto.
- Evals golden/mutation del contrato de agentes.
- Prueba real de Juice Shop con `httpx.probe` y loop A.
- Prueba real de `POC-CSP-001` con Sender, gate HITL y sandbox.
- Ejecución de imágenes oficiales de Subfinder, httpx, Nuclei y ZAP mediante
  adaptadores y `Harness.invoke`.
- Snapshots NVD/EPSS descargados desde sus APIs oficiales, con fecha y SHA-256.

## Resultados y pendientes

- Subfinder: ejecutado en red interna; no encontró subdominios adicionales.
- httpx oficial: ejecutado contra el alias del laboratorio.
- Nuclei oficial: ejecutado con cinco templates locales allowlisted y sin
  Interactsh; produjo dos líneas de salida resumidas.
- Recorrido integrado A/B/C: completado contra Juice Shop con SQLite
  persistente, diez eventos verificables, gate HITL y limpieza de objetivo/red.
  Recibo: `runs/juice-integrated-20261118-220113.json`; bitácora:
  `runs/juice-integrated-20261118-220113.sqlite`.
- ZAP oficial: ejecutado, pero la imagen terminó con código 3 por no poder
  acceder al archivo de resumen `/tmp/zap_out.json`; no se acredita como scan
  exitoso hasta resolver ese problema de la imagen/ejecución.
- Recibo de esa corrida: `runs/juice-official-scans-final-20261118-212810.json`.
- DefectDojo: no hay instancia ni token provistos; el cliente queda fail-closed.

## Decisión de archivo

No archivar como aprobado hasta que un Reviewer independiente complete esta
lista, confirme la aceptación de Juice Shop y, si corresponde, provea la
instancia DefectDojo.
