# Compatibilidad de 006/007 tras las corridas reales de Lorenzo

Corte: 20/11/2026, commits `41ad6b8` y `594cbd9`.
Revisión técnica asistida por Codex. No sustituye las revisiones humanas pendientes.

## Resultado

- No cambiaron `harness/` ni los contratos de 006/007 en estos dos commits.
- No fue necesario adaptar el código de validación, reporte o integración.
- `pytest.txt`: 152 tests aprobados sobre la rama actualizada.
- `evals-golden.txt`: 20/20 casos golden, sin modelo vivo.
- `progress.txt`: 002 0/14, 003 13/14, 004 13/15, 005 16/17, 006 13/15 y 007 12/15. Total de 002 a 007: 67/90 (74,4 %).
- `auditorias.json`: las tres cadenas JSON de las corridas de Lorenzo pasan `harness.run.verify_entries`.

## Alcance de la evidencia nueva

HTTPX identifica HTTP 302 y Apache 2.4.25 en DVWA. Nuclei registra una coincidencia informativa de robots.txt. ZAP contiene 11 tipos de alerta, incluida CSP ausente. Las ejecuciones usan `Harness.invoke`, tokens emitidos desde el RoE y Docker en red interna.

`tools/run_live_004_005.py` ejecuta adaptadores por separado. No reemplaza `fixture_runner` en `harness/team_pipeline.py`. Por tanto, la integración de A/B sigue usando fixtures y fuentes locales. El candidato F-CSP-001 sigue siendo manual: la evidencia nueva de ZAP no se propaga automáticamente al recorrido integrado.

La demo existente conserva su alcance. No se atribuye su resultado de cero CVE a la nueva salida HTTPX ni se considera validada una intrusión. La exportación continúa siendo JSON local, sin importación comprobada en DefectDojo.

## Cambios de documentación

Se corrigió la nota de la tarea 3.5 del 007: 004/005 ya estaban integrados con fixtures, y las corridas reales nuevas todavía son independientes. No se marcaron tareas adicionales como completadas.

En el material de exposición separado del repositorio se actualizaron las diapositivas 9, 11 y 12, sus notas y el guion completo. Se conservó el video sin audio: muestra el recorrido anterior con fixtures en A/B y comprobación real en C.

## Pendientes conservados

- Change 002: SQLite y `audit verify`.
- Revisión humana de Fernando sobre 004/005; esta revisión automatizada no la acredita.
- Revisión cruzada de Lautaro sobre 006/007 y archivado posterior.
- Recorrido integrado de A/B con herramientas reales y evidencia completa para cerrar 007 3.5.

No se ejecutaron escaneos nuevos para esta revisión: se verificaron las salidas guardadas y se repitieron tests/evals del código.
