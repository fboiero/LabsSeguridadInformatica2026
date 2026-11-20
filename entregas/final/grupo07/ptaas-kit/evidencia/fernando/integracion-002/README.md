# Integración de la bitácora SQLite en 006/007

Corte 20/11/2026 tras recibir `b8a6a46` de Lautaro. Trabajo asistido por Codex;
las revisiones humanas y archivados pendientes no se acreditan con esta corrida.

## Cambios

`harness.run.execute` utiliza `SqliteAuditLog` de 002. La ruta se determina con
el SHA-256 del engagement_id dentro de output, conserva entradas al reabrir,
rechaza cadenas corruptas o de otro engagement antes de ejecutar el pipeline y
cierra la conexión en finally. Se conserva la exportación JSON y ambos gates.
`team_pipeline.PROVENANCE` identifica ahora SQLite y la CLI de verificación.

## Verificación

- `pytest-red.txt`: cuatro tests nuevos fallaron antes de la implementación.
- `pytest.txt`: 166 tests aprobados después de conectar 002.
- `evals-golden.txt`: 20/20 con datos guardados, sin LLM vivo.
- `ruff.txt`: archivos modificados sin errores.
- `mypy.txt`: el control estricto completo sigue con 39 errores en ocho archivos sin cambios en esta integración (reporting, adapters/common, contracts, roe, policy_loader, adapters/nmap_adapter, tokens y poc/catalog). Ningún diagnóstico está en run.py o team_pipeline.py; no se declara aprobado este control.
- `progress.txt`: 80/90 tareas de 002 a 007 (88,9 %), sin marcar revisiones nuevas.
- `demo-pending.txt`: sin aprobaciones, validación y entrega PENDING_HITL; SQLite verifica.
- `demo-sandbox-ok.txt`: validación real en DVWA `validated`, entrega `exported_local_json`, SQLite verifica.
- `audit-verify.txt`: archivo sano OK/exit 0; copia alterada CORRUPTA/exit 1.
- `sqlite-summary.json`: reapertura con 21 registros persistidos y cadena sana.

La primera inicialización del worker Docker agotó el timeout de 15 segundos.
Se conservó esa salida parcial en `demo-sandbox.txt`; el reintento sobre otra
salida terminó correctamente sin aumentar límites ni cambiar el sandbox.
El worker temporal se eliminó y la bitácora se cerró también en ese fallo.

## Repetir

Desde la raíz del kit y con RoE vigente:

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe evals/run_evals.py --mode golden
.venv/Scripts/python.exe tools/progress.py
.venv/Scripts/python.exe -m harness.run --roe roe/roe-lab.example.yaml --output .demo-output-002-pending
.venv/Scripts/python.exe -m harness.audit verify <ruta-audit-db-impresa-por-run>
```

Las aprobaciones de la corrida sandbox se declaran como prueba automatizada,
no revisión académica final. Se limita a DVWA del lab. A/B continúan con
fixtures y el candidato CSP manual; las herramientas reales de Lorenzo se
probaron por separado. DefectDojo permanece como exportación JSON local.

Persistencia y concurrencia conservan el alcance de 002: una instancia por
archivo/proceso y soporte multi-hilo, sin garantía de múltiples procesos escritores.
