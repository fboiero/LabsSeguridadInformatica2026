# Evidencia reproducible — checkpoint 1

Desde el directorio `ptaas`, con el entorno de desarrollo instalado:

```powershell
.\.venv\Scripts\python.exe -B -m runtime.checkpoint --approve-fixture --output runs/mi-checkpoint
.\.venv\Scripts\python.exe -B -m harness.audit verify runs/mi-checkpoint/audit.db
.\.venv\Scripts\python.exe -B -m evals.run_evals
.\tools\attack-pilot-sandbox.ps1
```

Sin `--approve-fixture` no hay acción. El comando con aprobación carga el RoE
YAML, emite un token y registra `ATTEMPT` → `OK` para el host exacto y `BLOCKED`
para el host no autorizado. En ambos casos los nombres son sintéticos: no hay
HTTP, DNS ni proveedor de modelos. Solo una invocación llega al contador inerte.

| Control revisado | Evidencia |
|---|---|
| Scope, ventana y fases | `tests/test_roe.py`: alcance vacío/público, destinos inválidos, cronología y fase no autorizada. |
| Emisión y uso del token | Mismo archivo: aprobación separada, TTL acotado, fin exclusivo y rechazo de tokens copiados/reemplazados. |
| Auditar ambos caminos | `test_checkpoint_bundle_no_approval_then_inert_run` y `test_harness_only_trusts_one_live_issued_token`. |
| Aislamiento | `tools/attack-pilot-sandbox.ps1`: pruebas con `--network none`, usuario no privilegiado y montaje de solo lectura. No es el sandbox del change 006. |

Resultado: 67 tests locales y 26 tests en Docker sin red. Los 21 evals offline
incluyen rechazo de orden incorrecto, campos añadidos, referencias ajenas,
alertas omitidas/duplicadas y CVE inventados. Esos negativos identifican qué
control interviene, pero no estiman la tasa de error de los modelos. Para una
evaluación posterior, comparar el mismo set antes/después de cualquier cambio de
modelo o prompt y registrar formato inválido, referencias erróneas y escalados.

No se acredita revisión humana ni autenticidad/completitud de la bitácora sin
anclaje externo. Los artefactos crudos se quedan fuera de Git.
