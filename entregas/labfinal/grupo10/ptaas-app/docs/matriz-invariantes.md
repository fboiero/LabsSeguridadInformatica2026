# Matriz global de invariantes del PTaaS

Referencia: I1–I8 del marco teórico del kit. «Verificado» significa verificado
para el perfil inerte del Grupo 10, no para un pentest real. Un archivo citado
no sustituye ejecutar sus tests ni una revisión independiente.

| ID | Invariante | Test y evidencia | Estado y límite |
|---|---|---|---|
| I1 | Un solo punto de ejecución: `Harness.invoke` | `tests/tool_adapters/test_audit_fail_closed.py::test_intento_confirmado_antes_de_ejecutar` y `::test_no_se_puede_guardar_intento_no_ejecuta`; `tests/test_roe.py::test_checkpoint_bundle_no_approval_then_inert_run` | Verificado para los dos recorridos inertes. Los consumidores de archivos no actúan sobre activos. |
| I2 | Guard determinista, sin LLM | `tests/tool_adapters/test_audit_fail_closed.py::test_controles_originales_se_conservan`; `tests/test_roe.py::test_harness_only_trusts_one_live_issued_token` | Verificado para alcance, allowlist, fase y emisor local. No es una frontera ante código hostil en el proceso. |
| I3 | OK, BLOCKED, PENDING_HITL y ABORTED auditables | `tests/tool_adapters/test_audit_fail_closed.py` (intento, controles originales, falta de aprobación y kill switch); `tests/audit_log/test_integrity.py`; `tests/audit_log/test_privacy.py` | Verificado en el harness. Sin anclaje externo no se prueba completitud. El exportador local conserva el hash en el artefacto, no en la cadena del engagement. |
| I4 | Token de corta vida y de una fase | `tests/test_roe.py::test_issuance_caps_ttl_and_uses_exclusive_end`, `::test_issuance_needs_operator_and_current_window` y `::test_harness_only_trusts_one_live_issued_token` | Verificado en las CLI con emisor, máx. 300 s y vencimiento exclusivo. |
| I5 | Gates humanos antes de actuar, validar y entregar | `tests/test_runtime.py::test_sin_aprobacion_cero_llamadas`; `tests/test_defensive_report.py::test_export_fails_closed` y `::test_export_is_local_bound_and_no_overwrite` | Parcial: inicio inerte y exportación defensiva local; no hay gate de validación de explotabilidad ni entrega real. |
| I6 | Kill switch primero y aborto del engagement | `tests/tool_adapters/test_audit_fail_closed.py::test_kill_switch_primero` | Parcial: bloquea nuevas invocaciones mientras está activo; no se acredita estado terminal persistente ni cancelación de una ejecución en curso. |
| I7 | Validación en sandbox efímero | `tools/attack-pilot-sandbox.ps1`; `tests/test_defensive_report.py::test_incomplete_report_not_validated` | Parcial: validación documental en Docker sin red y con entradas de solo lectura. No acredita el `Sender` del change 006. |
| I8 | Solo catálogo de verificaciones curadas | Sin validador de PoCs ni catálogo operativo en el perfil del grupo. `tests/tool_adapters/test_audit_fail_closed.py::test_controles_originales_se_conservan` cubre rechazo de adaptador ausente y acción destructiva. | No acreditado: no ejecutamos PoCs. MITRE cataloga comportamientos, no verificaciones. |

La matriz completa la trazabilidad de los ocho invariantes; no afirma que los
ocho estén implementados. El archivo definitivo de `002` y `003` requiere revisión
independiente e integración según sus listas de tareas. Una copia para revisión
no cambia esos estados.
