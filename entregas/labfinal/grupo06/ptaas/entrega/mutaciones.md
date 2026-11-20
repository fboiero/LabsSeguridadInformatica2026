# Informe de mutaciones — controles evaluados

Cada mutación se aplicó sobre el código real, se ejecutó el test que debía
detectarla y se restauró el archivo original. Las salidas completas quedaron en
`entrega/evidencia/salidas/mutacion-M*.txt`.

| # | Control mutado | Mutación aplicada | Test que la detectó | Resultado |
|---|---|---|---|---|
| M1 | `Guard._in_scope` (`harness/contracts.py`) | `return True` al inicio | `test_activo_fuera_de_alcance...`, A2, A3 | 8 tests fallaron |
| M2 | Resta de exclusiones (`harness/tokens.py`) | Usar `scope_networks()` sin restar exclusiones | `test_exclusion_de_host_prevalece...` | 1 test falló |
| M3 | Validación de CIDR (`harness/roe.py`) | Devolver el CIDR sin comprobar prefijo ni laboratorio | `test_roe_con_cidr_...`, A8 | 10 tests fallaron |
| M4 | Ligadura a engagement (`Guard.is_allowed`) | Desactivar la comparación de `engagement_id` | `test_token_de_otro_engagement...`, A6 | 2 tests fallaron |
| M5 | Revalidación DNS (`Guard._resolves_in_scope`) | `return True` al inicio | A4 (fuera de alcance y mixta) | 2 tests fallaron |
| M6 | Validación de host en redirecciones (`RedirectPolicy`) | `_host_permitido` siempre `True` | A5 (host externo, protocol-relative, sufijo) | 3 tests fallaron |
| M7 | Validación de parámetros (`validate_parameters`) | Devolver los parámetros sin validar | A9 (`parameters`) | 5 tests fallaron |
| M8 | Lock de la bitácora (`AuditLog.record_decision`) | Quitar el lock y agregar 1 ms entre leer `prev` y append | A10 concurrente | La cadena se bifurcó (`prev=GENESIS` duplicado) |
| M9 | Fase autorizada (`tokens.issue`) | Desactivar el chequeo de `authorized_phases` | `test_roe_valido_emite_token_solo_de_la_fase_pedida` | 1 test falló |
| M10 (P5) | Parámetros que cambian el objetivo (`run_parametrized`, `harness/poc/catalog.py`) | No llamar a `_check_target_params` | `test_path_que_cambia_el_objetivo_se_rechaza` (6 casos), `test_param_name_con_caracteres_especiales_se_rechaza` (6 casos) | 12 tests fallaron |
| M11 (P5) | Aprobación humana del catálogo (`validate_entries`) | Desactivar el chequeo de `AGENT_APPROVERS` | `test_entrada_aprobada_por_un_agente_se_rechaza` (7 casos) | 7 tests fallaron |
| M12 (P5) | Recorrido de rutas (`_check_target_params`) | Quitar el rechazo de segmentos `..` | `test_path_que_cambia_el_objetivo_se_rechaza[/../../etc/passwd]` y `[/a/../../b]` | 2 tests fallaron |
| M13 (P5) | Segunda barrera de host (`SandboxSender._lab_host`, `harness/sandbox.py`) | `if not ok:` → `if False:` | `test_objetivo_fuera_del_lab_se_rechaza_antes_del_contenedor`, `test_esquema_o_url_no_permitidos` (gopher, ftp) | 3 tests fallaron |
| M14 (P5) | Destrucción del contenedor (`SandboxAdapter.run`) | `finally:` → `except ZeroDivisionError:` | `test_verificacion_finalizada_destruye_el_contenedor`, `test_fallo_del_runtime_destruye_igual_y_no_valida`, `test_evaluador_que_falla_...`, `test_si_la_destruccion_falla_...`, `test_timeout_...` | 5 tests fallaron |
| M15 (P5) | Gate HITL por hallazgo (`ApprovalStore.is_approved`, `harness/validation.py`) | Devolver siempre `True` | `test_sin_aprobacion_queda_pendiente_y_no_envia`, `test_parametros_cambiados_...`, `test_otra_verificacion_...`, `test_token_vencido_...` | 4 tests fallaron |
| M16 (P5) | Ligadura de la aprobación a los parámetros (`is_approved`) | No comparar `approved_hash` | `test_parametros_cambiados_despues_de_aprobar` | 1 test falló |
| M17 (P5) | Consistencia entre intentos (`_validate_one`) | No detectar resultados distintos | `test_intentos_contradictorios_no_validan` | 1 test falló |
| M18 (P5) | Estado respaldado por la bitácora (`_from_log`, `harness/report_builder.py`) | Aceptar `validated` declarado sin registro del loop C | `test_validado_declarado_sin_respaldo_falla`, `test_validado_declarado_con_resultado_negativo_...` | 2 tests fallaron |
| M19 (P5) | Verificación de la cadena (`_verified_entries`) | No rechazar una bitácora alterada | `test_bitacora_alterada_no_genera_informe` | 1 test falló |
| M20 (P5) | Referencias de evidencia (`_from_log`) | Aceptar hashes que no están en la bitácora | `test_referencia_inexistente_falla` | 1 test falló |
| M21 (P5) | Aprobación de entrega ligada al hash (`deliver_report`) | Usar cualquier aprobación registrada | `test_aprobacion_de_otra_version_se_rechaza` | 1 test falló |
| M22 (P5) | Bloqueo de informes DEMO (`deliver_report`, `export`) | Desactivar el chequeo de `demo` | `test_informe_demo_no_se_entrega_ni_exporta` | 1 test falló |
| M23 (P5) | Datos sensibles (`_check_sensitive`) | No buscar patrones | `test_dato_sensible_falla_indicando_patron_y_hallazgo` (6 casos) | 6 tests fallaron |
| M24 (P5) | Exportar solo entregados (`harness/defectdojo_export.py`) | Desactivar el chequeo de `delivered` | `test_exportar_un_informe_no_entregado_se_rechaza` | 1 test falló |
| M25 (P5) | Gate de primera acción activa (`harness/pipeline.py`) | No esperar la aprobación | `test_recorrido_sin_aprobacion_de_primera_accion` | 1 test falló |
| M26 (P5) | Candidatos sobre activos no relevados (`pipeline.run`) | No descartarlos | `test_recorrido_descarta_candidatos_fuera_de_lo_relevado` | 1 test falló |
| M27 (P5) | Evidencia previa (`pipeline.run`) | Aceptar un directorio de salida existente | `test_recorrido_no_sobrescribe_salida_existente` | 1 test falló |
| M28 (P5) | Informe DEMO en el recorrido (`pipeline.run`) | Seguir el camino de entrega | `test_recorrido_con_analisis_simulado_sale_demo` | 1 test falló |
| M29 (P5) | Verificación de la evidencia exportada (`verify_evidence`) | Devolver siempre válido | `test_verificacion_detecta_bitacora_exportada_alterada` | 1 test falló |
| M30 (P5) | Gate `active_analysis` (`harness/pipeline.py`, change 008) | No esperar la aprobación | `test_sin_aprobacion_del_analisis_activo_no_corre_zap` | 1 test falló |
| M31 (P5) | Aprobación humana de la tabla de mapeo (`load_mapping`) | No exigir `approved_by` | `test_tabla_sin_aprobacion_se_rechaza`, `test_tabla_aprobada_por_agente_se_rechaza` | 2 tests fallaron |
| M32 (P5) | Reporte de ZAP acotado al objetivo (`check_report_scope`) | No controlar el host | `test_instancia_fuera_del_objetivo_se_rechaza`, `test_reporte_de_zap_fuera_del_objetivo_aborta` | 2 tests fallaron |
| M33 (P5) | Exclusión de alertas informativas (`findings_from_alerts`) | No filtrar riesgo 0 | Primera corrida: **sobrevivió** (test débil). Con el test corregido: `test_alerta_informativa_no_genera_hallazgo` | 1 test falló tras corregir el test |
| M34 (P5) | Descarte de alertas sin mapeo (`findings_from_alerts`) | Incluirlas con un vector inventado | `test_alerta_sin_mapeo_se_descarta_con_el_plugin`, `test_recorrido_con_analisis_real_entrega_y_exporta` | 2 tests fallaron |
| M35 (P5) | Identidad de hallazgos sin verificación (`_from_log`, `report_builder.py`) | Volver a usar `poc_id` aunque no esté en el catálogo | `test_alertas_distintas_sin_verificacion_no_se_unifican`, `test_hallazgo_sin_verificacion_no_muestra_un_poc_inexistente` | 2 tests fallaron |
| M36 (P5, 002) | Triggers append-only (`harness/audit.py`) | Los triggers ya no abortan UPDATE/DELETE | `test_update_directo_es_rechazado_por_la_base`, `test_delete_directo_es_rechazado_por_la_base` | 2 tests fallaron |
| M37 (P5, 002) | Verificación de la cadena en SQLite (`SQLiteAuditStore.verify`) | No recorrer la cadena | `test_cadena_corrupta_al_abrir_no_acepta_registros`, `test_cli_verify_detecta_alteracion` | 2 tests fallaron |
| M38 (P5, 002) | Atomicidad del `append` | `BEGIN` diferido en lugar de `BEGIN IMMEDIATE` | `test_escrituras_concurrentes_no_bifurcan_la_cadena` | 1 test falló |
| M39 (P5, 002) | Aislamiento por engagement | Aceptar eventos de otro engagement | `test_archivo_de_otro_engagement_rechaza_el_evento` | 1 test falló |
| M40 (P5, 002) | Cadena corrupta al abrir | Seguir aceptando registros | `test_cadena_corrupta_al_abrir_no_acepta_registros` | 1 test falló |
| M41 (P5, 002) | Ancla de cabeza | No comparar el ancla | `test_ancla_detecta_borrado_del_ultimo_registro`, `test_cli_verify_con_ancla` | 2 tests fallaron |
| M42 (P5, revisión de P4) | Filtro de datos sensibles sobre el motivo de la bitácora (`report_builder._from_log`) | Quitar el chequeo de `reason` | `test_dato_sensible_en_el_motivo_de_la_bitacora_se_rechaza` (3 casos) | 3 tests fallaron |
| M43 (P5, I1) | Único camino (`tests/test_invariantes.py`) | Agregar en `harness/loops.py` una llamada directa a `subprocess.run(["nmap", ...])` | `test_i1_ninguna_herramienta_de_seguridad_se_ejecuta_fuera_de_un_adaptador` (señala archivo y línea) | 1 test falló |
| M44 (P5, I6) | Kill switch en `Harness.invoke` (`harness/contracts.py`) | No chequear `killswitch.engaged` | `test_kill_switch_aborta_sin_ejecutar`, `test_kill_switch_aborta_sin_contenedor` | 2 tests fallaron |

## Detalle de las mutaciones más relevantes

### M1 — El control de alcance (`_in_scope` en `True`)

Salida (resumen):

```text
FAILED tests/test_authorization.py::test_activo_fuera_de_alcance_se_bloquea_y_registra
FAILED tests/test_authorization.py::test_dominio_y_subdominio_en_alcance_pero_no_sufijo_enganoso
FAILED tests/test_redteam_guard.py::test_a2_sufijo_enganoso_se_bloquea[...] (4 casos)
FAILED tests/test_redteam_guard.py::test_a3_ipv4_mapeada_a_ipv6...
FAILED tests/test_redteam_guard.py::test_a3_ipv6_se_evalua_contra_su_cidr
8 failed, 45 passed
```

Restaurado: `53 passed`. Evidencia: `mutacion-M1-in_scope.txt`.

### M8 — Concurrencia de la bitácora

Sin lock y con una pausa entre leer el último hash y agregar el registro, dos
hilos tomaron el mismo `prev`:

```text
AssertionError: assert 'GENESIS' == '103e5543cab8...'
FAILED tests/test_redteam_guard.py::test_a10_escritura_concurrente_conserva_la_cadena
```

Con el lock restaurado: `1 passed`. Evidencia: `mutacion-M8-concurrencia.txt`.

### M10 a M12 — Controles del catálogo (P5, change 006)

Se mutó `harness/poc/catalog.py` y se corrieron los tests del catálogo
(`-k 'path or param_name or entrada or parametros_validos or test_poc_catalog'`).
La línea base tiene 1 fallo esperado
(`test_entrada_agregada_al_archivo_durante_el_loop_no_se_usa`, que depende de
`harness.validation`, todavía no implementado); cada mutación suma los fallos de
la tabla. El archivo se restauró y se comprobó con `cmp` que quedó idéntico.
Evidencia: `mutacion-P5-catalogo.txt`.

### M13 a M17 — Sandbox y loop C (P5, change 006)

Se mutaron `harness/sandbox.py` y `harness/validation.py` y se corrió
`tests/test_sandbox_loop_c.py` completo. Línea base: `62 passed, 1 skipped`
(el salteado es la prueba con Docker real). Cada mutación rompió al menos un
test y los dos archivos se restauraron y se compararon con `cmp`.

En M13 fallan solo los casos que el Guard no frena por su cuenta (`example.com`
con un token que lo incluye a propósito, `gopher://` y `ftp://`): `file://`,
`http://` sin host y la URL sin esquema los bloquea también el Guard. Es la
defensa en profundidad prevista en `design.md` (decisión 2).
Evidencia: `mutacion-P5-sandbox-loopc.txt`.

### M18 a M24 — Informe, entrega y exportación (P5, change 007)

Se mutaron `harness/report_builder.py` y `harness/defectdojo_export.py` y se
corrió `tests/test_reporting_e2e.py`. Línea base: `38 passed`. Cada mutación
rompió al menos un test; los archivos se restauraron y se compararon con `cmp`.
Evidencia: `mutacion-P5-007.txt`.

### M25 a M29 — Recorrido de un comando (P5, change 007 · 3.5)

Se mutó `harness/pipeline.py` y se corrieron los tests del recorrido
(`-k 'recorrido or verificacion'`). Línea base: `8 passed`. Cada mutación rompió
el test de su control; el archivo se restauró y se comparó con `cmp`.
En M26 no hay otra barrera: el Guard y el Sender aceptan `otro.dvwa.lab.test`
porque es un subdominio autorizado del lab. El único control que impide validar
un activo que el recon no relevó es el descarte del recorrido.
Evidencia: `mutacion-P5-007-recorrido.txt`.

### M30 a M34 — Análisis real en el recorrido (P5, change 008)

Se mutaron `harness/pipeline.py` y `harness/zap_analysis.py` y se corrió
`tests/test_analisis_real.py`. Línea base: `14 passed`. **M33 sobrevivió en la
primera corrida:** el test usaba la alerta 10111, que no trae CWE, y la descartaba
otra regla; el control de riesgo 0 no estaba probado. Se corrigió el test para
usar la 10027 (riesgo 0 con CWE 615) y la mutación pasó a detectarse. Es el caso
que la rúbrica describe: si una mutación no rompe nada, falta un test.
Evidencia: `mutacion-P5-008.txt`.

### M36 a M41 — Bitácora persistente (change 002, P5 a pedido de P1)

Se mutó `harness/audit.py` y se corrió `tests/test_audit_persistence.py`. Línea
base: `20 passed`. Cada mutación rompió al menos un test y el archivo se restauró
y se comparó con `cmp`. En M38 solo se aplicó el cambio de `BEGIN IMMEDIATE`; la
restricción `UNIQUE(prev)` quedó intacta (el reemplazo no coincidió con la
sangría) y aun así la escritura concurrente falló. Evidencia: `mutacion-P5-002.txt`.

## Lo que no se mutó y por qué

- `harness/reporting.py` (gates 007 · 3.1 y 3.3) es propiedad de P5. Los tests
  nuevos pasan contra el código existente (`red-007-gates.txt`), pero la
  mutación de ese control queda a cargo de P5 para no pisar su archivo.
- `harness/audit.py` (P1) no se modificó. La prueba A10 se hizo sobre
  `AuditLog` de `contracts.py`, que es la ruta que usa `Harness.invoke`. Una
  prueba de estrés manual de `InMemoryAuditStore` con 500 escrituras concurrentes
  dio cadena válida en esta corrida, pero no es una garantía formal; P1 debe
  cubrir la concurrencia de la implementación SQLite en 002 · 3.4.
