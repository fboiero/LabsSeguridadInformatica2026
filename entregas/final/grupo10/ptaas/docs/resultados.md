# Resultados de la primera integración

## Alcance comprobado

Entrega en `entregas/final/grupo10/ptaas/`, derivada parcialmente del kit docente
`a1abb79`. No se editaron sus fuentes en `labs/`. No se hicieron escaneos,
pruebas contra terceros ni llamadas a herramientas reales de pentest.

El usuario informó el acuerdo del grupo con las specs y confirmó la primera
demo con OpenCode, datos sintéticos y un máximo de seis generaciones.
Esto documenta esa comunicación; no inventa identidades ni firmas de revisores.

## Verificaciones

| Verificación | Resultado |
|---|---|
| Suite original del profesor, ejecutada aparte | 77 tests aprobados |
| Evals golden originales | 10/10 casos aprobados |
| Suite propia de esta integración | 38 tests aprobados |
| Evals propias de contratos (sin modelos) | 8/8, incluyendo cuatro salidas negativas |
| Ruff | Sin errores |
| mypy estricto | Sin errores en harness, runtime, evals y tools |
| Demo real mediante OpenCode | Cuatro roles, cinco generaciones, una consulta simulada |
| Verificación del archivo de esa demo | Estructura válida, sin anclaje externo |
| Mutación: omitir ATTEMPT en memoria | El test del registro previo falla, como debe |

Los tests se escribieron antes de los módulos: la primera ejecución falló al
importar `harness`, todavía inexistente. No se afirma haber observado un fallo
individual de cada assertion antes de implementar. La mutación posterior sí
comprobó que romper el registro previo produce un fallo funcional.

Los resultados offline no prueban razonamiento real de una IA; la demo real sí
usó el proveedor conectado. Ninguna de estas comprobaciones reemplaza la
revisión por otro integrante ni demuestra el PTaaS completo.

## Qué hicieron los agentes reales

Artefactos locales: `runs/opencode-compatible/result.json`, `draft.json` y
`audit.db` (ignorados por Git). El modelo predeterminado consultado al comprobar
la conexión era `openai/gpt-6.2-astra`; no está fijado en el código.

1. Planificador: organizó reconocimiento, correlación e informe, con dos
   iteraciones máximas de reconocimiento.
2. Reconocimiento: propuso `httpx.probe` sobre `dvwa.lab.test`; el harness
   autorizó y el adaptador devolvió un activo **sintético**.
3. Reconocimiento: propuso `stop` porque el único objetivo ya había sido visitado.
4. Correlación: devolvió cero candidatos al no haber feeds de vulnerabilidades.
5. Informe: produjo un borrador marcado simulado y sin hallazgos confirmados.

La conclusión no fue "el objetivo es seguro", sino que no se analizaron ni
validaron vulnerabilidades reales. El estado final fue `PENDING_HITL`, gate
`before_deliver`: el modelo no aprobó su propia entrega.

La primera prueba real conservó siete eventos; después se agregó también el
registro explícito de la pausa final del coordinador. Esa mejora se verificó
offline, sin volver a gastar llamadas al modelo. No se alteró la base histórica.

## Problemas detectados durante el desarrollo

- La documentación actual de OpenCode muestra una ruta de generación diferente
  de la instalada en V2.0.32. El intento inicial falló antes de generar. Se
  consultó el OpenAPI local y se cambió al operation ID estable
  `experimental.generate.text`, sin usar una sesión con herramientas.
- Windows usa una codificación de consola que puede romper salidas Unicode.
  El verificador propio devuelve JSON portable; para ejecutar `tools/progress.py`
  del profesor se usa `python -X utf8`, sin editar ese archivo.
- La revisión técnica detectó que la pausa final debía aparecer también en la
  bitácora: se agregó y se comprobó mediante la demo offline y los tests.

Estas revisiones fueron del mismo asistente, **no una revisión independiente**.

## Correspondencia de escenarios con tests

Rutas relativas a esta entrega. Los parámetros de un test cubren casos separados.

### audit-log

| Scenario | Archivo / test |
|---|---|
| recuperación entre procesos | `tests/audit_log/test_persistence.py::test_recuperacion_entre_procesos` |
| commit fallido | `tests/audit_log/test_persistence.py::test_commit_fallido_sin_fallback` |
| archivos independientes | `tests/audit_log/test_persistence.py::test_archivos_independientes` |
| identidad incompatible | `tests/audit_log/test_persistence.py::test_identidad_incompatible` |
| modificación de registro intermedio | `tests/audit_log/test_integrity.py::test_modificacion_de_registro_intermedio` |
| borrado intermedio | `tests/audit_log/test_integrity.py::test_borrado_intermedio` |
| archivo ausente | `tests/audit_log/test_integrity.py::test_archivo_ausente_no_se_crea` |
| truncamiento final estructuralmente consistente | `tests/audit_log/test_integrity.py::test_truncamiento_final_declara_limite` |
| corrupción detectada desde el comando | `tests/audit_log/test_integrity.py::test_corrupcion_desde_comando_no_se_repara` |
| intento de edición o borrado SQL | `tests/audit_log/test_integrity.py::test_edicion_y_borrado_sql_rechazados` |
| dos escritores | `tests/audit_log/test_concurrency.py::test_dos_escritores_sin_perdidas` |
| bloqueo persistente | `tests/audit_log/test_concurrency.py::test_bloqueo_persistente_acotado` |
| secreto sintético en evidencia o error | `tests/audit_log/test_privacy.py::test_secreto_en_error_o_salida_no_se_persiste`, `test_salida_exitosa_no_se_copia_a_bitacora` |
| objetivo inválido con credenciales | `tests/audit_log/test_privacy.py::test_objetivo_invalido_con_credenciales` |

### tool-adapters

Todos en `tests/tool_adapters/test_audit_fail_closed.py`.

| Scenario | Test |
|---|---|
| ejecución autorizada con historial disponible | `test_intento_confirmado_antes_de_ejecutar` |
| no se puede guardar el intento | `test_no_se_puede_guardar_intento_no_ejecuta` |
| acción bloqueada o pendiente de aprobación | `test_controles_originales_se_conservan[scope]`, `test_sin_aprobacion_no_ejecuta` |
| kill switch activo | `test_kill_switch_primero` |
| excepción del adaptador | `test_error_adaptador_se_registra_sin_reintento` |
| herramienta termina pero falla el registro final | `test_fallo_final_o_doble_suspende[False]` |
| fallo doble de herramienta y bitácora | `test_fallo_final_o_doble_suspende[True]` |
| reinicio con intento sin desenlace | `test_reinicio_con_intento_pendiente` |

### agent-contracts

Todos en `tests/test_runtime.py`.

| Scenario | Test |
|---|---|
| coordinación con proveedor controlado | `test_coordinacion_con_contextos_separados` |
| propuesta fuera del objetivo | `test_propuesta_fuera_de_alcance_se_bloquea` |
| falta aprobación inicial | `test_sin_aprobacion_cero_llamadas` |
| dos respuestas inválidas | `test_dos_invalidas_escalan_sin_filtrar` |
| candidato inventado | `test_candidato_sin_fuente_es_rechazado` |
| presupuesto agotado | `test_presupuesto_global_incluye_reintentos` |
| proveedor no disponible | `test_proveedor_no_disponible_sin_fallback` |
| borrador terminado | `test_coordinacion_con_contextos_separados` |

Los tests de transporte también verifican que no se use un shell y que los
errores crudos del proveedor no se expongan.

## Límites y pendientes

- No hay anclaje externo: truncamiento final y reescritura completa siguen fuera
  de la garantía. Los triggers no protegen contra un administrador del archivo.
- Solo un coordinador de ejecución por auditoría. No se implementó un servicio
  multiusuario ni una recuperación aprobada por interfaz humana.
- Solo cuatro roles en una demo. No están los tres loops completos, el sandbox,
  feeds reales, RoE firmado, herramientas reales o exportación profesional.
- Los ocho casos propios son un punto de partida; no cumplen aún los veinte
  casos de evals que propone el nivel logrado de la rúbrica avanzada.
- Falta revisión independiente del código, PR y archivo del change.
# Piloto MITRE y ruteo por rol — 18/11/2026

- Corrida real en OpenCode: 5 generaciones en la demo de ruteo, sin Bandit en
  esa corrida, más 1 generación del piloto. No hubo escaneos. La demo quedó
  en `before_deliver`; MITRE, en `review_attack_mapping`.
- MITRE propuso T1110 solo para la serie sintética de fallos. El fallo aislado
  y la alerta estática sin logs quedaron como evidencia insuficiente.
- 49 tests locales, 10 evals offline, Ruff y mypy estricto pasaron. Los 8
  casos del piloto también pasaron en Docker sin red. Esto no acredita el
  sandbox del change 006 ni la revisión independiente.
