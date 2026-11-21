# Design — Change 009

## Decisión
La orquestación del recorrido es **código propio y determinista**
(`harness/pipeline.py`): etapas en orden, loops con las reglas de parada `decide_*`
y espera de las decisiones humanas registradas por la CLI. No se usa LangGraph.

## Alternativa descartada y costo asumido

| | Orquestación propia (elegida) | LangGraph (descartada por ahora) |
|---|---|---|
| Quién propone acciones | Reglas deterministas (ZAP, tabla de mapeo, catálogo) | Agentes LLM (`prompts/`) |
| Gates humanos | El proceso espera (polling, tope `--wait`); si se corta, la corrida se pierde | `interrupt()`: se pausa, guarda estado y se reanuda |
| Reanudación | No: se repite la corrida en un directorio nuevo | Sí, con checkpointer |
| Tests | Deterministas, sin API key ni costo | Requieren evals `--mode live` (API key, costo, variabilidad) |
| Dependencias | Ninguna nueva | `langgraph` + SDK del modelo |

**Costo asumido:** no hay pausa/reanudación de los gates ni agentes LLM proponiendo
acciones en runtime. Los prompts y schemas de los agentes existen y se evalúan en modo
golden, pero no participan de las corridas.

**Por qué ahora:** reproducibilidad (mismo resultado en cada corrida, tests sin API
key), y riesgo: incorporar agentes LLM antes de la entrega agrega variabilidad sobre un
recorrido que ya tiene evidencia real verificada.

**Qué NO es un argumento:** la invariante I2 exige que el *Guard* sea determinista,
no la orquestación. Con LangGraph el Guard seguiría igual; usarlo no violaría I2.

## Tests que muestran que no se perdió el control
El control vive en el harness, no en el orquestador; la orquestación propia lo
respeta, y estos tests lo prueban:
- Nada se aprueba solo: `tests/test_reporting_e2e.py::test_recorrido_sin_aprobacion_de_primera_accion`
  (sin decisión humana no se ejecuta ninguna herramienta y no queda ninguna aprobación escrita).
- Gate de análisis: `tests/test_analisis_real.py::test_sin_aprobacion_del_analisis_activo_no_corre_zap`.
- Gate por hallazgo: `tests/test_reporting_e2e.py::test_recorrido_hallazgo_sin_decision_no_se_envia`.
- Gate de entrega por hash: `tests/test_reporting_e2e.py::test_entrega_sin_aprobacion_queda_en_report`.
- Todo pasa por `Harness.invoke` y queda en la bitácora persistente:
  `tests/test_audit_persistence.py::test_harness_registra_en_la_bitacora_persistente`.

## Cómo se incorporaría LangGraph después
Reemplazando `pipeline.run` por un grafo cuyos nodos llamen a las mismas funciones
(`run_recon`, `run_detection_p4`, `run_validation_loop`, `build_report`) y cuyos
agentes propongan a través de `Harness.invoke`. Los gates pasan a `interrupt()`
leyendo el mismo `ApprovalStore`. El plano de control no cambia.
