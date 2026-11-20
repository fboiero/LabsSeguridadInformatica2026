# Delta — vuln-analysis

Tests: `tests/test_detection_loop.py`, `tests/test_adapters_004_005.py`, `tests/test_schemas.py`

## Requirement: Análisis de bajo impacto
El análisis DEBE usar ZAP baseline y templates GET revisadas; no debe ejecutar PoCs, enviar payloads de explotación ni usar OAST.

### Scenario: template fuera de allow-list
- GIVEN una plantilla no registrada o con hash distinto al manifiesto
- WHEN se construye el argv
- THEN se rechaza antes de ejecutar Nuclei

### Scenario: plantilla solo lectura
- GIVEN una plantilla registrada
- WHEN se revisa
- THEN todos sus requests son GET y no incluye interactsh/OAST ni matchers de explotación

## Requirement: Loop B acotado
El loop B DEBE detenerse al resolver el hallazgo, con dos iteraciones sin evidencia nueva o al alcanzar el tope de policy.

### Scenario: no hay nueva evidencia
- GIVEN dos iteraciones consecutivas sin referencias nuevas
- WHEN se evalúa continuar
- THEN el estado pasa a `inconclusive` y `decide_detection` devuelve `stop`

### Scenario: hallazgo resuelto
- GIVEN evidencia suficiente que confirma o descarta un candidato
- WHEN se evalúa continuar
- THEN el loop se detiene con estado y justificación explícitos

## Requirement: Prioridad reproducible sin CVSS inventado
El score DEBE combinar CVSS v4, EPSS y criticidad de forma determinista; si falta CVSS v4, no se debe producir un score numérico.

### Scenario: mismos insumos
- GIVEN los mismos valores presentes de CVSS v4, EPSS y criticidad
- WHEN se calcula prioridad
- THEN el resultado es estable y está en rango

### Scenario: CVSS v4 ausente
- GIVEN solo un CVSS v3.1 o ningún CVSS
- WHEN se calcula prioridad
- THEN `cvss_v4_score` y `priority` quedan `null`
