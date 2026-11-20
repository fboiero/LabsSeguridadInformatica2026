## ADDED Requirements

Tests: `tests/test_poc_catalog.py`.

### Scenario: Catálogo válido y solo de laboratorio
- GIVEN el catálogo versionado del grupo
- WHEN se carga
- THEN todas las entradas son `inert_check`, `lab_only` y tienen aprobación registrada

### Scenario: ID o parámetro fuera del catálogo
- GIVEN una selección de agente con ID inexistente o parámetro extra
- WHEN se intenta enviar
- THEN se rechaza antes del sender

### Scenario: Gate por hallazgo
- GIVEN una entrada válida sin aprobación del Reviewer
- WHEN se intenta ejecutar
- THEN no se envía tráfico

### Scenario: Canario inerte
- GIVEN un endpoint del laboratorio que refleja un valor
- WHEN se usa la verificación de reflexión
- THEN el canario no contiene marcado ejecutable y solo se observa si aparece sin codificar
