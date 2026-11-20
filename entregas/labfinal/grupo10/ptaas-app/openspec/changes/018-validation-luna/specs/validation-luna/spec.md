## Requirements

Tests: `tests/test_validation_model.py` y `tests/test_relevo.py`.

### Scenario: Validación usa el modelo dedicado
- GIVEN una solicitud para el agente Validación
- WHEN el proveedor resuelve el modelo
- THEN usa `openai/gpt-5.6-luna` y no el modelo de Análisis

### Scenario: Validación request aceptado
- GIVEN una solicitud estructurada para Validación
- WHEN se envía al proveedor
- THEN se resuelve con el modelo dedicado y devuelve texto estructurado para que el coordinador lo valide
