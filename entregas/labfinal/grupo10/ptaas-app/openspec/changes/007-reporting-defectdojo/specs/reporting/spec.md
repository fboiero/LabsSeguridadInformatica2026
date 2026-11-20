Tests: `tests/test_recon_correlation_reporting.py`

## Requirements

### Scenario: Campos obligatorios
- GIVEN un hallazgo sin CWE, CVSS v4 o remediación
- WHEN se arma el informe
- THEN se rechaza indicando el campo faltante

### Scenario: Estado de validación visible
- GIVEN un hallazgo validado
- WHEN se arma el informe
- THEN conserva `validated` en la salida

### Scenario: Gate de entrega
- GIVEN un informe pendiente
- WHEN falta aprobación o el hash no coincide
- THEN no se exporta

### Scenario: Exportación reproducible
- GIVEN aprobación ligada al hash del informe
- WHEN se exporta
- THEN el archivo contiene el mismo hallazgo y hash de origen
