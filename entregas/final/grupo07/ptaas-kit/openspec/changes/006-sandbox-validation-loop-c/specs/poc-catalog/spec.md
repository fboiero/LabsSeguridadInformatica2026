# Delta — poc-catalog

Tests: tests/test_validation_flow.py

## Requirement: Selección vinculada
El id y CWE del catálogo DEBEN coincidir con el hallazgo; nuevos ids requieren change, revisión y aprobación.

### Scenario: El id no existe o el CWE difiere
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN el hallazgo queda no validado sin enviar tráfico
