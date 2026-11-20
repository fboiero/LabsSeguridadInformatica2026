## ADDED Requirements

Tests: `tests/test_evidence_demo.py`, `tests/test_defectdojo.py`.

### Scenario: Cambian los bytes de un recibo revisado
- GIVEN un conjunto de recibos con una aprobación ligada al resumen
- WHEN cambia un recibo
- THEN la aprobación anterior no habilita la entrega local

### Scenario: Cambia un informe tras su revisión
- GIVEN un informe modificado que aún contiene el hash anterior
- WHEN se intenta exportar o publicar con la aprobación anterior
- THEN no se escribe el archivo ni se intenta la llamada HTTP

### Scenario: Regresión de procedencia
- GIVEN una regla de procedencia desactivada en el evaluador
- WHEN corren los casos de contrato
- THEN al menos un caso detecta la regresión por mutación aplicada
