## ADDED Requirements

Tests: `tests/test_defensive_report.py`.

### Requirement: Validar un artefacto, no la explotabilidad
### Scenario: Evidencia estática preexistente
- GIVEN un informe Bandit local, legible y completo
- WHEN el operador genera un borrador sin red
- THEN solo salen referencias y metadatos sanitizados, nunca hallazgos confirmados

### Scenario: Evidencia incompleta
- GIVEN un informe con errores de análisis
- WHEN se intenta generar un borrador
- THEN no se emite un borrador válido

### Requirement: Exportación local con conformidad explícita
### Scenario: Falta aprobación o cambiaron los datos
- GIVEN ningún hash de aprobación, un borrador modificado o evidencia distinta
- WHEN se solicita exportar
- THEN la exportación no se escribe

### Scenario: Aprobación ligada a un borrador exacto
- GIVEN el hash del borrador aprobado por el operador y el artefacto original
- WHEN se solicita exportar
- THEN se escribe un JSON local nuevo con trazabilidad, sin publicarlo
