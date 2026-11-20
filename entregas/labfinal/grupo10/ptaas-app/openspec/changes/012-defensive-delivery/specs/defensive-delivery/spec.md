## ADDED Requirements

Tests: `tests/test_delivery.py`.

### Requirement: Validación documental del paquete
### Scenario: El borrador referencia solo evidencia conocida
- GIVEN un borrador pendiente con trazas de R1–R4
- WHEN el validador documental verifica el paquete
- THEN solo acepta referencias conocidas y ningún hallazgo confirmado

### Scenario: Una decisión no respaldada bloquea la entrega
- GIVEN una conclusión inventada, referencias cruzadas o análisis rechazado
- WHEN se verifica la consistencia
- THEN no se habilita la exportación

### Requirement: Exportación local ligada al contenido revisado
### Scenario: Sin aprobación o con bytes distintos
- GIVEN un hash faltante o distinto del informe y sus decisiones
- WHEN se solicita exportar
- THEN se rechaza

### Scenario: Formato genérico sin hallazgos inventados
- GIVEN un paquete consistente y un hash aprobado por una persona
- WHEN se genera la exportación
- THEN se emite un JSON local Generic Findings Import con cero hallazgos confirmados y sin publicar
