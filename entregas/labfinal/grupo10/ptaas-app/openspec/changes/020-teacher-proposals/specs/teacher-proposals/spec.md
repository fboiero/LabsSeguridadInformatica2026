## Requirements

Tests: `tests/test_proposals.py`.

### Scenario: Propuestas docentes visibles pero no ejecutables
- GIVEN una propuesta de SQLi, XSS, upload, autorización o CAPTCHA
- WHEN se carga el catálogo de propuestas
- THEN está visible para los agentes, permanece no ejecutable y está marcada como pendiente de revisión docente

### Scenario: Una propuesta pendiente no llega al sandbox
- GIVEN un identificador que pertenece al catálogo de propuestas docentes
- WHEN Relevo recibe ese identificador como solicitud de ejecución
- THEN lo rechaza antes de iniciar el sandbox y el identificador no está en el catálogo ejecutable
