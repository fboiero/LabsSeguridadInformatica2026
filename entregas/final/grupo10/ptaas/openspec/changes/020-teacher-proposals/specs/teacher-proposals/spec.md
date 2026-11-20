## Requirements

Tests: `tests/test_proposals.py`.

### Scenario: Propuestas docentes visibles pero no ejecutables
- GIVEN una propuesta de SQLi, XSS, upload, autorización o CAPTCHA
- WHEN se carga el catálogo de propuestas
- THEN está visible para los agentes, permanece no ejecutable y está marcada como pendiente de revisión docente
