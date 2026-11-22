## Requirements

Tests: `tests/test_relevo.py`.

### Scenario: El agente elige el siguiente control disponible
- GIVEN una sesión con un control ya observado
- WHEN Validación recibe el turno
- THEN el coordinador solo acepta una propuesta que todavía no fue ejecutada

### Scenario: Una sesión conserva su sandbox
- GIVEN una sesión nueva de Juice Shop
- WHEN se ejecutan varias comprobaciones aprobadas
- THEN todas usan la ruta de estado de sandbox de esa misma sesión y no crean un estado por comprobación
