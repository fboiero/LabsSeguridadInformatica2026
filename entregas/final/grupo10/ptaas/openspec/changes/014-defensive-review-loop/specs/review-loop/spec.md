## ADDED Requirements

Tests: `tests/test_review_loop.py`.

### Scenario: Elección iterativa con evidencia nueva
- GIVEN tarjetas saneadas de un caso
- WHEN el agente pide una referencia habilitada
- THEN el coordinador la incorpora y presenta el estado actualizado en la próxima vuelta

### Scenario: Tope, no progreso y escalado
- GIVEN decisiones repetidas, desconocidas o un presupuesto agotado
- WHEN se evalúa el próximo paso
- THEN se detiene y pasa a revisión humana sin ejecutar acciones sobre activos

### Scenario: Aprobación individual antes de usar Docker
- GIVEN una comprobación documental de catálogo
- WHEN falta autorización o corresponde a otra revisión
- THEN el sandbox no se inicia

### Scenario: Sandbox documental aislado y eliminado
- GIVEN una comprobación y su aprobación exacta
- WHEN termina el contenedor de revisión
- THEN se comprueba ausencia de rutas externas y que no queda ese contenedor
