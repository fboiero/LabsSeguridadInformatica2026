## Requirements

Tests: `tests/test_poc_catalog.py`, `tests/test_relevo.py`.

### Scenario: El agente propone una ruta nueva del dominio autorizado
- GIVEN una sesión de Juice Shop con Validación en el turno
- WHEN Validación devuelve un ID del catálogo y una ruta segura
- THEN el coordinador conserva el ID y la ruta para el gate humano

### Scenario: Una ruta fuera del dominio se rechaza
- GIVEN una propuesta con una ruta absoluta ajena o con secuencias de escape
- WHEN el coordinador valida la propuesta
- THEN la sesión se bloquea sin ejecutar ninguna consulta

### Scenario: El gate muestra la ruta exacta antes de ejecutar
- GIVEN una propuesta validada con ID y ruta
- WHEN la persona aprueba la consulta
- THEN el sender recibe exactamente esa ruta y no la ruta por defecto

### Scenario: Evaluadores de exposición devuelven validated
- GIVEN respuestas de solo lectura con los indicadores esperados
- WHEN se ejecutan las comprobaciones de `/ftp`, configuración, métricas, Swagger, CAPTCHA, productos, reseñas y catálogo de retos
- THEN cada evaluador marca el hallazgo como `validated`

### Scenario: Una ruta administrativa protegida no se reporta como hallazgo
- GIVEN una ruta administrativa que responde 401
- WHEN se evalúa la comprobación de acceso no autenticado
- THEN el resultado es `not_validated`

### Scenario: Rutas inseguras se rechazan antes del sender
- GIVEN una ruta con host externo, `..`, barra invertida o CRLF
- WHEN se valida el parámetro `path`
- THEN se lanza `ParameterError` y no se envía tráfico

### Scenario: La ruta elegida llega al sender
- GIVEN una comprobación de métricas con una ruta distinta de la predeterminada
- WHEN se ejecuta la comprobación aprobada
- THEN el sender recibe la ruta propuesta y el resultado se evalúa sobre esa respuesta
