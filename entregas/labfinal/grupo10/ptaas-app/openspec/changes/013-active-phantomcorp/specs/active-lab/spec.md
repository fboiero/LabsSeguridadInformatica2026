## ADDED Requirements

Tests: `tests/test_active_phantomcorp.py`.

### Requirement: Recorrido activo estrictamente acotado
### Scenario: R1 a R4 en el laboratorio autorizado
- GIVEN un servicio local cuya identidad se fijó como `phantomcorp`
- WHEN el operador aprueba el engagement y el adaptador ejecuta las cuatro operaciones fijas
- THEN se registra evidencia de R1, R2, R3 y R4 en orden, sin aceptar destinos externos

### Scenario: Comando fuera del catálogo
- GIVEN un agente que intenta cambiar el comando de R4
- WHEN se invoca el adaptador
- THEN se bloquea antes de hacer la solicitud y queda registrado

### Scenario: Falla o respuesta inesperada
- GIVEN un paso que no devuelve el marcador esperado
- WHEN continúa el recorrido
- THEN se detiene, no ejecuta el siguiente paso y el estado queda `FAILED`

### Scenario: Evidencia sanitizada y reproducible
- GIVEN respuestas del laboratorio que contienen secretos o flags
- WHEN se persiste la corrida
- THEN se guarda un resumen con hashes y marcadores, no credenciales ni contenido crudo
