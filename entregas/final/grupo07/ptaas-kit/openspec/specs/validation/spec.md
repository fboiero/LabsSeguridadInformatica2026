# Delta — validation

Tests: tests/test_authorization.py, tests/test_poc_catalog.py, tests/test_validation_flow.py

## Requirement: Solo catálogo curado
La validación DEBE limitarse a PoCs del catálogo versionado y aprobado, ajustando solo parámetros del activo.

### Scenario: PoC fuera del catálogo
- GIVEN un hallazgo priorizado sin PoC en el catálogo
- WHEN el agente de validación intenta proceder
- THEN la validación no se ejecuta y el hallazgo queda "no validado"

## Requirement: Gate humano por hallazgo
La validación DEBE requerir aprobación del Reviewer por cada hallazgo.

### Scenario: sin aprobación
- GIVEN un hallazgo sin aprobación del Reviewer
- WHEN se invoca la validación
- THEN el resultado es PENDING_HITL y no se ejecuta nada

## Requirement: Sandbox efímero
La validación DEBE ejecutarse en un sandbox aislado, sin persistencia ni acceso a datos reales.

### Scenario: fin de la validación
- GIVEN una validación finalizada
- WHEN el sandbox termina
- THEN el entorno es destruido y solo queda la evidencia en la bitácora

## Requirement: Gate ligado al hallazgo
Sin aprobación vigente para id, activo, PoC y parámetros exactos, la validación DEBE devolver PENDING_HITL sin llamar al Sender.

### Scenario: Se cambia un parámetro después de aprobar
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN la ejecución no se ejecuta y requiere nueva aprobación

## Requirement: Loop C acotado
El loop DEBE usar decide_validation con máximo dos intentos y registrar selección, versión y resultado sin respuestas crudas.

### Scenario: Falla el Sender
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN se registra BLOCKED y se libera el Sender

## Requirement: Sender restringido (recorte)
El Sender DEBE aceptar solo hosts exactos del lab y direcciones DNS dentro del CIDR autorizado, sin proxies ni redirecciones. Este recorte no constituye un contenedor aislado.

### Scenario: DNS resuelve fuera del lab o hay redirección
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN no se sigue la solicitud externa

## Requirement: Límites
Cada Sender DEBE limitar timeout, bytes y solicitudes y cerrarse incluso ante excepciones.

### Scenario: Se excede un límite
- GIVEN el proyecto en modo laboratorio
- WHEN ocurre el caso descrito
- THEN se rechaza sin persistir respuestas

## Requirement: Contenedor efímero sobre red interna
El modo sandbox DEBE comprobar que la red Docker es internal y del laboratorio,
ejecutar un worker read-only sin privilegios y eliminarlo al terminar o fallar.

### Scenario: red Docker pública
- GIVEN una red Docker que no es internal
- WHEN se crea una validación
- THEN se rechaza sin ejecutar worker

### Scenario: worker falla
- GIVEN un worker en ejecución
- WHEN devuelve error o timeout
- THEN se elimina el worker y no queda estado
