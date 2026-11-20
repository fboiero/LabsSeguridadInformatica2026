# Delta — validation

Tests: tests/test_poc_catalog.py, tests/test_authorization.py, tests/test_sandbox_loop_c.py

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

<!-- Archivado desde change 006 (2026-11-18) -->

## Requirement: Un sandbox por verificación, destruido siempre

Cada verificación DEBE ejecutarse en un contenedor propio, creado para esa
verificación y destruido al terminar, termine bien o mal. El sistema NO DEBE
reutilizar un contenedor entre verificaciones.

### Scenario: verificación finalizada

- GIVEN una verificación aprobada que termina con resultado `validated`
- WHEN el sandbox termina
- THEN no queda ningún contenedor con la etiqueta del engagement y en la bitácora queda solo la evidencia

### Scenario: el evaluador falla a mitad de la verificación

- GIVEN una verificación aprobada cuyo evaluador lanza una excepción
- WHEN termina la ejecución
- THEN el contenedor fue destruido igual y el hallazgo queda `not_validated`

### Scenario: la destrucción del contenedor falla

- GIVEN una verificación cuyo contenedor no se puede eliminar
- WHEN termina la ejecución
- THEN se registra `ABORTED` en la bitácora y el loop C no continúa con otro hallazgo hasta que una persona lo revise

### Scenario: contenedor huérfano de una corrida anterior

- GIVEN un contenedor con la etiqueta del engagement que quedó de una corrida interrumpida
- WHEN se inicia el loop C
- THEN el contenedor se elimina antes de la primera verificación y la eliminación queda en bitácora

## Requirement: El sandbox no sale del laboratorio

El sandbox NO DEBE alcanzar hosts fuera del laboratorio. El adaptador DEBE
rechazar un objetivo fuera de `targets.lab_only_domains` antes de crear el
contenedor, aunque la red esté mal configurada.

### Scenario: objetivo fuera del laboratorio

- GIVEN una verificación aprobada con `base_url` = `http://example.com`
- WHEN se invoca el `Sender`
- THEN se rechaza sin crear ningún contenedor y se registra `BLOCKED`

### Scenario: esquema no permitido

- GIVEN una verificación aprobada con `base_url` = `file:///etc/passwd` o `gopher://dvwa.lab.test`
- WHEN se invoca el `Sender`
- THEN se rechaza sin crear ningún contenedor

### Scenario: intento de conexión hacia afuera desde el sandbox

- GIVEN un sandbox creado en la red interna del laboratorio
- WHEN desde adentro se intenta abrir una conexión a `1.1.1.1:80`
- THEN la conexión falla

### Scenario: objetivo del laboratorio

- GIVEN una verificación aprobada con `base_url` = `http://dvwa.lab.test`
- WHEN se invoca el `Sender`
- THEN se obtiene un `ResponseRecord` con el código HTTP de DVWA

## Requirement: El envío pasa por el harness

El `Sender` DEBE ser un `ToolAdapter` invocado mediante `Harness.invoke` con un
token de fase `VALIDATE`. Ningún módulo DEBE crear el contenedor por fuera del
harness.

### Scenario: token de otra fase

- GIVEN un hallazgo aprobado y un token vivo de fase `ANALYZE`
- WHEN se intenta validar
- THEN el resultado es `BLOCKED`, no se crea ningún contenedor y el bloqueo queda en bitácora

### Scenario: kill switch activado

- GIVEN un hallazgo aprobado, un token vivo de fase `VALIDATE` y el kill switch activado
- WHEN se intenta validar
- THEN se registra `ABORTED` en la bitácora, se lanza `KillSwitchEngaged` y no se crea ningún contenedor

## Requirement: Límites de la verificación

Cada verificación DEBE hacer una sola solicitud, sin seguir redirecciones, con
un tiempo máximo y un tamaño de respuesta máximo configurados en
`profiles.yaml`.

### Scenario: el objetivo no responde a tiempo

- GIVEN un objetivo que no responde dentro del timeout configurado
- WHEN se ejecuta la verificación
- THEN el hallazgo queda `not_validated` con motivo "timeout" y el contenedor fue destruido

### Scenario: respuesta más grande que el límite

- GIVEN una respuesta mayor que el tamaño máximo configurado
- WHEN se ejecuta la verificación
- THEN el cuerpo se trunca al límite y la evidencia indica `truncated=true`

### Scenario: respuesta con redirección

- GIVEN un objetivo que responde `302` con `Location` hacia otro host
- WHEN se ejecuta la verificación
- THEN no se sigue la redirección y se evalúa la respuesta `302`

## Requirement: La aprobación cubre la verificación y sus parámetros

Una aprobación DEBE estar ligada al hallazgo, a la verificación del catálogo y
al hash de los parámetros. El sistema NO DEBE enviar tráfico si alguno de los
tres no coincide con lo aprobado.

### Scenario: sin aprobación

- GIVEN un hallazgo con una verificación propuesta y sin aprobación
- WHEN se ejecuta el loop C
- THEN el hallazgo queda `PENDING_HITL` y el `Sender` no es invocado

### Scenario: parámetros cambiados después de aprobar

- GIVEN una aprobación para `path=/` y una ejecución con `path=/admin`
- WHEN se ejecuta el loop C
- THEN el hallazgo vuelve a `PENDING_HITL` y el `Sender` no es invocado

### Scenario: otra verificación que la aprobada

- GIVEN una aprobación para `POC-HDR-001` y una ejecución con `POC-CSP-001` para el mismo hallazgo
- WHEN se ejecuta el loop C
- THEN el hallazgo queda `PENDING_HITL` y el `Sender` no es invocado

### Scenario: aprobación rechazada

- GIVEN un hallazgo rechazado por el Reviewer
- WHEN se ejecuta el loop C
- THEN el hallazgo queda `not_validated` con motivo "rechazado" y el `Sender` no es invocado

## Requirement: Sin respuesta del Reviewer no se valida

El sistema NO DEBE aprobar ni rechazar un hallazgo por su cuenta. Si el token de
la fase `VALIDATE` vence sin aprobación, el hallazgo DEBE pasar al informe como
"no validado (sin aprobación)".

### Scenario: el token vence sin aprobación

- GIVEN un hallazgo `PENDING_HITL` y el token de fase `VALIDATE` vencido
- WHEN se cierra el loop C
- THEN el hallazgo queda `not_validated` con motivo "sin aprobación" y nunca `validated`

## Requirement: Resultados consistentes

Un hallazgo DEBE quedar `validated` solo si todos sus intentos dan `validated`.
La cantidad de intentos NO DEBE superar `max_loop_iterations.validation` de
`policy.yaml`.

### Scenario: intentos contradictorios

- GIVEN un hallazgo cuyo primer intento da `validated` y el segundo `not_validated`
- WHEN se cierra el loop C para ese hallazgo
- THEN el hallazgo queda `not_validated` con motivo "inconsistente"

### Scenario: intentos agotados

- GIVEN un hallazgo con evidencia insuficiente después del máximo de intentos
- WHEN el loop C decide el siguiente paso
- THEN se detiene para ese hallazgo y no se crea otro contenedor

## Requirement: Evidencia por referencia, no por contenido

La bitácora DEBE registrar, por verificación: id y versión de la entrada del
catálogo, parámetros, resultado, código HTTP, SHA-256 y largo del cuerpo, y si
fue truncado. La bitácora NO DEBE contener el cuerpo de la respuesta.

### Scenario: evidencia de una verificación

- GIVEN una verificación ejecutada
- WHEN se lee la bitácora
- THEN contiene el hash y el largo del cuerpo, y el cuerpo no aparece en ningún registro

### Scenario: registro de la decisión del Reviewer

- GIVEN una aprobación o un rechazo hechos por la CLI
- WHEN se lee la bitácora
- THEN contiene quién decidió, cuándo, el motivo y el hash de parámetros aprobado

## Requirement: CLI de aprobación con responsable y motivo

La CLI DEBE exigir el nombre del Reviewer y un motivo para aprobar o rechazar, y
DEBE listar los hallazgos pendientes con la verificación y los parámetros
propuestos.

### Scenario: aprobación sin motivo

- GIVEN un hallazgo pendiente
- WHEN se ejecuta `approve` sin `--reason`
- THEN la CLI falla, no se registra ninguna aprobación y el hallazgo sigue `PENDING_HITL`

### Scenario: aprobación sin Reviewer

- GIVEN un hallazgo pendiente
- WHEN se ejecuta `approve` sin `--reviewer`
- THEN la CLI falla y no se registra ninguna aprobación

### Scenario: listado de pendientes

- GIVEN dos hallazgos `PENDING_HITL` y uno aprobado
- WHEN se ejecuta `list`
- THEN se muestran solo los dos pendientes, cada uno con su verificación y sus parámetros
