# Delta — authorization (change 003)

Tests: `tests/test_roe_tokens.py`, `tests/test_redteam_guard.py`

## Requirement: RoE completo y aprobado

El sistema NO DEBE aceptar un RoE sin identificador de engagement, aprobador,
referencia de aprobación, ventana temporal o contacto de emergencia.

### Scenario: RoE sin aprobador

- GIVEN un RoE con alcance y ventana válidos pero sin `approver`
- WHEN se carga el RoE
- THEN la carga falla con un error que nombra el campo faltante y no se emite ningún token

### Scenario: RoE sin contacto de emergencia

- GIVEN un RoE sin `emergency_contacts`
- WHEN se carga el RoE
- THEN la carga falla y no se crea ningún engagement autorizado

### Scenario: contactos de emergencia con entradas inválidas

- GIVEN un RoE con un contacto válido y otra entrada que no es texto
- WHEN se carga el RoE
- THEN la carga falla con `RoEValidationError` explicativo

## Requirement: Alcance acotado al laboratorio

El parser DEBE rechazar CIDR públicos, CIDR demasiado amplios y dominios que no
pertenezcan al laboratorio definido en `profiles.yaml`.

### Scenario: CIDR público o demasiado amplio

- GIVEN un RoE con `0.0.0.0/0`, `10.0.0.0/8` o `8.8.8.0/24`
- WHEN se carga el RoE
- THEN la carga falla indicando que el CIDR no está permitido

### Scenario: dominio fuera del laboratorio

- GIVEN un RoE con `example.com` en `scope.domains`
- WHEN se carga el RoE
- THEN la carga falla y no se emite token

## Requirement: Ventana temporal en UTC

Las fechas del RoE DEBEN interpretarse con su zona horaria y compararse en UTC.

### Scenario: misma ventana expresada en zonas distintas

- GIVEN una ventana `2026-11-11T22:00:00-03:00` a `2026-11-11T23:00:00-03:00`
- WHEN se comparan los instantes con la misma ventana escrita en `Z`
- THEN ambos formatos producen exactamente el mismo epoch

### Scenario: ventana invertida

- GIVEN un RoE cuyo `window.start` es posterior a `window.end`
- WHEN se carga el RoE
- THEN la carga falla indicando ventana invertida

## Requirement: Exclusiones prevalecen sobre el alcance

El emisor DEBE restar las exclusiones del alcance antes de crear el token,
incluidos los subdominios del dominio excluido.

### Scenario: exclusión que anula todo el alcance

- GIVEN un RoE cuyo alcance es `10.99.0.0/24` y cuya exclusión es `10.99.0.0/24`
- WHEN se carga el RoE
- THEN la carga falla porque la exclusión deja el alcance vacío

### Scenario: exclusiones combinadas que anulan todo el alcance

- GIVEN un RoE con CIDR y dominios en alcance, y exclusiones que cubren ambos
- WHEN se carga el RoE
- THEN la carga falla porque no queda ningún activo autorizado

### Scenario: host excluido dentro de un CIDR autorizado

- GIVEN un RoE que autoriza `10.99.0.0/24` y excluye `10.99.0.10/32`
- WHEN se emite un token de recon
- THEN el token no incluye `10.99.0.10` pero sí el resto del /24

## Requirement: Token por fase, con TTL y sin renovación automática

Un token DEBE habilitar solo la fase pedida y DEBE vencer según el TTL de
`policy.yaml` o el fin de la ventana del RoE, lo que ocurra primero.

### Scenario: fase no autorizada

- GIVEN un RoE que solo autoriza `recon`
- WHEN se pide un token para `validate`
- THEN la emisión se rechaza y queda registrada

### Scenario: fase desconocida

- GIVEN un emisor recibe una fase que no existe
- WHEN intenta emitir el token
- THEN rechaza la solicitud con `TokenIssuanceError` y registra el rechazo

### Scenario: token vencido

- GIVEN un token emitido con TTL corto
- WHEN se invoca una acción después de su `window_end`
- THEN la acción se bloquea y el token no se renueva solo

### Scenario: token vencido exactamente en `window_end`

- GIVEN un token cuyo reloj actual es exactamente `window_end`
- WHEN se comprueba su vigencia
- THEN el token está vencido y una acción se bloquea

### Scenario: fases omitidas o lista vacía

- GIVEN un RoE que omite `authorized_phases` o la declara como lista vacía
- WHEN se carga el RoE
- THEN si se omite, se usan solo las fases de `policy.yaml`; si está vacía, la carga falla

## Requirement: Emisión y rechazo registrados

Toda emisión y todo rechazo del emisor DEBEN quedar en la bitácora con
engagement, fase, acción y resultado, sin secretos.

### Scenario: rechazo registrado

- GIVEN un RoE válido y una fase no autorizada
- WHEN el emisor rechaza la emisión
- THEN existe un registro `BLOCKED` con la acción `scope.issue_token`

### Scenario: emisión sin bitácora

- GIVEN una solicitud de emisión sin un sink de auditoría
- WHEN se llama al emisor
- THEN el emisor rechaza la llamada antes de devolver un token

## Requirement: Token ligado a su engagement

El Guard NO DEBE aceptar un token emitido para otro engagement, aunque el
alcance y la fase coincidan.

### Scenario: token de otro engagement

- GIVEN un Guard configurado para `eng-1`
- WHEN se presenta un token de `eng-2`
- THEN la acción se bloquea y queda registrada

## Requirement: Hash de aprobación representa las restricciones del RoE

El hash de aprobación DEBE cambiar si cambia cualquier dato que afecte la
autorización, incluidas exclusiones, fases autorizadas, contactos o revocación.

### Scenario: cambio de una restricción cambia el hash

- GIVEN dos RoE idénticos salvo por una exclusión o una fase autorizada
- WHEN se calcula su `approval_hash`
- THEN los hashes son distintos
