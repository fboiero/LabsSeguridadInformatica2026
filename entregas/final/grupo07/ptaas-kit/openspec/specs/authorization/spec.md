# Delta — authorization

Tests: tests/test_authorization.py, tests/test_roe_tokens.py

## Requirement: Enforcement de alcance
El sistema DEBE rechazar toda acción activa sobre un activo fuera del RoE vigente.

### Scenario: activo fuera de alcance
- GIVEN un RoE que autoriza 10.0.0.0/24
- WHEN un agente intenta escanear 10.0.1.5
- THEN la acción es bloqueada y registrada en la bitácora

## Requirement: Vigencia del token
El sistema NO DEBE ejecutar acciones con un scope token vencido.

### Scenario: token vencido
- GIVEN un token cuya ventana terminó
- WHEN un agente invoca una acción en el activo autorizado
- THEN la acción es bloqueada (BLOCKED) y registrada

## Requirement: Fase del token
Un token DEBE habilitar únicamente acciones de su fase.

### Scenario: acción de otra fase
- GIVEN un token de fase ANALYZE
- WHEN se invoca una acción de VALIDATE
- THEN la acción es bloqueada y registrada

## Requirement: Kill switch
El sistema DEBE detener toda ejecución al activar el kill switch.

### Scenario: kill switch activo
- GIVEN un engagement en curso y el kill switch activado
- WHEN cualquier agente invoca una acción
- THEN se registra ABORTED y no se ejecuta la herramienta

<!-- Archivado desde el change 003-roe-and-tokens -->

## Requirement: Validación del RoE
El sistema DEBE rechazar, con un error que indique el campo y el motivo, todo RoE incompleto o inválido antes de emitir cualquier token.

### Scenario: RoE sin alcance
- GIVEN un RoE con `scope` vacío
- WHEN se lo parsea
- THEN se rechaza indicando que el alcance está vacío y no se emite ningún token

### Scenario: ventana invertida
- GIVEN un RoE cuyo `window.end` es anterior a `window.start`
- WHEN se lo parsea
- THEN se rechaza indicando que la ventana está invertida

## Requirement: Alcance máximo del laboratorio
El sistema NO DEBE aceptar un RoE cuyo alcance exceda los `targets` de `profiles.yaml`.

### Scenario: CIDR amplio
- GIVEN un RoE que declara `0.0.0.0/0` o `10.0.0.0/8`
- WHEN se lo parsea
- THEN se rechaza indicando que excede el alcance permitido en el laboratorio

## Requirement: Exclusiones prevalecen
Las exclusiones del RoE DEBEN prevalecer sobre el alcance.

### Scenario: dirección excluida dentro de un rango autorizado
- GIVEN un RoE que autoriza 10.99.0.0/28 y excluye 10.99.0.5/32
- WHEN se emite un token y un agente intenta sondear 10.99.0.5
- THEN la acción se bloquea y queda registrada, mientras que 10.99.0.4 sí se permite

### Scenario: exclusión que anula todo
- GIVEN un RoE cuyas exclusiones cubren todo el alcance
- WHEN se lo parsea
- THEN se rechaza indicando que no queda nada autorizado

## Requirement: Emisión por fase
El emisor DEBE entregar tokens de una sola fase, solo si el RoE la autoriza, con vida igual al mínimo entre el TTL de la fase y el fin de la ventana.

### Scenario: fase autorizada
- GIVEN un RoE válido que autoriza `recon`
- WHEN se pide un token de `recon` dentro de la ventana
- THEN se emite un token de fase `recon` con el TTL de `policy.yaml` y la emisión queda en bitácora

### Scenario: fase no autorizada
- GIVEN un RoE que no autoriza `validate`
- WHEN se pide un token de `validate`
- THEN se rechaza y el rechazo queda registrado como BLOCKED

## Requirement: Sin renovación automática
Un token vencido NO DEBE renovarse solo.

### Scenario: token vencido
- GIVEN un token cuya vida terminó
- WHEN pasa el tiempo
- THEN sigue vencido; para continuar hay que pedir uno nuevo, que se valida y se registra

## Requirement: Comparación en UTC
Las fechas del RoE DEBEN tener zona horaria y compararse en UTC.

### Scenario: fecha sin zona horaria
- GIVEN un RoE con `window.start` sin offset
- WHEN se lo parsea
- THEN se rechaza indicando que falta la zona horaria

## Requirement: Token atado al engagement
Un token NO DEBE habilitar acciones en otro engagement ni en otra fase.

### Scenario: token de otro engagement
- GIVEN un token emitido para `eng-otro`
- WHEN se lo usa en el Harness de `eng-lab-001`
- THEN la acción se bloquea y queda registrada

## Requirement: Revocación del RoE
Revocar el RoE DEBE impedir nuevas emisiones y detener el engagement.

### Scenario: RoE revocado
- GIVEN un RoE revocado durante el engagement
- WHEN se pide un token o se usa uno ya emitido
- THEN la emisión se rechaza y la acción se aborta por kill switch

## Requirement: Único constructor de tokens
Ninguna ruta del código de producción DEBE construir `ScopeToken` fuera del emisor.

### Scenario: construcción directa
- GIVEN el código de `harness/` y `tools/`
- WHEN se busca una construcción de `ScopeToken` fuera de `harness/tokens.py`
- THEN no se encuentra ninguna (el test falla si aparece)
