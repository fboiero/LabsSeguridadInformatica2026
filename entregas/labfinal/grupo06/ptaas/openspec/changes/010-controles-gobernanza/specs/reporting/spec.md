# Delta — reporting y engagement-lifecycle (change 010, propuesto)

Tests: a escribir al implementar (`tests/test_gobernanza.py`).

## Requirement: Divulgación coordinada antes de entregar

La entrega DEBE exigir receptor, canal y plazo de remediación definidos en la sección de
divulgación. El sistema NO DEBE entregar un informe con alguno de esos datos `unknown`.

### Scenario: receptor desconocido
- GIVEN un informe con aprobación registrada y receptor de divulgación `unknown`
- WHEN se intenta entregar
- THEN la entrega se rechaza indicando el dato faltante y queda en la bitácora

### Scenario: divulgación completa
- GIVEN un informe con receptor, canal y plazo definidos y aprobación registrada
- WHEN se entrega
- THEN la entrega procede y el plazo queda en la bitácora

## Requirement: Aviso por hallazgo sin publicación anticipada

Cada hallazgo entregado DEBE tener un aviso con activo, impacto, remediación, estado de
validación y fecha de publicación posterior al plazo acordado.

### Scenario: aviso sin remediación
- GIVEN un aviso de hallazgo sin remediación
- WHEN se genera
- THEN se rechaza indicando el campo

### Scenario: publicación antes del plazo
- GIVEN un aviso con fecha de publicación anterior al plazo de remediación
- WHEN se registra
- THEN se rechaza

## Requirement: Estados del hallazgo hasta el cierre

Después de la entrega, cada hallazgo DEBE pasar por recibido, verificado, en
remediación, retest y cerrado. El sistema NO DEBE permitir saltear estados.

### Scenario: cierre sin pasar por remediación
- GIVEN un hallazgo en estado "recibido"
- WHEN se intenta pasar a "cerrado"
- THEN la transición se rechaza y queda en la bitácora

## Requirement: Cierre con retest de la misma verificación

Un hallazgo NO DEBE cerrarse sin un retest registrado con la misma verificación del
catálogo y la misma versión que lo validaron.

### Scenario: retest con otra verificación
- GIVEN un hallazgo validado con `POC-HDR-001` v1.0.0
- WHEN se intenta cerrar con un retest de `POC-CSP-001`
- THEN el cierre se rechaza

### Scenario: retest que todavía valida
- GIVEN un retest con la misma verificación que vuelve a dar `validated`
- WHEN se intenta cerrar
- THEN el hallazgo vuelve a "en remediación"

## Requirement: Retención y destrucción de la evidencia

El RoE DEBE fijar el plazo de retención de la evidencia y su responsable. El engagement
NO DEBE cerrarse sin la constancia de destrucción de la evidencia vencida.

### Scenario: RoE sin plazo de retención
- GIVEN un RoE sin `evidence_retention_days`
- WHEN se carga
- THEN se rechaza indicando el campo

### Scenario: cierre sin constancia de destrucción
- GIVEN un engagement con evidencia vencida y sin constancia de destrucción
- WHEN se intenta cerrar
- THEN el cierre se rechaza

## Requirement: Limpieza verificada al cerrar

El cierre del engagement DEBE verificar que no quedan contenedores con su etiqueta ni
archivos temporales de la prueba.

### Scenario: contenedor huérfano al cerrar
- GIVEN un contenedor con la etiqueta del engagement todavía activo
- WHEN se intenta cerrar el engagement
- THEN el cierre se rechaza y se registra el contenedor

## Requirement: Detención por el contacto de emergencia

Un aviso del contacto de emergencia del RoE DEBE activar el kill switch y quedar en la
bitácora.

### Scenario: aviso de emergencia
- GIVEN un engagement en curso
- WHEN el contacto de emergencia registra un aviso de detención
- THEN se registra `ABORTED` y ninguna acción posterior se ejecuta
