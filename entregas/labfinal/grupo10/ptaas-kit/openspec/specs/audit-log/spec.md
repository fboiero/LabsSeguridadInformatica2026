# Spec — audit-log

Tests: `tests/test_audit_and_policy.py`, `tests/test_authorization.py`, `tests/audit_log/test_no_sensitive_data.py`

## Requirement: Registro total
El sistema DEBE registrar toda decisión del harness: OK, BLOCKED, PENDING_HITL y ABORTED, con agente, acción, objetivo, fase, token/engagement y marca de tiempo.

### Scenario: intento bloqueado
- GIVEN una acción fuera de alcance
- WHEN el harness la rechaza
- THEN existe un registro BLOCKED con el objetivo intentado

## Requirement: Append-only con integridad verificable
Cada registro DEBE incluir el hash del anterior (cadena); el sistema DEBE poder detectar alteración o borrado.

### Scenario: registro alterado
- GIVEN una bitácora íntegra
- WHEN se modifica un campo de un registro intermedio
- THEN la verificación de la cadena falla

### Scenario: registro borrado
- GIVEN una bitácora íntegra
- WHEN se elimina un registro intermedio
- THEN la verificación de la cadena falla

## Requirement: Sin datos sensibles en claro
La bitácora NO DEBE almacenar credenciales ni contenido de datos del cliente; solo referencias a evidencia.

### Scenario: evidencia grande
- GIVEN una evidencia con contenido del objetivo
- WHEN se registra la acción
- THEN la bitácora guarda una referencia, no el contenido

## Requirement: Evidencia verificable contra su referencia
La referencia de evidencia DEBE permitir verificar que un contenido dado es el que se registró; un contenido alterado NO DEBE coincidir con la referencia.

### Scenario: contenido alterado no coincide con la referencia
- GIVEN una evidencia registrada por su referencia
- WHEN se presenta un contenido alterado
- THEN la verificación contra la referencia falla
