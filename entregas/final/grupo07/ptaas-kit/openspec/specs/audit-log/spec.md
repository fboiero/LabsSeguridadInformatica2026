# Spec — audit-log

Tests: `tests/test_audit_and_policy.py`, `tests/test_authorization.py`, `tests/test_audit_persistence.py`

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

## Requirement: Persistencia por engagement
La bitácora DEBE persistir en almacenamiento durable (un archivo por engagement) de modo que un registro escrito se recupere tras reiniciar el proceso. Los registros de un engagement NO DEBEN mezclarse con los de otro.

### Scenario: recuperación tras reinicio
- GIVEN una bitácora con registros persistidos
- WHEN el proceso se reinicia y se vuelve a abrir el archivo
- THEN los registros previos siguen presentes y la cadena es válida

### Scenario: aislamiento entre engagements
- GIVEN dos engagements con archivos de bitácora distintos
- WHEN se registra una acción en el primero
- THEN el registro no aparece en el segundo

## Requirement: Verificación al abrir y bajo demanda
El sistema DEBE verificar la integridad de la cadena al abrir el archivo y también bajo demanda por línea de comandos. Si la cadena está corrupta, el engagement NO DEBE continuar.

### Scenario: cadena corrupta al abrir
- GIVEN un archivo de bitácora con una fila alterada por fuera del harness
- WHEN se intenta abrir la bitácora
- THEN la apertura falla y el engagement no continúa

## Requirement: Almacenamiento inmutable (append-only)
El almacenamiento NO DEBE permitir modificar ni borrar registros existentes; no existe API de UPDATE ni DELETE y el motor rechaza esas operaciones.

### Scenario: intento de modificación directa
- GIVEN una bitácora persistida
- WHEN se intenta un UPDATE o DELETE sobre una fila
- THEN la operación es rechazada por el almacenamiento

### Scenario: borrado forzado detectable
- GIVEN una bitácora persistida íntegra
- WHEN se elimina una fila evadiendo los controles
- THEN la verificación de la cadena falla

## Requirement: Escrituras concurrentes
La bitácora DEBE conservar una cadena de hashes válida aun con escritores concurrentes; dos registros no comparten el mismo `prev`.

### Scenario: dos escritores concurrentes
- GIVEN dos hilos que registran acciones a la vez sobre el mismo engagement
- WHEN ambos terminan
- THEN todos los registros están presentes y la cadena es íntegra
