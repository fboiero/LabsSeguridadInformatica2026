# Delta propuesto — tool-adapters

Estado: aprobado para implementar; extiende la integración, no los permisos.
Pendiente de revisión de código y archivo.
Tests: `tests/tool_adapters/test_audit_fail_closed.py`.
Todos los escenarios usan adaptadores simulados, sin red ni herramientas reales.

## Requirement: Registro previo obligatorio
El harness DEBE mantener kill switch, autorización, gates y validación de
adaptador antes de ejecutar. Para una acción permitida DEBE confirmar un evento
ATTEMPT antes de llamar al adaptador; sin ese commit NO DEBE llamarlo.
Los rechazos DEBEN registrar la decisión correspondiente sin ejecutar.

### Scenario: ejecución autorizada con historial disponible
- GIVEN una acción autorizada y almacenamiento operativo
- WHEN el harness la ejecuta exitosamente
- THEN el adaptador observa un ATTEMPT ya confirmado y luego se confirma DECISION con resultado OK

### Scenario: no se puede guardar el intento
- GIVEN una acción autorizada y un commit de ATTEMPT que falla
- WHEN se invoca el harness
- THEN el contador de llamadas al adaptador permanece en cero y se informa error de auditoría

### Scenario: acción bloqueada o pendiente de aprobación
- GIVEN una acción fuera de alcance o sin una aprobación requerida
- WHEN se invoca el harness
- THEN se registra BLOCKED o PENDING_HITL respectivamente y el adaptador no se llama

### Scenario: kill switch activo
- GIVEN el kill switch activado
- WHEN se invoca el harness con almacenamiento disponible
- THEN registra ABORTED sin ejecutar el adaptador ni eludir el chequeo inicial

## Requirement: Fallos de herramienta trazables y saneados
Una excepción del adaptador DEBE generar TOOL_ERROR con código seguro y el mismo
identificador que ATTEMPT si el almacenamiento está disponible. El harness
NO DEBE informar OK, filtrar la excepción cruda ni reintentar automáticamente.

### Scenario: excepción del adaptador
- GIVEN ATTEMPT confirmado y un adaptador simulado que lanza una excepción con un secreto sintético
- WHEN el harness maneja ese fallo
- THEN confirma TOOL_ERROR sin el secreto, informa error saneado y no reintenta

## Requirement: Fallo de registro posterior a la ejecución
Si no se puede confirmar el evento terminal, el coordinador DEBE suspender
nuevas ejecuciones del engagement e informar error de auditoría. NO DEBE
afirmar que la acción no ocurrió ni deshacerla o repetirla automáticamente.

### Scenario: herramienta termina pero falla el registro final
- GIVEN un adaptador que ya ejecutó y un almacenamiento cuyo commit terminal falla
- WHEN el harness intenta registrar el desenlace
- THEN informa resultado no confirmado, no retorna éxito y bloquea siguientes ejecuciones

### Scenario: fallo doble de herramienta y bitácora
- GIVEN un adaptador que falla después de ATTEMPT y un commit de TOOL_ERROR que también falla
- WHEN el harness maneja ambos errores
- THEN conserva el intento confirmado, informa error de auditoría saneado y suspende nuevas ejecuciones

## Requirement: Reanudación conservadora
Al reanudar el coordinador después de un reinicio, un ATTEMPT sin evento terminal
DEBE tratarse como resultado desconocido. NO DEBE confundirse con éxito, ausencia
de ejecución o permiso para repetir la acción. Se requiere revisión humana
antes de reanudar acciones, sin modificar ni borrar el intento original.

### Scenario: reinicio con intento sin desenlace
- GIVEN el coordinador detenido y un ATTEMPT confirmado sin evento terminal
- WHEN se intenta reanudar la auditoría
- THEN se bloquean ejecuciones hasta una revisión humana y no se repite el intento
