# Delta — audit-log (change 002)

Tests: `tests/test_audit_persistence.py`

## Requirement: Persistencia por engagement
La bitácora DEBE guardarse en un archivo por engagement y DEBE recuperarse íntegra tras reiniciar el proceso.

### Scenario: registro recuperado tras reinicio
- GIVEN un engagement con tres registros escritos
- WHEN el proceso se reinicia y el archivo se vuelve a abrir
- THEN los tres registros están presentes y la cadena es válida

### Scenario: archivo de otro engagement
- GIVEN un archivo de bitácora perteneciente al engagement A
- WHEN se intenta registrar un evento del engagement B en ese archivo
- THEN el evento se rechaza y el archivo no cambia

## Requirement: Verificación al abrir y bajo demanda
El sistema DEBE verificar la cadena completa al abrir la bitácora y DEBE ofrecer la misma verificación por línea de comandos.

### Scenario: cadena corrupta al abrir
- GIVEN un archivo de bitácora con un registro intermedio alterado
- WHEN el engagement intenta abrirse
- THEN el engagement no continúa y no acepta nuevos registros

### Scenario: verificación por línea de comandos
- GIVEN un archivo de bitácora con un registro borrado
- WHEN se ejecuta la verificación sobre ese archivo
- THEN el código de salida es distinto de cero y se informa el índice del primer registro inválido

## Requirement: Sin modificación ni borrado de registros
La bitácora DEBE ser append-only: ninguna operación de la API y ninguna sentencia SQL sobre la tabla de registros DEBE modificar ni borrar un registro escrito.

### Scenario: UPDATE directo sobre la tabla
- GIVEN un registro escrito en la bitácora
- WHEN se ejecuta una sentencia UPDATE sobre esa fila
- THEN la base rechaza la sentencia y la fila queda intacta

### Scenario: DELETE directo sobre la tabla
- GIVEN un registro escrito en la bitácora
- WHEN se ejecuta una sentencia DELETE sobre esa fila
- THEN la base rechaza la sentencia y la fila queda intacta

### Scenario: la API no ofrece borrado
- GIVEN el contrato público de la bitácora
- WHEN se enumeran sus operaciones
- THEN no existe ninguna operación para modificar ni borrar registros

## Requirement: Escrituras concurrentes sin bifurcar la cadena
Dos escritores que registren en el mismo engagement DEBEN producir una única cadena lineal, sin dos registros con el mismo `prev`.

### Scenario: dos escritores simultáneos
- GIVEN dos procesos que registran eventos en el mismo engagement
- WHEN ambos escriben al mismo tiempo
- THEN la verificación de la cadena es válida y no hay huecos ni enlaces duplicados

## Requirement: Ancla de cabeza
La verificación DEBE informar la cantidad de registros y el hash de cabeza, y el grupo DEBE guardar ese par fuera del archivo para detectar el borrado del último registro.

### Scenario: borrado del último registro
- GIVEN un ancla guardada con la cantidad y el hash de cabeza del archivo original
- WHEN se borra el último registro del archivo
- THEN la verificación contra el ancla falla aunque la cadena restante sea válida

## Requirement: Sin datos sensibles en la bitácora
La bitácora NO DEBE registrar campos con credenciales, secretos o contenido del cliente; DEBE rechazar el evento completo antes de escribir.

### Scenario: evento con credencial
- GIVEN un evento que incluye un campo `password`
- WHEN se intenta registrar en la bitácora
- THEN el evento se rechaza, no queda ningún registro y el error nombra el campo rechazado
