# Delta propuesto — audit-log

Estado: aprobado para implementar; pendiente de revisión de código y archivo.
No sustituye todavía la spec estable del kit.
Tests: `tests/audit_log/test_persistence.py`,
`tests/audit_log/test_integrity.py`, `tests/audit_log/test_concurrency.py`,
`tests/audit_log/test_privacy.py`.

## Requirement: Persistencia confirmada por engagement
El sistema DEBE conservar eventos confirmados en SQLite, en un archivo por
engagement, y NO DEBE continuar silenciosamente en memoria si falla el commit.

### Scenario: recuperación entre procesos
- GIVEN una auditoría con eventos confirmados y su proceso terminado
- WHEN otro proceso abre su archivo con la misma identidad
- THEN recupera todos los eventos confirmados en el mismo orden y con los mismos hashes

### Scenario: commit fallido
- GIVEN una escritura cuyo commit falla
- WHEN el almacenamiento responde al coordinador
- THEN informa error, no declara persistido el evento y no usa memoria como reemplazo

## Requirement: Aislamiento e identidad
El sistema DEBE comprobar la identidad del engagement al abrir y escribir.
NO DEBE mezclar eventos de otro engagement en el archivo.

### Scenario: archivos independientes
- GIVEN dos auditorías con archivos diferentes
- WHEN ambas registran eventos
- THEN cada archivo contiene solo eventos de su auditoría y su propia cadena

### Scenario: identidad incompatible
- GIVEN el archivo de una auditoría A
- WHEN se intenta abrir o escribir con identidad B
- THEN se rechaza sin modificar el archivo

## Requirement: Verificación antes de reanudar
El sistema DEBE verificar esquema, identidad, secuencia y hashes al abrir;
una base corrupta o incompatible NO DEBE habilitar acciones ni repararse sola.

### Scenario: modificación de registro intermedio
- GIVEN una base válida que luego fue alterada fuera de las vías protegidas
- WHEN se modifica un campo intermedio sin actualizar su hash y se intenta reabrir
- THEN la verificación falla y no se permite ejecutar herramientas

### Scenario: borrado intermedio
- GIVEN una base de tres o más eventos alterada fuera de las vías protegidas
- WHEN se elimina un evento intermedio y se verifica la base
- THEN la verificación falla por secuencia o enlace inconsistente

## Requirement: Verificador offline y límites explícitos
El sistema DEBE ofrecer un comando de verificación que no modifique archivos.
Un resultado estructural válido NO DEBE presentarse como prueba de completitud
o autenticidad sin anclaje externo confiable.

### Scenario: archivo ausente
- GIVEN una ruta a un archivo que no existe
- WHEN se ejecuta el comando de verificación
- THEN devuelve código 2 y no crea una base nueva

### Scenario: truncamiento final estructuralmente consistente
- GIVEN una base cuya cola fue borrada manteniendo una cadena y un esquema válidos, sin ancla externa
- WHEN se ejecuta el verificador
- THEN puede devolver código 0 por estructura válida, pero declara completitud y autenticidad no verificadas

### Scenario: corrupción detectada desde el comando
- GIVEN una base con un hash inconsistente
- WHEN se ejecuta el verificador
- THEN devuelve código 1 y no modifica ni repara la base

## Requirement: Solo agregado mediante vías protegidas
La API NO DEBE ofrecer edición o borrado de eventos y SQLite DEBE rechazar
UPDATE y DELETE ordinarios mediante triggers. Esto NO constituye protección
contra quien puede quitar esos controles o sustituir el archivo.

### Scenario: intento de edición o borrado SQL
- GIVEN la base con sus triggers intactos
- WHEN una conexión intenta UPDATE o DELETE sobre eventos
- THEN SQLite rechaza la operación y la cadena permanece igual

## Requirement: Escrituras concurrentes atómicas
El sistema DEBE serializar asignación de secuencia, lectura del hash previo e
inserción; NO DEBE perder eventos ni crear ramas en la cadena. Un bloqueo DEBE
terminar en error tras la espera acotada, nunca en ejecución sin registro.

### Scenario: dos escritores
- GIVEN dos conexiones al archivo de la misma auditoría
- WHEN ambas agregan eventos concurrentemente y sus commits tienen éxito
- THEN todos los eventos aparecen una sola vez con secuencias consecutivas y cadena verificable

### Scenario: bloqueo persistente
- GIVEN otra conexión que retiene el bloqueo de escritura más allá del plazo configurado
- WHEN se intenta confirmar un evento
- THEN se informa error acotado sin evento parcial ni fallback a memoria

## Requirement: Metadatos mínimos sin secretos
La bitácora DEBE aceptar solo campos acotados y referencias internas a evidencia.
NO DEBE copiar cuerpos, credenciales, tokens completos ni texto libre de errores.
Una entrada inválida de objetivo DEBE representarse sin conservar su texto crudo.

### Scenario: secreto sintético en evidencia o error
- GIVEN una salida de herramienta o excepción que contiene una contraseña de prueba
- WHEN el harness registra el desenlace
- THEN guarda metadatos y código seguro, y la contraseña no aparece en eventos ni diagnósticos

### Scenario: objetivo inválido con credenciales
- GIVEN un objetivo inválido que contiene una URL con credenciales sintéticas
- WHEN se registra el rechazo
- THEN se guarda un marcador y una huella, no las credenciales ni la URL original
