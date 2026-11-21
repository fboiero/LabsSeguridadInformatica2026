# Design — Change 002: persistencia de la bitácora

## Contexto
La bitácora hoy vive en memoria (`AuditLog` en `harness/contracts.py`). El contrato nuevo (`harness/audit.py`, firma `append` / `verify` con un fake en memoria) ya fija la forma de los registros y las reglas de la cadena. Este documento decide cómo se guarda en disco, cómo se verifica y qué no cubre.

## Decisiones

### Almacenamiento: un archivo SQLite por engagement
- Cada engagement tiene su propio archivo. Dos engagements nunca comparten tabla, cadena ni archivo (aislamiento, tarea 3.3).
- El archivo guarda el identificador del engagement en una tabla de metadatos. Un `append` cuyo engagement no coincide con el del archivo se rechaza y no deja registro.
- Tabla de registros: `seq` (entero, clave primaria, sin huecos), `ts`, `engagement`, `agent`, `action`, `target`, `phase`, `result`, `evidencia_ref` (nulable), `prev` y `hash`.

### Cadena de hashes
- `hash = SHA-256( JSON canónico de {prev, campos del registro} )`, con claves ordenadas. `seq` no entra en el hash: su continuidad se controla aparte.
- **GENESIS:** el primer registro de cada engagement tiene `prev = "GENESIS"`. Responde la pregunta abierta del proposal.
- Un registro modificado rompe el hash de ese registro. Un registro borrado en medio rompe el enlace `prev` del siguiente. Así lo exigen los Scenarios de `audit-log`.

### Inmutabilidad: capa de acceso y triggers
- La API expone solo `append` y `verify`. No hay métodos de modificación ni de borrado.
- Además, dos triggers `BEFORE UPDATE` y `BEFORE DELETE` sobre la tabla de registros abortan la operación. Responde la pregunta abierta del proposal: se usan **ambos**, porque la convención sola no alcanza.
- Límite: quien tenga acceso de escritura al archivo puede borrar los triggers con otra herramienta. Por eso los triggers no son la garantía; la garantía es la cadena verificable.

### Verificación: al abrir y bajo demanda
- Al abrir un engagement se verifica la cadena completa. Si falla, el engagement **no continúa**: no se aceptan `append` y se devuelve el índice del primer registro inválido.
- `python -m harness.audit verify <archivo>` ejecuta la misma verificación y devuelve código de salida 0 si la cadena está íntegra, distinto de 0 si no.
- **Firma decidida:** `verify()` sin argumentos. El archivo queda fijado al abrir el almacén; la CLI abre el archivo y llama a `verify()`. Así una sola firma sirve para la implementación en memoria y para la SQLite.

### Ancla de cabeza (límite conocido de la cadena)
- Una cadena por sí sola **no detecta el borrado del último registro**: el registro anterior sigue siendo una cadena válida.
- Mitigación: `verify` devuelve también la cantidad de registros y el hash de cabeza. El grupo guarda ese par en el informe o en el handoff de cada corrida. Una verificación contra un ancla que no coincide con el archivo falla.

### Concurrencia
- El archivo se abre en modo WAL. Cada `append` corre en una transacción `BEGIN IMMEDIATE`: el lector del último `hash` y la inserción del nuevo registro ocurren dentro de la misma transacción.
- Así dos escritores no pueden tomar el mismo `prev` y bifurcar la cadena. Lo prueba la tarea 3.4.

### Evidencia: referencia, no contenido
- La bitácora guarda `evidencia_ref`: un identificador y un hash del contenido guardado fuera de ella. No guarda el contenido.
- Eventos con claves sensibles (credencial, secreto, contenido del cliente) se rechazan antes de escribir. Es la regla de `validar_evento`: rechazar, no redactar.
- Cifrar la evidencia almacenada queda **fuera de alcance** de este change.

## Qué no cubre este change
- Protección contra un administrador con acceso root al disco que reescriba el archivo entero y recalcule la cadena. Solo el ancla de cabeza guardada fuera del archivo lo haría visible.
- Detección de credenciales por valor (solo se detectan por nombre de campo).
- Respaldo, rotación o retención de los archivos de bitácora.

## Riesgos
| Riesgo | Mitigación |
|---|---|
| Triggers desactivados a mano | La verificación de cadena lo detecta si hubo cambios. |
| Borrado del último registro | Ancla de cabeza guardada fuera del archivo. |
| Escrituras concurrentes que bifurcan la cadena | `BEGIN IMMEDIATE` + prueba de concurrencia (3.4). |
| Bitácora con datos del cliente | Rechazo por nombre de campo + Scenario negativo. |
