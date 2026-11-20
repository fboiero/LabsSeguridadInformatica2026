# Design — Change 002

Estado: aprobado para implementar, con acuerdo del grupo informado por el usuario.
La primera implementación y demo siguen este diseño; falta revisión independiente
del código antes de cerrar y archivar el change.

## 1. Almacenamiento

Usar `sqlite3` de la biblioteca estándar. Un archivo pertenece a un único
engagement (auditoría), identificado en metadatos de versión 1. Abrir un archivo
existente exige validar su esquema, identidad y cadena; no se crea encima de una
base corrupta ni se interpreta como nuevo un archivo de formato desconocido.

Cada evento contiene una secuencia consecutiva, versión, engagement, identificador
de invocación cuando corresponda, fecha UTC, agente, acción, objetivo saneado,
fase, tipo de evento, resultado o código de error, referencias a evidencia,
hash anterior y hash propio. No se persiste el ScopeToken completo.

El primer registro referencia `GENESIS`. Se calcula SHA-256 sobre JSON con
claves ordenadas (`sort_keys=True`), valores numéricos finitos y codificación
UTF-8, conservando el formato de serialización del kit y excluyendo solo el
hash propio. La secuencia y todos los campos de seguridad forman parte del
contenido protegido por el hash (no es una firma digital ni autentica al autor).

## 2. Transacciones y concurrencia

Leer el último hash, asignar la secuencia e insertar el siguiente evento dentro
de una transacción `BEGIN IMMEDIATE`. Confirmar antes de dar por registrado el
evento; usar `synchronous=FULL`. No sostener una transacción durante la ejecución
de una herramienta. Dos conexiones no pueden partir del mismo último hash.

Un bloqueo tiene espera acotada propuesta de 5 segundos; al agotarse se devuelve
un error de auditoría y no se continúa sin registro. No hay cola ilimitada ni
fallback silencioso a memoria. Los tests simulan bloqueo y errores de commit.

No exponer métodos de actualización/borrado e instalar triggers que rechacen
UPDATE y DELETE sobre eventos. No se garantiza resistencia a un administrador
capaz de quitar los triggers, reemplazar la base o editar su almacenamiento.

## 3. Verificación y su límite

Verificar identidad, versión, esquema, secuencias, `GENESIS`, enlaces y cada hash.
No corregir ni eliminar datos automáticamente. Un error impide reanudar acciones.

Comando propuesto en la futura copia ejecutable:
`python -m harness.audit verify <archivo>`.

- Código 0: estructura válida para el archivo disponible.
- Código 1: corrupción o incompatibilidad detectada.
- Código 2: error de uso o de acceso al archivo.

En caso válido mostrar engagement, cantidad, último hash y siempre:
**"Integridad estructural válida; completitud y autenticidad no verificadas sin anclaje externo"**.
El comando no crea archivos faltantes ni modifica la base verificada.

Eliminar el último evento, eliminar toda una cola o reemplazar la base por una
copia válida anterior puede conservar una cadena válida. Sin una referencia
confiable externa no puede conocerse ese pasado. Un contador o hash guardado
solamente en la misma base tampoco resuelve esta amenaza.

## 4. Intentos, decisiones y errores

Conservar los resultados actuales `OK`, `BLOCKED`, `PENDING_HITL` y `ABORTED`.
Agregar tipos de evento, no un nuevo resultado `ERROR` en ese enum:

- `ATTEMPT`: intento autorizado, confirmado antes de ejecutar el adaptador.
- `DECISION`: resultado del harness; solo `OK` significa ejecución exitosa.
- `TOOL_ERROR`: fallo de herramienta, vinculado al intento y con código seguro.

Los eventos de una invocación comparten un identificador generado por el harness.
Mantener las firmas existentes de `Harness.invoke` y `AuditLog.record`; cualquier
extensión del almacenamiento y métodos de eventos debe ser compatible y tipada.
El modo en memoria puede seguir sirviendo para tests existentes, pero no se
acepta como persistencia de la demo ni como sustitución ante un fallo de SQLite.

Flujo propuesto:

1. Mantener kill switch primero, autorización, gates y validación de adaptador.
2. Registrar la decisión rechazada o pendiente y no llamar al adaptador.
3. Para una ejecución permitida, confirmar `ATTEMPT`; ante fallo, no ejecutar.
4. Ejecutar el adaptador fuera de la transacción.
5. Confirmar `DECISION/OK` o `TOOL_ERROR`, según corresponda.
6. Si falla ese registro final, suspender nuevas ejecuciones y elevar un error
   operacional saneado. No se puede deshacer una herramienta que ya actuó.

En todos los fallos se informa error, nunca OK. Un error de herramienta registrado
no dispara reintentos automáticos. Al reanudar el coordinador tras un reinicio,
un `ATTEMPT` sin evento terminal significa resultado desconocido: se requiere
revisión humana y no se repite la acción. Esta comprobación de recuperación no
debe confundir una invocación activa del coordinador actual con un reinicio.
El modo propuesto admite un solo coordinador de ejecución por engagement; sus
conexiones de almacenamiento sí pueden escribir concurrentemente.

## 5. Datos sensibles

Usar una lista cerrada de campos, con tipos y longitudes acotados. No aceptar
mensajes libres de excepción, cuerpos HTTP, cookies, headers ni argumentos
completos. Los errores usan códigos constantes como `adapter_failure`.
El objetivo registra host/IP válido; si la entrada no es un objetivo válido,
guardar un marcador y su huella en lugar del texto potencialmente sensible.
Las referencias de evidencia son identificadores internos, no URLs con secretos.

Esto reduce filtraciones, no demuestra que cualquier texto arbitrario sea seguro.
Los tests deben incluir secretos sintéticos en errores, objetivos inválidos y
salidas del adaptador; no usar credenciales reales.

## 6. Integración mínima de runtime aprobada

Los cuatro especialistas de la primera demo son planificación, reconocimiento,
correlación e informe. Usan llamadas stateless separadas al modelo configurado
en OpenCode, sin tools ni sesiones de programación. Sus mandatos y schemas son
distintos; las respuestas válidas circulan como datos, no como instrucciones.

El coordinador es Python determinista para esta primera integración, no
LangGraph: reduce dependencias y permite probar los controles antes de incorporar
el runtime propuesto por el kit. No implementa los tres loops completos. Un modelo
decide si proponer una consulta simulada o detener el reconocimiento; el harness
impone alcance, aprobación y topes. El adaptador no hace tráfico de red.

El transporte usa el operation ID `experimental.generate.text` mediante la CLI,
que resuelve la ruta según la versión del servidor. No abre archivos de tokens.
En Windows se usa el ejecutable nativo, no el launcher CMD, para evitar pasar
prompts por un shell. Un error no cambia automáticamente al proveedor fixture.

Límites: seis generaciones por ejecución, dos intentos de schema por llamada de
agente, dos iteraciones de reconocimiento, 20.000 caracteres de prompt y timeout
de cliente de 120 segundos. El límite de llamadas no es un límite monetario;
el timeout del cliente tampoco garantiza cancelar una generación en el servidor.

## 7. Preparación, atribución y cierre

Se preparó un subconjunto adaptado y ejecutable en el espacio del grupo, no una
copia completa del kit. `harness/types.py` y los contratos/guard conservan y
adaptan contratos del profesor; la persistencia y la demo son cambios del grupo
con asistencia de IA. La base original se probó aparte, sin editar `labs/`.
La suite de la entrega es distinta de los 77 tests del kit original.
No promover los deltas a specs estables hasta completar revisión e integración.
