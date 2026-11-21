# Informe — Laboratorio 07 · Explotación

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha de integración:** 2026-11-20 (America/Buenos_Aires)

> Informe integrado de los cuatro integrantes. Las capturas originales conservan su procedencia; el cierre incorpora el estado consolidado y el mini-research.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal local para planificar el bloque, preparar y ejecutar requests HTTP contra el contenedor PhantomCorp del laboratorio, interpretar las respuestas observadas y redactar este informe y la evidencia de R1/R2. La IA ejecutó las requests registradas; no se consultó el código del objetivo para obtener las flags. Las pruebas de esta edición se verificaron con las respuestas HTTP y el estado del CTF (2/5). Lorenzo debe revisar y poder explicar los payloads antes de la entrega final.

Lautaro Mariño (@lautaromarino0) — bloque B (R3 y R4): se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a redactar las filas de R3 y R4 a partir del análisis de Lautaro, que revisó y ajustó cada payload y texto antes de commitearlo. **Contraste de pruebas:** sirvió de soporte para explotar en **caja negra** el target del Lab 07 corrido en un sandbox Linux (`server.py` en `/app` = WORKDIR del Dockerfile, `phantomcorp -> 127.0.0.1`), encadenando comandos en `/herramientas/ping` (R3) y saliendo de `public/` con `../` en `/descargar` (R4). **Verificación:** no se leyó el código del target ni `solucion.md`; las flags salieron de las respuestas HTTP y se validó el `sha256` de cada una contra el hash del reto en `retos.manifest`. El envío al CTF y el `status` consolidado se hacen desde el host.


**Guadalupe Gómez — bloque C (P1, P2, P5):** se utilizó **Claude (Anthropic)** para redactar las respuestas P1 (bypass del login), P2 (aridad del UNION) y P5 (autorización del IDOR), a partir de la evidencia HTTP real de R1/R2 capturada por Lorenzo (`evidencia/salidas/r1-r2-http.txt`) y de la consigna. No se leyó el código del target. **R5 (IDOR)** se operó en caja negra contra el target del lab corrido localmente (`server.py` en `/app`, `phantomcorp -> 127.0.0.1`): autenticada como `jperez` (id=3), `GET /perfil?id=1` devolvió el perfil del admin con `FLAG{idor_broken_access}`, verificada contra el `retos.manifest` por SHA-256 (`evidencia/salidas/r5-idor.txt`). No se leyó el código del target para obtener la flag. Guadalupe revisó el contenido y puede explicarlo.
**Fernando Cagliero — integración, análisis y research:** OpenAI Codex para redactar y revisar P3, P4 y el mini-research, y preparar el informe y el borrador del PR. Se contrastaron los conceptos con documentación oficial de Python, SQLite, PostgreSQL y MITRE ATT&CK. El ejemplo parametrizado se ejecutó en una base SQLite en memoria con datos ficticios. Pendiente la revisión personal de Fernando. La integración de los aportes y la validación de las flags se documentan en `evidencia/salidas/cierre-integracion.txt`.

## 1. Flags capturadas

Captura histórica parcial de Lorenzo con `./ctf status 07` (conservada sin alterar):

```text
R1  SQLi - bypass de autenticacion                         resuelto
R2  SQLi - extraccion de datos con UNION                   resuelto
R3  Inyeccion de comandos (RCE)                            pendiente
R4  Path traversal / LFI                                   pendiente
R5  IDOR - control de acceso roto                          pendiente
Progreso: 2/5 (40%)
```

La salida completa está en `evidencia/salidas/status-07.txt`. R3–R5 corresponden a otros bloques del reparto y no se atribuyen a Lorenzo en esta edición.

**Cierre de integración — 20/11/2026:** las cinco flags observadas en las salidas de los operadores se enviaron al verificador oficial desde una exportación limpia de la base con esta entrega. El estado consolidado es **5/5**; ver [captura](evidencia/salidas/status-07-consolidado.txt) y [registro de cierre](evidencia/salidas/cierre-integracion.txt). Esta comprobación valida los marcadores documentados y no constituye una nueva ejecución de los ataques.

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) | `user=admin' --` y `pass=not-the-password` | Reconstrucción inferida a partir de la consigna: `SELECT user, rol FROM users WHERE user='admin' --' AND pass='not-the-password'`. `--` inicia el comentario SQL y el motor ignora la condición de contraseña que sigue. | El servidor respondió `Bienvenido admin (rol: admin)` y devolvió la flag de R1; la autenticación ocurrió sin conocer la contraseña. | Consulta parametrizada para usuario y contraseña; almacenar contraseñas con un KDF adecuado y verificar el hash después de recuperar el registro. No concatenar valores dentro del SQL. |
| SQLi UNION (R2) | `q=x' UNION SELECT * FROM secrets -- `; control de aridad `UNION SELECT 1,2` (aceptado) frente a `UNION SELECT 1,2,3` (error). | Reconstrucción inferida según el buscador documentado: `SELECT nombre, precio FROM productos WHERE nombre LIKE '%x' UNION SELECT * FROM secrets -- %'`. Dos columnas funcionan; tres producen el error de aridad. `SELECT * FROM secrets` mostró una fila presentada como `flag_union - $FLAG{sqli_union_dump}`. | Lectura de un registro de la tabla `secrets` a través del buscador; la respuesta entregó la flag R2. El intento de nombres de columnas no observados dio `no such column: name`, por lo que no se afirma un esquema que no se haya comprobado. | Parametrizar `q` como dato de `LIKE`; no concatenarlo como SQL. Restringir además la consulta al conjunto de campos previsto y no exponer errores SQL al cliente. |
| Command injection (R3) | `host=127.0.0.1;cat /app/flags/cmdi.txt` (probe previo `host=127.0.0.1;id` → `uid=0(root)`). | El endpoint arma `ping -c1 <host>` y `host` va directo al shell: `ping -c1 127.0.0.1;cat /app/flags/cmdi.txt`. El `;` encadena un segundo comando. | **RCE como root** (uid=0): se leyó `/app/flags/cmdi.txt` → `FLAG{command_injection_rce}` (sha256 verificado contra `retos.manifest`). El alcance de lectura/escritura queda condicionado por los permisos y el aislamiento del contenedor; persistencia y pivoting no se demostraron en esta captura. | No pasar entrada a un shell: usar `subprocess` con lista de argumentos y sin `shell=True`; validar `host` con allowlist (regex de IP/hostname); correr el servicio sin privilegios, nunca como root. |
| Path traversal (R4) | `archivo=../flags/lfi.txt`. | El archivo se abre desde `public/`: `archivo` se concatena y queda `/app/public/../flags/lfi.txt` → `/app/flags/lfi.txt`. Un solo `../` alcanza porque `public/` cuelga de `/app`; `../../flags/lfi.txt` sobrepasa (`/flags`) y da `No such file`. | Lectura de un archivo **fuera de `public/`** → `FLAG{path_traversal_lfi}` (sha256 verificado contra `retos.manifest`). Permite leer archivos arbitrarios del servidor (config, secretos). | Canonicalizar con `os.path.realpath` y verificar que el resultado quede **dentro** del directorio base; rechazar `..`; servir solo desde un allowlist. No construir rutas por concatenación directa. |
| IDOR (R5) | `GET /perfil?id=1` estando autenticada como `jperez` (id=3). | El endpoint devuelve el perfil del `id` pedido **sin verificar que pertenezca al usuario de la sesión**: `/perfil?id=3` es el perfil propio, pero `/perfil?id=1` entrega el del admin. | Acceso a datos ajenos: se leyó la nota privada del admin, que contiene `FLAG{idor_broken_access}` (sha256 verificado contra `retos.manifest`). Con otros `id` se leería el perfil de cualquier usuario. | Verificar en el servidor, en **cada** request, que el recurso pedido pertenece al usuario autenticado (o que su rol lo autoriza); negar por defecto. No confiar en el `id` del cliente ni alcanza con ocultarlo. |

Los SQL reconstruidos son inferencias basadas en la plantilla/consigna y el comportamiento HTTP, no capturas internas de la consulta ejecutada. Las respuestas crudas y probes están en `evidencia/salidas/r1-r2-http.txt`.

## 3. Preguntas de análisis




### P1 — bypass R1.

 El login arma la consulta concatenando el usuario: `SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'`. Con `user=admin' --`, la comilla cierra el literal del usuario y `--` abre un comentario SQL, así que el motor **ignora todo lo que sigue**, incluida la condición `AND pass='...'`. La consulta efectiva queda `... WHERE user='admin'`, que devuelve la fila de admin sin comparar la contraseña. Por eso `pass=not-the-password` da igual: el servidor respondió `Bienvenido admin (rol: admin)` y entregó `FLAG{sqli_auth_bypass}` (`evidencia/salidas/r1-r2-http.txt`). El problema es concatenar la entrada dentro del SQL; con consulta parametrizada, `admin' --` sería un nombre de usuario literal que no existe, y el login fallaría.



### P2 — aridad de UNION.

 Un `UNION` solo funciona si las dos consultas devuelven el **mismo número de columnas**. El buscador original devuelve dos columnas (nombre y precio), así que para inyectar hay que igualar ese número, y no se conoce de entrada: se **infiere por prueba**. En la evidencia, `UNION SELECT 1,2` fue aceptado y devolvió una fila (`1 - $2`), mientras que `UNION SELECT 1,2,3` devolvió `...do not have the same number of result columns`. Ese error vs. no-error es el oráculo: se agregan columnas hasta que deja de fallar, y ahí se sabe que son dos. Con la aridad resuelta, `x' UNION SELECT * FROM secrets -- ` (dos columnas) trajo la fila `flag_union - $FLAG{sqli_union_dump}`. El probe de nombres de columna dio `no such column: name`, así que no se afirma un esquema no comprobado. Ver `evidencia/salidas/r1-r2-http.txt`.

### P3 — Qué sigue después del RCE

Tras conseguir ejecución remota de comandos, un posible objetivo del atacante sería la **persistencia**. Buscaría conservar acceso al sistema si se cierra la sesión inicial, se reinicia el proceso o se corrige el punto de entrada. La viabilidad depende de los permisos de la cuenta que ejecuta la aplicación, del aislamiento del contenedor y de qué estado conserva el entorno entre reinicios. [MITRE ATT&CK — Persistence](https://attack.mitre.org/tactics/TA0003/).

La evidencia de Lautaro registra `uid=0(root)` y la lectura de la flag mediante un comando encadenado en el target local (`evidencia/salidas/r3-r4-http.txt`). Eso acredita RCE y privilegios root en ese entorno. No acredita persistencia, acceso al host ni pivoting: esas acciones se analizan como posibilidades condicionadas y no se ejecutaron en este bloque.

Desde la defensa, una ejecución inesperada justifica correlacionar los registros HTTP con la actividad de procesos y revisar cambios en el entorno. Si se confirma un compromiso, corresponde aislar la instancia, preservar los registros y corregir la construcción del comando antes de restaurar el servicio desde una imagen confiable.

### P4 — Por qué parametrizar evita la SQLi

Al concatenar texto de un formulario con la consulta, ese texto llega al motor como parte de la instrucción SQL. Con una consulta parametrizada, la aplicación define la instrucción con marcadores y pasa los datos por separado. En SQLite, el motor prepara la instrucción y vincula cada valor al marcador que le corresponde. Si el usuario escribe una comilla, el motor la usa como parte del valor a comparar. El filtro de la consulta conserva su estructura. [SQLite — Binding Values To Prepared Statements](https://www.sqlite.org/c3ref/bind_blob.html).

En el login, la aplicación puede buscar el usuario con `WHERE nombre = ?` y verificar la contraseña contra el hash almacenado. En el buscador, el texto de búsqueda también se pasa como parámetro del filtro. En ambos casos la defensa reside en cómo el controlador entrega el valor al motor y admite texto legítimo como `O'Reilly` sin editarlo. El mini-research incluye un ejemplo comprobado con `sqlite3`. [Python — How to use placeholders to bind values in SQL queries](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).



### P5 — autorización del IDOR.

 Un IDOR aparece cuando el servidor usa un identificador que viene del cliente (p. ej. `?id=123`) para devolver un recurso **sin verificar que el usuario autenticado tenga derecho a ese recurso**. La corrección va en el **servidor y en cada request**: comprobar que el recurso pedido pertenece al usuario de la sesión (o que su rol lo autoriza) antes de devolverlo; negar por defecto. No alcanza con **ocultar o validar el `id` en el cliente** —quitarlo de la URL, cifrarlo, deshabilitar un botón—: el atacante controla la request y puede pedir cualquier `id` igual. Tampoco alcanza con IDs difíciles de adivinar (UUIDs): eso es secreto por oscuridad, no autorización. El control tiene que ser una verificación de pertenencia del lado del servidor, ligada a la identidad autenticada.

## 4. Bitácora de comandos

Las capturas de Lorenzo proceden del atacante del Compose contra `phantomcorp` local; Lautaro y Guadalupe documentan sus sesiones de caja negra sobre el target local en sus archivos de evidencia. El registro de comandos reproducibles está en `evidencia/comandos.txt`; las respuestas HTTP están en `evidencia/salidas/r1-r2-http.txt`, `r3-r4-http.txt` y `r5-idor.txt`. La captura `status-07.txt` conserva el estado histórico parcial de Lorenzo (2/5). En el cierre de integración se enviaron las cinco flags observadas desde las salidas de los operadores y se verificó el estado consolidado 5/5; ver `status-07-consolidado.txt` y `cierre-integracion.txt`.


## 5. Mini-research y revisión de integración

[Mini-research del grupo](research.md). La integración preserva las salidas crudas de cada autor. Las mejoras de defensa propuestas se distinguen de las técnicas efectivamente verificadas; la revisión personal y capacidad de explicar el trabajo corresponden a cada integrante.
