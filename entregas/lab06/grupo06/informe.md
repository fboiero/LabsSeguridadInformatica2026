# Informe — Laboratorio 06 · Enumeración

**Grupo:** 06
**Fecha:** 21/10/2026 (última actualización: 30/10/2026)

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Codex (OpenAI).** Lo usamos para interpretar la consigna, planificar el reparto de tareas, armar el borrador inicial del informe y organizar la bitácora y las evidencias.

**ChatGPT (OpenAI).** Lo usamos durante R3 y R4 para guiar las pruebas, interpretar las respuestas y redactar sus filas del inventario y las respuestas P3 y P4. También para preparar la copia temporal del validador que usamos desde Windows.

**Claude Code.** Lo usamos para ejecutar la enumeración de R2 y redactar su fila, su evidencia, P2 y los comandos correspondientes. En la revisión final también lo usamos para corregir la redacción del informe y del research, contrastar cada afirmación con las salidas guardadas y verificar las fuentes. Lo usamos para repetir la búsqueda dirigida de R5 contra el entorno del laboratorio y guardar la respuesta de `/phantomcms/VERSION`, que no había quedado registrada, sin leer el código del target.

**OpenCode.** Lo usamos el 28/10 para repetir la enumeración dirigida de R5 (archivos default, `gobuster` con `big.txt`, `nmap http-enum`) y guardar sus salidas.

Todas las solicitudes se hicieron desde la consola atacante contra `phantomcorp`, y las salidas se guardaron sin editar en `evidencias/`. Revisamos el contenido antes de incorporarlo.

## 1. Flags capturadas

```
   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ✓  R3     Metodos HTTP peligrosos habilitados
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia

  ██████████████████████████████  5/5 (100%)
```

Salida completa en [lab06-status-final.txt](evidencias/lab06-status-final.txt). Las flags se registraron en distintas sesiones y máquinas: R1 en la primera sesión ([estado tras R1](evidencias/lab06-status-after-r1.txt), 1/5) y R4 con una copia temporal del validador ([estado tras R4](evidencias/lab06-r4-status.txt), 1/5). Los envíos de R2 y R5 guardados responden «Correcta (ya la tenías)», es decir, son reenvíos de flags ya registradas. [progreso-06.done](evidencias/progreso-06.done) es una copia del archivo de progreso local del validador.

| Reto | Flag                                | Dónde apareció                                                                                                                                         |
| ---- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| R1   | `FLAG{dir_enumeration_backup}`      | Listado de `/backup`, junto a `notas-infra.txt` ([salida](evidencias/lab06-r1-backup.txt))                                                             |
| R2   | `FLAG{git_repo_exposed}`            | Comentario al final de `/.git/config` ([salida](evidencias/lab06-r2-git-config.txt))                                                                   |
| R3   | `FLAG{http_methods_put_enabled}`    | Cabecera `X-Dangerous-Methods` de la respuesta a `OPTIONS` ([salida](evidencias/lab06-r3-options.txt))                                                 |
| R4   | `FLAG{user_enumeration_api}`        | Campo `flag` del JSON de `/api/users` ([salida](evidencias/lab06-r4-api-users.txt))                                                                    |
| R5   | `FLAG{tech_fingerprint_phantomcms}` | Archivo default `/phantomcms/VERSION` ([salida](evidencias/lab06-r5-default-file.txt)); envío en [lab06-r5-submit.txt](evidencias/lab06-r5-submit.txt) |

## 2. Inventario de enumeración

| Hallazgo                                         | Ruta/Método               | Técnica                                                                               | Evidencia                                                                                                                                                                                                                                                                                                                           | Riesgo                                                                                                                                                                                            | ¿Qué habilita para el Lab 07?                                                                                                                                                                                              |
| ------------------------------------------------ | ------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Directorio de respaldos con listado público      | `GET /backup`             | `dirb` con `common.txt` (4612 palabras); confirmación con `curl`                      | `dirb`: `+ http://phantomcorp/backup (CODE:200\|SIZE:249)`. La respuesta es un «Index of /backup» con `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt`. [dirb](evidencias/lab06-r1-dirb.txt), [curl](evidencias/lab06-r1-backup.txt)                                                                                     | Cualquiera ve qué respaldos existen. Por los nombres, podría haber un volcado de la base y una configuración vieja; no los descargamos, así que no sabemos si son accesibles ni qué contienen.    | Si el `.sql.gz` se descarga, podría dar usuarios, hashes o estructura de tablas para preparar inyecciones SQL; un `config.old` podría dar credenciales.                                                                    |
| Ruta administrativa existente                    | `GET /admin`              | `dirb`                                                                                | `+ http://phantomcorp/admin (CODE:403\|SIZE:65)` [dirb](evidencias/lab06-r1-dirb.txt)                                                                                                                                                                                                                                               | El `403` indica que la ruta existe y está protegida; no sabemos con qué mecanismo.                                                                                                                | Un objetivo concreto para probar evasión de autenticación una vez que haya credenciales o un bypass.                                                                                                                       |
| Archivo de configuración de Git servido por HTTP | `GET /.git/config`        | Solicitud directa con `curl`; control de `/.git/HEAD`, `/.git/logs/HEAD` y `/.git/`   | `200` con el contenido del archivo, incluido `url = https://git.internal.phantomcorp/intranet.git`. Las otras tres rutas devolvieron `404`. [config](evidencias/lab06-r2-git-config.txt), [HEAD](evidencias/lab06-r2-git-head.txt), [logs/HEAD](evidencias/lab06-r2-git-logs-head.txt), [/.git/](evidencias/lab06-r2-git-index.txt) | Muestra que el sitio se publicó desde un repositorio y revela el nombre del servidor Git interno. Con `HEAD` en `404` no pudimos reconstruir el repositorio, así que no vimos código ni historia. | Saber que existe `git.internal.phantomcorp` y el repositorio `intranet`. Si otras rutas de `.git` estuvieran servidas, el código fuente permitiría buscar consultas armadas con strings u otras fallas antes de atacarlas. |
| Métodos `PUT` y `DELETE` anunciados              | `OPTIONS /`               | `curl -X OPTIONS`; script NSE `http-methods`                                          | `Allow: GET, POST, PUT, DELETE, OPTIONS`. Nmap: `Potentially risky methods: PUT DELETE`. [OPTIONS](evidencias/lab06-r3-options.txt), [nmap](evidencias/lab06-r3-nmap-http.txt)                                                                                                                                                      | El servidor declara aceptar métodos que permiten crear y borrar recursos. Es una declaración: no enviamos ningún `PUT` ni `DELETE`, así que no sabemos si funcionan ni con qué permisos.          | Probar, con un archivo inocuo, si `PUT` crea un recurso y si el servidor lo devuelve o lo ejecuta (ver P3).                                                                                                                |
| API interna que lista usuarios y roles           | `GET /api/users`          | `curl -i` sin credenciales                                                            | `200` con `admin` (`superuser`), `jperez` (`editor`) y `mgomez` (`viewer`), y la nota «endpoint interno de RRHH - no exponer». [salida](evidencias/lab06-r4-api-users.txt)                                                                                                                                                          | Cualquiera obtiene los nombres de usuario válidos y sabe cuál es el administrador. No da contraseñas, pero elimina la mitad del trabajo de adivinar credenciales.                                 | Ataques de contraseña dirigidos a `admin`, pruebas de bypass de login con un usuario conocido y pruebas de acceso a objetos por `id` (ver P4).                                                                             |
| Producto y versión del servidor                  | `GET /`                   | `whatweb` y `whatweb -a 3`                                                            | `HTTPServer[PhantomServer/3.7]`, `MetaGenerator[PhantomCMS 3.7]`, `X-Powered-By[PhantomCMS/3.7]`. [whatweb](evidencias/lab06-r5-whatweb.txt)                                                                                                                                                                                        | Anunciar producto y versión le ahorra al atacante identificarlos. El banner no confirma vulnerabilidades: habría que contrastar la versión con fallas conocidas.                                  | Buscar archivos default y fallas documentadas de PhantomCMS 3.7 en lugar de enumerar a ciegas.                                                                                                                             |
| Archivo default del CMS accesible                | `GET /phantomcms/VERSION` | Búsqueda dirigida con `curl`: nombres default combinados con directorios del producto | `200` con `PhantomCMS 3.7 (build 2024-11)`, «Archivo default del CMS» y `FLAG{tech_fingerprint_phantomcms}`. Fue la única ruta distinta de `404` entre 253 combinaciones probadas. [respuesta](evidencias/lab06-r5-default-file.txt), [búsqueda](evidencias/lab06-r5-busqueda-dirigida.txt)                                         | Confirma la versión exacta y agrega la fecha de compilación, más precisa que el banner. Que el archivo siga publicado indica que la instalación conserva los archivos de fábrica del producto.    | Con la versión y el build confirmados, buscar fallas conocidas de esa compilación y otros archivos de instalación del mismo directorio.                                                                                    |

### Salidas que sostienen el inventario

Extractos de las salidas guardadas (se omiten cabeceras HTTP repetidas y algunos campos de `whatweb`); las salidas completas están enlazadas en la tabla.

```text
$ dirb http://phantomcorp/ -S
+ http://phantomcorp/admin (CODE:403|SIZE:65)
+ http://phantomcorp/backup (CODE:200|SIZE:249)

$ curl -sS -i http://phantomcorp/backup
<h1>Index of /backup</h1>
respaldo-db-2024.sql.gz
config.old
notas-infra.txt   ->  FLAG{dir_enumeration_backup}

$ curl -sS -i http://phantomcorp/.git/config
HTTP/1.0 200 OK
[remote "origin"]
	url = https://git.internal.phantomcorp/intranet.git
# FLAG{git_repo_exposed}

$ curl -X OPTIONS -i http://phantomcorp/
HTTP/1.0 200 OK
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: FLAG{http_methods_put_enabled}

$ curl -i http://phantomcorp/api/users
HTTP/1.0 200 OK
{"users": [{"id": 1, "user": "admin", "role": "superuser"}, {"id": 2, "user": "jperez", "role": "editor"}, {"id": 3, "user": "mgomez", "role": "viewer"}], "note": "endpoint interno de RRHH - no exponer", "flag": "FLAG{user_enumeration_api}"}

$ whatweb http://phantomcorp
http://phantomcorp [200 OK] HTML5, HTTPServer[PhantomServer/3.7], MetaGenerator[PhantomCMS 3.7], Title[Intranet PhantomCorp], X-Powered-By[PhantomCMS/3.7]

$ curl -sS -i http://phantomcorp/phantomcms/VERSION
HTTP/1.0 200 OK
PhantomCMS 3.7 (build 2024-11)
Archivo default del CMS. Si llegaste aca por fingerprinting, bien.
FLAG{tech_fingerprint_phantomcms}
```

### Enumeración dirigida de R5

`whatweb` identificó PhantomCMS 3.7 por tres vías independientes: la cabecera `Server`, la cabecera `X-Powered-By` y la etiqueta `<meta name="generator">` ([normal](evidencias/lab06-r5-whatweb.txt), [agresivo](evidencias/lab06-r5-whatweb-a3.txt)).

Con el producto identificado, primero probamos archivos default con nombres genéricos en la raíz: `/changelog`, `/version`, `/robots.txt`, `/readme.txt`, `/sitemap.xml`, `/docs` e `/info.php`. Todos devolvieron `404` ([salida](evidencias/lab06-r5-probes-defaults.txt)). Pedir `/` con distintos User-Agent no cambió la respuesta ([salida](evidencias/lab06-r5-probes-dirigidas.txt)), y `gobuster` con `big.txt` (20470 palabras) y `nmap --script http-enum` solo encontraron `/admin` y `/backup` ([gobuster](evidencias/lab06-r5-gobuster-big.txt), [nmap](evidencias/lab06-r5-nmap-httpenum.txt)).

Las wordlists genéricas no alcanzaban, porque los productos suelen instalar sus archivos dentro de un directorio con su propio nombre. Combinamos 23 nombres default habituales (`readme`, `VERSION`, `CHANGELOG`, `license.txt`, `manifest.json`, sus variantes y `LEEME.txt`) con 11 ubicaciones posibles: la raíz, `phantomcms/`, `PhantomCMS/`, `phantom/`, `cms/`, `admin/`, `core/`, entre otras. De las 253 rutas, solo `/phantomcms/VERSION` respondió `200` ([búsqueda](evidencias/lab06-r5-busqueda-dirigida.txt)). El archivo devolvió `PhantomCMS 3.7 (build 2024-11)` y la flag ([respuesta](evidencias/lab06-r5-default-file.txt)). El directorio `/phantomcms/` en sí responde `404`, así que el archivo no aparece por enumeración de directorios: hay que pedirlo por su nombre exacto.

La flag de R5 se había presentado antes; la respuesta que la contiene no había quedado guardada, y la búsqueda dirigida se repitió el 30/10 para registrarla. El contenido coincide con la flag aceptada.

## 3. Preguntas de análisis

### P1 — Enumeración vs. reconocimiento

El reconocimiento responde qué hay expuesto; la enumeración entra en uno de esos servicios para ver qué contiene. En el Lab 05, con `nmap -Pn -sV -p-`, encontramos cuatro puertos abiertos (21, 80, 8080 y 31337) y leímos sus banners: eso nos dio el mapa de servicios. En este laboratorio tomamos uno solo, el HTTP del puerto 80, y le pedimos 4612 rutas con `dirb`: encontramos `/backup`, que lista respaldos, y `/admin`, que existe pero responde `403`. El reconocimiento nos dijo que había una web; la enumeración, qué recursos no enlazados tiene y cuáles están abiertos.

### P2 — El `.git` expuesto

Un directorio `.git` contiene el repositorio completo: los objetos con cada versión de cada archivo, la historia de commits y la configuración. Si el servidor lo sirve entero, un atacante puede descargar esos archivos uno por uno y reconstruir el repositorio con herramientas como git-dumper. Así obtiene el código fuente actual y también todo lo que alguna vez se commiteó, incluidas contraseñas o claves que después se borraron del código pero siguen en la historia. Por eso es más grave que «un archivo de más»: no expone un dato, expone el código entero y su pasado, y con el código se pueden buscar fallas sin tocar el servidor.

En PhantomCorp el servidor devolvió `/.git/config` con `200`, y ese archivo reveló el remoto `https://git.internal.phantomcorp/intranet.git`. Las rutas que hacen falta para reconstruir el repositorio, empezando por `/.git/HEAD`, devolvieron `404`, así que no pudimos bajar código ni historia. Lo verificado es que el sitio se desplegó desde un repositorio y el nombre del servidor Git interno; que el resto del `.git` no sea accesible por otras rutas no lo probamos.

### P3 — El método `PUT`

Un ataque concreto sería subir una webshell. El atacante envía `PUT /shell.php` con un script que ejecuta el comando recibido por parámetro. Si el servidor lo guarda dentro del directorio que publica y además interpreta ese tipo de archivo, basta con pedir `GET /shell.php?cmd=id` para ejecutar comandos en el servidor. Aunque el servidor no ejecute el archivo, `PUT` permite reemplazar páginas existentes (por ejemplo, para cambiar el contenido del sitio o insertar un script que robe sesiones), y `DELETE`, también anunciado, permite borrarlas.

En PhantomCorp solo sabemos que el servidor anuncia `PUT` y `DELETE` en la cabecera `Allow`. No enviamos ninguno de los dos, así que no comprobamos si aceptan escrituras, dónde se guardarían los archivos ni si se ejecutan.

### P4 — Enumeración de usuarios

Para entrar a una cuenta hace falta un usuario y una contraseña. Si el atacante no sabe qué usuarios existen, tiene que adivinar las dos cosas a la vez y no puede saber si falló por el usuario o por la clave. `/api/users` resuelve la primera mitad: da los nombres válidos y además marca cuál es `superuser`. Con eso la fase siguiente se vuelve mucho más eficiente: probar contraseñas comunes solo contra `admin`, aplicar password spraying (una contraseña contra los tres usuarios, para no disparar bloqueos) o usar credenciales filtradas de otros servicios. También sirve para ataques de inyección en el login, porque el atacante ya sabe qué usuario apuntar, y para pruebas de control de acceso por `id`, porque la API muestra que los identificadores son correlativos (1, 2, 3).

No intentamos iniciar sesión con estos usuarios: lo comprobado es la exposición, no el acceso a las cuentas.

### P5 — Rol defensor: tres mitigaciones

1. **`.git` expuesto.** Agregar en el servidor web una regla que deniegue cualquier ruta que contenga `/.git` (en nginx, `location ~ /\.git { deny all; }`) y, sobre todo, desplegar solo los archivos de la aplicación, sin el repositorio: generar el paquete con `git archive` o en un pipeline, en lugar de hacer `git clone` dentro del directorio publicado.
2. **`/backup` con listado.** Sacar los respaldos del directorio servido por la web y guardarlos en un almacenamiento sin acceso HTTP. Además, desactivar el listado de directorios en el servidor (en nginx, `autoindex off`).
3. **`/api/users` sin autenticación.** Exigir autenticación en la API y permitir el listado solo a un rol administrativo. Si el endpoint es solo para uso interno, publicarlo únicamente en la red interna o bloquearlo en el proxy de borde.

Para `PUT` y `DELETE`, la mitigación es aceptar en cada ruta solo los métodos que la aplicación usa y responder `405` al resto.

## 4. Bitácora de comandos

Todos los comandos se ejecutaron desde la consola atacante (`cyberlab-attacker`) contra `phantomcorp`. La secuencia completa está en [evidencias/comandos.txt](evidencias/comandos.txt).

```bash
# R1
dirb http://phantomcorp/ -S
curl -sS -i http://phantomcorp/backup
# R2
curl -sS -i http://phantomcorp/.git/config
curl -sS -i http://phantomcorp/.git/HEAD
curl -sS -i http://phantomcorp/.git/logs/HEAD
curl -sS -i http://phantomcorp/.git/
# R3
curl -X OPTIONS -i http://phantomcorp/
nmap --script http-methods,http-enum phantomcorp
# R4
curl -i http://phantomcorp/api/users
# R5
whatweb http://phantomcorp
whatweb -a 3 http://phantomcorp
nmap -Pn --script http-enum phantomcorp -p80
gobuster dir -u http://phantomcorp -w /usr/share/dirb/wordlists/big.txt
for p in /changelog /version /robots.txt /readme.txt /sitemap.xml /docs /info.php; do curl -sS -i "http://phantomcorp$p"; done
# búsqueda dirigida: cada nombre default en cada ubicación (lista completa en comandos.txt)
for d in "" phantomcms/ phantom/ cms/ ...; do for f in readme VERSION CHANGELOG ...; do curl -s -o /dev/null -w "%{http_code} /$d$f\n" "http://phantomcorp/$d$f"; done; done
curl -sS -i http://phantomcorp/phantomcms/VERSION
```

Las flags se presentaron con `./ctf submit 06 R<n> '<flag>'` desde la raíz del repositorio. Desde Windows usamos una copia temporal del validador dentro de la consola atacante, con los finales de línea convertidos a LF:

```powershell
docker exec cyberlab-attacker bash -c "cp -r /repo/bin /repo/labs /tmp/lab06-ctf/"
docker cp .\ctf cyberlab-attacker:/tmp/lab06-ctf/ctf
docker exec cyberlab-attacker bash -c "find /tmp/lab06-ctf -type f -exec sed -i 's/\r$//' {} +"
docker exec cyberlab-attacker bash /tmp/lab06-ctf/ctf status 06
```
