# Informe — Laboratorio 06 · Enumeración de servicios

**Grupo:** 04
**Integrantes:**
- Uriel Olivero — @uRIELoLIVERO
- Jeremias Antunez — @JereAntunez
- Facundo Anil — @FacundoAnil4
- Matias Lelli — @LelliMatias
---

## 0. Declaración de uso de IA

Se utilizó **Claude (Anthropic)** como asistente durante el laboratorio. Su uso fue el siguiente:

- **Guía del laboratorio:** Orientación paso a paso para ejecutar los cinco retos. Todos los comandos los ejecutó el grupo contra el contenedor `phantomcorp`.
- **Informe:** Claude ayudó a redactar el borrador de este informe a partir de las salidas de comandos que obtuvimos nosotros.
- **Research:** Claude redactó el borrador de research.md a partir de fuentes que buscó y citó. El grupo lo revisó leyéndolo completo y verificando las fuentes.
- **Cómo se verificó:** cada afirmación del inventario se contrastó con la salida guardada en `evidencia/` (`dirb`, `curl`, `whatweb`) y con `./ctf status 06`.

---

## 1. Parte práctica — flags capturadas

```
[jere@desktop LabsSeguridadInformatica2026]$ ./ctf status 06

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                      │                                                                                                                                                                    
  ╰────────────────────────────────────────────────────────────╯                                                                                                                                                                    

   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ✓  R3     Metodos HTTP peligrosos habilitados
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 06 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 2. Inventario de enumeración

| # | Hallazgo | Ruta / Método | Técnica usada | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|---|
| 1 | Directorio de backup accesible sin autenticación, con listado de archivos | `/backup/` | `dirb` + `curl -si` | `+ http://phantomcorp/backup (CODE:200\|SIZE:249)`; el listado muestra `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt` | **Alto** | Descarga de un respaldo de base de datos y de una configuración antigua: posibles credenciales y datos de usuarios |
| 2 | Ruta protegida que confirma su existencia | `/admin` | `dirb` | `+ http://phantomcorp/admin (CODE:403\|SIZE:65)` | **Medio** | Objetivo concreto para fuerza bruta de credenciales o intento de bypass de control de acceso |
| 3 | Repositorio Git expuesto por HTTP | `/.git/config` | `curl -si` | `url = https://git.internal.phantomcorp/intranet.git` (HTTP 200) | **Alto** | Volcado del repositorio con su historial, búsqueda de secretos commiteados y pista de un servidor Git interno para pivotar |
| 4 | Métodos HTTP peligrosos habilitados | `OPTIONS /` | `curl -X OPTIONS -i` | `Allow: GET, POST, PUT, DELETE, OPTIONS` más el header no estándar `X-Dangerous-Methods` | **Crítico** | Subida de un archivo al servidor (webshell) con `PUT` y posible ejecución remota de código; `DELETE` permite borrar contenido |
| 5 | API interna de RRHH que lista usuarios sin autenticación | `GET /api/users` | `curl -si` | Usuarios `admin` (superuser), `jperez` (editor), `mgomez` (viewer); el JSON incluye `"note": "endpoint interno de RRHH - no exponer"` | **Medio** | Password spraying, fuerza bruta dirigida contra `admin` y phishing dirigido |
| 6 | Tecnología y versión expuestas en tres lugares y en un archivo de versión | `/`, `/phantomcms/VERSION` | `whatweb`, `whatweb -a 3`, `curl -si` | `HTTPServer[PhantomServer/3.7]`, `MetaGenerator[PhantomCMS 3.7]`, `X-Powered-By[PhantomCMS/3.7]`; el archivo indica `PhantomCMS 3.7 (build 2024-11)` | **Bajo (base)** | Búsqueda de CVEs de esa versión y enumeración dirigida a archivos por defecto del producto |
| 7 | Archivos con extensiones comunes en la raíz (resultado negativo) | `/` con `.bak,.old,.txt` | `dirb -X .bak,.old,.txt` | `DOWNLOADED: 13836 - FOUND: 0` | **Informativo** | Descarta archivos sueltos en la raíz: la exposición de respaldos está dentro de `/backup/` |

### Observaciones sobre las pruebas

- `dirb` con `common.txt` generó 4612 palabras y encontró solo dos rutas, `/admin` y `/backup`. Los hallazgos 3, 4, 5 y 6 **no salen de la wordlist**: se encontraron con `curl` sobre rutas y métodos puntuales (`/.git/config`, `OPTIONS`, `/api/users`, `/phantomcms/VERSION`). Correr solo `dirb` habría dejado afuera los hallazgos de mayor riesgo.
- `whatweb -a 3` devolvió exactamente lo mismo que la pasada normal. El servidor ya filtra la versión en `Server`, `X-Powered-By` y el meta `generator`, así que el modo agresivo no sumó información.
- Para encontrar el archivo de versión se probaron 6 rutas candidatas (`/VERSION`, `/version.txt`, `/README`, `/CHANGELOG`, `/phantomcms/VERSION`, `/phantomcms/README`). Solo `/phantomcms/VERSION` respondió 200.
- No se descargó nada de `/backup/`, no se volcó el repositorio Git y no se probó subir archivos con `PUT`. Los riesgos de los hallazgos 1, 3 y 4 se clasifican por lo que la enumeración mostró (existencia, nombres de archivo y métodos permitidos), no por una explotación verificada.
- El fingerprint del Lab 06 (PhantomCMS 3.7) no coincide con el del Lab 05 (PhantomCMS 2.4.1). El entorno es otro y se volvió a verificar en vez de asumir el dato anterior.

### Evidencia de respaldo

`dirb http://phantomcorp/` (fragmento):

```
GENERATED WORDS: 4612
---- Scanning URL: http://phantomcorp/ ----
+ http://phantomcorp/admin (CODE:403|SIZE:65)
+ http://phantomcorp/backup (CODE:200|SIZE:249)
DOWNLOADED: 4612 - FOUND: 2
```

`dirb http://phantomcorp/ -X .bak,.old,.txt` (fragmento):

```
EXTENSIONS_LIST: (.bak,.old,.txt) | (.bak)(.old)(.txt) [NUM = 3]
DOWNLOADED: 13836 - FOUND: 0
```

`curl -si http://phantomcorp/backup/` (fragmento):

```
<h1>Index of /backup</h1>
respaldo-db-2024.sql.gz
config.old
notas-infra.txt   ->  <flag omitida>
```

`curl -si http://phantomcorp/.git/config` (fragmento):

```
HTTP/1.0 200 OK
[core]
        repositoryformatversion = 0
        bare = false
[remote "origin"]
        url = https://git.internal.phantomcorp/intranet.git
```

`curl -X OPTIONS -i http://phantomcorp/`:

```
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: <flag omitida>
```

`curl -si http://phantomcorp/api/users` (fragmento):

```
{"users": [{"id": 1, "user": "admin", "role": "superuser"},
           {"id": 2, "user": "jperez", "role": "editor"},
           {"id": 3, "user": "mgomez", "role": "viewer"}],
 "note": "endpoint interno de RRHH - no exponer", "flag": "<omitida>"}
```

`whatweb http://phantomcorp`:

```
http://phantomcorp [200 OK] HTML5, HTTPServer[PhantomServer/3.7], IP[172.18.0.3],
MetaGenerator[PhantomCMS 3.7], Title[Intranet PhantomCorp], X-Powered-By[PhantomCMS/3.7]
```

`curl -si http://phantomcorp/phantomcms/VERSION` (fragmento):

```
PhantomCMS 3.7 (build 2024-11)
Archivo default del CMS. Si llegaste aca por fingerprinting, bien.
<flag omitida>
```

Archivos completos en la carpeta `evidencia/` de esta entrega: index.txt, dirb_common.txt, dirb_ext.txt, r1_backup.txt, r2_git.txt, r3_options.txt, r4_users.txt, r5_whatweb.txt, r5_whatweb_a3.txt, r5_paths.txt, r5_version.txt y status06.txt.

---

## 3. Preguntas de análisis

**P1 — Enumeración vs. reconocimiento.**

El reconocimiento del Lab 05 respondió "¿qué hay?" con un alcance amplio. Con `nmap -Pn -sV -p- phantomcorp` identificamos cuatro puertos abiertos (21, 80, 8080 y 31337) y las versiones de sus servicios, entre ellas "PhantomCMS 2.4.1" en el puerto 80. La salida fue un **mapa** de la superficie.

La enumeración de este lab responde "¿qué esconde cada cosa?" y es profunda: se queda en un solo servicio, el puerto 80. Con `dirb` encontramos `/backup/` y `/admin`, con `curl` pedimos `/.git/config` y `/api/users`, con `OPTIONS` vimos que `PUT` y `DELETE` están habilitados y con `whatweb` y `/phantomcms/VERSION` confirmamos PhantomCMS 3.7. La salida fue un **inventario detallado**, que es lo que permite planificar un ataque.

Dos cosas concretas: en el Lab 05 descubrimos *qué puertos y servicios hay* (`nmap`); en el Lab 06 descubrimos *qué hay dentro del servicio web* (`dirb`, `curl`). Además, el fingerprint cambió de 2.4.1 a 3.7 entre los dos labs, lo que confirma que los datos del recon hay que reverificarlos en la enumeración.

**P2 — El `.git` expuesto.**

El archivo `/.git/config` respondió 200 y ya filtró el nombre del repositorio (`intranet`) y la URL de un servidor Git interno (`git.internal.phantomcorp`), un host de la red interna que no conocíamos. Pero lo importante es lo que habilita: si `/.git/` es accesible por HTTP, un atacante puede usar una herramienta como `git-dumper` para reconstruir **el código fuente completo de la aplicación y todo su historial de commits**. Eso incluye credenciales, claves o tokens que alguien commiteó por error y borró después: siguen en los commits anteriores.

Es más grave que "un archivo de más" porque no expone un dato aislado sino **toda la aplicación y su historia**. Con el código, el atacante puede revisarlo offline en busca de vulnerabilidades para la fase de explotación, encontrar secretos y conocer la estructura interna sin hacer ruido contra el servidor. También indica una mala práctica de despliegue: el sitio se publicó con `git clone` o `git pull` directamente sobre el webroot. No volcamos el repositorio, así que no podemos afirmar qué contiene; lo que está verificado es que el directorio es accesible.

**P3 — El método `PUT` habilitado.**

La respuesta a `OPTIONS /` incluyó `Allow: GET, POST, PUT, DELETE, OPTIONS`. Un ataque concreto que usa `PUT`, descrito sin ejecutarlo:

1. El atacante confirma con `OPTIONS` que el servidor acepta `PUT`.
2. Con `PUT` sube a una ruta servida por el web server un archivo malicioso, por ejemplo un script que ejecuta los comandos del sistema que recibe por parámetro (una webshell).
3. Lo solicita con `GET` y, si el servidor ejecuta ese tipo de archivo, el atacante obtiene **ejecución remota de código** con los privilegios del servicio web.

A partir de ahí puede leer archivos, extraer los datos de la base, instalar persistencia o moverse hacia otros sistemas de la red interna. Hay un antecedente real de este patrón: la vulnerabilidad CVE-2017-12615 de Apache Tomcat 7.0.0 a 7.0.79 en Windows permitía subir un archivo JSP con `PUT` cuando ese método estaba habilitado, y luego ejecutarlo. `DELETE` habilitado suma el riesgo de borrar contenido o evidencia. Por esto clasificamos el hallazgo como **crítico**. No probamos subir ningún archivo: el lab pide enumerar, no explotar.

**P4 — La API de usuarios.**

Aunque `/api/users` no muestra contraseñas, entregar **nombres de usuario válidos** elimina la mitad del problema del atacante: antes tenía que adivinar usuario y contraseña, ahora solo la contraseña. Además conoce los roles y sabe que `admin` es `superuser`, la cuenta de mayor valor. Para la fase de explotación (Lab 07) eso habilita:

- **Password spraying:** probar unas pocas contraseñas comunes contra los tres usuarios conocidos, sin superar el umbral de bloqueo de una sola cuenta.
- **Fuerza bruta dirigida** contra `admin` en el panel `/admin`, que respondió 403 y por lo tanto existe.
- **Phishing dirigido:** saber que `jperez` es editor y `mgomez` viewer permite armar mensajes creíbles.

El propio JSON dice "endpoint interno de RRHH - no exponer", o sea que la organización sabía que no debía estar público. Relacionado: el `403` de `/admin` es más informativo para un atacante que un `404`, porque confirma que la ruta existe y le da un objetivo concreto; un `404` no le dice nada.

**P5 — Ahora sos el defensor.**

1. **`/backup/` accesible.** Sacar los respaldos del webroot y guardarlos en un almacenamiento interno con control de acceso y cifrado. Mientras tanto, deshabilitar el listado de directorios (`autoindex off;` en nginx o `Options -Indexes` en Apache) y denegar el acceso a esa ruta. Los respaldos que estuvieron expuestos se consideran comprometidos: hay que rotar las credenciales que contengan `config.old` y el respaldo de la base.
2. **`.git` expuesto.** No desplegar con `git clone` sobre el webroot: publicar solo los artefactos necesarios desde un pipeline de despliegue, sin la carpeta `.git`. Como defensa en profundidad, denegar en el servidor toda ruta que empiece con `/.git`. Revisar el historial por secretos commiteados y rotarlos.
3. **`PUT` y `DELETE` habilitados.** Restringir los métodos a `GET` y `POST` (por ejemplo `limit_except GET POST { deny all; }` en nginx o `<LimitExcept GET POST>` en Apache) para que el resto devuelva error. Además, el usuario del servicio web no debería tener permisos de escritura sobre el webroot, así que aunque el método se habilite por error no pueda crear archivos.

Medidas complementarias para otros hallazgos: exigir autenticación y autorización en `/api/users` o dejarlo solo en la red interna, quitar los banners con versión (`Server`, `X-Powered-By`, meta `generator`) y el archivo `/phantomcms/VERSION`, y mantener PhantomCMS parcheado: el build indicado es de 2024-11 y no sabemos si recibió actualizaciones.

---

## 4. Bitácora de comandos

```bash
# Desde la raíz del repo
make setup
./ctf lab 06
make shell

# Dentro de la consola del atacante
mkdir -p ~/lab06 && cd ~/lab06
ping -c 2 phantomcorp
curl -si http://phantomcorp/ | tee index.txt

# R1 - enumeración de directorios
dirb http://phantomcorp/ | tee dirb_common.txt
curl -si http://phantomcorp/backup/ | tee r1_backup.txt
dirb http://phantomcorp/ -X .bak,.old,.txt | tee dirb_ext.txt

# R2 - .git expuesto
curl -si http://phantomcorp/.git/config | tee r2_git.txt

# R3 - métodos HTTP
curl -X OPTIONS -i http://phantomcorp/ | tee r3_options.txt

# R4 - API de usuarios
curl -si http://phantomcorp/api/users | tee r4_users.txt

# R5 - fingerprinting
whatweb http://phantomcorp | tee r5_whatweb.txt
whatweb -a 3 http://phantomcorp | tee r5_whatweb_a3.txt
for p in /VERSION /version.txt /README /CHANGELOG /phantomcms/VERSION /phantomcms/README; do
  echo -n "$p -> "
  curl -s -o /dev/null -w "%{http_code}\n" http://phantomcorp$p
done | tee r5_paths.txt
curl -si http://phantomcorp/phantomcms/VERSION | tee r5_version.txt

# Guardar la evidencia en /loot
cp ~/lab06/*.txt /loot/

# Entrega de flags (desde la raíz del repo, fuera de la consola)
./ctf submit 06 R1 'FLAG{...}'
./ctf submit 06 R2 'FLAG{...}'
./ctf submit 06 R3 'FLAG{...}'
./ctf submit 06 R4 'FLAG{...}'
./ctf submit 06 R5 'FLAG{...}'
./ctf status 06 | tee status06.txt
```

---

## 5. Conclusión

La enumeración mostró que el servidor web que en el recon aparecía solo como "PhantomCMS" esconde una cadena de malas configuraciones: un directorio de backup con un respaldo de base de datos, un repositorio Git accesible, una API de RRHH que lista usuarios sin autenticación y un servidor que acepta `PUT` y `DELETE`. El hallazgo más grave es el **`PUT` habilitado**, porque abre la puerta a subir una webshell y obtener ejecución remota. Le siguen `/backup/` y `/.git`, que pueden entregar credenciales y código fuente, y la API de usuarios, que reduce el esfuerzo de un ataque de credenciales contra `admin`.

Aprendimos que la enumeración con wordlist es solo una parte: `dirb` encontró `/admin` y `/backup`, pero el `.git`, los métodos HTTP, la API y el archivo de versión solo aparecieron preguntando por rutas y métodos puntuales, guiados por el fingerprint y por lo que ya sabíamos del producto. También aprendimos a leer el código de respuesta como información (un 403 confirma que algo existe) y a mirar los headers y no solo el cuerpo, porque la respuesta a `OPTIONS` llegó sin cuerpo. Dejamos explícito lo que no verificamos: no descargamos los respaldos, no volcamos el repositorio y no probamos subir archivos. Estos tres puntos, junto con las cuentas enumeradas, son la base del plan de explotación del Lab 07.