# Informe — Laboratorio 06 · Enumeración

**Grupo:** 10 · **Fecha:** 2026-11-03

**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Belén Rocío Ramello | 15226 | @belramello |
| Carolina Paula Corazza | 15239 | @carocor1 |
| Chiara Agustina Kordek | 14719 | @chiarakordek |
| Juan Pablo Saby | 15026 | @JuanSaby |

---

## 0. Declaración de uso de IA

En cumplimiento con las directivas de `CONTRIBUTING.md`, se declara el uso de **Antigravity + Claude** y **OpenCode con GPT-6.1 Sol (OpenAI)** durante el desarrollo del laboratorio:
- **Finalidad de uso:** Asistencia en la revisión de la consigna, planificación metodológica, análisis de la estructura interna de Git (objetos, zlib, árboles y blobs).
- **Partes asistidas:** Metodología y documentación de la exposición de Git y la enumeración de usuarios; organización de evidencias e integración del informe.
- **Verificación:** Los análisis se contrastaron con las solicitudes y respuestas reales de `curl`, sus códigos HTTP y cabeceras. Para el repositorio expuesto se validó el hash SHA-256 de la flag contra `retos.manifest`; para la API se comprobó la aceptación de la flag por el motor oficial y se conservaron las salidas del envío y del estado CTF.

---

## 1. Flags capturadas

Estado oficial unificado del laboratorio (`./ctf status 06`), con los cinco retos completados al 100%:

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

[ OK ] ¡Lab 06 COMPLETO! Ponete las pilas con la próxima unidad.
```

Evidencia unificada: [salida consolidada de ctf status 06](evidencia/salidas/ctf_status_global.txt).

### Registros individuales y validaciones por reto

- **R1:** `FLAG{dir_enumeration_backup}`, recuperada del listado de `/backup/`. [Envío R1](evidencia/salidas/r1_04_ctf_submit.txt).
- **R2:** `FLAG{git_repo_exposed}`, recuperada de `/.git/config`. [Envío R2](evidencia/salidas/07_ctf_submit_status.txt).
- **R3:** `FLAG{http_methods_put_enabled}`, recuperada de la cabecera `X-Dangerous-Methods` en `OPTIONS /`. [Envío R3](evidencia/salidas/r3_03_ctf_submit.txt).
- **R4:** `FLAG{user_enumeration_api}`, recuperada de la respuesta JSON en `/api/users`. [Envío R4](evidencia/salidas/r4_04_ctf_submit_r4.txt).
- **R5:** `FLAG{tech_fingerprint_phantomcms}`, recuperada del archivo default `/phantomcms/VERSION`. [Envío R5](evidencia/salidas/r5_03_ctf_submit.txt).

A continuación se conservan las capturas y notas de las ejecuciones locales de los integrantes:

![Salida real de ctf status 06 con R4 validado](evidencia/capturas/ctf_status_r4.png)
*(Captura local de la ventana de Git Bash/Mintty durante la validación de R4).*

---

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| **R1 — Directorio de respaldos con listado accesible** | `GET /backup/` | Enumeración de directorios con `dirb` (wordlist común) y verificación con `curl` | [hallazgos de `dirb`](evidencia/salidas/r1_01_dirb_hallazgos.txt); [listado de `/backup/`](evidencia/salidas/r1_02_backup_listing.txt); [rutas conocidas con `http-enum`](evidencia/salidas/r1_03_http_enum.txt) | **Medio (demostrado):** el servidor devuelve el índice del directorio y nombra respaldos sensibles (`respaldo-db-2024.sql.gz`, `config.old`). En esta instancia los archivos individuales devolvieron 404, por lo que no se descargó contenido; el impacto demostrado es el listado de directorios habilitado y la divulgación de la existencia y los nombres de esos respaldos. `/admin` existe pero responde 403 | Los nombres `respaldo-db-2024.sql.gz` (volcado de base) y `config.old` señalan objetivos concretos para intentar recuperar en el Lab 07, por ejemplo mediante el path traversal de `GET /descargar?archivo=` |
| **Repositorio Git expuesto (Configuración y URL interna)** | `GET /.git/config` | Petición HTTP directa a rutas predecibles de control de versiones | Código `200 OK`, `Content-Type: text/plain`. Revela `bare = false` y `url = https://git.internal.phantomcorp/intranet.git` junto a comentarios de desarrollo | **Medio** (Demostrado). Divulgación de arquitectura interna y ubicación del repositorio central de código. No escala a Crítico en este servidor porque `.git/objects/` e historial no son accesibles (404) | Permite identificar el nombre del repositorio interno (`intranet.git`) y el dominio de desarrollo (`git.internal.phantomcorp`) para ataques dirigidos de falsificación de peticiones (SSRF) o pivot lateral |
| **Métodos anunciados pero no implementados (R3)** | `OPTIONS /`, `PUT /chiara-r3-test.txt`, `DELETE /chiara-r3-test.txt` | `curl -i` desde la consola atacante | [OPTIONS y flag R3](evidencia/salidas/r3_01_options_http.txt); [pruebas de PUT/DELETE](evidencia/salidas/r3_02_put_test.txt); [envío CTF](evidencia/salidas/r3_03_ctf_submit.txt) | La lista `Allow` es inconsistente y puede inducir a error. En este target no se comprobó carga ni borrado; en un servidor que sí aceptara escrituras, el riesgo sería mayor | No habilitó una explotación directa. Orienta la enumeración, pero el command injection del Lab 07 es independiente |
| **R4 — API interna que expone usuarios y roles sin autenticación** | `GET /api/users` | Enumeración dirigida de rutas de API con `curl` y análisis del JSON | [HTTP 200 y listado de usuarios](evidencia/salidas/r4_02_api_users_http.txt); [petición sin credenciales](evidencia/salidas/r4_02_api_users_peticion.txt) | **Medio, valoración cualitativa:** exposición demostrada de tres usuarios, sus identificadores y roles. Permite reconocer cuentas y priorizar objetivos; no demuestra acceso a ellas ni recuperación de contraseñas | Nombres para orientar futuras pruebas de autenticación e IDs `1`, `2` y `3` para investigar autorización por objeto, si el endpoint del Lab 07 utiliza esos mismos identificadores. No demuestra IDOR por sí solo |
| **R5 — CMS y versión expuestos (fingerprinting)** | `GET /` (cabeceras y `<meta generator>`) y `GET /phantomcms/VERSION` | Fingerprinting con `whatweb -a 3` y confirmación con `curl` | [salida de `whatweb`](evidencia/salidas/r5_01_whatweb.txt); [archivo default del CMS](evidencia/salidas/r5_02_version_default.txt) | **Medio (demostrado):** el stack se publica en claro (`Server: PhantomServer/3.7`, `X-Powered-By: PhantomCMS/3.7`, `<meta generator>` PhantomCMS 3.7) y el archivo default `/phantomcms/VERSION` confirma producto, versión y build (`PhantomCMS 3.7 (build 2024-11)`). No se identificó un CVE aplicable a este producto ficticio; el riesgo es la exposición de versión | Conocer producto, versión y build exactos permite buscar vulnerabilidades específicas de esa versión antes de la explotación; la convención del archivo default (`/phantomcms/VERSION`) es en sí un vector de enumeración reutilizable |

### Evidencia de soporte del inventario (R2)

#### 1. Petición y respuesta a `/.git/config`
```http
GET http://phantomcorp/.git/config HTTP/1.1
Host: phantomcorp

HTTP/1.0 200 OK
Server: PhantomServer/3.7
Date: Sun, 01 Nov 2026 21:45:02 GMT
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

#### 2. Comprobación de límites de exposición (Inaccesibilidad de objetos/historial)
```http
GET http://phantomcorp/.git/HEAD HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/logs/HEAD HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/index HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/objects/info/packs HTTP/1.1 -> 404 Not Found
GET http://phantomcorp/.git/description HTTP/1.1 -> 404 Not Found
```

### Evidencia de soporte del inventario (R4)

**Fecha de ejecución:** 2026-11-03.

#### 1. Alcance y entorno

La consigna pide identificar una API interna que lista personal. Se tomó como punto de partida la pista `/api/...` y el ejemplo `/api/users` publicado en el enunciado. Se realizaron únicamente dos solicitudes `GET` al objetivo de la cátedra, sin credenciales, cookies ni cabecera `Authorization`; no se afirma haber inventariado toda la API.

Los contenedores preexistentes correspondían a otros laboratorios. Para no reemplazarlos, se construyó el objetivo del **Lab 06** en el proyecto independiente `lab06-r4-carolina`, con el [Compose de reproducción](evidencia/entorno-r4.compose.yml). La red es interna, sin puertos publicados al host ni montajes del repositorio o de archivos personales. Al finalizar se detuvieron únicamente los dos contenedores de ese proyecto.

No se obtuvo la flag leyendo el código del objetivo ni `solucion.md`; se recuperó de la respuesta HTTP. No se ejecutaron pruebas de autenticación, fuerza bruta ni explotación del Lab 07.

#### 2. Rutas consultadas y respuestas

| Orden | Solicitud | Respuesta observada | Interpretación |
|---|---|---|---|
| 1 | `GET http://phantomcorp/api` | `404 Not Found`, `Content-Type: text/html; charset=utf-8` | Esta ruta concreta no devuelve un índice de API; no permite concluir que no existan subrutas. |
| 2 | `GET http://phantomcorp/api/users` | `200 OK`, `Content-Type: application/json` | Devuelve directamente el listado de personal y la flag, sin iniciar sesión. |

Se conservan la [traza de la petición a `/api`](evidencia/salidas/r4_01_api_peticion.txt) y su [respuesta cruda](evidencia/salidas/r4_01_api_http.txt), incluido el resultado negativo. El código de salida `0` de `curl` indica que completó la transferencia, no que el HTTP 404 sea un resultado exitoso de enumeración.

Extracto de la [solicitud real que permitió enumerar usuarios](evidencia/salidas/r4_02_api_users_peticion.txt):

```text
> GET /api/users HTTP/1.1
> Host: phantomcorp
> User-Agent: curl/8.14.1
> Accept: */*
>
```

Cabeceras y cuerpo de la [respuesta cruda](evidencia/salidas/r4_02_api_users_http.txt). El cuerpo se conserva en una línea, como fue recibido:

```http
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Date: Tue, 03 Nov 2026 19:33:22 GMT
Content-Type: application/json
X-Powered-By: PhantomCMS/3.7

{"users": [{"id": 1, "user": "admin", "role": "superuser"}, {"id": 2, "user": "jperez", "role": "editor"}, {"id": 3, "user": "mgomez", "role": "viewer"}], "note": "endpoint interno de RRHH - no exponer", "flag": "FLAG{user_enumeration_api}"}
```

#### 3. Usuarios identificados y límites de la comprobación

| ID publicado | Usuario publicado | Rol declarado por la API |
|---|---|---|
| 1 | `admin` | `superuser` |
| 2 | `jperez` | `editor` |
| 3 | `mgomez` | `viewer` |

La API identifica directamente estos tres usuarios del escenario, sin inferirlos mediante diferencias en mensajes de error. La nota `endpoint interno de RRHH - no exponer` refuerza que el listado está destinado a uso interno. No se comprobó si las cuentas permiten iniciar sesión ni si sus roles se aplican correctamente: la evidencia demuestra su publicación, no el control de las cuentas.

La respuesta no incluye contraseñas, hashes, correos ni tokens de sesión. Los nombres y la flag pertenecen al entorno ficticio de la cátedra, no a personas o servicios externos.

#### 4. Riesgo de la exposición

El impacto demostrado es sobre la **confidencialidad**: cualquier cliente con conectividad HTTP al servicio puede obtener el listado observado sin aportar credenciales. No se demostró que el contenedor fuera accesible desde Internet, ni que se pudiera modificar información o afectar la disponibilidad.

Conocer usuarios válidos reduce la incertidumbre para futuras pruebas de autenticación: en lugar de adivinar simultáneamente usuario y contraseña, un atacante puede concentrarse en las cuentas publicadas. El rol `superuser` señala a `admin` como un objetivo potencialmente más valioso, aunque no se hayan probado sus permisos efectivos. Los identificadores consecutivos revelan referencias concretas que pueden orientar la revisión de controles de acceso.

La valoración **media** se fundamenta en la exposición anónima de identidades y roles internos con una sola solicitud, sin evidencia de contraseñas, sesiones, acceso a cuentas ni una cadena de explotación completada. No se asigna un CVSS ni se presenta como una vulnerabilidad crítica sin pruebas que lo respalden.

#### 5. Información aprovechable para el Lab 07

- **Usuarios:** `admin`, `jperez` y `mgomez` son entradas conocidas para planificar pruebas de autenticación autorizadas, sin afirmar que ya se haya obtenido acceso.
- **Roles declarados:** `superuser`, `editor` y `viewer` permiten definir qué diferencias de permisos deberían revisarse en la fase de explotación.
- **Identificadores:** `1`, `2` y `3` podrían utilizarse para investigar autorización por objeto en `GET /perfil?id=`, si se confirma que ambas partes del escenario comparten esos IDs. Conocer un ID no habilita por sí mismo a leer el perfil correspondiente.

En R4 no se consultó `/perfil`, no se modificaron identificadores para acceder a perfiles y no se resolvió IDOR. Esa conexión es una hipótesis de trabajo para el Lab 07, no un resultado ya demostrado.

#### 6. Fuentes del análisis de R4

- [Consigna del Lab 06](../../../labs/lab06-enumeracion-de-servicios/README.md), [rúbrica](../../../labs/lab06-enumeracion-de-servicios/docs/rubrica.md) y [protocolo de evidencia](../../../docs/PROTOCOLO-EVIDENCIA.md).
- [OWASP WSTG v4.2 — Testing for Account Enumeration and Guessable User Account](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account): fundamento del riesgo de revelar usuarios. Sus pruebas sobre autenticación no se ejecutaron aquí; se observó una divulgación directa mediante API.
- [MITRE — CWE-200](https://cwe.mitre.org/data/definitions/200.html): referencia conceptual sobre exposición de información y confidencialidad, no una clasificación de causa raíz ni una estimación automática de severidad.
- Documentación oficial de Docker, consultada mediante Context7: [directorio de proyecto de Compose](https://docs.docker.com/reference/cli/docker/compose/) y [redes internas](https://docs.docker.com/reference/compose-file/networks/#internal).

### Evidencia de soporte del inventario (R1)

**Fecha de ejecución:** 2026-11-05.

#### 1. Enumeración de directorios

Se ejecutó `dirb` con la wordlist común contra el objetivo autorizado `phantomcorp`. Reportó dos rutas: `/admin` con código `403` (existe pero está protegida) y `/backup` con código `200` (accesible). Un barrido adicional con `gobuster` sobre `big.txt` y el script `http-enum` de Nmap no agregaron rutas nuevas; `http-enum` también señaló `/backup/` como posible respaldo. Se conservan los [hallazgos de `dirb`](evidencia/salidas/r1_01_dirb_hallazgos.txt) y la [salida de `http-enum`](evidencia/salidas/r1_03_http_enum.txt).

#### 2. Recurso sensible expuesto

La solicitud `GET /backup/` devolvió `200 OK` con un índice de directorio que lista `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt`, y la propia página admite que «este directorio no deberia estar accesible». La flag `FLAG{dir_enumeration_backup}` aparece en ese listado ([captura](evidencia/salidas/r1_02_backup_listing.txt)). Al pedir los archivos individuales (`/backup/config.old`, `/backup/notas-infra.txt`) el servidor respondió `404`: en esta instancia el índice es una página estática y no se descargó el contenido de los respaldos. El hallazgo demostrado es, por lo tanto, el listado de directorio habilitado y la divulgación de la existencia y los nombres de respaldos sensibles, no la exfiltración de esos archivos.

#### 3. Riesgo e información para el Lab 07

El listado revela que existen un volcado de base de datos (`respaldo-db-2024.sql.gz`) y una configuración antigua (`config.old`). Aunque aquí no se pudieron descargar, son objetivos concretos para la fase de explotación: el endpoint `GET /descargar?archivo=` del Lab 07 (path traversal) es un camino para intentar alcanzar precisamente ese tipo de archivos fuera del directorio público. Como mitigación, conviene deshabilitar el listado de directorios y retirar los respaldos del árbol servido por el servidor web.

### Evidencia de soporte del inventario (R5)

**Fecha de ejecución:** 2026-11-05.

#### 1. Fingerprinting del stack

`whatweb -a 3 http://phantomcorp` identificó el servidor y el CMS a partir de las respuestas HTTP: `HTTPServer [PhantomServer/3.7]`, `X-Powered-By [PhantomCMS/3.7]` y `MetaGenerator [PhantomCMS 3.7]`, además del título «Intranet PhantomCorp» ([salida de `whatweb`](evidencia/salidas/r5_01_whatweb.txt)). Las mismas cabeceras y la etiqueta `<meta name="generator" content="PhantomCMS 3.7">` ya se observaban en la respuesta de la raíz capturada en R2.

#### 2. Archivo default del CMS

Con el producto identificado, se buscó su archivo default. La ruta `GET /phantomcms/VERSION` devolvió `200 OK` con `PhantomCMS 3.7 (build 2024-11)` y el texto «Archivo default del CMS. Si llegaste aca por fingerprinting, bien.», junto con la flag `FLAG{tech_fingerprint_phantomcms}` ([captura](evidencia/salidas/r5_02_version_default.txt)). El archivo se localizó por enumeración de rutas, no leyendo el código del objetivo.

#### 3. Riesgo asociado a la exposición tecnológica

Publicar producto, versión y build exactos (en cabeceras, en `<meta generator>` y en un archivo default) le ahorra trabajo de reconocimiento a un atacante: puede buscar directamente vulnerabilidades conocidas de esa versión concreta. No se identificó un CVE aplicable a PhantomCMS, por tratarse de un producto ficticio del laboratorio, de modo que no se asigna severidad por un CVE inexistente; el riesgo demostrado es la divulgación de versión. Como mitigación, conviene suprimir o normalizar las cabeceras `Server` y `X-Powered-By`, quitar la etiqueta `generator` y retirar el archivo default del CMS del servidor público.

### Evidencia de soporte del inventario (R3)

**Fecha de ejecución:** 2026-11-02.

Solicitudes realizadas desde la consola atacante contra el target local `phantomcorp`:

```http
OPTIONS / HTTP/1.1
Host: phantomcorp

HTTP/1.0 200 OK
Server: PhantomServer/3.7
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: FLAG{http_methods_put_enabled}
```

La respuesta anuncia métodos de escritura, pero las comprobaciones directas no los aceptaron:

```http
PUT /chiara-r3-test.txt HTTP/1.1 -> 501 Unsupported method ('PUT')
DELETE /chiara-r3-test.txt HTTP/1.1 -> 501 Unsupported method ('DELETE')
GET /chiara-r3-test.txt HTTP/1.1 -> 404 Not Found
```

La flag R3 fue aceptada por el verificador oficial del curso en una copia temporal del entorno atacante. Bash/WSL del host devolvió `E_ACCESSDENIED`, por lo que el archivo local `.progreso/06.done` no se actualizó. El registro previo de la sección 1 se conserva como evidencia histórica de R2 y no representa un estado consolidado después de validar R3.

---

## 3. Preguntas de análisis

### P1 — Enumeración vs. recon.
**Consigna:** *Diferenciá enumeración de reconocimiento con dos cosas concretas que hiciste en el Lab 05 y en este.*

**Respuesta fundamentada:**
Reconocimiento y enumeración son dos fases sucesivas en la evaluación de seguridad (enmarcadas en la táctica *Discovery* `TA0007` de MITRE ATT&CK), pero difieren radicalmente en su **alcance**, **profundidad** y el **propósito de las preguntas** que formulan sobre el objetivo:

- **Reconocimiento (Lab 05):** Es de alcance amplio y horizontal («¿Qué hay?»). Su objetivo es trazar el mapa perimetral de la superficie de ataque, identificando qué hosts están activos, qué puertos escuchan y qué tecnologías generales se anuncian, sin profundizar en la lógica interna de cada servicio.
  - *Acción concreta 1 (Lab 05):* Escaneo general de puertos TCP con `nmap -sV -p-` para descubrir los servicios expuestos en el host (detectando el puerto 21 con ProFTPD 1.3.5, el puerto 80 con un servidor web y el puerto 8080 con un panel interno).
  - *Acción concreta 2 (Lab 05):* Inspección de `robots.txt` y captura pasiva de banners con `ncat` para identificar versiones de software declaradas sin enviar solicitudes a recursos internos de la aplicación.

- **Enumeración (Lab 06):** Es de alcance profundo y vertical («¿Qué esconde cada cosa?»). Se asume la existencia del servicio ya identificado (servidor web en el puerto 80) y se interroga activamente por recursos, métodos, archivos y endpoints no visibles en la interfaz pública.
  - *Acción concreta 1 (Lab 06):* Fuerza bruta de rutas y directorios no enlazados mediante `dirb` con extensiones comunes (`.bak`, `.old`, `.txt`), localizando el directorio oculto `/backup/` que contenía nombres de volcados de base de datos (`respaldo-db-2024.sql.gz`).
  - *Acción concreta 2 (Lab 06):* Consulta dirigida a endpoints de APIs internas (`GET /api/users`) e inspección directa de archivos de control de versiones (`GET /.git/config`), extrayendo el listado de personal con sus roles y la URL del repositorio interno, información que no estaba enlazada en el index.

### P2 — El `.git` expuesto
**Consigna:** *El `.git` expuesto: explicá qué podría reconstruir un atacante con él y por qué es más grave que "un archivo de más".*

**Respuesta fundamentada:**
Un archivo convencional expuesto (como una página HTML o un PDF) solo revela información estática y aislada. En contraste, el directorio `.git/` contiene la estructura completa del sistema de control de versiones (árbol de objetos, ramas, índices y reflogs). Si la exposición es completa, un atacante no solo descarga el archivo que está en producción, sino que puede reconstruir el **código fuente íntegro de la aplicación con todo su historial de cambios**:
1. **Acceso a objetos comprimidos (`.git/objects/`):** Al descargar secuencialmente los commits, árboles (*trees*) y blobs (descomprimiéndolos con zlib), se restaura el árbol de trabajo completo con la totalidad de los archivos de la aplicación.
2. **Historial y diferencias temporales:** A través de los objetos `commit` y `parent`, un atacante puede ejecutar operaciones equivalentes a `git log` y `git diff`. Esto permite inspeccionar código histórico, revisiones anteriores y notas de desarrollo.
3. **Fuga de secretos commiteados por error:** Frecuentemente los desarrolladores commitean contraseñas de bases de datos, tokens de API o claves privadas que luego son "eliminadas" en commits posteriores. Como Git mantiene los snapshots históricos en sus blobs, el atacante recupera las credenciales en claro con solo inspeccionar commits pasados.
4. **Auditoría de caja blanca (White-box):** Contar con el código fuente le permite al atacante analizar vulnerabilidades de lógica, inyecciones SQL o fallas de autenticación con precisión absoluta, eliminando la necesidad de realizar pruebas a ciegas.

En el caso puntual analizado en PhantomCorp, se constató empíricamente que el servidor expone únicamente `/.git/config` (devolviendo 404 para `HEAD`, `logs/` y `objects/`). Por lo tanto, aunque no fue posible reconstruir el árbol de objetos localmente, la exposición reveló información sensible de infraestructura interna (URL del repositorio interno).

### P3 — El método `PUT`.
**Consigna:** *El método `PUT` habilitado: describí un ataque concreto que lo use.*

**Respuesta fundamentada:**
El método HTTP `PUT` está diseñado por el estándar RFC 7231 para permitir que un cliente cree o reemplace por completo un recurso en el servidor en la URI especificada. Cuando este método se encuentra habilitado sin la debida autenticación y en un directorio servido por el servidor web, habilita un vector clásico de **subida de archivos arbitrarios (WebShell)** conducente a **Ejecución Remota de Código (RCE)**.

**Descripción del ataque concreto:**
1. **Petición del atacante:**
   El atacante envía una solicitud HTTP directa con el payload malicioso en el cuerpo:
   ```http
   PUT /webshell.php HTTP/1.1
   Host: target.com
   Content-Type: application/x-php

   <?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>
   ```
2. **Condiciones necesarias para el éxito:**
   - Que el servidor web (o módulo WebDAV) acepte peticiones `PUT` anónimas sin exigir credenciales ni tokens de autorización.
   - Que el usuario bajo el cual corre el proceso del servidor web (ej. `www-data` o `nobody`) posea permisos de escritura (`write`) en el sistema de archivos del directorio webroot servido.
   - Que el servidor web esté configurado con un motor de ejecución (ej. módulo PHP, CGI o procesador de scripts) capaz de interpretar el archivo subido en esa ruta, en lugar de servirlo como texto plano descargable.
3. **Impacto:**
   Una vez creado el archivo, el atacante invoca `GET /webshell.php?cmd=id` o `GET /webshell.php?cmd=whoami`. El código se ejecuta del lado del servidor con los privilegios del servicio web, permitiendo interactuar con el sistema operativo, leer configuraciones internas, pivotear en la red o escalar privilegios.

**Comportamiento observado en PhantomCorp:**
En nuestro objetivo, la solicitud `OPTIONS /` anunció `Allow: GET, POST, PUT, DELETE, OPTIONS`, pero las solicitudes de prueba `PUT /chiara-r3-test.txt` y `DELETE` respondieron con código `501 Unsupported method`, demostrando que el archivo no fue creado. Este hallazgo evidencia una **inconsistencia en la configuración del servidor** donde la cabecera `Allow` declara métodos no implementados, sirviendo de señuelo o desalineación técnica.

### P4 — Enumeración de usuarios.
**Consigna:** *La API de usuarios: ¿por qué enumerar usuarios válidos es un problema aunque no muestre contraseñas? Pensá en la fase siguiente.*

**Respuesta fundamentada:**
Obtener un listado de usuarios válidos mediante un endpoint público como `/api/users` constituye una falla seria de confidencialidad que debilita estructuralmente la postura de seguridad, incluso si la respuesta no incluye contraseñas ni hashes:

1. **Reducción del 50% en la incertidumbre de autenticación:**
   Cualquier proceso de autenticación requiere dos factores: una identidad válida y un secreto que la corrobore. Al enumerar usuarios legítimos (`admin`, `jperez`, `mgomez`), el atacante elimina la mitad de la complejidad: ya no necesita adivinar quién existe en el sistema ni lidiar con nombres inexistentes.
2. **Ataques de Password Spraying eludiendo bloqueos:**
   Permite diseñar ataques de rociado de contraseñas (*Password Spraying*), donde se prueba una única contraseña probable (ej. `Phantom2024!`, `Password123`) contra todas las cuentas válidas a intervalos espaciados. Esto reduce drásticamente las alertas por intentos fallidos y evita bloquear cuentas legítimas.
3. **Focalización y priorización de cuentas privilegiadas:**
   La API expuso no solo nombres sino también roles: identificó a `admin` con rol `superuser`. Esto permite concentrar los recursos de ataque directamente sobre la cuenta con mayores privilegios del sistema, maximizando el impacto de un eventual compromiso.
4. **Vínculo directo con la fase de explotación (Lab 07):**
   - **Vulnerabilidades de Control de Acceso por Objeto (IDOR):** La API reveló identificadores numéricos directos (`id: 1`, `id: 2`, `id: 3`). En la fase de explotación, al auditar endpoints como `GET /perfil?id=`, el atacante sabe de antemano qué ID corresponde al administrador (`id=1`) y qué IDs corresponden a usuarios de menor privilegio, facilitando la prueba y explotación de fallas de control de acceso horizontal y vertical.
   - **Ingeniería social dirigida (Spear Phishing):** Conocer la nómina de personal y sus funciones permite crear vectores de engaño altamente creíbles hacia el personal interno.

### P5 — Rol defensor (Mitigaciones)
A continuación se detallan las mitigaciones técnicas concretas para **tres** de los hallazgos demostrados en el laboratorio:

#### 1. Mitigación para Repositorio Git expuesto (Hallazgo R2 — `/.git/config`)
- **Regla de denegación en servidor web / proxy inverso:** Configurar una directiva explícita que bloquee de forma estricta cualquier petición dirigida a archivos o directorios ocultos que comiencen con punto (`.`).
  - *En Nginx:*
    ```nginx
    location ~ /\.git {
        deny all;
        return 404;
    }
    ```
  - *En Apache:*
    ```apache
    <DirectoryMatch "/\.git">
        Require all denied
    </DirectoryMatch>
    ```
- **Higiene en pipelines de despliegue (CI/CD):** No desplegar usando `git clone` en la carpeta servida. Utilizar empaquetados limpios con `git archive` o contenedores multi-stage donde solo se copien los artefactos finales de producción, descartando la carpeta `.git`.
- **Escaneo de secretos:** Incorporar herramientas como `gitleaks` en pre-commit hooks para evitar que configuraciones o URLs internas queden versionadas.

#### 2. Mitigación para Directorio de respaldos accesible (Hallazgo R1 — `/backup/`)
- **Deshabilitar Directory Browsing (Listado de directorios):** Evitar que el servidor genere índices automáticos de archivos cuando no exista un `index.html`.
  - *En Apache:* Eliminar la directiva `Indexes` en la configuración del directorio (`Options -Indexes`).
  - *En Nginx:* Asegurar la directiva `autoindex off;` en el bloque `location /backup/` o en la configuración general del servidor.
- **Almacenamiento de respaldos fuera del webroot:** Los volcados de base de datos (`.sql.gz`) y archivos de configuración antiguos (`.old`, `.bak`) **jamás** deben residir dentro del directorio público servido (`/var/www/html` o document root). Deben almacenarse en directorios internos del sistema de archivos no alcanzables por el servidor web, con permisos de lectura restringidos exclusivamente a procesos administrativos (`chmod 600`).

#### 3. Mitigación para API de usuarios interna expuesta (Hallazgo R4 — `/api/users`) y Métodos HTTP (R3)
- **Autenticación y Control de Acceso basado en Roles (RBAC):** El endpoint `/api/users` no debe responder a solicitudes anónimas. Se debe exigir autenticación obligatoria mediante tokens de sesión o Bearer JWT firmados, verificando que el usuario autenticado posea permisos explícitos de Recursos Humanos o Administración para consultar el padrón de personal.
- **Restricción de verbos HTTP y consistencia en cabecera `Allow`:** Configurar el servidor web y framework de backend para rechazar de manera predeterminada todos los métodos HTTP que no formen parte de la funcionalidad pública (como `PUT`, `DELETE` o `TRACE`), permitiendo únicamente los requeridos (`GET`, `POST`), y asegurando que la cabecera `Allow` refleje con fidelidad los métodos efectivamente implementados.

---

## 4. Bitácora de comandos

Secuencia completa y cronológica de comandos ejecutados en el laboratorio para cada reto y para la validación global:

```bash
# ======================================================================
# Reto 2: Repositorio Git expuesto (2026-11-01)
# ======================================================================

# Verificación de conectividad general
curl -i -s http://phantomcorp/

# Inspección de configuración de Git
curl -i -s http://phantomcorp/.git/config

# Sondeo de referencias y metadatos adicionales de Git
curl -i -s http://phantomcorp/.git/HEAD
curl -i -s http://phantomcorp/.git/logs/HEAD
curl -i -s http://phantomcorp/.git/index
curl -i -s http://phantomcorp/.git/objects/info/packs
curl -i -s http://phantomcorp/.git/description
curl -i -s http://phantomcorp/.git/COMMIT_EDITMSG
curl -i -s http://phantomcorp/.git/

# Validación criptográfica y envío de R2
echo -n 'FLAG{git_repo_exposed}' | sha256sum
./ctf submit 06 R2 'FLAG{git_repo_exposed}'

# ======================================================================
# Reto 4: Enumeración de usuarios mediante API (2026-11-03)
# ======================================================================

# Construir objetivo y levantar instancia aislada para R4
docker compose -p lab06-r4-carolina --project-directory . -f entregas/lab06/grupo10/evidencia/entorno-r4.compose.yml up -d --build

# Consultas dirigidas a la API sin autenticación
curl -i -s http://phantomcorp/api
curl -i -s http://phantomcorp/api/users

# Envío y validación de R4
./ctf submit 06 R4 'FLAG{user_enumeration_api}'

# Detener contenedores de R4
docker compose -p lab06-r4-carolina --project-directory . -f entregas/lab06/grupo10/evidencia/entorno-r4.compose.yml stop

# ======================================================================
# Reto 1 y Reto 5: Directorios y Fingerprinting (2026-11-05)
# ======================================================================

# R1: Enumeración de directorios con dirb y extensiones
dirb http://phantomcorp/ -X .bak,.old,.txt,.html

# R1: Inspección de respaldo y confirmación con nmap http-enum
curl -s -i http://phantomcorp/backup/
nmap --script http-enum -p80 phantomcorp

# R1: Envío y validación de flag R1
./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'

# R5: Fingerprinting de tecnología con whatweb
whatweb -a 3 http://phantomcorp

# R5: Consulta de archivo default del CMS
curl -s -i http://phantomcorp/phantomcms/VERSION

# R5: Envío y validación de flag R5
./ctf submit 06 R5 'FLAG{tech_fingerprint_phantomcms}'

# ======================================================================
# Reto 3: Métodos HTTP peligrosos habilitados (2026-11-06)
# ======================================================================

# R3: Comprobación de métodos permitidos mediante OPTIONS
curl -i -X OPTIONS http://phantomcorp/

# R3: Comprobación práctica de PUT y DELETE en ruta de prueba
curl -i -X PUT http://phantomcorp/chiara-r3-test.txt --data-binary 'prueba de laboratorio'
curl -i -X DELETE http://phantomcorp/chiara-r3-test.txt
curl -i http://phantomcorp/chiara-r3-test.txt

# R3: Envío y validación de flag R3
./ctf submit 06 R3 'FLAG{http_methods_put_enabled}'

# ======================================================================
# Estado final unificado del laboratorio (5/5 completado)
# ======================================================================

./ctf status 06
```
