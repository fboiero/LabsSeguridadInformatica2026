# Informe — Laboratorio 06 · Enumeración

**Grupo:** 07

**Integrantes:**
- Lorenzo Blanc — @LoloBlanc
- Fernando Cagliero — @Ferca19
- Guadalupe Gómez — @guadagomezgg8
- Lautaro Mariño — @lautaromarino0

**Fecha de operación:** 01/11/2026

## 0. Declaración de uso de IA

**Lorenzo Blanc — Parte A (operador):** se utilizó **Codex (OpenAI)** para preparar y operar el entorno Docker de la cátedra, ejecutar las herramientas de enumeración, organizar sus salidas y redactar la parte práctica, la bitácora y P1. La validación se realiza contra las respuestas HTTP y las salidas reales de las herramientas, con cada flag comprobada mediante `./ctf submit 06` y el estado final mediante `./ctf status 06`. No se obtienen flags leyendo el código del target ni `solucion.md`. Los ejemplos del Lab 05 se atribuyen al reconocimiento de Guadalupe ya documentado por el grupo.

**Coordinación:** Lorenzo realiza la Parte A (operador) y Fernando la Parte C
(inventario de R3, R4 y R5, y P3), según el intercambio acordado por el grupo.
Las partes B y D conservan los responsables del reparto original.

**Fernando Cagliero — Parte C (inventario R3–R5 y P3):** se utilizó **OpenAI Codex**
para analizar las capturas de Lorenzo, redactar las tres filas del inventario
y explicar en P3 el escenario de una webshell subida mediante `PUT`.
Se contrastaron métodos, estado HTTP, cuentas y roles, CMS, versión, build y
ruta del archivo default con los archivos originales de `evidencia/`. Se
consultaron las fuentes primarias de IETF, OWASP y WhatWeb para distinguir
hallazgos observados de riesgos y comprobaciones pendientes. La revisión es
documental: no se repitió la operación del contenedor ni se atribuyen a
Fernando las capturas o las flags de Lorenzo. Las comprobaciones adicionales
de documentos y evidencias se detallan al final de la sección 4.

**Lautaro Mariño — Parte B (inventario R1–R2 y P2):** se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a redactar las filas R1 y R2, P2 y la sección correspondiente de la bitácora a partir del análisis que hizo Lautaro de las capturas de Lorenzo (`03`, `04` y `05`); Lautaro revisó y ajustó cada texto antes de commitearlo. **Contraste de pruebas:** sirvió de soporte para contrastar algunas de las pruebas, mediante una enumeración complementaria contra el target oficial del Lab 06 en un sandbox Linux sin Docker (`evidencia/20` a `23`), y para ubicar y cotejar las fuentes (MITRE CWE, OWASP WSTG, documentación de Git, git-dumper y Nmap). **Verificación:** cada afirmación de las filas remite a una línea de evidencia; las respuestas nuevas (404 de los archivos de `/backup` y de `HEAD`/`index`/`refs`) se capturaron con `curl` y se adjuntan. El comportamiento de `http-git` se comprobó en el código del script. No se consultó `git.internal.phantomcorp` ni ningún tercero, no se leyó el código del target ni `solucion.md`, y no se atribuyen a Lautaro las capturas ni las flags de Lorenzo.

**Guadalupe Gómez — Parte D (research, P4, P5 y armado):** se utilizó **Claude (Anthropic)** como asistente. **Redacción:** mejoró la redacción de P4, P5 y del mini-research (`research.md`, tema B: wordlists) a partir de las capturas de Lorenzo (`03`, `04`, `05`, `07`, `12`, `14` y `21`) y de las filas del inventario de las Partes B y C. Cada parte fue revisada y ajustada antes de commitearlos. **Fuentes:** ayudó a ubicar y cotejar las fuentes de la Parte D (OWASP Cheat Sheet Series, OWASP API Security Top 10 2023, OWASP WSTG, SecLists, Assetnote y la documentación de dirb en Kali). **Verificación:** cada afirmación de P4 y P5 remite a una línea de evidencia o a una fila del inventario; los conteos del research (4612, 9224 y 819 peticiones) salen de los encabezados de `03`, `12` y `14`.

## 1. Flags capturadas

Las cinco flags se obtuvieron operando herramientas contra el contenedor `phantomcorp` del Lab 06. El progreso inicial era 0/5; cada flag se extrajo de la respuesta del servicio y fue aceptada por el verificador oficial. Captura textual de `./ctf status 06` (salida completa en [evidencia/17-status-repo.txt](evidencia/17-status-repo.txt)):

```text
PROGRESO · LAB 06
   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ✓  R3     Metodos HTTP peligrosos habilitados
   ✓  R4     Enumeracion de usuarios via API
   ✓  R5     Fingerprinting de tecnologia

██████████████████████████████  5/5 (100%)
[ OK ] ¡Lab 06 COMPLETO! Ponete las pilas con la próxima unidad.
```

| Reto | Operación y resultado observado | Flag validada | Evidencia |
|---|---|---|---|
| R1 | `dirb` encontró `/backup` con `CODE:200`; `curl /backup/` devolvió el listado y la flag. `/admin` respondió 403. | `FLAG{dir_enumeration_backup}` | [dirb](evidencia/03-dirb.txt), [respuesta de backup](evidencia/04-backup.txt) |
| R2 | `GET /.git/config` respondió 200, con `url = https://git.internal.phantomcorp/intranet.git` y la flag. | `FLAG{git_repo_exposed}` | [configuración expuesta](evidencia/05-git-config.txt) |
| R3 | `OPTIONS /` respondió 200 con `Allow: GET, POST, PUT, DELETE, OPTIONS`; la flag estaba en `X-Dangerous-Methods`. | `FLAG{http_methods_put_enabled}` | [respuesta OPTIONS](evidencia/06-options.txt) |
| R4 | `GET /api/users` respondió 200 con `admin` (superuser), `jperez` (editor), `mgomez` (viewer), la nota de endpoint interno de RRHH y la flag. | `FLAG{user_enumeration_api}` | [JSON de usuarios](evidencia/07-api-users.txt) |
| R5 | `whatweb` identificó `MetaGenerator[PhantomCMS 3.7]` y `X-Powered-By[PhantomCMS/3.7]`; una wordlist dirigida encontró `/phantomcms/VERSION`, que respondió 200 con versión, build y flag. | `FLAG{tech_fingerprint_phantomcms}` | [whatweb](evidencia/08-whatweb.txt), [enumeración dirigida](evidencia/14-dirb-cms.txt), [VERSION](evidencia/15-cms-version.txt) |

Las respuestas prueban exposición y enumeración. No se intentó subir una webshell ni reconstruir el repositorio: anunciar `PUT` no demuestra por sí solo escritura efectiva, y obtener `.git/config` no prueba que todos los objetos Git sean descargables.

## 2. Inventario de enumeración

Las filas R1 y R2 (Parte B, Lautaro) se basan en las capturas de Lorenzo y en una
enumeración complementaria adjunta como `evidencia/20` a `23` (ver sección 4).
Las filas R3, R4 y R5 de la Parte C se completaron a partir
de las capturas originales de Lorenzo adjuntas en `evidencia/`.

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| R1 — Directorio de backups con listado público | `GET /backup/` sobre HTTP/80; además `GET /admin` → 403. | `dirb` con `common.txt` (4612 rutas), ejecutado por Lorenzo, y confirmación con `curl -sS -i http://phantomcorp/backup/`. Luego, `curl` a cada archivo del listado y a `/admin`. | [03-dirb.txt](evidencia/03-dirb.txt): `+ http://phantomcorp/backup (CODE:200\|SIZE:249)` y `+ http://phantomcorp/admin (CODE:403\|SIZE:65)`. [04-backup.txt](evidencia/04-backup.txt): `Index of /backup` con `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt`. [21-backup-archivos.txt](evidencia/21-backup-archivos.txt): los tres archivos responden **404**; `/admin` responde 403 con `Panel admin. Necesitas credenciales.` | Listado de directorio expuesto (CWE-548) [B1]: revela que en el web root hay un volcado de base de datos y una configuración vieja, archivos que en un caso real suelen contener datos y credenciales en claro [B2]. **En este lab los archivos no se sirven**: lo confirmado es la fuga de nombres y de la existencia de respaldos, no la descarga de datos. El 403 confirma que existe un panel administrativo con autenticación. | Junto con R4 define el blanco de autenticación: `/admin` con la cuenta `admin` (superuser). Los nombres exactos del listado permiten probar variantes dirigidas (`.bak`, otras extensiones de compresión, rutas hermanas) en lugar de fuerza bruta a ciegas; si un respaldo se pudiera descargar, sería la vía más directa a credenciales. Con la evidencia actual no habilita acceso directo. |
| R2 — Metadatos de repositorio Git expuestos | `GET /.git/config` sobre HTTP/80. | Pedido directo de un archivo conocido de Git con `curl -sS -i` (Lorenzo). Enumeración complementaria: `curl` a las rutas estándar de `.git` que usan las herramientas de volcado y el script NSE `http-git`. | [05-git-config.txt](evidencia/05-git-config.txt): HTTP 200 con `[remote "origin"]` y `url = https://git.internal.phantomcorp/intranet.git`. [22-git-artefactos.txt](evidencia/22-git-artefactos.txt): `/.git/`, `HEAD`, `index`, `logs/HEAD`, `refs/heads/main`, `refs/heads/master` y `packed-refs` responden **404**. [23-nmap-http-git.txt](evidencia/23-nmap-http-git.txt): `http-git` no reporta repositorio, porque abandona si `/.git/HEAD` no responde [B6]. | Exposición de un repositorio de control de versiones (CWE-527) [B3]. Confirmado: el host Git interno y el nombre del repositorio (`intranet.git`), útiles para mapear infraestructura interna. La URL no trae credenciales embebidas. **No confirmado:** sin `HEAD` ni refs no hay commit por donde empezar, así que desde este servidor no se puede reconstruir código ni historia (ver P2). | Señala el repositorio de la intranet como fuente de código y secretos para el Lab 07: si `HEAD` y `objects/` quedaran accesibles, se podría reconstruir con `git-dumper` y pasar a análisis de caja blanca de `/admin` y `/api/users` [B4]. El host `git.internal.phantomcorp` queda **fuera de alcance** salvo autorización explícita; no se consultó. |
| R3 — Métodos HTTP anunciados | `OPTIONS /` sobre HTTP/80; `PUT` y `DELETE` en `Allow`. | `curl -sS -X OPTIONS -i http://phantomcorp/`, ejecutado por Lorenzo. | [06-options.txt](evidencia/06-options.txt): `HTTP/1.0 200 OK` y `Allow: GET, POST, PUT, DELETE, OPTIONS`. | Posible creación, modificación o borrado no autorizado si esos métodos se aceptan sin controles adecuados. Una webshell requeriría además escritura en una ruta ejecutable; el anuncio de métodos no demuestra esas condiciones. | Dirigir la validación de autorización y escritura a las rutas pertinentes, inicialmente con un archivo inerte y recuperando su contenido. Evaluar ejecución solo si se demuestra que la ubicación procesa código; no se probó en este lab. |
| R4 — API interna que divulga cuentas y roles | `GET /api/users` sobre HTTP/80. | Consulta con `curl -sS -i http://phantomcorp/api/users`, sin credenciales en el comando registrado. | [07-api-users.txt](evidencia/07-api-users.txt): HTTP 200, JSON con `admin`/`superuser`, `jperez`/`editor` y `mgomez`/`viewer`; nota `endpoint interno de RRHH - no exponer`. | Divulgación de cuentas válidas y privilegios declarados, útil para seleccionar objetivos. La respuesta no muestra contraseñas ni demuestra acceso como esos usuarios. | Preparar pruebas de autenticación dirigidas a usuarios existentes, incluida la cuenta administrativa, y evaluar controles frente a fuerza bruta o credential stuffing. La enumeración no demuestra que esas técnicas tengan éxito. |
| R5 — Identificación del CMS y archivo default público | `GET /` y `GET /phantomcms/VERSION` sobre HTTP/80. | `whatweb`, contraste con el HTML y enumeración dirigida mediante `dirb`; confirmación con `curl`. | [08-whatweb.txt](evidencia/08-whatweb.txt): `MetaGenerator[PhantomCMS 3.7]`, `X-Powered-By[PhantomCMS/3.7]`; [14-dirb-cms.txt](evidencia/14-dirb-cms.txt) encontró la ruta, y [15-cms-version.txt](evidencia/15-cms-version.txt) devolvió HTTP 200 con `PhantomCMS 3.7 (build 2024-11)`. | Fuga de producto, versión y build, y confirmación de un archivo default accesible que permite afinar la enumeración. Identificar el CMS no prueba una vulnerabilidad explotable. | Orientar la búsqueda de archivos y configuraciones del producto identificado y verificar su aplicabilidad. PhantomCMS es ficticio en el lab: no se le atribuye un CVE real; una coincidencia de versión, por sí sola, no autoriza a afirmar explotación. |

## 3. Preguntas de análisis

**P1 — Enumeración vs. recon.**

El **reconocimiento** construye un panorama amplio: qué puertos y servicios hay y qué versiones anuncian. La **enumeración** profundiza en un servicio identificado para descubrir rutas, archivos, métodos y datos que no aparecen en su página principal.

Dos ejemplos concretos del **Lab 05**, operado por Guadalupe y documentado por el grupo, son el barrido `nmap -Pn -p- phantomcorp`, que encontró el puerto 31337, y el banner grabbing `ncat -w3 phantomcorp 21 </dev/null`, que identificó `ProFTPD 1.3.5`. Ambas acciones aportaron al mapa de servicios; Lorenzo utilizó esa evidencia sin atribuirse su captura.

En el **Lab 06**, operado para este aporte, `dirb` probó 4612 rutas y encontró `/backup` (200) y `/admin` (403); después se confirmó el contenido público de `/backup/` con `curl`. Como segundo ejemplo, `curl -sS -i http://phantomcorp/api/users` reveló tres cuentas válidas y sus roles. Ya no se trata de saber que existe HTTP: se identificaron recursos y datos concretos dentro de ese servicio, como muestran las evidencias de R1 y R4.

Las etapas se complementan y sus técnicas pueden superponerse: el fingerprinting aporta identificación tanto al recon como a la enumeración. En este lab, conocer `PhantomCMS 3.7` permitió dirigir la búsqueda hasta `/phantomcms/VERSION`. Los resultados alimentan la planificación del Lab 07; no equivalen a haber explotado los riesgos potenciales.

**P2 — El `.git` expuesto.**

Un `.git` no es "un archivo de más": es la base de datos completa del proyecto. Git guarda cada versión de cada archivo como objetos en `objects/`, los encadena mediante commits y marca la rama actual con `HEAD` y `refs/`; `logs/` registra los movimientos de cada ref [B5]. Si esas piezas se pueden pedir por HTTP, un atacante reconstruye:

1. **El código fuente actual** de la intranet, incluidos archivos que el servidor nunca muestra: configuración, scripts de despliegue, consultas a la base.
2. **Toda la historia:** autores y sus emails, fechas, mensajes y cada versión anterior. Una contraseña o API key que se borró en un commit posterior sigue en los objetos viejos.
3. **Datos de infraestructura:** remotos, ramas y rutas internas.

No hace falta que el servidor liste directorios. `git-dumper` pide los archivos conocidos (`HEAD`, `index`, `config`, `packed-refs`, `logs/HEAD`), extrae de ellos refs y hashes, baja los objetos siguiendo el padre de cada commit y termina con `git checkout .` [B4]. Por eso es más grave que un archivo suelto: desde un punto de entrada se recorre todo el grafo, y el atacante pasa a auditar en caja blanca la autenticación de `/admin`, el endpoint `/api/users` o las credenciales de la base. MITRE lo clasifica como CWE-527 y la mitigación es sacar el repositorio del servidor de producción [B3].

**Qué muestra nuestra evidencia.** `GET /.git/config` devolvió 200 con el remoto `https://git.internal.phantomcorp/intranet.git` ([05-git-config.txt](evidencia/05-git-config.txt)). Para medir hasta dónde llegaba la exposición se pidieron las rutas estándar de un repositorio, incluidas todas las que `git-dumper` usa para encontrar refs y hashes: `HEAD`, `index`, `logs/HEAD`, `refs/heads/main`, `refs/heads/master`, `packed-refs`, `description`, `COMMIT_EDITMSG`, `ORIG_HEAD`, `/.gitignore` y el propio `/.git/`. Todas dieron **404** ([22-git-artefactos.txt](evidencia/22-git-artefactos.txt)). Sin `HEAD` ni refs no hay un hash de commit por donde empezar, así que **en este lab no se puede reconstruir el código ni la historia**. Lo que sí se filtró es el host de Git interno y el nombre del repositorio, que orientan un ataque a la infraestructura de desarrollo.

Un detalle útil para el operador: el script `http-git` de nmap no detectó nada ([23-nmap-http-git.txt](evidencia/23-nmap-http-git.txt)) porque abandona si `/.git/HEAD` no responde 200 [B6]. Una herramienta automática dio negativo donde el pedido manual de `config` dio positivo; un resultado vacío de un escáner no prueba que el `.git` no esté expuesto.

**Fuentes de la Parte B** (consultadas el 02/11/2026):

- **[B1]** MITRE. [CWE-548 — Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html).
- **[B2]** OWASP WSTG v4.2. [WSTG-CONF-04 — Review Old Backup and Unreferenced Files for Sensitive Information](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/).
- **[B3]** MITRE. [CWE-527 — Exposure of Version-Control Repository to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/527.html).
- **[B4]** arthaud. [git-dumper](https://github.com/arthaud/git-dumper), sección "How does it work?".
- **[B5]** Git. [gitrepository-layout](https://git-scm.com/docs/gitrepository-layout): `objects/`, `refs/`, `HEAD`, `index`, `logs/` y `packed-refs`.
- **[B6]** Nmap. [Script NSE `http-git`](https://nmap.org/nsedoc/scripts/http-git.html); en su código: "If we can't get a valid /.git/HEAD, don't even bother continuing".

**P3 — El método `PUT`.**

En R3, [06-options.txt](evidencia/06-options.txt) registra `OPTIONS /` con
`Allow: GET, POST, PUT, DELETE, OPTIONS`. Según RFC 9110, `Allow` anuncia los
métodos asociados al recurso y `PUT` solicita crear o reemplazar su estado;
no define que ese estado deba ser un archivo en disco. Por eso, que aparezca
`PUT` no prueba una subida sin autenticación ni es una vulnerabilidad por sí
solo: puede ser legítimo en una API con autorización adecuada [C1].

**Ataque concreto posible, no ejecutado en este lab:** supongamos una
configuración que acepta escritura sin autorización en una ruta pública y
que ejecuta PHP en ella. Ruta e intérprete son supuestos del ejemplo, no
hallazgos del fingerprint de PhantomCMS.

1. El atacante envía `PUT /uploads/diagnostico.php` con una **webshell** como
   contenido: un script que recibe instrucciones y las ejecuta en el servidor.
2. El servidor acepta la petición y guarda ese contenido en una ubicación
   que el atacante puede solicitar por HTTP. Para afirmar una escritura real
   habría que comprobar el resultado, no solo un código de respuesta exitoso.
3. El atacante solicita `GET /uploads/diagnostico.php`. **Si** esa ubicación
   procesa PHP en lugar de servirlo como texto, el intérprete ejecuta la
   webshell con los permisos del proceso web. Podría acceder a datos de la
   aplicación o modificar recursos dentro de esos permisos; no implica
   automáticamente acceso de administrador [C2].

OWASP recomienda contrastar los métodos anunciados con su comportamiento y
verificar la recuperación del recurso escrito. Para el Lab 07, el primer paso
sería una comprobación autorizada con un archivo inerte y su recuperación,
antes de evaluar las condiciones de ejecución. En la evidencia actual solo
hay `OPTIONS`: no se probó escritura, la ruta del ejemplo ni ejecución.
Si se permitiera escritura arbitraria pero no ejecución, aún podría haber
alteración de contenido; el impacto debe ajustarse a lo que se demuestre [C2].

**Fuentes de la Parte C:**

- **[C1]** IETF. [RFC 9110, §9.3.4 — PUT](https://www.rfc-editor.org/rfc/rfc9110.html#name-put)
  y [§10.2.1 — Allow](https://www.rfc-editor.org/rfc/rfc9110.html#name-allow).
- **[C2]** OWASP WSTG v4.2. [Test HTTP Methods](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods/).
  Enumeración de métodos, comprobación de escritura e impacto potencial.
- **[C3]** OWASP WSTG v4.2. [Testing for Account Enumeration and Guessable User Account](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account/).
  Utilidad de las cuentas válidas para dirigir pruebas de autenticación (R4).
- **[C4]** WhatWeb. [Documentación oficial](https://github.com/urbanadventurer/WhatWeb/blob/master/README.md).
  Identificación de tecnologías y versiones a partir de indicios de las respuestas (R5).

**P4 — Enumeración de usuarios.**

Un ataque de autenticación tiene dos incógnitas: el usuario y la contraseña. `GET /api/users` resuelve la primera sin pedir credenciales. Según [07-api-users.txt](evidencia/07-api-users.txt), la API responde 200 con tres cuentas válidas (`admin`, `jperez` y `mgomez`) y su rol, junto con la nota `endpoint interno de RRHH - no exponer`. No muestra contraseñas, pero en la fase siguiente vale casi lo mismo por tres razones:

1. **Reduce el espacio de búsqueda.** Sin la lista, el atacante tendría que adivinar pares usuario/contraseña. Con ella, solo prueba contraseñas contra cuentas que sabe que existen. OWASP identifica la enumeración de cuentas como el paso que permite dirigir las pruebas de autenticación [C3].
2. **Ordena los objetivos por privilegio.** El rol `superuser` señala qué cuenta conviene atacar primero, y R1 ya mostró dónde usarla: `/admin` responde 403 con `Panel admin. Necesitas credenciales.` ([21-backup-archivos.txt](evidencia/21-backup-archivos.txt)). El atacante tiene usuario, rol y puerta de entrada; le falta una sola pieza.
3. **Habilita ataques que evitan los bloqueos por cuenta.** Con nombres válidos se puede hacer *password spraying* (probar una contraseña débil contra las tres cuentas, con pocos intentos por cuenta para no disparar el bloqueo) o *credential stuffing* (probar pares filtrados de otros sitios con esos nombres) [D1]. Tener los nombres exactos es el requisito previo de ambos.

Además, `jperez` y `mgomez` sugieren una convención de inicial más apellido. Es una **hipótesis**, no un hallazgo: si se confirmara, permitiría deducir otras cuentas o direcciones de correo para phishing. El problema de fondo es de diseño: la propia respuesta declara que el endpoint es interno, pero está expuesto sin autenticación. OWASP lo clasifica como una función que no verifica quién la invoca (API5:2023) [D2].

Para el Lab 07, esto convierte un ataque a ciegas en uno dirigido contra `admin` en `/admin`. La evidencia actual solo prueba la divulgación: no demuestra que alguna contraseña sea débil ni que el login carezca de límites de intentos. Eso es lo que habría que medir, dentro del alcance autorizado.

**P5 — Rol defensor (3 mitigaciones).**

Se eligieron los tres hallazgos que entregan información directamente útil para la fase siguiente. Cada mitigación incluye cómo comprobar que funcionó, usando la misma prueba que lo detectó.

| Hallazgo | Mitigación concreta | Cómo se verifica |
|---|---|---|
| **R4 — `/api/users` sin autenticación** | Exigir autenticación y autorización por rol en el endpoint, con denegación por defecto: solo RRHH o administración pueden listar cuentas [D2]. Como la respuesta dice que es interno, no publicarlo hacia afuera. Devolver solo los campos necesarios: el rol de cada cuenta no tiene que viajar en un listado. Complemento para la fase siguiente: MFA y límite de intentos en el login de `/admin`, que son la defensa principal contra spraying y stuffing [D1]. | `curl -sS -i http://phantomcorp/api/users` sin credenciales debe responder 401/403 y no devolver el JSON con cuentas. |
| **R1 — `/backup/` con listado público** | Sacar los respaldos del directorio publicado y guardarlos fuera del servidor web, cifrados y con acceso restringido. Desactivar el listado automático de directorios (en nginx, `autoindex off;`) [B1]. Revisar el web root periódicamente en busca de archivos viejos o sin referencia (`.old`, `.sql.gz`, notas), que es justo lo que busca un atacante con `dirb` [B2]. | `dirb` con la misma wordlist ya no debe reportar `/backup`, y `curl -sS -i http://phantomcorp/backup/` debe devolver 404 sin `Index of`. |
| **R2 — `/.git/config` accesible** | No desplegar el directorio `.git` en producción: publicar un artefacto de build o el resultado de `git archive`, no un clon del repositorio [B3]. Como defensa adicional, bloquear en el servidor cualquier ruta que empiece con `/.git` (en nginx, `location ~ /\.git { deny all; }`). Como `config` estuvo expuesto, revisar si el repositorio tuvo secretos commiteados y rotarlos por precaución. | `curl -sS -i http://phantomcorp/.git/config` debe responder 403/404. Repetir también las rutas de [22-git-artefactos.txt](evidencia/22-git-artefactos.txt). |

Quedan fuera de las tres, pero conviene corregirlos: deshabilitar `PUT` y `DELETE` donde no se usen (R3) [C2], y quitar los headers `Server` y `X-Powered-By` junto con el archivo `/phantomcms/VERSION` (R5). Ocultar la versión no corrige ninguna vulnerabilidad, pero quita al atacante un atajo para dirigir la búsqueda.

**Fuentes de la Parte D** (consultadas el 19/11/2026):

- **[D1]** OWASP Cheat Sheet Series. [Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): definición de credential stuffing y password spraying; MFA como defensa principal.
- **[D2]** OWASP API Security Top 10 2023. [API5:2023 — Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/): funciones que no controlan el rol de quien las invoca; denegación de acceso por defecto.
- Las referencias [B1]–[B3], [C2] y [C3] son las de las Partes B y C.

## 4. Bitácora de comandos

### Preparación y alcance

- Rama existente `lab06-grupo07`, obtenida de `origin` y actualizada con `upstream/main` antes de operar. Identidad de commits: Lorenzo Blanc. No se realizó push.
- Docker Desktop estaba detenido y se inició con `docker desktop start`. Se construyeron las imágenes oficiales del atacante y del target, sin modificar sus fuentes. El target no publica puertos hacia el host.
- Toda la enumeración se hizo desde `cyberlab-attacker` contra `phantomcorp`, resuelto como `172.20.0.2` en esta ejecución. No se consultó el host de Git interno revelado por R2 ni ningún tercero.
- Fecha local: **01/11/2026**, aproximadamente 21:29–21:30 (UTC−3). Las respuestas y las herramientas del contenedor registran **02/11/2026 00:29–00:30 UTC**: es la misma ejecución.

Desde PowerShell, en la raíz del repositorio:

```powershell
git fetch origin
git fetch upstream
git switch --track origin/lab06-grupo07
git merge --no-edit upstream/main
docker desktop start
docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/lab06-enumeracion-de-servicios/entorno/target.compose.yml up -d --build
docker exec -it cyberlab-attacker bash
```

Dentro del atacante, las salidas se guardaron en `/loot/lab06/`. El script [operar.sh](evidencia/operar.sh) registra la primera secuencia:

```bash
mkdir -p /loot/lab06
date -Is | tee /loot/lab06/01-fecha-contenedor.txt
ping -c1 phantomcorp | tee /loot/lab06/02-conectividad.txt
dirb http://phantomcorp/ /usr/share/dirb/wordlists/common.txt -r -S -o /loot/lab06/03-dirb.txt
curl -sS -i http://phantomcorp/backup/ | tee /loot/lab06/04-backup.txt
curl -sS -i http://phantomcorp/.git/config | tee /loot/lab06/05-git-config.txt
curl -sS -X OPTIONS -i http://phantomcorp/ | tee /loot/lab06/06-options.txt
curl -sS -i http://phantomcorp/api/users | tee /loot/lab06/07-api-users.txt
whatweb --color=never http://phantomcorp | tee /loot/lab06/08-whatweb.txt
curl -sS -i http://phantomcorp/ | tee /loot/lab06/09-index.txt
```

Para R5 se probó primero `/readme.html` (404) y luego otros nombres habituales de README, CHANGELOG y VERSION; las respuestas negativas se conservan en los archivos `10`, `11` y `13`. Una segunda ejecución de `dirb` con la wordlist común y extensiones `.txt,.html` realizó 9224 peticiones sin hallazgos (`12-dirb-archivos.txt`). Finalmente se armó una wordlist propia con nombres de archivos habituales y prefijos del CMS identificado; está adjunta completa como [cms-wordlist.txt](evidencia/cms-wordlist.txt). No deriva del código del target.

```bash
dirb http://phantomcorp/ /usr/share/dirb/wordlists/common.txt -X .txt,.html -r -S -o /loot/lab06/12-dirb-archivos.txt
# Copiar evidencia/cms-wordlist.txt a /loot/lab06/cms-wordlist.txt para repetir:
dirb http://phantomcorp/ /loot/lab06/cms-wordlist.txt -r -S -o /loot/lab06/14-dirb-cms.txt
curl -sS -i http://phantomcorp/phantomcms/VERSION | tee /loot/lab06/15-cms-version.txt
```

`-r` evita recursión y `-S` reduce el ruido de la salida; no cambian la wordlist. La búsqueda dirigida generó 819 candidatos y encontró un recurso con 200: `/phantomcms/VERSION`.

### Validación de flags y compatibilidad Windows

El primer envío desde PowerShell/Git Bash fue rechazado: la traza mostró que el argumento había llegado sin las llaves de `FLAG{...}`. Además, `git ls-files --eol` confirmó archivos del motor y manifiesto con LF en Git y CRLF en el checkout de Windows. Para evitar ambos problemas, se exportaron **sin modificar su contenido** `ctf`, `bin/lib/{ui,banner,check}.sh` y el manifiesto del Lab 06 desde `HEAD` a `.loot/lab06/validador/`, con LF. No se editaron fuentes versionadas ni hashes esperados.

El script [validar.sh](evidencia/validar.sh) se ejecutó dentro del atacante: extrajo cada flag de su respuesta HTTP capturada y ejecutó el `./ctf submit 06` oficial sobre esa copia del motor. Los cinco envíos fueron aceptados; se adjuntan los archivos `submit-R1.txt` a `submit-R5.txt` y `16-status-final.txt`. El archivo de progreso generado por el verificador se copió a `.progreso/06.done` del repositorio; después se ejecutó también `./ctf status 06` desde Git Bash en la raíz original, que confirmó 5/5 (`17-status-repo.txt`).

Para repetir los envíos en un checkout Unix con el motor oficial disponible, desde la raíz:

```bash
./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'
./ctf submit 06 R2 'FLAG{git_repo_exposed}'
./ctf submit 06 R3 'FLAG{http_methods_put_enabled}'
./ctf submit 06 R4 'FLAG{user_enumeration_api}'
./ctf submit 06 R5 'FLAG{tech_fingerprint_phantomcms}'
./ctf status 06
```

La copia del motor, `.loot/` y `.progreso/` quedan locales y no se versionan. Las salidas relevantes se copiaron a `evidencia/`, dentro del directorio del grupo, para que el inventario pueda verificarse desde el repositorio.

### Revisión de la Parte C — Fernando, 02/11/2026

Se revisaron los archivos originales `06-options.txt`, `07-api-users.txt`,
`08-whatweb.txt`, `09-index.txt`, `14-dirb-cms.txt` y `15-cms-version.txt`.
Se contrastaron el header `Allow`, los tres usuarios y roles del JSON,
los indicios de WhatWeb y la versión/build del archivo default. Se conservaron
los bytes de todas las evidencias, las flags, P1 y la bitácora del operador.

Se comprobó la estructura Markdown, las seis columnas de cada fila del
inventario, la existencia de los enlaces locales y las fuentes oficiales.
La sintaxis de los bloques bash se revisó con `bash -n`, sin ejecutarlos.
Desde la raíz del repositorio se ejecutaron `git diff --check` y
`bash bin/validar-repo.sh`; los resultados de la validación corresponden a
compilación, sintaxis, manifiestos y documentación, no a nuevas operaciones
de enumeración o explotación. Ambos comandos finalizaron sin errores; la
validación general informó `VALIDACIÓN: todo OK`.

Entorno de revisión: Python 3.12.2 y Git Bash en Windows, solo biblioteca
estándar. Para la validación general se usó una función `python3` que delega
en el Python instalado, con la caché dirigida a una carpeta temporal externa
al repositorio.

### Enumeración complementaria de la Parte B — Lautaro, 02/11/2026

Para fundamentar R1, R2 y P2 se profundizó sobre `/backup` y `.git`. **Entorno distinto al de la Parte A:** sandbox Linux sin Docker, asistido por Claude (ver sección 0). Se ejecutó sin modificaciones el target oficial `labs/lab06-enumeracion-de-servicios/entorno/phantomcorp/server.py` con `python3`, que es el mismo `CMD` de su Dockerfile, y `phantomcorp` se resolvió a `127.0.0.1` con una entrada en `/etc/hosts`. No se leyó el código del target ni se consultó el host Git interno. Herramientas: curl y Nmap 7.94SVN. Hora del sandbox: `2026-11-03T01:30:03+00:00`, es decir 02/11/2026 22:30 (UTC−3).

```bash
date -Is | tee 20-fecha-parte-b.txt
# R1: ¿se pueden bajar los archivos del listado? ¿qué responde /admin?
for p in /backup/ /backup/respaldo-db-2024.sql.gz /backup/config.old /backup/notas-infra.txt /admin /admin/; do
  echo "=== GET $p"; curl -sS -i --max-time 5 "http://phantomcorp$p"; echo
done | tee 21-backup-archivos.txt
# R2: ¿qué más del .git está expuesto, además de config?
for p in /.git/ /.git/config /.git/HEAD /.git/index /.git/logs/HEAD /.git/refs/heads/main \
         /.git/refs/heads/master /.git/packed-refs /.git/description /.git/COMMIT_EDITMSG \
         /.git/ORIG_HEAD /.gitignore; do
  echo "=== GET $p"; curl -sS -i --max-time 5 "http://phantomcorp$p" | head -15; echo
done | tee 22-git-artefactos.txt
nmap -Pn -p80 --script http-git phantomcorp -oN 23-nmap-http-git.txt
```

Resultados: el listado de `/backup/` y el contenido de `/.git/config` coinciden con las capturas de Lorenzo. Lo nuevo: los tres archivos del listado dan 404, `/admin` da 403, y de las doce rutas de Git solo `/.git/config` responde 200. Los archivos se adjuntan con los fines de línea CRLF de HTTP normalizados a LF.
