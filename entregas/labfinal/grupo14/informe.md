# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 14
**Integrantes:** Fede Peron (@fedeeperon) · Laureano Gomez Redondo (@Laureano-GR) · Martín Cesano (@MartinCesano) · Martín Gaido (@martingaidoo) · Valentina Chiapero (@valechiapero) — ver `INTEGRANTES.md`
**Fecha:** 2026-11-20  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

Para este engagement se utilizó **Claude Code (modelo Opus)** como asistente, bajo
la conducción del grupo: el equipo fijó el alcance, dirigió el engagement y validó
los resultados contra el target; la IA ayudó a ejecutar y ordenar los comandos, a
estructurar la evidencia y a redactar este informe. Todo el trabajo se hizo dentro
de la consola del atacante del lab (`cyberlab-attacker`) contra el único target
autorizado, `phantomcorp`.

Condiciones que respetamos:

- **No se usó `solucion.md`.** El archivo de solución de la cátedra nunca se abrió;
  ninguna flag ni hallazgo proviene de ahí.
- **Auditoría de caja negra.** Cada ruta, vector, severidad y conclusión de este
  informe se justifica a partir del **comportamiento observado del target**
  (respuestas HTTP y enumeración ejecutada contra el sistema). La salida cruda de
  cada paso está en `evidencia/` y es reproducible con los comandos del apartado 4.
- **Flags verificadas.** Los cuatro hitos se validaron con `./ctf submit`, que
  compara el SHA-256 de la flag contra `retos.manifest`.

---

## 1. Resumen ejecutivo

- **Qué se hizo:** una auditoría de caja negra (sin credenciales ni documentación)
  del sistema **"Clientes"** de PhantomCorp, limitada al host del lab.
- **Resultado global:** **el sistema fue comprometido por completo.** Partiendo de
  cero, se logró entrar al panel interno, robar credenciales y ejecutar comandos
  en el servidor **como administrador (root)**, llegando hasta la base de datos de
  clientes.
- **Riesgo de negocio:** quedó expuesta la base de **48.210 clientes con nombre,
  DNI y número de tarjeta**. Una fuga de este tipo implica incumplimiento de la
  Ley 25.326 (Protección de Datos Personales), daño reputacional y potencial
  fraude con tarjetas. Un atacante externo podría haber hecho lo mismo sin dejar
  credenciales ni pistas evidentes.
- **Recomendación prioritaria:** **eliminar la ejecución de comandos del endpoint
  `/api/reporte`** — es la falla que convierte cualquier acceso en control total
  del servidor. En paralelo: **sacar el backup de configuración de la web**,
  **rotar el token y las credenciales expuestas** y **parametrizar el login**.
  Corregir sólo el login no alcanza: el archivo que contiene el token se sirve
  **sin autenticación**, de modo que el compromiso total es alcanzable aun sin la
  inyección SQL.

| Severidad | Cantidad de hallazgos |
|---|---|
| Crítica | 2 |
| Alta | 1 |
| Media | 1 |
| Baja | 0 |

---

## 2. Alcance y metodología

**En alcance:** únicamente el host `phantomcorp` (servicio HTTP en el puerto 80),
dentro de la red `labnet` del laboratorio.

**Fuera de alcance:** cualquier otro host, la infraestructura del lab, acciones
destructivas (borrado de datos, DoS) y todo lo externo al laboratorio
(Ley 26.388). No se ejecutó ninguna acción destructiva: el acceso con permisos de
root se usó sólo para **leer** el archivo de datos y demostrar impacto.

**Marco seguido** — metodología estándar de pentest (alineada con PTES / OWASP),
encadenando las unidades 05–10 del curso:

```
recon/enum  ->  explotación (foothold)  ->  post-explotación (loot)  ->  impacto
  (U05–06)          (U07)                      (U08)                     (U09–10)
```

Herramientas: `nmap`, `curl` (consola del atacante del lab). Toda la evidencia se
guardó en `/loot` (montado en el repo) y se adjunta en `evidencia/`.

---

## 3. Narrativa del ataque

Sin credenciales ni documentación, se arrancó por **reconocimiento**. Un escaneo
de `nmap` sobre los 1000 puertos TCP más comunes (`nmap -Pn -sV phantomcorp`)
confirmó un único servicio: un servidor HTTP propio, `PhantomClientes/2.0`, en el
puerto 80. La raíz del sitio sólo mostraba un "portal público" vacío, así que se
buscó superficie oculta: **`/robots.txt` delataba una ruta `Disallow: /portal-rrhh`**
que no estaba enlazada desde ningún lado. Al pedir `/portal-rrhh` apareció el
**portal interno de RRHH** con un formulario de login — y, en un comentario del
HTML, la primera flag. *(Hito R1)*

El formulario declaraba `action=/portal/login`. Al postear ahí credenciales
falsas, el servidor respondía `401`. Al inyectar una comilla en el usuario
(`admin'`) respondió con un **error de SQL** (`unrecognized token`), confirmando
una **inyección SQL** en la consulta de autenticación. Se abusó de ella con la
carga clásica de bypass **`user=admin' -- `**, que comenta el chequeo de
contraseña: el servidor dio la bienvenida al dashboard de administración.
**Foothold conseguido sin contraseña válida.** *(Hito R2)*

El dashboard ya autenticado revelaba una pista de post-explotación: *"Backup de
config disponible en: `/backup/rrhh.conf`"*. Ese archivo se servía por HTTP **sin
ningún control de acceso** y contenía credenciales de base de datos y, sobre todo,
un **token de API** (`API_TOKEN=phantom-api-7c1e`). *(Hito R3)*

El propio backup indicaba cómo usar el token: `/api/reporte?token=...&cmd=...`.
Sin token, el endpoint devolvía un rechazo; con el token looteado, el parámetro
`cmd` se ejecutaba tal cual en el servidor: `id` confirmó **ejecución de comandos
como `root` (uid=0)**. Desde ahí se **enumeró el filesystem** (`ls /` → `ls /app`
→ `ls /app/priv`) hasta localizar `clientes.db.txt`, que se leyó exponiendo la
**base de 48.210 clientes (nombre, DNI, tarjeta)** — los *crown jewels*. *(Hito R4)*

```
robots.txt → /portal-rrhh   →   SQLi 'admin'-- '   →   /backup/rrhh.conf   →   RCE root → enum fs → datos de clientes
   (R1 recon)                     (R2 foothold)          (R3 loot token)        (R4 impacto)
```

---

## 4. Hallazgos (detalle técnico)

> Ordenados por severidad, críticos primero. Los comandos se ejecutan desde la
> consola del atacante (`make shell`) contra `http://phantomcorp/`. Cada salida
> cruda está en `evidencia/`.

### H-01 · Ejecución remota de comandos (command injection) en `/api/reporte`
- **Severidad:** Crítica · **CVSS 3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  *(explotable por red, sin interacción; el token que lo "protege" se obtiene sin
  autenticación — ver H-03 —, por lo que PR:N; da control total del contenedor).*
- **CWE:** CWE-78 (OS Command Injection).
- **Ubicación:** `GET /api/reporte`, parámetro `cmd` (gateado por `token`).
- **Descripción:** el valor del parámetro `cmd` se ejecuta como comando del
  sistema operativo en el servidor. Se observa directamente en el comportamiento:
  `cmd=id` devuelve la salida real de `id` precedida por un prompt `$`, y
  `cmd=ls -la /app/priv` devuelve un listado de directorio. Cualquiera que posea el
  token puede ejecutar comandos arbitrarios. Según la salida de `id`, el proceso
  corre como **root**, de modo que el impacto es total.
- **Evidencia (reproducible):** `evidencia/09-sin-token.txt`, `10-rce-id.txt`,
  `final_r4_fs_enum.txt`, `12-crown-jewels.txt`
  ```bash
  # sin token: denegado
  $ curl -s "http://phantomcorp/api/reporte?cmd=id"
  token invalido; conseguilo del backup de RRHH
  # con el token looteado (H-03): RCE como root
  $ curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
  $ id
  uid=0(root) gid=0(root) groups=0(root)
  # enumeración del filesystem hasta los datos (post-explotación)
  $ curl -s -G http://phantomcorp/api/reporte --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=ls -la /app"
  drwxr-xr-x priv
  -rwxr-xr-x server.py
  $ curl -s -G http://phantomcorp/api/reporte --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=ls -la /app/priv"
  -rw-r--r-- clientes.db.txt
  # lectura de los datos de clientes (crown jewels)
  $ curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=cat%20/app/priv/clientes.db.txt"
  clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
  ```
- **Impacto:** control total del servidor como root: lectura/exfiltración de la
  base de clientes (48.210 registros con DNI y tarjeta), movimiento lateral y
  persistencia. Es el hallazgo que concreta el daño al negocio.
- **Remediación:** **no pasar entrada del usuario al shell.** No invocar un shell
  con la entrada del usuario (`os.popen`, `os.system`, `subprocess(..., shell=True)`
  o equivalentes). Si se necesita un "reporte", implementarlo con llamadas de
  código a funciones fijas (sin shell), o `subprocess.run([...], shell=False)` con
  una **lista blanca** de operaciones permitidas. Un token **no es un control
  suficiente**: aun con autenticación fuerte, ejecutar `cmd` arbitrario sería
  inaceptable. Ejecutar el servicio con un **usuario sin privilegios** (no root).

### H-02 · Inyección SQL con bypass de autenticación en el login del portal
- **Severidad:** Crítica · **CVSS 3.1:** 9.1 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
  *(sin autenticación previa; C:H porque da acceso al panel interno de RRHH como
  administrador; I:H porque se vulnera la integridad del control de
  autenticación: el atacante actúa con la identidad y permisos del admin).*
- **CWE:** CWE-89 (SQL Injection).
- **Ubicación:** `POST /portal/login` (ruta declarada en el `action` del
  formulario; la app también acepta `POST /portal-rrhh/login`), parámetros
  `user` / `pass`.
- **Descripción:** el login es vulnerable a inyección SQL. Con `user=admin'` el
  servidor filtra el error `unrecognized token: "x'"`: la comilla extra rompe el
  literal y el valor de `pass` (`x`) queda fuera de él, lo que indica que ambos
  campos se concatenan entre comillas en una consulta del tipo
  `… WHERE user='<user>' AND pass='<pass>'`. Con `admin' -- ` el resto de la
  consulta (el chequeo de contraseña) queda comentado y se devuelve la sesión del
  administrador.
- **Evidencia (reproducible):** `evidencia/05-login-fallido.txt`,
  `06-sqli-probe.txt`, `final_r2_login_formaction.txt`, `07-sqli-bypass.txt`
  ```bash
  # credenciales falsas -> 401
  $ curl -s -i -X POST http://phantomcorp/portal/login --data "user=admin&pass=x" | head -1
  HTTP/1.0 401 Unauthorized
  # una comilla confirma la SQLi (fuga de error)
  $ curl -s -X POST http://phantomcorp/portal/login --data-urlencode "user=admin'" --data "pass=x"
  Error SQL: unrecognized token: "x'"
  # bypass: comenta el chequeo de pass -> sesión admin
  $ curl -s -X POST http://phantomcorp/portal/login --data-urlencode "user=admin' -- " --data "pass=x"
  Bienvenido admin. Dashboard RRHH.
  FLAG{final_sqli_foothold}
  Backup de config disponible en: /backup/rrhh.conf
  ```
- **Impacto:** acceso al panel interno de RRHH como administrador sin conocer la
  contraseña. Es el **foothold** que habilita el resto de la cadena (descubrir el
  backup → token → RCE). La misma inyección podría usarse para extraer otros datos
  de la base; no se intentó, por las reglas del engagement.
- **Remediación:** **consultas parametrizadas / prepared statements**
  (`cursor.execute("… WHERE user=? AND pass=?", (user, pw))`). Nunca concatenar
  entrada en SQL. Complementar con hashing de contraseñas (bcrypt/argon2), mínimo
  privilegio en la cuenta de BD de la aplicación y mensajes de error genéricos (no
  filtrar el error de SQL al cliente).

### H-03 · Backup de configuración accesible por HTTP con secretos en claro
- **Severidad:** Alta · **CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  *(divulgación de información sensible, sin autenticación).*
- **CWE:** CWE-538 (información sensible en archivo accesible) / CWE-522
  (credenciales insuficientemente protegidas) / CWE-330 (uso de valores
  insuficientemente aleatorios).
- **Ubicación:** `GET /backup/rrhh.conf` (servido sin ningún control de acceso).
- **Descripción:** un archivo de configuración de respaldo queda accesible por la
  web y expone credenciales de base de datos y el token de API en texto plano.
- **Evidencia (reproducible):** `evidencia/08-backup-conf.txt`
  ```bash
  $ curl -s http://phantomcorp/backup/rrhh.conf
  DB_USER=rrhh_app
  DB_PASS=Rh-2026
  API_TOKEN=phantom-api-7c1e
  # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}
  ```
- **Impacto:** entrega al atacante las credenciales de la base y el **token que
  habilita el RCE de H-01**. Es el eslabón de post-explotación que convierte el
  acceso al portal en compromiso total. El endpoint ni siquiera exige el foothold:
  se sirve a cualquier cliente no autenticado. Además, el token observado tiene
  **muy poca entropía** (`phantom-api-` + 4 caracteres hexadecimales ≈ 65.536
  valores posibles): aun sin este archivo sería susceptible a fuerza bruta.
  *(Inferencia por el formato observado; no se probó, para no generar carga sobre
  el target.)*
- **Remediación:** **sacar los backups del directorio servido por web** (denegar
  por defecto) y nunca exponer archivos de configuración por HTTP. **Rotar de
  inmediato** el token y las credenciales filtradas. Reemplazar el token por uno
  **no predecible**, generado con un CSPRNG y al menos 128 bits de entropía
  (p. ej. `secrets.token_urlsafe(32)`), con expiración y límite de intentos.
  Gestionar secretos fuera del código/web (variables de entorno o gestor de
  secretos); nunca versionarlos en texto plano.

### H-04 · Exposición de portal interno y fuga de rutas vía `robots.txt`
- **Severidad:** Media · **CVSS 3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  *(divulgación de superficie de ataque oculta).*
- **CWE:** CWE-200 (exposición de información sensible) / CWE-615 (información
  sensible en comentarios de código).
- **Ubicación:** `GET /robots.txt` → `Disallow: /portal-rrhh`; portal interno
  `GET /portal-rrhh` alcanzable desde la red sin segmentación; comentario de
  desarrollo en el HTML del portal.
- **Descripción:** `robots.txt` publica la ruta del portal interno de RRHH, que no
  está enlazado pero es accesible. `robots.txt` no es un control de acceso: lo que
  se "oculta" ahí queda señalizado para cualquiera. Además, el HTML del portal
  incluye un comentario de desarrollo olvidado, y el header `Server` revela
  producto y versión.
- **Evidencia (reproducible):** `evidencia/03-robots.txt`, `04-portal.html`,
  `02-raiz.html`
  ```bash
  $ curl -s http://phantomcorp/robots.txt
  User-agent: *
  Disallow: /portal-rrhh
  $ curl -s http://phantomcorp/portal-rrhh
  …<h1>Portal interno RRHH</h1><form method=post action=/portal/login>…
  <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->
  ```
- **Impacto:** reduce a segundos el reconocimiento: le entrega al atacante la
  ubicación del punto de entrada (el login vulnerable de H-02).
- **Remediación:** **no listar rutas sensibles en `robots.txt`.** Segmentar el
  portal interno para que no sea accesible desde redes no confiables (VPN / red de
  administración / autenticación a nivel de red). Quitar comentarios con
  información útil del HTML entregado al cliente y **neutralizar el banner
  `Server: PhantomClientes/2.0`**, que revela producto y versión.

---

## 5. Conclusión

La postura de seguridad del sistema "Clientes" es **crítica**: una sola caja
concentra cuatro fallas que, encadenadas, llevan de un atacante anónimo a la
exfiltración total de datos personales con privilegios de root. Ninguno de los
hitos requirió credenciales legítimas.

La cadena **era perfectamente evitable** y, además, **redundantemente frágil**: no
hay un único eslabón débil sino varios controles ausentes. Conviene subrayar que,
por H-03, el backup con el token se sirve **sin autenticación**, de modo que **el
RCE de H-01 es alcanzable incluso sin la SQLi** — por eso la remediación no puede
ser puntual sobre el login. La corrección de fondo es tratar **toda entrada como
hostil** (parametrizar consultas, no invocar el shell) y **no exponer secretos ni
superficie interna** (sacar backups de la web, rotar y fortalecer el token,
segmentar el portal, correr el servicio sin privilegios). Resueltos H-01 y H-03,
el impacto cae de "compromiso total" a, a lo sumo, divulgación de rutas.

---

## 6. Anexo

**Resultado de los hitos** (`evidencia/00-ctf-status-final.txt`):

```
   ✓  R1     Recon/enum: portal interno localizado
   ✓  R2     Explotacion: foothold por SQLi
   ✓  R3     Post: token de API looteado
   ✓  R4     Impacto: crown jewels (datos de clientes)
   ██████████████████████████████  4/4 (100%)
```

| Hito | Flag | Hallazgo asociado |
|---|---|---|
| R1 | `FLAG{final_recon_portal}` | H-04 |
| R2 | `FLAG{final_sqli_foothold}` | H-02 |
| R3 | `FLAG{final_token_looted}` | H-03 |
| R4 | `FLAG{final_crown_jewels}` | H-01 |

**Bitácora de evidencia** (carpeta `evidencia/`):

| Archivo | Contenido |
|---|---|
| `00-ctf-status-final.txt` | Captura de `./ctf status final` (4/4) |
| `01-nmap.txt` | Escaneo del servicio HTTP (`nmap -sV -p80`) |
| `01b-nmap-top1000.txt` | Escaneo de los 1000 puertos top (`nmap -Pn -sV`): único servicio abierto |
| `02-raiz.html` / `03-robots.txt` / `04-portal.html` | Recon: superficie pública, fuga de rutas y portal interno (R1) |
| `05-login-fallido.txt` / `06-sqli-probe.txt` / `07-sqli-bypass.txt` | SQLi: baseline (401), confirmación por error y bypass (R2) |
| `final_r2_login_formaction.txt` | SQLi contra `/portal/login` (la ruta del `action` del form) |
| `08-backup-conf.txt` | Backup con credenciales y token (R3) |
| `09-sin-token.txt` / `10-rce-id.txt` / `11-rce-ls.txt` / `12-crown-jewels.txt` | RCE gateado por token: denegación, `id` root, listado y dump de clientes (R4) |
| `final_r4_fs_enum.txt` | Enumeración del filesystem post-RCE (`ls /` → `/app` → `/app/priv`) |

Target: `PhantomClientes/2.0` (HTTP/80). Engagement ejecutado el 2026-11-20 desde
la consola del atacante del lab contra `phantomcorp`. Sin acciones destructivas.
