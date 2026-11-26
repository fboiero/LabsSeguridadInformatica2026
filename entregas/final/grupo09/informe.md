# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 09
**Integrantes:**
- Cocchi Santiago — `santicocchi`
- Mosello Francisco — `FranMossello`
- Torres Santiago
- Ferraro Franco
- Spat Tomas

**Fecha:** 20/11/2026  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

En este engagement se usaron herramientas de IA de forma declarada y acotada:

- **PTaaS (Pentest as a Service)** — plataforma propia basada en un swarm de agentes
  (nuestro TP del curso). Se usó para la fase de **relevamiento/RoE**, el **recon**
  automatizado y la **validación controlada de hallazgos de configuración** (headers de
  seguridad) en un sandbox aislado, con gates HITL (aprobación humana) y bitácora
  append-only encadenada por hash. El PTaaS **no genera exploits**: sólo parametriza PoCs
  inertes de un catálogo versionado y firmado. Los hallazgos H-05, H-06 y H-07 provienen de
  esta corrida.
- **Claude Code (Anthropic)** — asistente usado para **redactar y estructurar este informe**
  a partir de la evidencia que el grupo recolectó, y para el desarrollo del PTaaS.

**Validación de la salida:** toda la cadena de explotación (hitos R1→R4, hallazgos H-01 a
H-04) la ejecutó **manualmente el grupo** contra el lab, y cada comando de la sección de
evidencia fue **reproducido** y confirmado antes de documentarlo. Los hallazgos del PTaaS se
validaron en sandbox y se contrastaron contra el target. Ninguna flag ni hallazgo se tomó de
material de solución: se obtuvieron ejecutando el engagement.

---

## 1. Resumen ejecutivo

- **Qué se hizo:** una auditoría de seguridad de caja negra del sistema **"Clientes"** de
  PhantomCorp, sin credenciales ni documentación previa, limitada al host autorizado del
  laboratorio.
- **Resultado global:** **el sistema fue comprometido por completo.** Partiendo de cero, se
  logró ejecutar comandos arbitrarios en el servidor y acceder a la base de datos de clientes.
  El compromiso es **total** (los cuatro hitos del engagement alcanzados: 4/4).
- **Riesgo de negocio:** quedó expuesta la **base de clientes completa — 48.210 registros con
  nombre, DNI y número de tarjeta**. Una fuga así implica incumplimiento de la Ley 25.326 de
  Protección de Datos Personales, riesgo de fraude con tarjetas, daño reputacional y posibles
  sanciones. Además, el atacante obtuvo control del servidor, por lo que podría alterar o
  destruir información.
- **Recomendación prioritaria (acción #1):** **eliminar el endpoint `/api/reporte` que ejecuta
  comandos del sistema operativo** (o reescribirlo sin pasar entrada del usuario a la shell).
  Es el eslabón que convierte el acceso web en control total del servidor.

| Severidad | Cantidad de hallazgos |
|---|---|
| Crítica | 1 |
| Alta | 2 |
| Media | 1 |
| Baja | 3 |

---

## 2. Alcance y metodología

**Alcance (in-scope):** únicamente el host `phantomcorp` del laboratorio (red aislada del
lab, `10.99.0.0/24`). Servicio HTTP en el puerto 80.

**Fuera de alcance:** cualquier otro host del lab (DVWA, Juice Shop) y toda red externa.
No se realizó ninguna acción destructiva (sin borrado de datos, sin DoS), conforme a las
Reglas del Engagement. Autorización acotada al target del lab (Ley 26.388).

**Metodología:** se siguió un flujo estándar de pentest alineado con **PTES**,
**NIST SP 800-115** y **OWASP WSTG**, encadenando las fases:

```
recon / enumeración  ->  explotación (foothold)  ->  post-explotación (loot)  ->  impacto
```

- **Recon + enumeración:** descubrimiento de contenido, análisis de `robots.txt`, revisión
  de respuestas y código fuente HTML, fingerprinting del servidor.
- **Explotación:** prueba de inyección en el formulario de login.
- **Post-explotación:** búsqueda de secretos y material de configuración.
- **Impacto:** demostración del alcance real sobre los datos del negocio.

El scoring de severidad usa **CVSS v4.0** y el mapeo de debilidades **CWE**. La fase de
hallazgos de configuración se corrió con el PTaaS en sandbox aislado (ver sección 0).

---

## 3. Narrativa del ataque

El sistema se presenta públicamente como un portal mínimo ("Portal publico"). La puerta de
entrada no estaba a la vista: **la reveló el propio `robots.txt`**, que pedía a los buscadores
no indexar `/portal-rrhh`. Ese directorio "oculto" resultó ser el **portal interno de RRHH**,
no enlazado desde ningún lado pero perfectamente accesible **(R1 — foothold de recon)**. El
HTML del portal incluso dejaba un comentario delator confirmando el hallazgo.

El portal pedía usuario y contraseña. No las teníamos, pero no hicieron falta: el login era
vulnerable a **inyección SQL**. Autenticando con `admin'--` como usuario, la consulta quedó
truncada y el servidor nos dio la bienvenida como **administrador** sin validar contraseña
alguna **(R2 — foothold de explotación)**. El dashboard de admin nos regaló la siguiente pista:
la ruta a un backup de configuración.

Ese backup, `/backup/rrhh.conf`, estaba servido **sin autenticación** y filtraba credenciales
de base de datos y, lo importante, un **token de API** (`API_TOKEN=phantom-api-7c1e`)
**(R3 — loot)**. El propio archivo documentaba para qué servía el token: el endpoint
`/api/reporte`.

Con el token en mano, `/api/reporte?token=...&cmd=...` **ejecutó comandos arbitrarios del
sistema operativo** en el servidor. Un simple `cmd=cat /app/priv/clientes.db.txt` nos devolvió
los **crown jewels: la base de clientes completa, 48.210 registros con nombre, DNI y tarjeta**
**(R4 — impacto)**. Compromiso total en cuatro pasos encadenados.

```
robots.txt -> /portal-rrhh      (R1 recon)
SQLi en /portal/login           (R2 foothold)
/backup/rrhh.conf -> API_TOKEN   (R3 loot)
/api/reporte (RCE) -> clientes   (R4 impacto)
```

---

## 4. Hallazgos (detalle técnico)

> Ordenados por severidad, críticos primero. Comandos ejecutados desde la consola de ataque
> del lab (`make shell`) contra el host `phantomcorp`.

### H-01 · Inyección de comandos del SO (RCE) en `/api/reporte`
- **Severidad:** Crítica · **CVSS:** 9.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` · **CWE-78** (OS Command Injection)
- **Ubicación:** `GET /api/reporte`, parámetro `cmd` (gateado por `token`).
- **Descripción:** el endpoint pasa el parámetro `cmd` directamente a la shell del sistema.
  Cualquier comando provisto se ejecuta con los privilegios del servicio. El único control es
  un token estático que, además, se filtra sin autenticación (ver H-03), por lo que no
  constituye una barrera real.
- **Evidencia (reproducible):**
  ```bash
  # con el token looteado en H-03
  curl "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
  # $ id
  # uid=0(root) gid=0(root) groups=0(root)

  # lectura de los crown jewels
  curl "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=cat%20/app/priv/clientes.db.txt"
  # clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
  ```
- **Impacto:** **control total del servidor** (ejecución de comandos arbitrarios) y acceso a
  la base de datos de clientes (48.210 registros con PII y datos de tarjeta). Un atacante puede
  exfiltrar, alterar o destruir toda la información del negocio.
- **Remediación:** **eliminar la ejecución de comandos del SO.** Nunca pasar entrada del
  usuario a `os.popen`/`system`/`exec`. Si se necesita un reporte, implementarlo con una
  función acotada y una lista blanca de operaciones permitidas (sin shell). Ejecutar el
  servicio con un usuario sin privilegios (no root).

### H-02 · Inyección SQL con bypass de autenticación en `/portal/login`
- **Severidad:** Alta · **CVSS:** 8.7 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N` · **CWE-89** (SQL Injection) / **CWE-287** (Auth bypass)
- **Ubicación:** `POST /portal/login`, parámetros `user` / `pass`.
- **Descripción:** la consulta de login se arma por concatenación de strings
  (`... WHERE user='{user}' AND pass='{pw}'`). Inyectar `admin'--` en `user` comenta la
  verificación de contraseña y devuelve la fila de administrador, logrando acceso sin
  credenciales válidas.
- **Evidencia (reproducible):**
  ```bash
  curl -s -X POST http://phantomcorp/portal/login \
       --data "user=admin'--&pass=x"
  # Bienvenido admin. Dashboard RRHH.
  # FLAG{final_sqli_foothold}
  # Backup de config disponible en: /backup/rrhh.conf
  ```
- **Impacto:** acceso al **dashboard de administración de RRHH** sin autenticación, y
  divulgación de la ruta al backup de configuración (que habilita H-03 y la cadena hacia RCE).
- **Remediación:** usar **consultas parametrizadas** (prepared statements), nunca concatenar
  entrada del usuario en SQL. Almacenar contraseñas con hashing fuerte (bcrypt/argon2) y
  verificar en la aplicación, no en la query. No revelar rutas internas en las respuestas.

### H-03 · Backup de configuración con secretos accesible sin autenticación
- **Severidad:** Alta · **CVSS:** 8.7 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N` · **CWE-538** (File Exposure) / **CWE-522** (Insufficiently Protected Credentials)
- **Ubicación:** `GET /backup/rrhh.conf`.
- **Descripción:** un archivo de configuración con credenciales de base de datos y el token de
  la API queda servido por HTTP sin ningún control de acceso.
- **Evidencia (reproducible):**
  ```bash
  curl http://phantomcorp/backup/rrhh.conf
  # DB_USER=rrhh_app
  # DB_PASS=Rh-2026
  # API_TOKEN=phantom-api-7c1e
  # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}
  ```
- **Impacto:** filtración de **credenciales de base de datos y del token de API** que habilita
  el RCE de H-01. Es el pivote de post-explotación que conecta el foothold con el impacto total.
- **Remediación:** no publicar backups ni archivos de configuración desde el servidor web;
  mantenerlos fuera del webroot y con control de acceso. **Rotar** las credenciales y el token
  expuestos. Usar secretos no predecibles y gestionados (vault), y tokens de API con expiración
  y scope mínimo.

### H-04 · Divulgación de recursos internos (robots.txt + comentario HTML)
- **Severidad:** Media · **CVSS:** 6.9 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N` · **CWE-615** (Information Exposure Through Comments) / **CWE-200**
- **Ubicación:** `GET /robots.txt` y comentario en el HTML de `/portal-rrhh`.
- **Descripción:** `robots.txt` revela la ruta del portal interno no enlazado
  (`Disallow: /portal-rrhh`), y el HTML del portal incluye un comentario que confirma el
  hallazgo. `robots.txt` no es un control de seguridad: funciona como mapa para el atacante.
- **Evidencia (reproducible):**
  ```bash
  curl http://phantomcorp/robots.txt
  # User-agent: *
  # Disallow: /portal-rrhh

  curl -s http://phantomcorp/portal-rrhh | grep -o "FLAG{[^}]*}"
  # FLAG{final_recon_portal}
  ```
- **Impacto:** acelera el recon al apuntar directamente al portal interno (R1), punto de
  entrada de toda la cadena.
- **Remediación:** no usar `robots.txt` para "ocultar" rutas sensibles; proteger el portal
  interno con autenticación y controles de red. Eliminar comentarios y rutas internas del HTML
  servido en producción.

### H-05 · Ausencia de Content-Security-Policy *(validado por PTaaS en sandbox)*
- **Severidad:** Baja · **CVSS:** 2.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N` · **CWE-693** (Protection Mechanism Failure)
- **Ubicación:** respuestas HTTP del servicio (header `Content-Security-Policy` ausente).
- **Descripción:** el servidor no envía una política de contenido, lo que reduce las defensas
  del navegador frente a inyección de contenido/XSS en caso de que exista un sink reflejado.
- **Evidencia (reproducible):** *(el servicio rechaza `HEAD` con 501; se vuelcan los headers con un GET)*
  ```bash
  curl -s -D - -o /dev/null http://phantomcorp/ | grep -i content-security-policy
  # (sin resultado: header ausente)
  ```
- **Impacto:** endurecimiento ausente; agrava el impacto potencial de otras vulnerabilidades
  del lado del cliente.
- **Remediación:** definir una `Content-Security-Policy` restrictiva (por ejemplo
  `default-src 'self'`) y revisarla por aplicación.

### H-06 · Clickjacking: falta de X-Frame-Options / frame-ancestors *(validado por PTaaS)*
- **Severidad:** Baja · **CVSS:** 2.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N` · **CWE-1021** (Improper Restriction of Rendered UI Layers)
- **Ubicación:** respuestas HTTP (sin `X-Frame-Options` ni `frame-ancestors` en CSP).
- **Descripción:** las páginas pueden embeberse en un `iframe` de un sitio malicioso,
  habilitando ataques de clickjacking sobre el portal.
- **Evidencia (reproducible):**
  ```bash
  curl -s -D - -o /dev/null http://phantomcorp/portal-rrhh | grep -iE "x-frame-options|frame-ancestors"
  # (sin resultado: protección ausente)
  ```
- **Impacto:** un atacante puede engañar a un usuario para que interactúe con el portal
  embebido (UI redress).
- **Remediación:** enviar `X-Frame-Options: DENY` o `Content-Security-Policy: frame-ancestors 'none'`.

### H-07 · Exposición de versión del servidor (banner) *(validado por PTaaS)*
- **Severidad:** Baja · **CVSS:** 2.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N` · **CWE-200** (Information Exposure)
- **Ubicación:** header `Server` de las respuestas HTTP.
- **Descripción:** el servidor expone su identificación (`Server: PhantomClientes/2.0`),
  facilitando fingerprinting al atacante.
- **Evidencia (reproducible):**
  ```bash
  curl -s -D - -o /dev/null http://phantomcorp/ | grep -i ^server
  # Server: PhantomClientes/2.0
  ```
- **Impacto:** información de reconocimiento que ayuda a dirigir ataques.
- **Remediación:** suprimir o generalizar el banner `Server`.

---

## 5. Conclusión

La postura de seguridad del sistema "Clientes" es **crítica**: no requiere técnicas sofisticadas
ni fuerza bruta, sino que **encadena errores básicos y evitables** de cada fase. La cadena era
**totalmente evitable** en varios puntos.

El eslabón que, arreglado, habría cortado la cadena antes es la **inyección SQL del login
(H-02)**: sin el bypass de autenticación, el atacante no habría llegado al dashboard que revela
el backup, ni al token, ni al RCE. Con consultas parametrizadas, la cadena se detiene en R1.
De forma independiente, **eliminar el RCE de `/api/reporte` (H-01)** corta el impacto final aun
si el resto persiste, por eso es la remediación #1.

En conjunto, las fallas reflejan la ausencia de prácticas de desarrollo seguro: concatenación de
SQL, ejecución de comandos del SO con entrada del usuario, secretos expuestos y falta de
endurecimiento. Priorizar H-01 y H-02 reduce el riesgo de total a bajo de forma inmediata.

---

## 6. Anexo

### 6.1 Estado final del engagement

```
$ ./ctf status final

  ╭────────────────────────────────────────────────────────────╮
  │                    PROGRESO · LAB final                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Recon/enum: portal interno localizado
   ✓  R2     Explotacion: foothold por SQLi
   ✓  R3     Post: token de API looteado
   ✓  R4     Impacto: crown jewels (datos de clientes)

  ██████████████████████████████  4/4 (100%)

[ OK ] ¡Lab final COMPLETO!
```

### 6.2 Bitácora de comandos y evidencia

Los comandos de explotación figuran en la evidencia de cada hallazgo (sección 4) y en los
archivos de la carpeta `evidencia/`, capturados desde la consola de ataque del lab contra el
host `phantomcorp`, sin acciones destructivas:

- `evidencia/r1-recon-portal.txt` — `robots.txt` y portal interno (R1).
- `evidencia/r2-sqli-foothold.txt` — bypass de login por SQLi (R2).
- `evidencia/r3-loot-token.txt` — backup de config con el token (R3).
- `evidencia/r4-rce-impacto.txt` — RCE y lectura de los datos de clientes (R4).
- `evidencia/h-config-headers.txt` — headers de respuesta (H-05/H-06/H-07).
- `evidencia/ctf-status-final.txt` — salida de `./ctf status final` (4/4).

### 6.3 Procedencia de los hallazgos de configuración (PTaaS)

Los hallazgos H-05, H-06 y H-07 se validaron con la plataforma PTaaS en sandbox aislado, con
bitácora append-only encadenada por hash y aprobación HITL. Referencia de la corrida:

```
engagement: demo-integrador-20261120-161146
procedencia del target: ptaas-phantomcorp@9b12f5ad  repo@706cd04c
loop C: CWE-693 (CSP) y CWE-1021 (clickjacking) → validated en sandbox
```
