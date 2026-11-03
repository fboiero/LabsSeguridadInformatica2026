# Mini-research — Laboratorio 07

**Tema elegido:**

- [x] **A.** Consultas parametrizadas / prepared statements: cómo separan datos de código y por qué eliminan la SQLi de raíz (con ejemplo en un lenguaje).
- [ ] **B.** sqlmap por dentro: cómo detecta la inyección (boolean-based, time-based, error-based) y qué significa cada técnica.
- [ ] **C.** Un caso real de RCE por command injection (CVE a elección): vector, impacto y parche.
- [ ] **D.** Broken Access Control (OWASP A01): IDOR vs. otras fallas de control de acceso, y el principio de "denegar por defecto".

---

## Planteo y postura del grupo

En las actividades R1 y R2 de este laboratorio explotamos dos variantes de inyección SQL (bypass de autenticación en `/login` y extracción mediante `UNION` en `/buscar`). En ambos casos, el problema de fondo fue el mismo: el servidor construyó las consultas concatenando texto proveniente del usuario con las instrucciones SQL de la aplicación.

La recomendación unánime de la industria y de los estándares de seguridad (OWASP, NIST, CWE) es el uso de **consultas parametrizadas** (también conocidas como *prepared statements*). Sin embargo, muchas veces se las describe vagamente como "una forma segura de filtrar o escapar caracteres peligrosos". Nuestra postura es que las consultas parametrizadas **no son un filtro ni una función de escape**, sino un cambio arquitectónico fundamental en el ciclo de vida de la ejecución de una consulta: separan en momentos temporales y canales lógicos distintos la **definición del código** (la estructura sintáctica) de la **provisión de los datos** (los valores escalares). Al transformar la entrada del usuario en un literal inmutable que nunca pasa por el analizador sintáctico del motor, la inyección queda eliminada de raíz por imposibilidad matemática y estructural.

---

## Desarrollo

### 1. La causa raíz: ruptura de la frontera datos/código

Una inyección SQL ocurre cuando una cadena de caracteres proporcionada por un cliente es interpretada por el motor de base de datos como **sintaxis de control** en lugar de como un **valor literal**.

En arquitecturas tradicionales vulnerables, la aplicación arma la sentencia mediante interpolación o concatenación de strings:

```text
sql = "SELECT id, rol FROM users WHERE user = '" + input_usuario + "' AND pass = '" + input_pass + "'"
```

Cuando el servidor envía este texto consolidado a la base de datos, el motor recibe un único flujo continuo de caracteres. El analizador léxico (*lexer*) y el analizador sintáctico (*parser*) del gestor no tienen forma de saber qué palabras escribió el programador y qué palabras provino de un usuario malicioso. Si `input_usuario` contiene caracteres con significado sintáctico en SQL (como comillas simples `'`, delimitadores de comentarios `--` o palabras clave como `UNION` y `OR`), el parser modifica el **Árbol Sintáctico Abstracto** (*Abstract Syntax Tree* o AST). Como resultado, la consulta que se ejecuta es estructuralmente distinta a la que el desarrollador pretendía.

### 2. Anatomía interna de un motor SQL: por qué el AST define la ejecución

Para comprender la parametrización, es necesario observar las etapas internas que atraviesa cualquier consulta en un motor de base de datos relacional (como SQLite, PostgreSQL o MySQL):

```
                                      Fase 1: PREPARE
[ Plantilla SQL con ? ] ──> [ Lexer / Parser ] ──> [ Árbol Sintáctico (AST) ] ──> [ Optimizador / Compilador ] ──> [ Plan de Ejecución compilado ]
                                                                                                                            │
                                                                                                                            ▼
                                      Fase 2: EXECUTE                                                                 [ Máquina Virtual / VDBE ]
[ Parámetros (datos puros) ] ───────────────────────────────────────────────────────────────────────────────────────────────> │
                                                                                                                            ▼
                                                                                                                      [ Resultados ]
```

1. **Análisis léxico y sintáctico (Lexing/Parsing):** El motor lee la cadena de texto, genera tokens (`SELECT`, `FROM`, operadores, identificadores y literales) y construye el AST, validando la gramática SQL.
2. **Optimización y compilación del plan:** El planificador analiza el AST, consulta las estadísticas de las tablas e índices, y genera un plan de ejecución de bajo nivel (por ejemplo, en SQLite, bytecode que será ejecutado por el VDBE — *Virtual Database Engine*).
3. **Ejecución:** El motor recorre los registros aplicando las operaciones lógicas dictadas por el plan compilado.

En una consulta concatenada, las fases 1, 2 y 3 ocurren juntas en una sola llamada (`query(string)`). La entrada del atacante entra en la **Fase 1**, corrompiendo el AST antes de que el plan de ejecución sea creado.

### 3. El mecanismo de las Consultas Parametrizadas (Prepared Statements)

Una consulta parametrizada desacopla el ciclo en dos fases independientes y explícitas:

#### Fase A: Preparación (`PREPARE` / `Parse`)
La aplicación envía a la base de datos la estructura de la consulta utilizando marcadores de posición (*placeholders*, como `?` en SQLite/MySQL o `$1, $2` en PostgreSQL):

```sql
PREPARE stmt FROM 'SELECT id, rol FROM users WHERE user = ? AND pass = ?';
```

El motor de base de datos somete esta plantilla al analizador léxico, al parser y al optimizador. En este punto, el AST y el plan de ejecución quedan **cerrados e inmutables**. El árbol define de manera rígida que la instrucción es un `SELECT`, que opera sobre la tabla `users`, y que contiene una cláusula `WHERE` compuesta por una conjunción lógica (`AND`) de dos igualdades contra dos valores que serán suministrados a posteriori.

#### Fase B: Enlace de parámetros y ejecución (`BIND` / `Execute`)
Cuando la aplicación dispone de los valores del usuario, los transmite al motor por un canal de datos separado, asociándolos a cada marcador:

```sql
EXECUTE stmt USING ('admin\' --', 'clave123');
```

A nivel de protocolo de red (por ejemplo, en el *Extended Query Protocol* de PostgreSQL o en la API nativa C de SQLite con `sqlite3_bind_text`), los valores viajan con su tipo de dato explícito (cadena, entero, blob) y se cargan directamente en los registros o variables del plan de ejecución compilado.

**El motor no vuelve a invocar al parser sintáctico.** El texto `'admin\' --'` nunca se analiza como gramática SQL. Para la base de datos, la comilla `'` y los guiones `--` tienen exactamente el mismo valor semántico que cualquier letra alfanumérica. El motor compara el campo `user` de la tabla contra la secuencia exacta de 9 caracteres `"admin' --"`. Como ningún usuario tiene ese valor como nombre, la comparación simplemente evalúa como falsa.

### 4. Demostración práctica en código (Python con `sqlite3`)

A continuación se compara el comportamiento ante un intento de explotación de bypass de login (R1):

```python
import sqlite3

# Configuración de base de datos en memoria para prueba
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER, user TEXT, pass TEXT, rol TEXT)")
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'clave_super_secreta', 'admin')")
conn.commit()

# Payload del atacante (intento de comentar la verificación de pass)
user_input = "admin' --"
pass_input = "cualquiera"

# --- IMPLEMENTACIÓN 1: VULNERABLE (Concatenación de strings) ---
consulta_vulnerable = f"SELECT user, rol FROM users WHERE user = '{user_input}' AND pass = '{pass_input}'"
print("Consulta vulnerable generada:", consulta_vulnerable)
cursor.execute(consulta_vulnerable)
resultado_vuln = cursor.fetchone()
print("Resultado vulnerable:", resultado_vuln)
# Salida: ('admin', 'admin') -> ¡BYPASS EXITOSO!

# --- IMPLEMENTACIÓN 2: SEGURA (Consulta parametrizada / Prepared Statement) ---
consulta_segura = "SELECT user, rol FROM users WHERE user = ? AND pass = ?"
print("\nPlantilla enviada al parser:", consulta_segura)
cursor.execute(consulta_segura, (user_input, pass_input))
resultado_seguro = cursor.fetchone()
print("Resultado parametrizado:", resultado_seguro)
# Salida: None -> ¡INYECCIÓN NEUTRALIZADA!
```

En la segunda implementación, SQLite compila la plantilla con `sqlite3_prepare_v2` y luego vincula `user_input` con `sqlite3_bind_text`. La inyección es rechazada limpiamente sin necesidad de escribir expresiones regulares ni reglas de filtrado manual.

### 5. Por qué fallan las defensas ingenuas (Escaping y Blacklisting)

Históricamente, muchos desarrolladores intentaron defenderse agregando barras invertidas (`addslashes`) o buscando comillas mediante listas negras. Estos enfoques fallan sistemáticamente:

1. **Bypass por codificación de caracteres multibyte:** En entornos donde la base de datos y la aplicación utilizan conjuntos de caracteres multibyte (como GBK o Big5), secuencias como `%bf%27` hacen que el backend intente escapar la comilla inyectando una barra invertida (`%5c`). La combinación `%bf%5c` es interpretada por el motor como un único carácter ideográfico válido, dejando la comilla `%27` libre y activa para romper la sintaxis.
2. **Inyección de segundo orden (*Second-Order SQLi*):** Si la aplicación "escapa" una comilla antes de guardar un dato en la base, el motor almacena la cadena original sin la barra. Cuando otra parte del sistema recupera ese valor de la base y lo concatena en una segunda consulta sin parametrizar, la inyección ocurre de todas formas.
3. **Campos numéricos:** Las funciones de escape operan sobre comillas, pero en consultas como `SELECT * FROM items WHERE id = ` + input_id, el atacante no necesita usar comillas para alterar la lógica (basta con inyectar `1 OR 1=1`).

Las consultas parametrizadas son inmunes a estos tres problemas porque no dependen de modificar el texto para hacerlo "inofensivo": garantizan que ningún dato se interprete jamás como código.

### 6. Límites y lo que las consultas parametrizadas NO resuelven

Es crucial señalar que las consultas parametrizadas no pueden usarse para cualquier parte de una sentencia SQL. El estándar SQL prohíbe el uso de marcadores de posición (`?`) en:

- Nombres de tablas (`SELECT * FROM ?`)
- Nombres de columnas (`SELECT ? FROM productos`)
- Direcciones de ordenamiento (`ORDER BY fecha ?` — `ASC` / `DESC`)

Si una aplicación necesita nombres de tablas o columnas dinámicas (por ejemplo, en un listado ordenable por interfaz de usuario), la parametrización no aplica directamente a esos identificadores. En esos casos, la única defensa efectiva es una **lista blanca estricta (allowlisting)** en el código de la aplicación:

```python
COLUMNAS_VALIDAS = {"precio", "nombre", "fecha"}
orden = input_columna if input_columna in COLUMNAS_VALIDAS else "fecha"
cursor.execute(f"SELECT nombre, precio FROM productos ORDER BY {orden}")
```

---

## Reflexión

Comprender las consultas parametrizadas a nivel de AST y de compilador nos enseñó que la seguridad eficaz no consiste en agregar "parches de desinfección" sobre un diseño inseguro, sino en mantener una separación arquitectónica estricta entre el plano de control (código) y el plano de datos. En el desarrollo profesional, confiar en funciones de escape o filtros caseros es asumir que conocemos todos los vectores de evasión posibles; adoptar *prepared statements* y ORMs que parametrizan por defecto traslada la garantía de seguridad directamente al núcleo del motor de base de datos.

---

## Fuentes

1. **OWASP Foundation.** (2023). *SQL Injection Prevention Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html — **Primaria** (estándar de la industria).
2. **The PostgreSQL Global Development Group.** (2024). *PostgreSQL Documentation: Chapter 55. Frontend/Backend Protocol — Message Flow: Extended Query*. https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY — **Primaria** (documentación técnica oficial).
3. **SQLite Consortium.** (2024). *The Virtual Database Engine (VDBE) and C-language Interface: sqlite3_prepare_v2 & sqlite3_bind*. https://www.sqlite.org/c3ref/prepare.html y https://www.sqlite.org/opcode.html — **Primaria** (especificación de arquitectura).
4. **MITRE Corporation.** (2024). *CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')*. Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/89.html — **Primaria** (estándar de clasificación de vulnerabilidades).
5. **Halfond, W. G., Viegas, J., & Orso, A.** (2006). A classification of SQL-injection attacks and countermeasure techniques. *Proceedings of the IEEE International Symposium on Secure Software Engineering*, 1–15. https://doi.org/10.1109/ISSSE.2006.14 — **Arbitrada** (paper académico).
