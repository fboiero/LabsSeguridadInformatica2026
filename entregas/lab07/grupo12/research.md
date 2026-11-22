# Mini-research — Laboratorio 07

**Grupo:** 12  
**Tema elegido:**
- [x] **A.** Consultas parametrizadas / prepared statements: cómo separan datos de código y por qué eliminan la SQLi de raíz (con ejemplo en un lenguaje).
- [ ] **B.** sqlmap por dentro: cómo detecta la inyección (boolean-based, time-based, error-based) y qué significa cada técnica.
- [ ] **C.** Un caso real de RCE por command injection (CVE a elección): vector, impacto y parche.
- [ ] **D.** Broken Access Control (OWASP A01): IDOR vs. otras fallas de control de acceso, y el principio de "denegar por defecto".

---

## Desarrollo

### 1. La raíz del problema: Inyección como confusión entre canal de control y canal de datos
Desde el punto de vista de la teoría de lenguajes y compiladores, la vulnerabilidad de **Inyección SQL (CWE-89)** es un caso particular de mezcla inapropiada entre el **canal de control** (la gramática de la sentencia SQL escrita por el desarrollador) y el **canal de datos** (los valores externos suministrados por el usuario).

Cuando una aplicación construye consultas mediante interpolación o concatenación de cadenas (por ejemplo, usando *f-strings* en Python o concatenación con `+`), aplana ambos canales en un único flujo de caracteres antes de entregárselo al motor de base de datos. Al recibir esa cadena única, el analizador léxico (*lexer*) y el analizador sintáctico (*parser*) del RDBMS no disponen de ningún metadato que distinga qué caracteres escribió el programador y cuáles provinieron de la petición HTTP. En consecuencia, metacaracteres como `'`, `--`, `;` o palabras reservadas como `UNION` y `OR` dentro del input del usuario son promovidos a tokens sintácticos reales, alterando el **Árbol de Sintaxis Abstracta (AST)** de la consulta.

---

### 2. Arquitectura interna de las Consultas Parametrizadas (Prepare $\rightarrow$ Bind $\rightarrow$ Execute)
Las **consultas parametrizadas** (*Prepared Statements*) resuelven este problema de raíz porque modifican el protocolo de comunicación entre la aplicación y el motor de base de datos, dividiendo el procesamiento en dos etapas estrictamente desacopladas:

```text
[ ENFOQUE VULNERABLE: Concatenación ]
Input usuario ("admin' --") + Plantilla SQL
       │
       ▼
Cadena única mezclada ──► [ Lexer / Parser SQL ] ──► AST alterado (Bypass de Auth)

──────────────────────────────────────────────────────────────────────────────────

[ ENFOQUE SEGURO: Consulta Parametrizada (Prepared Statement) ]
1) Plantilla con '?'  ──► [ Lexer / Parser SQL ] ──► AST fijo + Bytecode (VDBE)
                                                            │
2) Input ("admin' --") ─────────► [ Bind en registro ] ─────┼──► Ejecución segura
   (No pasa por el parser SQL)                              ▼
                                                  Busca literal "admin' --"
```

Tomando como referencia el motor **SQLite** utilizado en el portal de PhantomCorp (`server.py`), el ciclo interno a nivel de su API en C se compone de tres llamadas fundamentales:

1. **`sqlite3_prepare_v2()` (Compilación estructural):**
   El motor recibe únicamente la plantilla con marcadores de posición (`SELECT user, rol FROM users WHERE user = ? AND pass = ?`). El parser valida la gramática, construye el AST, optimiza índices y traduce la sentencia a un programa en bytecode para su máquina virtual interna (**VDBE** — *Virtual Database Engine*). En ese bytecode, los signos `?` se compilan como instrucciones `OP_Variable` que leen el contenido de un registro de memoria específico. **En este punto, el compilador SQL termina su trabajo y se cierra.**
2. **`sqlite3_bind_text()` (Enlace tipado de parámetros):**
   La librería cliente envía los valores (`user` y `pass`) en paquetes binarios separados indicando su longitud exacta en bytes y su tipo de dato. El motor deposita esos bytes directamente en los registros de las variables de la máquina virtual VDBE sin invocar jamás al parser SQL.
3. **`sqlite3_step()` (Ejecución del bytecode):**
   La máquina virtual ejecuta las instrucciones precompiladas comparando byte a byte el valor de la columna con el buffer enlazado. Cualquier comilla `'`, comentario `--` o cláusula `UNION` contenida en el parámetro es tratada como simples bytes de texto literal.

---

### 3. Ejemplo práctico en Python (`sqlite3` — DB-API 2.0) aplicado a PhantomCorp
A continuación se contrasta el código vulnerable de `server.py` (retos R1 y R2) con su remediación exacta utilizando la biblioteca estándar `sqlite3` (conforme al estándar PEP 249):

```python
import sqlite3

# =========================================================================
# 1. REMEDIACIÓN DEL LOGIN (Reto R1)
# =========================================================================
def login_vulnerable(db: sqlite3.Connection, user: str, pw: str):
    # VULNERABLE: f-string concatena antes de enviar a SQLite.
    # Si user = "admin' --", comenta la validación de pass.
    sql = f"SELECT user, rol FROM users WHERE user='{user}' AND pass='{pw}'"
    return db.execute(sql).fetchone()

def login_seguro(db: sqlite3.Connection, user: str, pw: str):
    # SEGURO: Los signos '?' actúan como placeholders compilados.
    # Los datos viajan en una tupla separada como segundo argumento de execute().
    sql = "SELECT user, rol FROM users WHERE user = ? AND pass = ?"
    return db.execute(sql, (user, pw)).fetchone()


# =========================================================================
# 2. REMEDIACIÓN DEL BUSCADOR CON CLÁUSULA LIKE (Reto R2)
# =========================================================================
def buscar_seguro(db: sqlite3.Connection, termino: str):
    # Error común: intentar escribir "WHERE nombre LIKE '%?%'" (inválido en SQL).
    # Forma correcta: el placeholder es únicamente '?' y los comodines '%'
    # se agregan al valor del parámetro en Python antes del bind.
    sql = "SELECT nombre, precio FROM productos WHERE nombre LIKE ?"
    parametro_like = f"%{termino}%"
    return db.execute(sql, (parametro_like,)).fetchall()
```

---

### 4. Límites de la parametrización: qué elementos NO admiten placeholders
Un aspecto crítico en ingeniería de software segura es comprender que **los placeholders (`?` o `%s`) solo pueden representar valores literales de datos (escalares)**, nunca identificadores estructurales ni palabras clave de la gramática SQL. No es posible parametrizar:
- Nombres de tablas (`FROM ?` es un error de sintaxis).
- Nombres de columnas (`ORDER BY ?` ordenaría por una constante literal y no por la columna).
- Direcciones de ordenamiento (`ASC` / `DESC`).

Si una aplicación necesita permitir que el usuario elija por qué columna ordenar una tabla, concatenar ese parámetro reabriría la vulnerabilidad de SQLi. En esos casos, la única defensa válida es aplicar una **lista blanca estricta (*Allowlist*)** en el código del servidor antes de armar la consulta:

```python
COLUMNAS_PERMITIDAS = {"nombre": "nombre", "precio": "precio"}
ORDEN_PERMITIDO = {"asc": "ASC", "desc": "DESC"}

col_segura = COLUMNAS_PERMITIDAS.get(input_col, "nombre")
ord_seguro = ORDEN_PERMITIDO.get(input_ord.lower(), "ASC")

sql = f"SELECT nombre, precio FROM productos WHERE nombre LIKE ? ORDER BY {col_segura} {ord_seguro}"
filas = db.execute(sql, (f"%{termino}%",)).fetchall()
```

---

## Fuentes

1. **OWASP Foundation (2024).** *SQL Injection Prevention Cheat Sheet — Primary Defenses: Option 1: Use of Prepared Statements (with Parameterized Queries)*. Open Worldwide Application Security Project.  
   Disponible en: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
2. **SQLite Consortium (2024).** *SQLite C/C++ Interface: Compiling an SQL Statement (`sqlite3_prepare_v2`) & Binding Values To Prepared Statements (`sqlite3_bind`)*. Documentación técnica oficial de SQLite.  
   Disponible en: https://www.sqlite.org/c3ref/prepare.html y https://www.sqlite.org/c3ref/bind_blob.html
3. **Python Software Foundation (2024).** *`sqlite3` — DB-API 2.0 interface for SQLite databases: How to use placeholders to bind values in SQL queries*. Python 3.12 Standard Library Documentation.  
   Disponible en: https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries
4. **MITRE Corporation (2024).** *CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')*. Common Weakness Enumeration.  
   Disponible en: https://cwe.mitre.org/data/definitions/89.html

---

## Reflexión

El análisis del funcionamiento interno de las consultas parametrizadas demuestra por qué la seguridad por diseño supera siempre a los parches reactivos basados en listas negras o filtros de caracteres. Mientras que intentar bloquear comillas o palabras como `UNION` lleva a una carrera armamentista contra técnicas de codificación y evasión, separar la compilación del árbol sintáctico SQL del enlace de los datos desactiva el mecanismo mismo de la inyección. Comprender esta frontera entre código y datos es transferible a todas las demás vulnerabilidades de inyección (como Command Injection con `subprocess.run(..., shell=False)` o Prompt Injection en agentes LLM), consolidando el principio más importante del desarrollo seguro: jamás interpolar entrada no confiable dentro de un intérprete de comandos.
