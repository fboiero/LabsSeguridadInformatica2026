# Mini-research — Laboratorio 07: Explotación y Seguridad Web

**Grupo:** 10
**Integrantes:**
- Belén Rocío Ramello — 15226 — @belramello
- Carolina Paula Corazza — 15239 — @carocor1
- Chiara Agustina Kordek — 14719 — @chiarakordek
- Juan Pablo Saby — 15026 — @JuanSaby

**Tema elegido:** **A.** Consultas parametrizadas / prepared statements: cómo separan datos de código y por qué eliminan la SQLi de raíz (con ejemplo en un lenguaje).

---

## Desarrollo

### 1. La causa raíz de la inyección SQL: El problema de la interpretación contextual
La inyección de comandos o datos en sistemas de software obedece invariablemente a un fallo de diseño fundamental: la pérdida de la frontera entre **instrucciones de control** (el lenguaje de programación o consulta) y **datos de usuario** (el contenido provisto desde el exterior).

En el modelo tradicional no seguro de construcción de consultas mediante concatenación de cadenas (`string formatting` o interpolación):
```python
# ANTIPATRÓN VULNERABLE
query = f"SELECT * FROM usuarios WHERE email = '{email}' AND password = '{password}'"
cursor.execute(query)
```
La aplicación genera una única cadena textual que fusiona sintaxis SQL y datos del usuario antes de que el motor de base de datos tenga conocimiento de la instrucción. Cuando el motor recibe este texto, su analizador sintáctico procesa toda la cadena de manera homogénea. Si la variable `email` contiene caracteres con significado léxico especial en SQL (como `'`, `;`, `--` o `/*`), el analizador léxico (*lexer*) los trata como delimitadores de token, alterando el Árbol de Sintaxis Abstracta (*Abstract Syntax Tree* o AST) de la consulta.

### 2. Anatomía interna de un Prepared Statement
Las consultas preparadas (*Prepared Statements*) resuelven este problema redefiniendo el ciclo de vida de la ejecución en la base de datos a través de un protocolo cliente-servidor de dos etapas:

```
[Cliente / Backend]                           [Motor de Base de Datos (DBMS)]
        │                                                     │
        │─── 1. PREPARE: "SELECT * FROM t WHERE k = ?" ──────>│ Compilación sintáctica
        │                                                     │ Generación de AST fijo
        │<── 2. Statement Handle (ID de consulta compilada) ──│ Optimización de plan
        │                                                     │
        │─── 3. EXECUTE: ID + Parámetros binarios [val1] ────>│ Asignación directa a memoria
        │                                                     │ Ejecución del plan fijo
        │<── 4. Resultados de la consulta ────────────────────│
```

1. **Fase de Preparación y Compilación (`PREPARE`):**
   La aplicación envía la estructura lógica de la consulta al DBMS utilizando marcadores de posición (*placeholders*, como `?` o `$1`):
   ```sql
   SELECT id, nombre, rol FROM usuarios WHERE email = ?
   ```
   El DBMS ejecuta el análisis léxico, el parseo gramatical y la optimización del plan de ejecución sobre esta plantilla abstracta. **El árbol sintáctico queda fijado y precompilado en memoria con un identificador único.**

2. **Fase de Asignación y Ejecución (`EXECUTE`):**
   En un mensaje independiente (habitualmente codificado a nivel de protocolo binario, como en el protocolo extendido de PostgreSQL o MySQL), la aplicación envía los valores de los parámetros tipados junto con el identificador del *statement*.

El motor de base de datos no vuelve a compilar ni a interpretar la consulta: simplemente inserta el valor del parámetro en los registros de memoria asignados a las variables del árbol precompilado. Si el parámetro contiene comillas, caracteres de comentario o comandos SQL completos, el motor los trata estrictamente como una secuencia de bytes de texto (un dato literal escalar), imposibilitando de manera absoluta que modifiquen la semántica de la consulta.

### 3. Implementación comparativa en Python (PEP 249 / SQLite & PostgreSQL)

#### Implementación Vulnerable vs. Defensiva:

```python
import sqlite3

def buscar_usuario_vulnerable(cursor, termino: str):
    # INSEGURO: Permite escapar el delimitador e inyectar operadores relacionales
    query = f"SELECT id, nombre FROM productos WHERE nombre = '{termino}'"
    return cursor.execute(query).fetchall()

def buscar_usuario_defensivo(cursor, termino: str):
    # SEGURO: Utiliza el binding de parámetros de la especificación DB-API 2.0 (PEP 249)
    # El placeholder '?' indica al driver y al motor que reserve una posición tipada
    query = "SELECT id, nombre FROM productos WHERE nombre = ?"
    return cursor.execute(query, (termino,)).fetchall()

def busqueda_parcial_defensiva(cursor, termino: str):
    # SEGURO frente a búsquedas con LIKE:
    # Los comodines '%' deben formar parte del valor del parámetro, NO de la query SQL
    query = "SELECT id, nombre FROM productos WHERE nombre LIKE ?"
    parametro = f"%{termino}%"
    return cursor.execute(query, (parametro,)).fetchall()
```

### 4. Consideraciones y limitaciones de la parametrización
Es fundamental notar que los *Prepared Statements* son válidos exclusivamente para valores de datos escalares (parámetros que actúan como literales en expresiones de comparación o asignación). **No pueden utilizarse marcadores de posición para identificadores de esquema o sintaxis estructural**, tales como:
- Nombres de tablas (`FROM ?` $\rightarrow$ inválido).
- Nombres de columnas (`SELECT ? FROM tabla` $\rightarrow$ interpretado como constante literal, no como columna).
- Cláusulas de ordenamiento o dirección (`ORDER BY campo ?` $\rightarrow$ inválido).

Para estos casos donde los identificadores deban ser dinámicos, la defensa complementaria obligatoria consiste en aplicar **listas blancas estrictas** (*allow-listing*): mapear las opciones del usuario contra un diccionario o conjunto inmutable validado en el código de la aplicación.

---

## Fuentes

1. **OWASP Foundation (2024).** *SQL Injection Prevention Cheat Sheet.* OWASP Cheat Sheet Series. Disponible en: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
2. **SQLite Consortium (2024).** *Binding Values To Prepared Statements.* SQLite C/C++ Interface Specification. Disponible en: https://www.sqlite.org/c3ref/bind_blob.html
3. **PostgreSQL Global Development Group (2024).** *Extended Query Protocol: Parse, Bind, and Execute.* PostgreSQL 16 Documentation, Chapter 55: Frontend/Backend Protocol. Disponible en: https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY
4. **Python Software Foundation (2024).** *PEP 249 – Python Database API Specification v2.0.* Disponible en: https://peps.python.org/pep-0249/

---

## Reflexión

Comprender el funcionamiento de los *Prepared Statements* a nivel de arquitectura de base de datos desmitifica la seguridad web: demuestra que la prevención de inyecciones no es una tarea de "adivinar qué caracteres prohibir" mediante filtros o sanitización artesanal, sino de diseñar interfaces que preserven el tipado estricto y la separación física entre instrucciones y datos. La seguridad por diseño (*Security by Design*) radica precisamente en apoyarse en garantías sintácticas y compiladas provistas por el compilador o motor, eliminando clases enteras de vulnerabilidades por definición técnica.

