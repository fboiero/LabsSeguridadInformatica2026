# Mini-research — Laboratorio 07

**Tema elegido:** **A.** Consultas parametrizadas / prepared statements: cómo
separan datos de código y por qué eliminan la SQLi de raíz.

**Justificación de la elección:** es la defensa directa de las dos SQLi que
explotamos (R1 y R2) y la respuesta a la P4. Entender el mecanismo es lo que
distingue "escapo comillas" (frágil) de "la inyección no puede ocurrir".

## Desarrollo

**El problema que resuelven.** Una SQL injection ocurre cuando la aplicación
**arma la consulta concatenando** el input del usuario, mezclando en un mismo
string los *datos* (lo que el usuario escribe) y el *código* (la estructura de la
consulta). Ahí el motor no tiene forma de saber dónde termina la instrucción y
dónde empieza el dato, y un `'`, un `--` o un `UNION` del atacante se interpretan
como SQL. Es la clase de vulnerabilidad **CWE-89** y el corazón de **OWASP A03:
Injection**.

**Cómo funciona una consulta parametrizada.** En vez de pegar el valor dentro del
string, la consulta se escribe con **marcadores de posición** (`?` o `:nombre`) y
el valor se envía por separado:

```python
# VULNERABLE (concatena: dato y código en el mismo string)
cur.execute("SELECT user, rol FROM users WHERE user='" + u + "' AND pass='" + p + "'")

# SEGURO (parametrizado: el valor viaja aparte)
cur.execute("SELECT user, rol FROM users WHERE user = ? AND pass = ?", (u, p))
```

El driver (en Python, siguiendo la interfaz **PEP 249 / DB-API 2.0**) hace dos
cosas clave:
1. **Prepara** primero la consulta: el motor analiza y compila la *estructura* del
   SQL cuando los placeholders todavía están vacíos. En ese momento el plan de la
   consulta ya quedó fijo.
2. **Vincula (bind)** los valores después, por un canal distinto del texto SQL. El
   valor nunca se re-parsea como SQL: entra como el contenido literal de un campo.

**Por qué mata la inyección de raíz.** Como la estructura se compila *antes* de
ver el dato, el input no puede cambiarla. Si el atacante manda `admin' -- ` como
usuario, el motor busca literalmente un usuario llamado `admin' -- ` (y no lo
encuentra); las comillas y el `--` son caracteres de un string, no SQL. No es que
se "escapen los caracteres peligrosos" (eso es una lista negra, siempre
incompleta): es que **datos y código viajan por canales separados** y el dato
nunca tiene estatus de código. Por eso OWASP pone a las consultas parametrizadas
como la defensa primaria número 1 contra SQLi.

**Límites y complementos.** Parametrizar cubre los *valores*, no los
*identificadores* (nombres de tabla/columna) ni cláusulas como `ORDER BY`: eso se
defiende con **listas blancas**. Se complementa con **mínimo privilegio** del
usuario de BD (que el dump de R2 duela menos) y con **no filtrar errores SQL**
verbosos al cliente (los errores verbosos del lab fueron los que nos dejaron
afinar el UNION).

## Fuentes (mín. 3, verificables)

1. OWASP — *SQL Injection Prevention Cheat Sheet* (Defensa 1: Prepared
   Statements / Parameterized Queries):
   https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
2. PortSwigger Web Security Academy — *SQL injection* (mecanismo y prevención con
   consultas parametrizadas):
   https://portswigger.net/web-security/sql-injection
3. Python — PEP 249 *Database API Specification v2.0* (`paramstyle` y
   `execute(sql, parameters)`):
   https://peps.python.org/pep-0249/
4. MITRE — *CWE-89: Improper Neutralization of Special Elements used in an SQL
   Command*: https://cwe.mitre.org/data/definitions/89.html

## Reflexión (3–5 líneas)

Lo que más nos ordenó la cabeza fue dejar de pensar la defensa como "filtrar
entradas malas" y pasar a "separar los canales": el input jamás debería poder
cambiar la estructura de una consulta. Explotar R1 y R2 a mano, viendo cómo el
`--` y el `UNION` se volvían código, hizo evidente por qué parametrizar no es una
opción más sino *la* solución. Y nos quedó claro que no alcanza sola: mínimo
privilegio, listas blancas para identificadores y no exponer errores SQL son el
resto del paquete.
