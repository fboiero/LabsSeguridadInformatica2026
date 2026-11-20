# Mini-research — Laboratorio 07

**Grupo:** 06
**Tema elegido:** A. Consultas parametrizadas: cómo separan datos de código y por qué eliminan la SQLi de raíz.
**Fecha:** 30/10/2026

## Desarrollo

Una SQL injection ocurre cuando la aplicación arma la sentencia SQL pegando dentro del texto valores que controla el usuario. En R1 y R2 lo vimos: una comilla en el valor cerraba el texto previsto y lo que venía después (`--`, `UNION`) pasaba a ser parte de la consulta. El problema no es un carácter en particular, sino que código y datos viajan juntos en el mismo string.

Una consulta parametrizada separa las dos cosas. La aplicación envía la sentencia con marcadores en lugar de los valores, y después entrega los valores por otra vía. En SQLite, los marcadores pueden ser `?`, `?NNN` o nombres como `:nombre`, y los valores se asignan en tiempo de ejecución con la familia de funciones `sqlite3_bind()` [2]. Como la sentencia ya está analizada cuando llegan los datos, un valor no puede cambiar su estructura. OWASP lo resume así: la estructura SQL se define aparte de los valores, que se enlazan mediante la API de la base y se tratan como datos y no como sintaxis; por eso la ubica como primera defensa [3].

En Python, el módulo `sqlite3` aplica esta idea con el segundo argumento de `execute()`. Su documentación advierte que armar consultas con operaciones de strings de Python es vulnerable a inyección y pide usar siempre marcadores [1]. El siguiente ejemplo usa una base en memoria con datos ficticios, sin relación con el laboratorio:

```python
import sqlite3
con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE usuarios (nombre TEXT, clave TEXT)")
con.execute("INSERT INTO usuarios VALUES (?, ?)", ("admin", "clave-ficticia"))
sql = "SELECT nombre FROM usuarios WHERE nombre = ? AND clave = ?"
casos = [("admin", "clave-ficticia"), ("admin", "incorrecta"), ("admin' --", "incorrecta")]
for nombre, clave in casos:
    filas = con.execute(sql, (nombre, clave)).fetchall()
    print(repr(nombre), repr(clave), "=>", filas)
    assert bool(filas) == (nombre == "admin" and clave == "clave-ficticia")
con.close()
print("OK: el texto con comilla y comentario se trata como un valor literal.")
```

Al ejecutarlo, solo el primer caso devuelve una fila. El tercero usa el mismo payload de R1, `admin' --`, y no devuelve nada: el motor buscó un usuario cuyo nombre es literalmente `admin' --`, y no existe. La comilla y el comentario no tuvieron ningún efecto sobre la consulta.

La protección depende de usar bien el mecanismo. Si el SQL se concatena antes de pasarlo a `execute()`, la consulta sigue siendo vulnerable aunque se use la misma función [3]. Los marcadores representan valores, no nombres de tablas, columnas ni palabras clave como `ASC` o `DESC`; cuando esas partes tienen que ser dinámicas, OWASP recomienda elegirlas de una lista cerrada definida por la aplicación [3]. Escapar caracteres a mano no reemplaza el enlace de parámetros, y validar un valor no lo vuelve seguro para concatenarlo [3]. Por último, parametrizar resuelve la inyección SQL y nada más: no corrige un control de acceso roto como el de R5 ni el guardado de contraseñas en texto plano, que el ejemplo usa solo para simplificar.

## Fuentes

1. Python Software Foundation. «[sqlite3 — DB-API 2.0 interface for SQLite databases](https://docs.python.org/3.12/library/sqlite3.html)», apartado «How to use placeholders to bind values in SQL queries». Documentación de Python 3.12.
2. SQLite. «[SQL Language Expressions](https://www.sqlite.org/lang_expr.html#varparam)», sección 4: Parameters.
3. OWASP Cheat Sheet Series. «[SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)».

Fuentes consultadas el 30/10/2026.

## Reflexión

El ejemplo nos ayudó a entender por qué el mismo `admin' --` que nos dio acceso en R1 no tiene efecto contra una consulta parametrizada. La seguridad no viene de detectar caracteres peligrosos, sino de que los datos nunca lleguen a interpretarse como código. Si tuviéramos que corregir PhantomCorp, empezaríamos por buscar toda consulta armada con strings y reemplazarla por una parametrizada, sabiendo que eso no resuelve las otras fallas del laboratorio.

## Declaración de uso de IA

Codex (OpenAI) asistió en la investigación, la redacción y el ejemplo. Claude Code se usó en la revisión final para corregir la redacción, verificar que cada fuente respalde lo que se le atribuye y volver a ejecutar el ejemplo. El ejemplo corre localmente con Python y SQLite, sin conexión a ninguna red ni al entorno del laboratorio.
