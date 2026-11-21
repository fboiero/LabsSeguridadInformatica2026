# Mini-research — Laboratorio 07

**Tema elegido:** A. Consultas parametrizadas y sentencias preparadas.

## Desarrollo

Una consulta parametrizada combina una instrucción SQL con marcadores y los valores asociados a esos marcadores. En Python, `sqlite3` permite pasar el texto de la consulta y una tupla de valores como argumentos separados de `execute()`. En SQLite, preparar la sentencia define su estructura y vincular un valor lo asigna a un marcador de esa sentencia. Así, una comilla que llega desde un formulario se compara como parte del texto. La concatenación inserta esa comilla en la instrucción y puede cambiar cómo la interpreta el motor. [Documentación de Python](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries), [API de SQLite](https://www.sqlite.org/c3ref/bind_blob.html).

El siguiente ejemplo usa una base SQLite en memoria. La misma consulta busca un nombre simple, un nombre con apóstrofo y un producto ausente.

```python
import sqlite3
from contextlib import closing

with closing(sqlite3.connect(":memory:")) as db:
    db.execute("CREATE TABLE productos (nombre TEXT NOT NULL, precio INTEGER NOT NULL)")
    db.executemany(
        "INSERT INTO productos (nombre, precio) VALUES (?, ?)",
        [("Cable", 900), ("Guía O'Reilly", 1500)],
    )

    consulta = "SELECT precio FROM productos WHERE nombre = ?"
    for nombre, esperado in [
        ("Cable", (900,)),
        ("Guía O'Reilly", (1500,)),
        ("Adaptador", None),
    ]:
        resultado = db.execute(consulta, (nombre,)).fetchone()
        assert resultado == esperado, (nombre, resultado)
        print(f"{nombre!r} -> {resultado}")
```

La prueba devolvió `(900,)` para Cable, `(1500,)` para Guía O’Reilly y `None` para Adaptador. El apóstrofo se conservó en la comparación y el filtro por nombre siguió aplicado en los tres casos.

El mismo principio vale con otras interfaces. PostgreSQL permite enviar valores separados del texto SQL con `PQexecParams`, que usa marcadores como `$1`. Cada marcador ocupa el lugar de un valor. Si el usuario puede elegir cómo ordenar una lista, la aplicación puede traducir opciones como «nombre» o «precio» a columnas fijas definidas en el código y seguir parametrizando los valores del filtro. [Documentación de libpq](https://www.postgresql.org/docs/18/libpq-exec.html#LIBPQ-PQEXECPARAMS).

## Fuentes (mín. 3, verificables)

1. Python. Uso de marcadores y tuplas de parámetros con `sqlite3.execute()`. [Documentación de sqlite3](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).
2. SQLite. Marcadores admitidos y vínculo de valores a sentencias preparadas. [Binding Values To Prepared Statements](https://www.sqlite.org/c3ref/bind_blob.html).
3. PostgreSQL. Separación de consulta y valores en `PQexecParams`. [Command Execution Functions](https://www.postgresql.org/docs/18/libpq-exec.html#LIBPQ-PQEXECPARAMS).

## Reflexión (3–5 líneas)

- El ejemplo muestra por qué conviene admitir apóstrofos en nombres legítimos.
- El filtro sigue funcionando porque la consulta y el valor llegan por separado.
- Al revisar un login o un buscador, buscaría esa separación en cada llamada a la base.
- Probaría también nombres con signos y valores ausentes para comprobar el comportamiento del filtro.
