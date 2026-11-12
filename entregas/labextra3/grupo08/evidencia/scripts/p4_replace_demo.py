#!/usr/bin/env python3
"""P4 evidence: why replace("'", "") is not a fix and parametrization is.

In-memory SQLite, standard library only. Each case prints the input, the SQL
actually sent to the engine, and the result.
"""
import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE usuarios (id INTEGER, user TEXT, password TEXT)")
db.executemany("INSERT INTO usuarios VALUES (?, ?, ?)", [
    (1, "admin", "sup3r-s3cr3t0"),
    (2, "O'Brien", "pa'ss"),          # legitimate data that contains quotes
])


def filtro(s):
    """The classmate's proposed 'fix'."""
    return s.replace("'", "")


def login_filtrado(user, pwd):
    sql = ("SELECT user FROM usuarios WHERE user = '" + filtro(user)
           + "' AND password = '" + filtro(pwd) + "'")
    return sql, db.execute(sql).fetchall()


def login_parametrizado(user, pwd):
    sql = "SELECT user FROM usuarios WHERE user = ? AND password = ?"
    return sql + f"   params={(user, pwd)!r}", db.execute(sql, (user, pwd)).fetchall()


def perfil_filtrado(uid):
    # Numeric context: there are no quotes to remove.
    sql = "SELECT user FROM usuarios WHERE id = " + filtro(uid)
    return sql, db.execute(sql).fetchall()


def perfil_parametrizado(uid):
    sql = "SELECT user FROM usuarios WHERE id = ?"
    return sql + f"   params={(uid,)!r}", db.execute(sql, (uid,)).fetchall()


def caso(titulo, fn, *args):
    sql, filas = fn(*args)
    print(f"  {titulo}")
    print(f"    SQL   : {sql}")
    print(f"    filas : {filas}")


print("== 1) String context: the replace blocks breakout here... (SQLite) ==")
caso("filtro      user=\"admin'--\"", login_filtrado, "admin'--", "x")
caso("filtro      pass=\"' OR 1=1 --\"", login_filtrado, "x", "' OR 1=1 --")

print("\n== 2) ...but it corrupts legitimate data (functional regression) ==")
caso("filtro      O'Brien / pa'ss (correct credentials)", login_filtrado, "O'Brien", "pa'ss")
caso("param.      O'Brien / pa'ss (correct credentials)", login_parametrizado, "O'Brien", "pa'ss")

print("\n== 3) Numeric context: no quotes needed, the filter is irrelevant ==")
caso("filtro      id=\"0 OR 1=1\"", perfil_filtrado, "0 OR 1=1")
caso("param.      id=\"0 OR 1=1\"", perfil_parametrizado, "0 OR 1=1")

print("\n== 4) Engine-dependent: backslash as escape (MySQL default mode) ==")
sql, _ = login_filtrado("\\", " OR 1=1 -- ")
print("  filtro      user=\"\\\"  pass=\" OR 1=1 -- \"   (NOT executed: SQLite does not treat \\ as an escape)")
print(f"    SQL   : {sql}")
print("    In MySQL, \\' is an escaped quote: the user literal becomes \"' AND password = \"")
print("    and \"OR 1=1 -- \" is left OUTSIDE the literal, as code -> bypass with no quote at all.")

print("\n== 5) Parametrized: the same attacks are just data ==")
for u, p in [("admin'--", "x"), ("x", "' OR 1=1 --"), ("\\", " OR 1=1 -- "), ("admin", "sup3r-s3cr3t0")]:
    caso(f"param.      user={u!r} pass={p!r}", login_parametrizado, u, p)
