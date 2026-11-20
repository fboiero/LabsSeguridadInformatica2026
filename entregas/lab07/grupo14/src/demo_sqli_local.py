"""Demo LOCAL y didactica (NO es el lab): SQLi por concatenacion vs consulta parametrizada.
Usa una base sqlite3 en memoria con datos propios. Solo stdlib."""
import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users(user TEXT, pass TEXT, rol TEXT)")
db.execute("INSERT INTO users VALUES('admin','clave_larga_x','admin'),('ana','1234','user')")

def login_vulnerable(u, p):
    q = f"SELECT user, rol FROM users WHERE user='{u}' AND pass='{p}'"
    return q, db.execute(q).fetchall()

def login_seguro(u, p):
    q = "SELECT user, rol FROM users WHERE user=? AND pass=?"
    return q, db.execute(q, (u, p)).fetchall()

if __name__ == "__main__":
    payload = "admin' --"
    q, r = login_vulnerable(payload, "cualquiera")
    print("VULNERABLE:", q, "->", r)
    assert r == [("admin", "admin")]          # bypass: entra sin clave
    q, r = login_seguro(payload, "cualquiera")
    print("SEGURO    :", q, "-> params", (payload, "cualquiera"), "->", r)
    assert r == []                            # el payload es solo un nombre de usuario raro
    print("OK")
