"""Change 002 — bitácora persistente en SQLite, append-only y hash-encadenada.

Cubre: persistencia tras reinicio, aislamiento por engagement, inmutabilidad
(UPDATE/DELETE bloqueados), detección de alteración/borrado, verificación al
abrir y escrituras concurrentes.
"""
import sqlite3
import subprocess
import sys
import threading

import pytest

from harness.audit import AuditChainCorrupted, SqliteAuditLog, verify_file
from harness.contracts import Action, Guard, Harness, KillSwitch, Phase, Result
from harness.policy_loader import phase_allowlist
from tests.conftest import FakeAdapter, make_token


def _rec(audit: SqliteAuditLog, n: int = 3, agent: str = "recon") -> None:
    for i in range(n):
        audit.record(agent, Action(f"a{i}", Phase.RECON), "10.0.0.5",
                     make_token(), Result.OK)


def _drop_triggers(db: str) -> sqlite3.Connection:
    """Simula un atacante con acceso al archivo: quita los triggers de guarda."""
    con = sqlite3.connect(db)
    con.executescript(
        "DROP TRIGGER IF EXISTS audit_no_update; DROP TRIGGER IF EXISTS audit_no_delete;")
    con.commit()
    return con


# --- 2.1 persistencia / recuperación tras reinicio ---
def test_persistencia_tras_reinicio(tmp_path):
    db = str(tmp_path / "eng-1.db")
    a = SqliteAuditLog(db); _rec(a, 3); a.close()
    reopened = SqliteAuditLog(db)                 # "reinicio": reabrir el archivo
    assert len(reopened.entries) == 3
    assert reopened.verify()


# --- 3.3 aislamiento entre engagements ---
def test_engagements_aislados(tmp_path):
    a = SqliteAuditLog(str(tmp_path / "A.db")); _rec(a, 2)
    b = SqliteAuditLog(str(tmp_path / "B.db"))
    assert len(b.entries) == 0


# --- 2.3 inmutabilidad: el motor rechaza UPDATE y DELETE ---
def test_update_y_delete_bloqueados_por_trigger(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 3); a.close()
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE audit SET target='x' WHERE seq=1"); con.commit()
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("DELETE FROM audit WHERE seq=1"); con.commit()
    con.close()
    assert SqliteAuditLog(db).verify()            # siguió íntegra


# --- 3.1 alterar una fila → verificador falla y no abre ---
def test_alteracion_se_detecta(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 3); a.close()
    con = _drop_triggers(db)
    con.execute("UPDATE audit SET target='10.9.9.9' WHERE seq=2"); con.commit(); con.close()
    assert verify_file(db) is False
    with pytest.raises(AuditChainCorrupted):
        SqliteAuditLog(db)                        # no continúa con cadena corrupta


# --- 3.2 borrar una fila intermedia → verificador falla ---
def test_borrado_intermedio_se_detecta(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 4); a.close()
    con = _drop_triggers(db)
    con.execute("DELETE FROM audit WHERE seq=2"); con.commit(); con.close()
    assert verify_file(db) is False


# --- 3.4 escrituras concurrentes conservan la cadena ---
def test_escrituras_concurrentes(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db)

    def worker(agent):
        for i in range(20):
            a.record(agent, Action(f"x{i}", Phase.RECON), "10.0.0.5",
                     make_token(), Result.OK)

    t1 = threading.Thread(target=worker, args=("w1",))
    t2 = threading.Thread(target=worker, args=("w2",))
    t1.start(); t2.start(); t1.join(); t2.join()
    a.close()

    reopened = SqliteAuditLog(db)
    assert len(reopened.entries) == 40
    assert reopened.verify()
    prevs = [e["prev"] for e in reopened.entries]
    assert len(set(prevs)) == len(prevs)          # ningún 'prev' compartido


# --- verificación al abrir: cadena sana abre sin problema ---
def test_cadena_sana_abre(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 5); a.close()
    assert SqliteAuditLog(db).verify()


# --- CLI: python -m harness.audit verify <archivo> (criterio de aceptación 2) ---
def test_cli_verify(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 3); a.close()
    ok = subprocess.run([sys.executable, "-m", "harness.audit", "verify", db],
                        check=False, capture_output=True, text=True)
    assert ok.returncode == 0
    con = _drop_triggers(db)
    con.execute("UPDATE audit SET result='BLOCKED' WHERE seq=1"); con.commit(); con.close()
    bad = subprocess.run([sys.executable, "-m", "harness.audit", "verify", db],
                         check=False, capture_output=True, text=True)
    assert bad.returncode == 1


# --- sin datos sensibles: solo metadatos, nunca contenido/credenciales ---
def test_sin_datos_sensibles(tmp_path):
    db = str(tmp_path / "e.db"); a = SqliteAuditLog(db); _rec(a, 1)
    permitidas = {"ts", "engagement", "agent", "action", "target", "phase",
                  "result", "prev", "hash"}
    assert set(a.entries[0]) == permitidas        # no hay 'evidence'/'content'/'secret'


# --- 2.5 integra con Harness sin cambiar su contrato público ---
def test_integra_con_harness(tmp_path):
    db = str(tmp_path / "e.db")
    audit = SqliteAuditLog(db)
    harness = Harness(Guard(phase_allowlist()), audit,
                      {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))},
                      KillSwitch())
    harness.invoke("recon", Action("httpx.probe", Phase.RECON), "10.0.0.5",
                   make_token())
    audit.close()
    reopened = SqliteAuditLog(db)
    assert reopened.entries[-1]["result"] == Result.OK.value
    assert reopened.verify()
