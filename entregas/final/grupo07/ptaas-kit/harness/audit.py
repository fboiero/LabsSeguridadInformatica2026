"""Change 002 — bitácora persistente (SQLite, append-only, hash encadenado).

`SqliteAuditLog` hereda de `contracts.AuditLog` y persiste cada registro en un
archivo SQLite por engagement, con la MISMA cadena de hashes, de modo que:

- los registros sobreviven a un reinicio del proceso;
- alterar o borrar una fila rompe la cadena y el verificador lo detecta;
- el motor rechaza UPDATE/DELETE (triggers), y no hay API de modificación;
- la cadena se verifica al abrir: si está corrupta, el engagement no continúa.

CLI:  ``python -m harness.audit verify <archivo.db>``  (OK → 0, CORRUPTA → 1).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import threading
import time

from harness.contracts import Action, AuditLog, Result, ScopeToken

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    engagement TEXT NOT NULL,
    agent      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    phase      TEXT NOT NULL,
    result     TEXT NOT NULL,
    prev       TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit es append-only: UPDATE prohibido'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit es append-only: DELETE prohibido'); END;
"""

# Campos que entran al hash, en el mismo orden/forma que contracts.AuditLog.
_FIELDS = ("ts", "engagement", "agent", "action", "target", "phase", "result", "prev")


class AuditChainCorrupted(Exception):
    """La cadena de hashes no valida: el engagement NO DEBE continuar."""


def _hash(body: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _row_body(row: sqlite3.Row) -> dict[str, object]:
    return {k: row[k] for k in _FIELDS}


def _verify_rows(rows: list[sqlite3.Row]) -> bool:
    """Recorre las filas en orden y valida la cadena de hashes."""
    prev = "GENESIS"
    for row in rows:
        body = _row_body(row)
        if body["prev"] != prev:
            return False
        if _hash(body) != row["hash"]:
            return False
        prev = str(row["hash"])
    return True


class SqliteAuditLog(AuditLog):
    """Bitácora append-only persistida en SQLite. Drop-in de `AuditLog`.

    Un archivo por engagement (aislamiento por construcción). Mantiene además el
    espejo en memoria `entries` que leen el Harness y los tests.
    """

    def __init__(self, db_path: str) -> None:
        super().__init__()  # entries = []
        self.db_path = db_path
        self._lock = threading.Lock()
        self._con = sqlite3.connect(db_path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.executescript(_SCHEMA)
        self._con.commit()
        rows = self._rows()
        if not _verify_rows(rows):
            raise AuditChainCorrupted(f"cadena corrupta en {db_path}")
        self.entries = [{**_row_body(r), "hash": r["hash"]} for r in rows]

    def _rows(self) -> list[sqlite3.Row]:
        return self._con.execute("SELECT * FROM audit ORDER BY seq").fetchall()

    def record(self, agent: str, action: Action, target: str,
               token: ScopeToken, result: Result) -> dict[str, object]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else "GENESIS"
            body: dict[str, object] = {
                "ts": time.time(), "engagement": token.engagement_id,
                "agent": agent, "action": action.name, "target": target,
                "phase": token.phase.value, "result": result.value, "prev": prev,
            }
            body["hash"] = _hash(body)
            self._con.execute(
                "INSERT INTO audit (ts,engagement,agent,action,target,phase,result,prev,hash)"
                " VALUES (:ts,:engagement,:agent,:action,:target,:phase,:result,:prev,:hash)",
                body,
            )
            self._con.commit()
            self.entries.append(body)
            return body

    def verify(self) -> bool:
        """Verifica la cadena contra el almacenamiento durable (no el espejo)."""
        with self._lock:
            return _verify_rows(self._rows())

    def close(self) -> None:
        self._con.close()


def verify_file(db_path: str) -> bool:
    """Verifica un archivo de bitácora sin instanciar la clase (para la CLI)."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM audit ORDER BY seq").fetchall()
    finally:
        con.close()
    return _verify_rows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness.audit")
    sub = parser.add_subparsers(dest="cmd", required=True)
    verify_cmd = sub.add_parser("verify", help="verifica la cadena de un archivo de bitácora")
    verify_cmd.add_argument("archivo")
    args = parser.parse_args(argv)
    if args.cmd == "verify":
        ok = verify_file(args.archivo)
        print("OK" if ok else "CORRUPTA")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
