"""Contrato de la bitácora persistente (change 002). Firma + fake en memoria.

Invariantes que este contrato expresa:
  - append-only: no existe operación para modificar ni borrar registros.
  - cada registro guarda el hash del anterior; el primero usa GENESIS.
  - verify informa si la cadena está íntegra; nunca repara nada.
  - un evento con credenciales o contenido del cliente se rechaza (no se redacta).

La implementación SQLite (tareas 2.2 a 2.4) debe cumplir esta misma firma.

    python -m harness.audit verify <archivo.db> [--anchor-count N --anchor-head HASH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from harness.contracts import AuditLog, Result

GENESIS = "GENESIS"

# Claves que nunca pueden entrar a la bitácora. La detección es por nombre de
# campo: no inspecciona valores, así que no reemplaza una revisión de los eventos.
CLAVES_SENSIBLES = frozenset({
    "password", "passwd", "pass", "secreto", "secret", "api_key", "credencial",
    "contenido", "contenido_evidencia",
})


class EventoSensible(ValueError):
    """Se intentó registrar una clave sensible; el registro se rechaza."""


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: str
    hash: str
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    motivo: str = ""
    indice: int | None = None


def hash_de(prev: str, data: Mapping[str, Any]) -> str:
    cuerpo = {"prev": prev, **data}
    return hashlib.sha256(json.dumps(cuerpo, sort_keys=True).encode()).hexdigest()


def validar_evento(data: Mapping[str, Any]) -> None:
    sensibles = sorted(k for k in data if k.lower() in CLAVES_SENSIBLES)
    if sensibles:
        raise EventoSensible(f"campos sensibles no permitidos en la bitácora: {sensibles}")


def verificar_cadena(entries: Sequence[Entry]) -> VerifyResult:
    prev = GENESIS
    for indice, entrada in enumerate(entries):
        if entrada.prev != prev:
            return VerifyResult(False, "eslabón roto: prev no coincide", indice)
        if hash_de(entrada.prev, entrada.data) != entrada.hash:
            return VerifyResult(False, "hash no coincide con el contenido", indice)
        prev = entrada.hash
    return VerifyResult(True)


class AuditStore(Protocol):
    """Firma que comparten la implementación en memoria y la SQLite."""

    def append(self, data: Mapping[str, Any]) -> Entry:
        """Agrega un registro al final. Nunca modifica ni borra los anteriores."""
        ...

    def verify(self) -> VerifyResult:
        """Verifica la cadena completa del almacén abierto."""
        ...


class InMemoryAuditStore:
    """Fake del contrato: sin disco, mismas reglas de cadena y de datos."""

    def __init__(self) -> None:
        self._entries: list[Entry] = []

    def append(self, data: Mapping[str, Any]) -> Entry:
        validar_evento(data)
        prev = self._entries[-1].hash if self._entries else GENESIS
        evento = dict(data)
        entrada = Entry(len(self._entries) + 1, prev, hash_de(prev, evento), evento)
        self._entries.append(entrada)
        return entrada

    def verify(self) -> VerifyResult:
        return verificar_cadena(self._entries)

    def entries(self) -> list[Entry]:
        return list(self._entries)


# ==== Implementación SQLite (change 002 · 2.2 a 2.5) ===================================
# Diseño de P1 (openspec/changes/002-audit-persistence/design.md), implementado por P5.
# Única diferencia con el esquema propuesto: el evento se guarda como JSON canónico en
# una columna (`data`) en lugar de columnas fijas, para que la misma implementación
# sirva para las decisiones del harness y para la bitácora de evidencia del recorrido.
# El hash es el mismo que el del contrato en memoria: hash_de(prev, data).


class EngagementMismatch(ValueError):
    """El evento o el archivo pertenecen a otro engagement."""


class AuditCorrupt(RuntimeError):
    """La cadena no verificó al abrir: el engagement no continúa."""


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (clave TEXT PRIMARY KEY, valor TEXT NOT NULL)",
    ("CREATE TABLE IF NOT EXISTS registros ("
     " seq INTEGER PRIMARY KEY,"
     " prev TEXT NOT NULL UNIQUE,"          # una cadena lineal: ningún antecesor repetido
     " hash TEXT NOT NULL UNIQUE,"
     " data TEXT NOT NULL)"),
    ("CREATE TRIGGER IF NOT EXISTS registros_no_update BEFORE UPDATE ON registros "
     "BEGIN SELECT RAISE(ABORT, 'bitácora append-only: UPDATE prohibido'); END"),
    ("CREATE TRIGGER IF NOT EXISTS registros_no_delete BEFORE DELETE ON registros "
     "BEGIN SELECT RAISE(ABORT, 'bitácora append-only: DELETE prohibido'); END"),
)


class SQLiteAuditStore:
    """Bitácora append-only en un archivo SQLite por engagement.

    Verifica la cadena al abrir; si no verifica, no acepta más registros.
    Solo expone append, verify, entries, anchor, verify_anchor y close.
    """

    def __init__(self, path: str | Path, engagement_id: str):
        self.path = Path(path)
        self.engagement_id = engagement_id
        self._con = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                    check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA busy_timeout=30000")
        try:
            self._con.execute("BEGIN IMMEDIATE")
            for sentence in _SCHEMA:
                self._con.execute(sentence)
            row = self._con.execute("SELECT valor FROM meta WHERE clave='engagement'").fetchone()
            if row is None:
                self._con.execute("INSERT INTO meta VALUES ('engagement', ?)", (engagement_id,))
            self._con.execute("COMMIT")
        except Exception:
            self._con.execute("ROLLBACK")
            self._con.close()
            raise
        if row is not None and row[0] != engagement_id:
            self._con.close()
            raise EngagementMismatch(f"el archivo pertenece al engagement {row[0]}, "
                                     f"no a {engagement_id}")
        self._integrity = self.verify()

    @classmethod
    def open_existing(cls, path: str | Path) -> SQLiteAuditStore:
        """Abre un archivo existente sin crearlo (CLI de verificación)."""
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"no existe la bitácora {path}")
        con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            row = con.execute("SELECT valor FROM meta WHERE clave='engagement'").fetchone()
        finally:
            con.close()
        if row is None:
            raise ValueError(f"{path} no es una bitácora del harness")
        return cls(path, str(row[0]))

    def append(self, data: Mapping[str, Any]) -> Entry:
        validar_evento(data)
        if not self._integrity.ok:
            raise AuditCorrupt(f"la bitácora no verificó al abrir ({self._integrity.motivo}, "
                               f"entrada {self._integrity.indice}): no se aceptan registros")
        eng = data.get("engagement")
        if eng is not None and eng != self.engagement_id:
            raise EngagementMismatch(f"evento del engagement {eng} en la bitácora de "
                                     f"{self.engagement_id}")
        evento = dict(data)
        self._con.execute("BEGIN IMMEDIATE")   # lectura del último hash + inserción, atómicas
        try:
            row = self._con.execute(
                "SELECT seq, hash FROM registros ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            digest = hash_de(prev, evento)
            self._con.execute("INSERT INTO registros (seq, prev, hash, data) VALUES (?,?,?,?)",
                              (seq, prev, digest, json.dumps(evento, sort_keys=True)))
            self._con.execute("COMMIT")
        except Exception:
            self._con.execute("ROLLBACK")
            raise
        return Entry(seq, prev, digest, evento)

    def entries(self) -> list[Entry]:
        rows = self._con.execute(
            "SELECT seq, prev, hash, data FROM registros ORDER BY seq").fetchall()
        return [Entry(r[0], r[1], r[2], json.loads(r[3])) for r in rows]

    def verify(self) -> VerifyResult:
        entries = self.entries()
        result = verificar_cadena(entries)
        if not result.ok:
            return result
        for i, entry in enumerate(entries):
            if entry.seq != i + 1:
                return VerifyResult(False, "hueco en la numeración", i)
        return VerifyResult(True)

    def anchor(self) -> tuple[int, str]:
        entries = self.entries()
        return len(entries), entries[-1].hash if entries else GENESIS

    def verify_anchor(self, count: int, head: str) -> VerifyResult:
        result = self.verify()
        if not result.ok:
            return result
        if self.anchor() != (count, head):
            return VerifyResult(False, "el ancla no coincide: falta o sobra el final de la cadena")
        return VerifyResult(True)

    def close(self) -> None:
        self._con.close()


class PersistentAuditLog(AuditLog):
    """AuditLog del harness que además persiste cada decisión (2.5).

    Mantiene el contrato público de AuditLog (record, record_decision, entries) para
    que Harness no cambie; cada decisión se escribe también en un SQLiteAuditStore.
    """

    def __init__(self, path: str | Path, engagement_id: str):
        super().__init__()
        self.store = SQLiteAuditStore(path, engagement_id)

    def record_decision(self, agent: str, action_name: str, target: str,
                        engagement_id: str, phase: str, result: Result) -> dict[str, Any]:
        body = super().record_decision(agent, action_name, target, engagement_id, phase, result)
        self.store.append({k: body[k] for k in ("ts", "engagement", "agent", "action",
                                                "target", "phase", "result")})
        return body

    def close(self) -> None:
        self.store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m harness.audit")
    sub = parser.add_subparsers(dest="command", required=True)
    ver = sub.add_parser("verify", help="verificar la cadena de un archivo de bitácora")
    ver.add_argument("path", type=Path)
    ver.add_argument("--anchor-count", type=int)
    ver.add_argument("--anchor-head")
    args = parser.parse_args(argv)
    try:
        store = SQLiteAuditStore.open_existing(args.path)
    except (OSError, ValueError, sqlite3.DatabaseError) as exc:
        print(json.dumps({"ok": False, "motivo": str(exc)}, ensure_ascii=False))
        return 2
    try:
        if args.anchor_count is not None or args.anchor_head is not None:
            result = store.verify_anchor(args.anchor_count if args.anchor_count is not None
                                         else -1, args.anchor_head or "")
        else:
            result = store.verify()
        count, head = store.anchor()
        print(json.dumps({"ok": result.ok, "motivo": result.motivo, "indice": result.indice,
                          "count": count, "head": head, "engagement": store.engagement_id},
                         ensure_ascii=False))
    finally:
        store.close()
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
