"""Bitácora persistente. SHA-256 verifica estructura, no autenticidad ni completitud."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from .types import Action, Result, ScopeToken

LIMITATION = (
    "Integridad estructural válida; completitud y autenticidad no verificadas sin anclaje externo"
)
_FIELDS = {
    "version", "seq", "ts", "engagement", "agent", "action", "target", "phase", "event",
    "result", "error_code", "invocation_id", "prev",
}
_TRIGGERS = {"events_no_update", "events_no_delete", "metadata_no_update", "metadata_no_delete"}


class AuditUnavailable(RuntimeError):
    """No es seguro continuar sin persistencia."""


class AuditIntegrityError(RuntimeError):
    """Archivo corrupto, incompatible o de otro engagement."""


class AuditRecoveryRequired(RuntimeError):
    """Hay una ejecución previa cuyo resultado no puede darse por conocido."""


def _encoded(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, allow_nan=False)


def _digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(_encoded(body).encode("utf-8")).hexdigest()


def _label(value: str) -> str:
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}", value):
        return value
    return "invalid:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_target(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        host = value.lower().rstrip(".")
        if len(host) <= 253 and all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in host.split(".")
        ):
            return host
        return "invalid:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _check_chain(entries: list[dict[str, Any]], engagement: str) -> None:
    previous = "GENESIS"
    for sequence, entry in enumerate(entries, 1):
        body = {key: value for key, value in entry.items() if key != "hash"}
        if (
            set(body) != _FIELDS or body["version"] != 1 or body["seq"] != sequence
            or body["engagement"] != engagement or body["prev"] != previous
            or not isinstance(body["ts"], (float, int)) or not math.isfinite(body["ts"])
            or body["phase"] not in {"recon", "correlate", "analyze", "validate", "report"}
            or body["event"] not in {"ATTEMPT", "DECISION", "TOOL_ERROR"}
            or body["result"] not in {None, "OK", "BLOCKED", "PENDING_HITL", "ABORTED"}
            or _digest(body) != entry.get("hash")
        ):
            raise AuditIntegrityError("audit_chain_invalid")
        previous = entry["hash"]


def _read(connection: sqlite3.Connection, engagement: str | None = None) -> tuple[str, list[dict[str, Any]]]:
    try:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise AuditIntegrityError("audit_database_invalid")
        metadata = connection.execute("SELECT version, engagement FROM metadata WHERE id=1").fetchall()
        if len(metadata) != 1 or metadata[0][0] != 1:
            raise AuditIntegrityError("audit_schema_invalid")
        stored_id = metadata[0][1]
        if not isinstance(stored_id, str) or (engagement is not None and engagement != stored_id):
            raise AuditIntegrityError("audit_engagement_mismatch")
        triggers = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        if not _TRIGGERS <= triggers:
            raise AuditIntegrityError("audit_protection_missing")
        entries = []
        for sequence, body_json, digest in connection.execute("SELECT seq, body, hash FROM events ORDER BY seq"):
            body = json.loads(body_json)
            if not isinstance(body, dict) or body.get("seq") != sequence:
                raise AuditIntegrityError("audit_sequence_invalid")
            entries.append({**body, "hash": digest})
        _check_chain(entries, stored_id)
        return stored_id, entries
    except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError):
        raise AuditIntegrityError("audit_file_invalid") from None


def _summary(engagement: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "engagement": engagement, "event_count": len(entries),
        "head_hash": entries[-1]["hash"] if entries else "GENESIS",
        "external_anchor": False, "notice": LIMITATION,
    }


def verify_file(path: str | Path) -> dict[str, Any]:
    location = Path(path).resolve()
    if not location.is_file():
        raise AuditUnavailable("audit_file_unavailable")
    try:
        connection = sqlite3.connect(location.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            engagement, entries = _read(connection)
            return _summary(engagement, entries)
        finally:
            connection.close()
    except sqlite3.OperationalError:
        raise AuditUnavailable("audit_file_unavailable") from None


class AuditLog:
    """AuditLog() conserva el modo en memoria del kit; la demo exige un archivo."""

    def __init__(self, path: str | Path | None = None, engagement_id: str | None = None,
                 *, timeout: float = 5.0):
        self.path = Path(path) if path is not None else None
        self.engagement_id = engagement_id
        self._memory: list[dict[str, Any]] = []
        self._connection: sqlite3.Connection | None = None
        self._failed = False
        if self.path is None:
            return
        if not engagement_id or _label(engagement_id) != engagement_id:
            raise AuditIntegrityError("audit_engagement_invalid")
        existed = self.path.exists()
        try:
            self._connection = sqlite3.connect(self.path, timeout=timeout)
            self._connection.execute("PRAGMA synchronous=FULL")
            if not existed:
                self._initialize(engagement_id)
            _read(self._connection, engagement_id)
        except (sqlite3.Error, AuditIntegrityError):
            self.close()
            raise AuditIntegrityError("audit_open_failed") from None

    def _initialize(self, engagement_id: str) -> None:
        assert self._connection is not None
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, engagement TEXT NOT NULL)")
        connection.execute("INSERT INTO metadata VALUES (1, 1, ?)", (engagement_id,))
        connection.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY CHECK(seq>0), body TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)")
        for table in ("events", "metadata"):
            for operation in ("UPDATE", "DELETE"):
                name = f"{table}_no_{operation.lower()}"
                connection.execute(
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                    "BEGIN SELECT RAISE(ABORT, 'append_only'); END"
                )
        connection.commit()

    @property
    def entries(self) -> list[dict[str, Any]]:
        if self.path is None:
            return self._memory
        if self._connection is None:
            raise AuditUnavailable("audit_closed")
        return _read(self._connection, self.engagement_id)[1]

    def verify(self) -> dict[str, Any]:
        entries = self.entries
        engagement = self.engagement_id or "unbound"
        _check_chain(entries, engagement)
        return _summary(engagement, entries)

    def assert_resumable(self) -> None:
        pending: set[str] = set()
        for entry in self.entries:
            invocation = entry["invocation_id"]
            if entry["event"] == "ATTEMPT":
                pending.add(invocation)
            elif invocation is not None:
                pending.discard(invocation)
        if pending:
            raise AuditRecoveryRequired("audit_unresolved_attempt_requires_human")

    def _commit(self) -> None:
        assert self._connection is not None
        self._connection.commit()

    def record(self, agent: str, action: Action, target: str,
               token: ScopeToken, result: Result) -> dict[str, Any]:
        return self.record_event(agent, action, target, token, "DECISION", result=result)

    def record_event(self, agent: str, action: Action, target: str, token: ScopeToken,
                     event: str, invocation_id: str | None = None, *,
                     result: Result | None = None, error_code: str | None = None) -> dict[str, Any]:
        if self._failed:
            raise AuditUnavailable("audit_suspended")
        if self.engagement_id is not None and token.engagement_id != self.engagement_id:
            raise AuditIntegrityError("audit_engagement_mismatch")
        if event not in {"ATTEMPT", "DECISION", "TOOL_ERROR"}:
            raise ValueError("unsupported_event")
        if error_code not in {None, "adapter_failure"}:
            raise ValueError("unsupported_error_code")
        connection = self._connection
        try:
            if self.path is not None:
                if connection is None:
                    raise AuditUnavailable("audit_closed")
                connection.execute("BEGIN IMMEDIATE")
                entries = _read(connection, self.engagement_id)[1]
            else:
                entries = self._memory
            body = {
                "version": 1, "seq": len(entries) + 1, "ts": time.time(),
                "engagement": token.engagement_id, "agent": _label(agent),
                "action": _label(action.name), "target": safe_target(target),
                "phase": token.phase.value, "event": event,
                "result": result.value if result is not None else None,
                "error_code": error_code,
                "invocation_id": _label(invocation_id) if invocation_id is not None else None,
                "prev": entries[-1]["hash"] if entries else "GENESIS",
            }
            entry = {**body, "hash": _digest(body)}
            if connection is not None:
                connection.execute("INSERT INTO events VALUES (?, ?, ?)", (body["seq"], _encoded(body), entry["hash"]))
                self._commit()
            else:
                self._memory.append(entry)
                self.engagement_id = token.engagement_id
            return entry
        except (sqlite3.Error, AuditIntegrityError):
            self._failed = True
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise AuditUnavailable("audit_write_failed_execution_suspended") from None

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None,
                 traceback: TracebackType | None) -> None:
        self.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Verificar estructura de una bitácora sin modificarla")
    parser.add_argument("operation", choices=["verify"])
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_file(args.file), ensure_ascii=True, indent=2))
    except AuditIntegrityError:
        print("audit_integrity_error")
        return 1
    except (AuditUnavailable, OSError):
        print("audit_file_unavailable")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
