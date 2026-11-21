"""Lectura exclusivamente local de snapshots NVD normalizados (Change 005).

No descarga feeds, ni escanea activos, ni convierte registros sin prueba en hallazgos.
Los snapshots se normalizan offline antes de entregarlos a este lector.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED = {"schema_version", "source", "retrieved_at", "snapshot_date", "sha256", "record_count", "records"}


class SnapshotError(ValueError):
    """El archivo de snapshot tiene datos, procedencia o integridad inválidos."""


@dataclass(frozen=True)
class NVDSnapshot:
    source: str
    retrieved_at: datetime
    snapshot_date: date
    sha256: str
    status: str  # current | stale | missing
    records: dict[str, dict[str, Any]]

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        """Devuelve una copia de los datos registrados o None; nunca infiere CVE."""
        record = self.records.get(cve_id)
        return dict(record) if record is not None else None


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise SnapshotError("retrieved_at inválido")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SnapshotError("retrieved_at inválido") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SnapshotError("retrieved_at requiere zona horaria")
    return parsed.astimezone(UTC)


def load_nvd_snapshot(
    path: str | Path,
    *,
    now: datetime | None = None,
    max_age_days: int = 30,
) -> NVDSnapshot:
    """Valida un snapshot JSON normalizado local; no hace llamadas a la red.

    `sha256` es el hash de la lista `records` serializada con sort_keys=True,
    separators=(',', ':'), ensure_ascii=False. Es un control de integridad contra
    alteraciones accidentales, no una firma de autenticidad de la fuente.
    """
    if type(max_age_days) is not int or max_age_days < 0:
        raise ValueError("max_age_days debe ser un entero no negativo")
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ValueError("now debe tener zona horaria")
    clock = clock.astimezone(UTC)

    file_path = Path(path)
    try:
        content = file_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SnapshotError("snapshot missing: archivo NVD ausente") from exc
    except (OSError, UnicodeError) as exc:
        raise SnapshotError("no se pudo leer snapshot NVD") from exc
    try:
        payload = json.loads(content)
    except (ValueError, TypeError) as exc:
        raise SnapshotError("JSON del snapshot inválido") from exc
    if not isinstance(payload, dict) or set(payload) != _REQUIRED:
        raise SnapshotError("esquema de snapshot inválido")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise SnapshotError("schema_version incompatible")
    if not isinstance(payload["source"], str) or not payload["source"].strip():
        raise SnapshotError("source inválido")
    retrieved = _parse_utc(payload["retrieved_at"])

    if not isinstance(payload["snapshot_date"], str):
        raise SnapshotError("snapshot_date inválido: se esperaba texto")

    try:
        snapshot_date = date.fromisoformat(payload["snapshot_date"])
    except ValueError as exc:
        raise SnapshotError("snapshot_date inválido") from exc
    if snapshot_date > clock.date() or retrieved > clock:
        raise SnapshotError("fecha del snapshot en el futuro")
    records = payload["records"]
    if not isinstance(records, list):
        raise SnapshotError("records debe ser una lista")
    if type(payload["record_count"]) is not int or payload["record_count"] != len(records):
        raise SnapshotError("record_count no coincide")
    hash_value = payload["sha256"]
    if not isinstance(hash_value, str) or not _SHA256.fullmatch(hash_value):
        raise SnapshotError("sha256 inválido")
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if actual != hash_value:
        raise SnapshotError("fallo de integridad: hash sha256 no coincide")
    index: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("cve_id"), str):
            raise SnapshotError("registro NVD sin cve_id")
        cve_id = record["cve_id"]
        if not _CVE.fullmatch(cve_id) or cve_id in index:
            raise SnapshotError("cve_id inválido o duplicado")
        if not isinstance(record.get("product"), str) or not record["product"].strip():
            raise SnapshotError("producto no válido")
        if not isinstance(record.get("version"), str) or not record["version"].strip():
            raise SnapshotError("versión no válida")
        cwe = record.get("cwe", "unknown")
        if not isinstance(cwe, str) or not cwe.strip():
            raise SnapshotError("cwe inválido")
        score = record.get("cvss_v4_score")
        if score is not None and (type(score) not in (int, float) or not 0 <= score <= 10):
            raise SnapshotError("CVSS v4 inválido")
        index[cve_id] = dict(record)
    age = (clock.date() - snapshot_date).days
    return NVDSnapshot(
        source=payload["source"],
        retrieved_at=retrieved,
        snapshot_date=snapshot_date,
        sha256=hash_value,
        status="stale" if age > max_age_days else "current",
        records=index,
    )
