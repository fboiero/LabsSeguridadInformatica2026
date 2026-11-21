"""Lectura exclusivamente local de snapshots EPSS normalizados (Change 005).

No consulta Internet ni infiere probabilidades para CVE ausentes. Los archivos
se preparan fuera de este lector y deben conservar su procedencia verificable.
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
_REQUIRED = {
    "schema_version", "source", "retrieved_at", "snapshot_date",
    "sha256", "record_count", "records",
}


class EPSSSnapshotError(ValueError):
    """Snapshot EPSS ausente, ilegible, alterado o con contenido inválido."""


@dataclass(frozen=True)
class EPSSSnapshot:
    source: str
    retrieved_at: datetime
    snapshot_date: date
    sha256: str
    status: str  # current | stale
    records: dict[str, float]

    def lookup(self, cve_id: str) -> float | None:
        """Retorna el EPSS registrado o None, sin inventar un valor por defecto."""
        return self.records.get(cve_id)


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EPSSSnapshotError("retrieved_at inválido")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EPSSSnapshotError("retrieved_at inválido") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EPSSSnapshotError("retrieved_at requiere zona horaria")
    return parsed.astimezone(UTC)


def load_epss_snapshot(
    path: str | Path,
    *,
    now: datetime | None = None,
    max_age_days: int = 7,
) -> EPSSSnapshot:
    """Valida un JSON EPSS local, sin efectuar conexiones de red.

    `sha256` se calcula sobre `records` con sort_keys=True,
    separators=(',', ':'), ensure_ascii=False. Detecta cambios accidentales,
    pero no autentica por sí solo la procedencia del archivo.
    """
    if type(max_age_days) is not int or max_age_days < 0:
        raise ValueError("max_age_days debe ser un entero no negativo")
    clock = now if now is not None else datetime.now(UTC)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ValueError("now debe tener zona horaria")
    clock = clock.astimezone(UTC)

    try:
        content = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise EPSSSnapshotError("snapshot missing: archivo EPSS ausente") from exc
    except (OSError, UnicodeError) as exc:
        raise EPSSSnapshotError("no se pudo leer snapshot EPSS") from exc
    try:
        payload = json.loads(content)
    except (ValueError, TypeError) as exc:
        raise EPSSSnapshotError("JSON del snapshot inválido") from exc
    if not isinstance(payload, dict) or set(payload) != _REQUIRED:
        raise EPSSSnapshotError("esquema de snapshot inválido")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise EPSSSnapshotError("schema_version incompatible")
    if not isinstance(payload["source"], str) or not payload["source"].strip():
        raise EPSSSnapshotError("source inválido")
    retrieved = _parse_utc(payload["retrieved_at"])
    if not isinstance(payload["snapshot_date"], str):
        raise EPSSSnapshotError("snapshot_date inválido: se esperaba texto")
    try:
        snapshot_date = date.fromisoformat(payload["snapshot_date"])
    except ValueError as exc:
        raise EPSSSnapshotError("snapshot_date inválido") from exc
    if snapshot_date > clock.date() or retrieved > clock:
        raise EPSSSnapshotError("fecha del snapshot en el futuro")

    records = payload["records"]
    if not isinstance(records, list):
        raise EPSSSnapshotError("records debe ser una lista")
    if type(payload["record_count"]) is not int or payload["record_count"] != len(records):
        raise EPSSSnapshotError("record_count no coincide")
    digest = payload["sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise EPSSSnapshotError("sha256 inválido")
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if actual != digest:
        raise EPSSSnapshotError("fallo de integridad: hash sha256 no coincide")

    index: dict[str, float] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"cve_id", "epss"}:
            raise EPSSSnapshotError("estructura de registro EPSS inválida")
        cve_id, score = record["cve_id"], record["epss"]
        if not isinstance(cve_id, str) or not _CVE.fullmatch(cve_id) or cve_id in index:
            raise EPSSSnapshotError("cve_id inválido o duplicado")
        if type(score) not in (int, float) or not 0 <= score <= 1:
            raise EPSSSnapshotError("epss fuera de rango")
        index[cve_id] = float(score)

    age = (clock.date() - snapshot_date).days
    return EPSSSnapshot(
        source=payload["source"],
        retrieved_at=retrieved,
        snapshot_date=snapshot_date,
        sha256=digest,
        status="stale" if age > max_age_days else "current",
        records=index,
    )
