"""Recolector local de metadatos; no contacta al laboratorio ni acredita hitos."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_LIMIT = 4096
_MILESTONES = ("R1", "R2", "R3", "R4")
_FIELDS = {"version", "lab", "milestone", "source", "captured_at"}
_SOURCES = ("lab_export_metadata", "operator_review_note", "synthetic_fixture")


class IntakeError(ValueError):
    """Entrada fuera del contrato del recolector."""


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _stage(path: Path) -> Path:
    root = path.absolute()
    if ".." in root.parts or root.drive.startswith("\\\\"):
        raise IntakeError("local_staging_required")
    for item in (*reversed(root.parents), root):
        info = item.lstat()
        if _linked(info) or not stat.S_ISDIR(info.st_mode):
            raise IntakeError("staging_must_be_plain_directory")
    return root


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError("duplicate_field")
        result[key] = value
    return result


def _read_metadata(path: Path, before: os.stat_result, milestone: str) -> dict[str, str]:
    if _linked(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _LIMIT:
        raise IntakeError("unsafe_artifact")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not os.path.samestat(before, opened) or opened.st_nlink != 1:
            raise IntakeError("artifact_changed")
        raw = stream.read(_LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > _LIMIT or after.st_size != len(raw) or after.st_mtime_ns != before.st_mtime_ns:
        raise IntakeError("artifact_changed_or_large")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    if (not isinstance(data, dict) or not _FIELDS <= data.keys() <= _FIELDS | {"original_sha256"}
            or type(data["version"]) is not int or data["version"] != 1):
        raise IntakeError("metadata_schema")
    source, captured = data["source"], data["captured_at"]
    if data["lab"] != "phantomcorp" or data["milestone"] != milestone or source not in _SOURCES:
        raise IntakeError("metadata_scope")
    if not isinstance(captured, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", captured):
        raise IntakeError("metadata_timestamp")
    datetime.strptime(captured, "%Y-%m-%dT%H:%M:%SZ")
    original = data.get("original_sha256")
    metadata = {"source": source, "captured_at": captured, "sha256": hashlib.sha256(raw).hexdigest()}
    if "original_sha256" in data:
        if not isinstance(original, str) or not re.fullmatch(r"[a-f0-9]{64}", original):
            raise IntakeError("metadata_original_digest")
        metadata["declared_original_sha256"] = original
    elif source == "lab_export_metadata":
        raise IntakeError("metadata_original_digest_required")
    return metadata


def collect(staging: Path) -> dict[str, Any]:
    root = _stage(staging)
    rows: list[dict[str, Any]] = []
    for milestone in _MILESTONES:
        path = root / f"{milestone.lower()}.json"
        row: dict[str, Any] = {"milestone": milestone, "expected_file": path.name, "credited": False}
        try:
            before = path.lstat()
        except FileNotFoundError:
            row["status"] = "missing"
        except OSError:
            row["status"] = "rejected"
        else:
            try:
                row.update(_read_metadata(path, before, milestone))
            except (ValueError, OSError, RecursionError):
                row["status"] = "rejected"
            else:
                row["status"] = "artifact_received"
        rows.append(row)
    return {"version": 1, "lab": "phantomcorp", "state": "PENDING_HITL",
            "collected_at": datetime.now(UTC).isoformat(timespec="seconds"), "milestones": rows,
            "limitations": ["El hash identifica metadatos importados, no autentica su origen ni acredita el hito.",
                            "Se requiere revisar la evidencia original por separado."]}


def write_draft(staging: Path, output: Path) -> dict[str, Any]:
    root = _stage(staging)
    if output.resolve().is_relative_to(root):
        raise IntakeError("output_must_be_outside_staging")
    result = collect(root)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-dir", required=True, type=Path, help="Carpeta local aprobada por el operador")
    parser.add_argument("--output", required=True, type=Path, help="Archivo nuevo, fuera de la carpeta aprobada")
    args = parser.parse_args()
    try:
        result = write_draft(args.approved_dir, args.output)
    except (IntakeError, OSError, RuntimeError) as error:
        print(f"intake_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    print(" | ".join(f"{row['milestone']}: {row['status']}" for row in result["milestones"]))
    return 3 if any(row["status"] == "rejected" for row in result["milestones"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
