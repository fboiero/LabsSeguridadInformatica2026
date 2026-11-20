"""Importa evidencia defensiva sin enviar contenido del código al modelo."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

_LEVELS = {"LOW", "MEDIUM", "HIGH", "UNDEFINED"}
_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNDEFINED": 3}
_MAX_BYTES = 2_000_000
_MAX_ALERTS = 20


class BanditInputError(ValueError):
    pass


@dataclass(frozen=True)
class BanditEvidence:
    alerts: list[dict[str, str]]
    total_alerts: int
    source_sha256: str


def load_report(path: Path) -> BanditEvidence:
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise BanditInputError("bandit_report_too_large")
        data = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise BanditInputError("bandit_report_unreadable") from None
    if not isinstance(data, dict) or data.get("errors") != []:
        raise BanditInputError("bandit_scan_incomplete_or_invalid")
    rows = data.get("results")
    if not isinstance(rows, list):
        raise BanditInputError("bandit_results_invalid")
    alerts = []
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise BanditInputError("bandit_alert_invalid")
        rule = row.get("test_id")
        severity, confidence = row.get("issue_severity"), row.get("issue_confidence")
        if (
            not isinstance(rule, str) or not re.fullmatch(r"B[0-9]{3}", rule)
            or not isinstance(severity, str) or severity not in _LEVELS
            or not isinstance(confidence, str) or confidence not in _LEVELS
        ):
            raise BanditInputError("bandit_alert_invalid")
        alerts.append({"id": f"bandit-{number}", "rule": rule,
                       "severity": severity, "confidence": confidence})
    alerts.sort(key=lambda row: (_ORDER[row["severity"]], _ORDER[row["confidence"]]))
    return BanditEvidence(alerts[:_MAX_ALERTS], len(alerts), hashlib.sha256(raw).hexdigest())
