"""Adaptadores de solo lectura para snapshots locales NVD, EPSS y CWE."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, cast

from harness.adapters.common import load_profiles
from harness.contracts import Action, Phase, ScopeToken

_ROOT = Path(__file__).resolve().parents[2]


class SnapshotStaleError(ValueError):
    """El snapshot es demasiado viejo para correlacionar con confianza."""


@dataclass(frozen=True)
class LookupAction(Action):
    query: str = ""
    context: tuple[str, ...] = ()


def _snapshot(name: str, snapshot_dir: Path | None = None) -> dict[str, Any]:
    path = (snapshot_dir or (_ROOT / "harness" / "data")) / name
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not data.get("as_of") or not data.get("source_url"):
        raise ValueError(f"snapshot {name} incompleto o no soportado")
    age_days = (date.today() - date.fromisoformat(data["as_of"])).days
    max_age = load_profiles()["snapshots"]["max_age_days"]
    if age_days < 0 or age_days > max_age:
        raise SnapshotStaleError(f"snapshot {name} fuera de ventana de {max_age} días")
    return cast(dict[str, Any], data)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


class CveLookup:
    name = "cve.lookup"
    allowed_phases = (Phase.CORRELATE,)
    destructive = False

    def __init__(self, snapshot_dir: Path | None = None):
        self._snapshot_dir = snapshot_dir

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        query = getattr(action, "query", "")
        data = _snapshot("nvd-snapshot.json", self._snapshot_dir)
        match = next((row for row in data["records"]
                      if _normalize(query) in {_normalize(alias) for alias in row["aliases"]}), None)
        return {"record": match, "snapshot": {"as_of": data["as_of"],
                                                 "source_url": data["source_url"]},
                "status": "ok" if match else "unknown"}


class EpssLookup:
    name = "epss.lookup"
    allowed_phases = (Phase.CORRELATE,)
    destructive = False

    def __init__(self, snapshot_dir: Path | None = None):
        self._snapshot_dir = snapshot_dir

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        cve = getattr(action, "query", "")
        data = _snapshot("epss-snapshot.json", self._snapshot_dir)
        match = next((row for row in data["records"] if row["cve"] == cve), None)
        return {"score": match["score"] if match else None,
                "percentile": match["percentile"] if match else None,
                "record": match, "snapshot": {"as_of": data["as_of"],
                                                 "source_url": data["source_url"]}}


class CweMapLookup:
    name = "cwe.map"
    allowed_phases = (Phase.CORRELATE,)
    destructive = False

    def __init__(self, snapshot_dir: Path | None = None):
        self._snapshot_dir = snapshot_dir

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        query = getattr(action, "query", "")
        cwe = query if query.startswith("CWE-") else "CWE-" + query
        data = _snapshot("cwe-map.json", self._snapshot_dir)
        row = next((item for item in data["records"] if item["cwe"] == cwe), None)
        context = set(getattr(action, "context", ()))
        technique = None
        if row and row.get("attack_technique") and set(row.get("requires_context", [])) <= context:
            technique = row["attack_technique"]
        return {"cwe": row["cwe"] if row else "unknown",
                "label": row["label"] if row else None,
                "attack_technique": technique,
                "snapshot": {"as_of": data["as_of"], "source_url": data["source_url"]}}
