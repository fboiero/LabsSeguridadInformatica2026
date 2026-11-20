"""Correlación offline y análisis B con allowlist determinista."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CandidateFinding:
    id: str
    title: str
    cwe: str
    evidence_refs: tuple[str, ...]
    nvd: dict[str, Any] | None = None
    epss: float | None = None


class SnapshotStore:
    def __init__(self, nvd: dict[str, Any], epss: dict[str, float]) -> None:
        self.nvd, self.epss = nvd, epss

    @classmethod
    def from_files(cls, nvd_path: Path, epss_path: Path) -> SnapshotStore:
        nvd_raw = json.loads(nvd_path.read_text(encoding="utf-8"))
        epss_raw = json.loads(epss_path.read_text(encoding="utf-8"))
        nvd = nvd_raw.get("data", nvd_raw) if isinstance(nvd_raw, dict) else {}
        epss = epss_raw.get("data", epss_raw) if isinstance(epss_raw, dict) else {}
        return cls(nvd, epss)

    def lookup(self, cve: str) -> tuple[dict[str, Any] | None, float | None]:
        return self.nvd.get(cve), self.epss.get(cve)


def correlate(observations: list[dict[str, Any]], snapshots: SnapshotStore) -> list[CandidateFinding]:
    result: list[CandidateFinding] = []
    for item in observations:
        refs = tuple(item.get("evidence_refs", ()))
        if not refs or any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError("candidate_requires_evidence")
        cve = item.get("cve")
        nvd, epss = snapshots.lookup(cve) if isinstance(cve, str) else (None, None)
        result.append(CandidateFinding(item["id"], item["title"], item["cwe"], refs, nvd, epss))
    return result


ALLOWLIST = ("juice-shop-headers", "juice-shop-cookies", "juice-shop-errors",
             "juice-shop-reflection", "juice-shop-directory")


class SafeTemplateScanner:
    templates = frozenset(ALLOWLIST)

    def argv(self, template: str, target: str) -> tuple[str, ...]:
        if template not in self.templates or target != "juice-shop.lab.test":
            raise ValueError("template_or_target_not_allowed")
        return ("nuclei", "-u", "http://juice-shop.lab.test:3000", "-t", template,
                "-jsonl", "-silent")


def detection_loop(detections: list[list[dict[str, Any]]], max_rounds: int = 3) -> dict[str, Any]:
    if not 1 <= max_rounds <= 3:
        raise ValueError("invalid_analysis_budget")
    seen: set[str] = set()
    trace: list[dict[str, Any]] = []
    for index, batch in enumerate(detections[:max_rounds], 1):
        ids = {str(item["id"]) for item in batch}
        new = sorted(ids - seen)
        trace.append({"round": index, "new": new, "count": len(ids)})
        if not new and index > 1:
            return {"status": "inconclusive", "stop_reason": "no_progress", "trace": trace}
        seen.update(ids)
    return {"status": "resolved" if seen else "inconclusive",
            "stop_reason": "budget_exhausted" if len(trace) == max_rounds else "resolved",
            "trace": trace}


def valid_cwe(value: str) -> bool:
    return re.fullmatch(r"CWE-[1-9][0-9]{1,5}", value) is not None
