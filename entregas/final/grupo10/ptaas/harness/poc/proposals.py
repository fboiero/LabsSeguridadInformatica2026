"""Propuestas de comprobaciones todavía deshabilitadas y pendientes de revisión docente."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_PATH = Path(__file__).with_name("proposals.yaml")


def load_proposals(path: Path = _PATH) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("status") != "pending_teacher_review":
        raise ValueError("proposal_catalog_status")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise TypeError("proposal_catalog_entries")
    for entry in entries:
        if entry.get("enabled") is not True or entry.get("executable") is not False or entry.get("review_required") is not True:
            raise ValueError("proposal_must_be_visible_but_not_executable")
    return entries
