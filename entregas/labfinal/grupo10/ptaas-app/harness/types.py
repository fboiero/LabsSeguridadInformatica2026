"""Contratos conservados del kit docente, commit a1abb79 (harness/contracts.py)."""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class Phase(str, Enum):
    RECON = "recon"
    CORRELATE = "correlate"
    ANALYZE = "analyze"
    VALIDATE = "validate"
    REPORT = "report"


class Result(str, Enum):
    OK = "OK"
    BLOCKED = "BLOCKED"
    PENDING_HITL = "PENDING_HITL"
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class ScopeToken:
    engagement_id: str
    allowed_cidrs: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    window_start: float
    window_end: float
    phase: Phase

    def is_live(self, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        return self.window_start <= current < self.window_end


@dataclass(frozen=True)
class Action:
    name: str
    phase: Phase
    destructive: bool = False
    requires_human_approval: bool = False
    parameters: dict[str, str] | None = None


class ToolAdapter(Protocol):
    name: str
    allowed_phases: tuple[Phase, ...]
    destructive: bool

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]: ...
