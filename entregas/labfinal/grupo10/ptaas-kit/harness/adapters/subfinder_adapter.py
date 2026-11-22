"""Adaptador subfinder.enum: relevamiento pasivo de subdominios con salida JSONL validada."""
from __future__ import annotations

import json
import subprocess
from typing import Any

from harness.adapters.common import (
    AdapterOutputError,
    Runner,
    ToolExecutionError,
    default_runner,
    validate_target,
)
from harness.contracts import Action, Phase, ScopeToken


def build_argv(domain: str) -> list[str]:
    """Construye argv fijo y validado para subfinder (sin shell=True)."""
    target = validate_target(domain)
    return ["subfinder", "-d", target, "-silent", "-oJ"]


class SubfinderEnum:
    name = "subfinder.enum"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner = default_runner, timeout_s: int = 120):
        self._runner = runner
        self._timeout_s = timeout_s

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        argv = build_argv(target)
        try:
            raw = self._runner(argv, self._timeout_s)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            raise ToolExecutionError(f"error ejecutando subfinder: {type(exc).__name__}") from exc

        hosts: set[str] = set()
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise AdapterOutputError("salida JSONL inválida en subfinder.enum") from exc
            if not isinstance(record, dict) or not isinstance(record.get("host"), str):
                raise AdapterOutputError("registro sin campo 'host' en subfinder.enum")
            normalized = validate_target(record["host"].rstrip("."))
            hosts.add(normalized)

        return {
            "tool": "subfinder",
            "target": validate_target(target),
            "format": "jsonl",
            "hosts": sorted(hosts),
        }
