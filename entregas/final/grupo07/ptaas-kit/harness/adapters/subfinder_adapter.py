"""Enumeración pasiva de dominios vía subfinder; salida JSONL validada."""
from __future__ import annotations

import json
from typing import Any

from harness.adapters.common import Runner, default_runner, load_profiles, validate_target
from harness.contracts import Action, Phase, ScopeToken


def build_argv(domain: str, profile: dict[str, Any] | None = None) -> list[str]:
    p = profile or load_profiles()["subfinder"]
    target = validate_target(domain)
    return [p["binary"], *p["fixed_args"], "-rl", str(p["rate_limit_rps"]),
            "-timeout", str(p["timeout_s"]), "-max-time", str(p["max_time_minutes"]),
            "-d", target]


def parse_jsonl(raw: str) -> list[str]:
    hosts: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            host = validate_target(str(item["host"]))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"JSONL de subfinder inválido en línea {line_number}") from exc
        if ":" in host or "/" in host:
            raise ValueError(f"hostname de subfinder inválido en línea {line_number}")
        hosts.add(host)
    return sorted(hosts)


class SubfinderEnum:
    name = "subfinder.enum"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner = default_runner,
                 profile: dict[str, Any] | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["subfinder"]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        raw = self._runner(build_argv(target, self._profile), self._profile["timeout_s"])
        return {"tool": "subfinder", "hosts": parse_jsonl(raw), "format": "jsonl"}
