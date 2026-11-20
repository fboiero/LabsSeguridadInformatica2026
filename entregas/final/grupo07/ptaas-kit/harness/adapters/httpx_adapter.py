"""Probe HTTP liviano de un hostname; argv y JSONL quedan acotados."""
from __future__ import annotations

import json
from typing import Any

from harness.adapters.common import Runner, default_runner, load_profiles, validate_target
from harness.contracts import Action, Phase, ScopeToken


def build_argv(target: str, profile: dict[str, Any] | None = None) -> list[str]:
    p = profile or load_profiles()["httpx"]
    host = validate_target(target)
    return [p["binary"], "-u", host, *p["fixed_args"], "-rl", str(p["rate_limit_rps"]),
            "-timeout", str(p["timeout_s"]), "-retries", "0"]


def parse_jsonl(raw: str, expected_host: str) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            host = validate_target(str(item.get("host") or item.get("input") or ""))
            if host != expected_host:
                continue
            tech = item.get("tech") or item.get("technologies") or []
            if not isinstance(tech, list) or any(not isinstance(value, str) for value in tech):
                raise ValueError("tech debe ser una lista de textos")
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"JSONL de httpx inválido en línea {line_number}") from exc
        assets.append({
            "host": host,
            "status_code": item.get("status_code"),
            "title": item.get("title"),
            "technologies": sorted(set(tech)),
        })
    return assets


class HttpxProbe:
    name = "httpx.probe"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner = default_runner,
                 profile: dict[str, Any] | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["httpx"]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        host = validate_target(target)
        raw = self._runner(build_argv(host, self._profile), self._profile["timeout_s"])
        return {"tool": "httpx", "target": host,
                "assets": parse_jsonl(raw, host), "format": "jsonl"}
