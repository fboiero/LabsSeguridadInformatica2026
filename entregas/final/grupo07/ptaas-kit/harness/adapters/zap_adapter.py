"""ZAP baseline con spider corto, passive scan y reporte JSON temporal."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from harness.adapters.common import (
    Runner,
    default_runner,
    load_profiles,
    validate_target,
    validate_url,
)
from harness.contracts import Action, Phase, ScopeToken


def _target_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return validate_url(target)
    return "http://" + validate_target(target)


def build_argv(target: str, profile: dict[str, Any] | None = None,
               report_path: str | None = None) -> list[str]:
    p = profile or load_profiles()["zap"]
    url = _target_url(target)
    if report_path is None:
        report_path = str(Path(p.get("report_dir", tempfile.gettempdir())) / "zap-baseline.json")
    return [p["binary"], "-t", url, *p["fixed_args"], "-J", report_path]


def _alerts(report: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            if isinstance(alert, dict):
                alerts.append(alert)
    return alerts


class ZapBaselineScan:
    name = "zap.baseline_scan"
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self, runner: Runner = default_runner,
                 profile: dict[str, Any] | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["zap"]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        report_dir = Path(self._profile.get("report_dir", tempfile.gettempdir()))
        report_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="zap-", suffix=".json", dir=report_dir,
                                         delete=False) as report:
            report_path = Path(report.name)
        try:
            argv = build_argv(target, self._profile, str(report_path))
            self._runner(argv, self._profile["timeout_s"])
            raw = report_path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise TypeError("reporte ZAP inválido")
            return {"tool": "zap", "target": target, "alerts": _alerts(parsed),
                    "format": "json"}
        finally:
            report_path.unlink(missing_ok=True)
