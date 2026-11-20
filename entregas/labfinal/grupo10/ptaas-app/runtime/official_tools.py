"""Adaptadores Docker para binarios oficiales, siempre detrás de Harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from harness.audit import AuditLog
from harness.contracts import Guard, Harness, KillSwitch
from harness.types import Action, Phase, ScopeToken, ToolAdapter

TARGET = "juice-shop.lab.test"
URL = "http://juice-shop.lab.test:3000"
IMAGES = {
    "subfinder.passive": "projectdiscovery/subfinder@sha256:2f5ddea311db2a8b848e40f1b669fc655d0eb78b74a74ead93d3850e372b12bf",
    "httpx.probe.official": "projectdiscovery/httpx@sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc",
    "nuclei.safe_templates": "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
    "zap.baseline_scan": "zaproxy/zap-stable@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af",
}


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout_sha256: str
    stdout_lines: int
    stderr_sha256: str


class OfficialDockerAdapter:
    destructive = False
    allowed_phases = (Phase.RECON, Phase.ANALYZE)

    def __init__(self, name: str, network: str, image: str) -> None:
        self.name, self.network, self.image = name, network, image

    def _argv(self, target: str) -> list[str]:
        if target != TARGET:
            raise ValueError("official_tool_target_not_allowed")
        user = "1000:1000" if self.name == "zap.baseline_scan" else "65534:65534"
        tmpfs = "/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000" if self.name == "zap.baseline_scan" else "/tmp:rw,noexec,nosuid,size=64m"
        prefix = ["docker", "run", "--rm", "--pull", "never", "--network", self.network,
                  "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "--user", user, "--pids-limit", "64", "--memory", "512m",
                  "--tmpfs", tmpfs, "--env", "HOME=/tmp"]
        if self.name == "zap.baseline_scan":
            prefix += ["--tmpfs", "/home/zap:rw,noexec,nosuid,size=32m,uid=1000,gid=1000",
                       "--tmpfs", "/zap/wrk:rw,noexec,nosuid,size=64m,uid=1000,gid=1000"]
        if self.name == "nuclei.safe_templates":
            templates = Path(__file__).resolve().parent.parent / "templates" / "nuclei"
            prefix += ["--mount", f"type=bind,source={templates},target=/opt/ptaas-templates,readonly"]
        prefix.append(self.image)
        commands = {
            "subfinder.passive": ["-d", TARGET, "-silent"],
            "httpx.probe.official": ["-u", URL, "-json", "-silent", "-status-code", "-title"],
            "nuclei.safe_templates": ["-u", URL, "-t", "/opt/ptaas-templates", "-jsonl", "-silent",
                                       "-no-interactsh"],
            "zap.baseline_scan": ["zap-baseline.py", "-t", URL, "-J", "/zap/wrk/zap.json", "-I"],
        }
        return prefix + commands[self.name]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if action.name != self.name or token.phase not in self.allowed_phases:
            raise ValueError("official_tool_action_mismatch")
        command = self._argv(target)
        phase_timeout = 180 if self.name in {"zap.baseline_scan", "nuclei.safe_templates"} else 60
        completed = subprocess.run(command, capture_output=True, text=True, timeout=phase_timeout, check=False)
        output = completed.stdout[-65536:]
        error_output = completed.stderr[-65536:]
        error_excerpt = " ".join(error_output.split())[:256]
        result = DockerResult(completed.returncode, hashlib.sha256(output.encode()).hexdigest(),
                              len(output.splitlines()), hashlib.sha256(error_output.encode()).hexdigest())
        result_payload = {"tool": self.name, "image": self.image, "returncode": result.returncode,
                          "stdout_sha256": result.stdout_sha256, "stdout_lines": result.stdout_lines,
                          "stderr_sha256": result.stderr_sha256, "stderr_excerpt": error_excerpt,
                          "target": TARGET, "raw_output_persisted": False}
        return result_payload


def run_official_scans(network: str, audit_path: str | None = None) -> dict[str, Any]:
    now = time.time()
    outputs: list[dict[str, Any]] = []
    audit = AuditLog(audit_path, "juice-shop-integrated") if audit_path else AuditLog()
    tools = (("subfinder.passive", Phase.RECON), ("httpx.probe.official", Phase.RECON),
             ("nuclei.safe_templates", Phase.ANALYZE), ("zap.baseline_scan", Phase.ANALYZE))
    for name, phase in tools:
        engagement = audit.engagement_id or "juice-shop-official-scans"
        token = ScopeToken(engagement, (), (TARGET,), now - 1, now + 900, phase)
        adapter = OfficialDockerAdapter(name, network, IMAGES[name])
        harness = Harness(Guard({phase: {name}}), audit,
                          {name: cast(ToolAdapter, adapter)}, KillSwitch())
        action = Action(name, phase, parameters={"target": TARGET})
        outputs.append(harness.invoke("security_scanner", action, TARGET, token))
    state = "SCANS_COMPLETE" if all(item["returncode"] == 0 for item in outputs) else "SCANS_COMPLETE_WITH_ERRORS"
    summary = audit.verify()
    audit.close()
    return {"state": state, "target": TARGET, "network": "internal_only",
            "tools": outputs, "audit": summary}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run_official_scans(args.network), ensure_ascii=True))
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(json.dumps({"state": "FAILED", "reason": type(error).__name__}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
