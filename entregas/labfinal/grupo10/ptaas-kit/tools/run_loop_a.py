#!/usr/bin/env python3
"""Ejecuta el Loop A (relevamiento) contra fixtures grabadas o contra `lab/`.

Uso:
    python tools/run_loop_a.py --mode fixture --output ../evidencia/ptaas
    python tools/run_loop_a.py --mode lab --output ../evidencia/ptaas
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.adapters.common import RateLimiter, default_runner
from harness.adapters.httpx_adapter import HttpxProbe, stdlib_http_runner
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.engagement import Engagement
from harness.loop_a import AssetGraph, run_loop_a
from harness.policy_loader import load_policy, phase_allowlist

LAB_DOMAINS = ("dvwa.lab.test", "juiceshop.lab.test")
LAB_PORTS = {"dvwa.lab.test": "http://dvwa.lab.test", "juiceshop.lab.test": "http://juiceshop.lab.test:3000"}


def _build_fixture_runners() -> tuple[SubfinderEnum, HttpxProbe]:
    sub_lines = (ROOT / "fixtures" / "recon" / "subfinder.jsonl").read_text(encoding="utf-8").splitlines()
    httpx_lines = [
        json.loads(ln)
        for ln in (ROOT / "fixtures" / "recon" / "httpx.jsonl").read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    by_host = {rec["host"]: json.dumps(rec) for rec in httpx_lines}

    def sub_runner(argv: list[str], timeout_s: int) -> str:
        domain = argv[argv.index("-d") + 1]
        matched = [ln for ln in sub_lines if ln.strip() and json.loads(ln).get("input") == domain]
        return "\n".join(matched)

    def http_runner(argv: list[str], timeout_s: int) -> str:
        url = argv[argv.index("-u") + 1]
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return by_host.get(host, json.dumps({"url": url, "host": host, "status_code": 404, "tech": []}))

    return SubfinderEnum(runner=sub_runner), HttpxProbe(runner=http_runner, rate_limiter=RateLimiter(rps=5))


def _build_lab_runners() -> tuple[SubfinderEnum, HttpxProbe]:
    def sub_runner(argv: list[str], timeout_s: int) -> str:
        if shutil.which("subfinder"):
            return default_runner(argv, timeout_s)
        domain = argv[argv.index("-d") + 1]
        return json.dumps({"host": domain, "input": domain, "source": "lab-seed"})

    def http_runner(argv: list[str], timeout_s: int) -> str:
        url = argv[argv.index("-u") + 1]
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        mapped_url = LAB_PORTS.get(host, url)
        patched_argv = [mapped_url if item == url else item for item in argv]
        if shutil.which("httpx"):
            return default_runner(patched_argv, timeout_s)
        return stdlib_http_runner(patched_argv, timeout_s)

    return SubfinderEnum(runner=sub_runner), HttpxProbe(runner=http_runner, rate_limiter=RateLimiter(rps=5))


def execute(mode: str, output_dir: Path) -> dict:
    policy = load_policy()
    engagement = Engagement(roe_valid=True)
    engagement.advance()
    engagement.approve("first_active_action")
    engagement.advance()

    now = time.time()
    token = ScopeToken(
        engagement_id="eng-labfinal-grupo10",
        allowed_cidrs=("10.99.0.0/24",),
        allowed_domains=LAB_DOMAINS,
        window_start=now - 5,
        window_end=now + int(policy["phases"]["recon"]["token_ttl_minutes"]) * 60,
        phase=Phase.RECON,
    )

    sub_adapter, http_adapter = _build_fixture_runners() if mode == "fixture" else _build_lab_runners()
    audit = AuditLog()
    harness = Harness(
        guard=Guard(phase_allowlist(policy)),
        audit=audit,
        tools={"subfinder.enum": sub_adapter, "httpx.probe": http_adapter},
        killswitch=KillSwitch(),
    )

    result = run_loop_a(harness=harness, token=token, seed_domains=list(LAB_DOMAINS))
    result["mode"] = mode
    result["engagement_state"] = engagement.state.value
    graph = AssetGraph.from_dict({"assets": result["assets"], "out_of_scope": result["out_of_scope"]})

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "loop_a_result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "asset_graph.json").write_text(
        json.dumps(graph.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output_dir / "audit_log.json").write_text(
        json.dumps(audit.entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    verified = AuditLog.verify_entries(audit.entries)
    (output_dir / "audit_verify.txt").write_text(
        f"mode={mode}\nentries={len(audit.entries)}\naudit_verify={'OK' if verified else 'FAILED'}\n",
        encoding="utf-8",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["fixture", "lab"], default="fixture")
    parser.add_argument("--output", type=Path, default=ROOT.parent / "evidencia" / "ptaas")
    args = parser.parse_args()
    result = execute(args.mode, args.output)
    print(
        f"Loop A ({args.mode}): {len(result['assets'])} activos, "
        f"{len(result['out_of_scope'])} out_of_scope, "
        f"stop_reason={result['stop_reason']!r}, audit_verified={result['audit_verified']}"
    )
    return 0 if result["audit_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
