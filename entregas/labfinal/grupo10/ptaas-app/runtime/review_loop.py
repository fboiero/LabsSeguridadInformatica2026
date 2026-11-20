"""Bounded evidence review. No access to targets, scanners, or PoCs."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

from .providers import ModelProvider, OpenCodeProvider, ProviderError

CASES = {lab: {"inventory": "deployment_descriptor_fixture", "runtime": "no_runtime_attestation",
               "policy": "published_port_review_required"} for lab in ("dvwa", "juice-shop")}
_IMAGE = "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
_CHECK = "document_consistency_v1"
_WORKER = '''
import json, os, sys
interfaces = os.listdir('/sys/class/net')
routes = open('/proc/net/route', encoding='ascii').read().splitlines()[1:]
data = json.loads(sys.stdin.read(32768))
isolated = set(interfaces) == {'lo'} and not any(line.split()[0] != 'lo' for line in routes if line.strip())
checked = (data['check'] == 'document_consistency_v1' and data['synthetic'] is True
           and data['seen'].get('inventory') == 'deployment_descriptor_fixture'
           and data['state'] == 'PENDING_HITL')
print(json.dumps({'network_isolated': isolated, 'checked': checked}))
raise SystemExit(0 if isolated and checked else 2)
'''


class ReviewError(ValueError):
    pass


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(data: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical({key: value for key, value in data.items() if key != "approval_sha256"})).hexdigest()


def review(lab: str, provider: ModelProvider | None = None, *, max_rounds: int = 3) -> dict[str, Any]:
    if lab not in CASES or not 1 <= max_rounds <= 3:
        raise ReviewError("invalid_review_scope")
    cards = CASES[lab]
    seen = {"inventory": cards["inventory"]}
    trace = []
    reason = "budget_exhausted"
    for _ in range(max_rounds):
        try:
            if provider is None:
                decision: Any = {"action": "request", "ref": "runtime"} if "runtime" not in seen else {
                    "action": "escalate", "ref": None}
            else:
                decision = json.loads(provider.generate(json.dumps({"agent": "quality_sol", "laboratory": lab,
                    "seen": seen, "available": list(cards), "instructions": (
                        'Review synthetic deployment metadata. Return only {"action":"request", "ref":"runtime"} '
                        'with a useful unread reference, or {"action":"finish"|"escalate", "ref":null}. '
                        'Escalate if actual runtime evidence is needed. Do not infer a vulnerability.')})))
            if not isinstance(decision, dict) or set(decision) != {"action", "ref"}:
                raise ReviewError("invalid_decision")
            action, ref = decision["action"], decision["ref"]
            if not ((action == "request" and isinstance(ref, str) and ref in cards)
                    or (action in ("finish", "escalate") and ref is None)):
                raise ReviewError("invalid_decision")
        except ProviderError:
            reason = "provider_error"
            break
        except (ValueError, RecursionError):
            reason = "invalid_decision"
            break
        trace.append(decision)
        if action != "request":
            reason = "agent_finished" if action == "finish" else "agent_escalated"
            break
        if not isinstance(ref, str):
            reason = "invalid_decision"
            break
        if ref in seen:
            reason = "no_progress"
            break
        seen[ref] = cards[ref]
    result = {"state": "PENDING_HITL", "review_id": uuid4().hex, "laboratory": lab, "synthetic": True,
              "check": _CHECK, "seen": seen, "trace": trace, "stop_reason": reason, "max_rounds": max_rounds,
              "provider": provider.name if provider else "fixture", "confirmed_findings": []}
    result["approval_sha256"] = _digest(result)
    return result


def sandbox(result: dict[str, Any], approval: str | None) -> dict[str, Any]:
    if approval is None:
        return {"state": "PENDING_HITL", "started": False}
    if approval != result.get("approval_sha256") or approval != _digest(result) or result.get("check") != _CHECK:
        raise ReviewError("case_or_approval_mismatch")
    lab, seen = result.get("laboratory"), result.get("seen")
    if (not isinstance(lab, str) or lab not in CASES or not isinstance(seen, dict)
            or not 1 <= len(seen) <= 3 or any(CASES[lab].get(key) != value for key, value in seen.items())
            or seen.get("inventory") != CASES[lab]["inventory"] or result.get("confirmed_findings") != []
            or result.get("state") != "PENDING_HITL" or result.get("synthetic") is not True):
        raise ReviewError("document_not_reviewable")
    payload = {"check": _CHECK, "seen": seen, "state": "PENDING_HITL", "synthetic": True}
    name = "ptaas-review-" + uuid4().hex
    args = ["docker", "run", "--rm", "--pull", "never", "--name", name, "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534", "--pids-limit", "32",
            "--memory", "128m", "-i", _IMAGE, "python", "-I", "-B", "-c", _WORKER]
    try:
        worker = subprocess.run(args, input=_canonical(payload).decode(), text=True, capture_output=True, timeout=25, check=False)
    finally:
        listing = subprocess.run(["docker", "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"],
                                 text=True, capture_output=True, timeout=10, check=False)
        if listing.returncode != 0 or listing.stdout.strip():
            raise ReviewError("sandbox_removal_unverified")
    if worker.returncode or json.loads(worker.stdout) != {"network_isolated": True, "checked": True}:
        raise ReviewError("sandbox_check_failed")
    return {"state": "DOCUMENT_CHECKED", "check": _CHECK, "approval_sha256": approval,
            "network_isolated": True, "container_removed": True, "container": name, "confirmed_findings": []}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    loop = commands.add_parser("review")
    loop.add_argument("--lab", choices=CASES, required=True)
    loop.add_argument("--live", action="store_true")
    loop.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("validate")
    check.add_argument("case", type=Path)
    check.add_argument("--approve-sha256")
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ReviewError("output_exists")
        if args.command == "review":
            result = review(args.lab, OpenCodeProvider() if args.live else None)
        else:
            with args.case.open("rb") as stream:
                raw = stream.read(16385)
            if len(raw) > 16384 or not isinstance(data := json.loads(raw), dict):
                raise ReviewError("invalid_case")
            result = sandbox(data, args.approve_sha256)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
        print(result["state"])
    except (OSError, ValueError, RecursionError, ProviderError, subprocess.SubprocessError) as error:
        print(f"review_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
