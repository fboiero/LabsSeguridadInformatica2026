"""Read-only checks for the Juice Shop availability review receipt."""
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_BYTES = 32768


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def check_receipt(raw: bytes) -> dict[str, str]:
    require(len(raw) <= MAX_BYTES, "receipt_too_large")
    case = json.loads(raw)
    require(isinstance(case, dict) and "synthetic" not in case, "unsupported_receipt")
    require(case["container_removed"] is True and bool(re.fullmatch(r"sha256:[a-f0-9]{64}", case["image"])),
            "invalid_container_record")
    asset = {"address": "juice-shop.lab.test", "port": 3000, "status": 200, "source": "docker-loopback-health"}
    ref = digest({"juice-shop.lab.test:3000": asset})
    trace = [{"round": n, "changed": n == 1, "graph_digest": ref} for n in (1, 2)]
    require(case["a"] == {"state": "RECON_COMPLETE", "stop_reason": "graph_stabilized", "rounds": 2,
                         "assets": [asset], "out_of_scope": [], "trace": trace}, "invalid_recon_trace")
    analysis = {"status": "inconclusive", "stop_reason": "no_progress", "trace": [
        {"round": 1, "new": [ref], "count": 1}, {"round": 2, "new": [], "count": 1}]}
    require(case["b"] == analysis, "invalid_analysis_handoff")
    gate = {"state": "PENDING_HITL", "started": False}
    require(case["c"] == {"stop_reason": "agent_escalated", **gate}, "invalid_review_gate")

    report = case["report"]
    require(report["engagement"] == "juice-shop-defensive-abc" == case["audit"]["engagement"]
            and report["publication"] == "PENDING_HITL" and report["findings"] == [], "invalid_report_state")
    evidence = {digest({"assets": [asset], "trace": trace, "posture": posture,
                        "analysis": analysis, "review_gate": gate}) for posture in ("true|none|{}", "true|none|null")}
    refs = report["evidence_sha256"]
    require(set(refs) == {ref} and refs[ref] in evidence, "invalid_report_evidence")
    report_hash = digest({k: v for k, v in report.items() if k != "report_sha256"})
    require(report["report_sha256"] == report_hash, "invalid_report_digest")
    return {"receipt_sha256": hashlib.sha256(raw).hexdigest(), "report_sha256": report_hash, "graph_sha256": ref}


def main() -> int:
    try:
        require({p.name for p in Path("/sys/class/net").iterdir()} == {"lo"}, "not_isolated")
        checked = check_receipt(sys.stdin.buffer.read(MAX_BYTES + 1))
        require(checked["receipt_sha256"] == sys.argv[1], "receipt_hash_mismatch")
    except (IndexError, KeyError, OSError, TypeError, ValueError, RecursionError):
        print("receipt_check_failed", file=sys.stderr)
        return 1
    print(json.dumps({"state": "DOCUMENT_CHECKED", "network_isolated": True, **checked}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
