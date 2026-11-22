"""Presentación offline de recibos reales previos; no ejecuta herramientas de red."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .reporting import build_report, report_digest, verify_approval

_FILES = {
    "availability": "juiceshop-real-20261118-203231.json",
    "inventory": "juice-recon-real-20261118-210744.json",
    "headers": "juice-poc-real-20261118-204806-csp.json",
    "tools": "juice-official-scans-final-20261118-212810.json",
    "integrated": "juice-integrated-20261118-220113.json",
}
_FEEDS = {
    "nvd-snapshot.json": "NVD CVE API 2.0",
    "epss-snapshot.json": "FIRST EPSS API v1",
}
_SNAPSHOTS = Path(__file__).resolve().parents[1] / "data"


def snapshot_summary(directory: Path) -> dict[str, Any]:
    result = {}
    for name, source in _FEEDS.items():
        with (directory / name).open("rb") as stream:
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("snapshot_too_large")
        snapshot = json.loads(raw)
        data, metadata = snapshot["data"], snapshot["metadata"]
        if not isinstance(data, dict) or not data or metadata["source"] != source:
            raise ValueError("invalid_snapshot")
        encoded = json.dumps(data, sort_keys=True, indent=2, allow_nan=False).encode()
        if hashlib.sha256(encoded).hexdigest() != metadata["sha256"]:
            raise ValueError("snapshot_digest_mismatch")
        result[name] = {"source": source, "records": len(data), "sha256": hashlib.sha256(raw).hexdigest()}
    return result


def build(runs: Path, snapshots: Path = _SNAPSHOTS) -> dict[str, Any]:
    receipts = {}
    evidence = {}
    for kind, name in _FILES.items():
        with (runs / name).open("rb") as stream:
            raw = stream.read(65_537)
        if len(raw) > 65_536:
            raise ValueError("receipt_too_large")
        data = json.loads(raw)
        if not isinstance(data, dict) or not all(data.get(k) is True for k in (
            "target_removed", "network_removed",
        )):
            raise ValueError("receipt_cleanup_missing")
        receipts[kind] = data
        evidence[kind] = {"file": name, "sha256": hashlib.sha256(raw).hexdigest()}

    if (receipts["availability"].get("http") != {"method": "GET", "path": "/", "status": 200}
            or receipts["inventory"].get("stop_reason") != "graph_stabilized"
            or receipts["inventory"].get("rounds") != 2):
        raise ValueError("unexpected_lab_receipt")
    headers = receipts["headers"]
    if not (headers.get("poc_id") == "POC-CSP-001" and headers.get("detail") == "CSP ausente"
            and headers.get("status") == "validated" and headers.get("http_status") == 200
            and headers.get("confirmed_findings") == []):
        raise ValueError("unexpected_headers_receipt")

    tools = {item["tool"]: item["returncode"] for item in receipts["tools"]["tools"]}
    integrated = receipts["integrated"]
    if (integrated.get("state") not in {"INTEGRATED_COMPLETE", "INTEGRATED_WITH_LIMITATIONS"}
            or integrated.get("audit_file") is None
            or integrated["final_audit"]["audit"]["event_count"] != 10):
        raise ValueError("integrated_receipt_incomplete")
    report = build_report([], evidence, engagement="juice-shop-evidence-review")
    report.update(mode="archived_receipts_no_network", receipts=evidence, inventory_rounds=2,
                  observed_control="CSP ausente en GET / (HTTP 200)", tool_exit_codes=tools,
                  exploitability="not_assessed", snapshot_inventory=snapshot_summary(snapshots),
                  cve_correlation="not_supported_by_lab_evidence")
    report["report_sha256"] = report_digest(report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, default=Path("runs"))
    parser.add_argument("--snapshots", type=Path, default=_SNAPSHOTS)
    parser.add_argument("--approve-sha256")
    parser.add_argument("--export-empty", type=Path, help="Archivo local sin hallazgos, no publica")
    args = parser.parse_args()
    try:
        report = build(args.runs, args.snapshots)
        if args.export_empty is not None:
            verify_approval(report, args.approve_sha256)
            with args.export_empty.open("x", encoding="utf-8") as stream:
                json.dump({"type": "PTaaS Grupo 10 Evidence Review",
                           "description": "Revision de recibos; no acredita ausencia de vulnerabilidades.",
                           "findings": []}, stream, indent=2)
        if args.approve_sha256 is not None:
            verify_approval(report, args.approve_sha256)
            print(json.dumps({"state": "REVIEW_ACCEPTED_LOCAL", "published": False,
                              "report_sha256": report["report_sha256"]}))
        else:
            print(json.dumps(report, indent=2, ensure_ascii=True))
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        parser.exit(2, f"Demo bloqueada: {type(error).__name__}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
