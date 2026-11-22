"""Ejecuta el tramo A/B de la demo integrada y deja una bitácora SQLite."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from harness.audit import verify_file

from .official_tools import run_official_scans


def run(network: str, audit_path: Path) -> dict[str, Any]:
    if audit_path.exists():
        raise ValueError("audit_output_exists")
    scans = run_official_scans(network, str(audit_path))
    summary = verify_file(audit_path)
    return {"state": "A_B_COMPLETE", "scans": scans, "audit": summary,
            "correlation": {"status": "unknown", "reason": "no_lab_cve_evidence",
                            "candidates": [], "epss": None}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.network, args.audit)
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=True))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"integrated_blocked: {type(error).__name__}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
