"""Conserva en la bitácora persistente el resultado del Sender efímero."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, cast

from harness.audit import AuditLog, verify_file
from harness.contracts import Guard, Harness, KillSwitch
from harness.types import Action, Phase, ScopeToken, ToolAdapter


class ReceiptAdapter:
    name = "poc_catalog.validate"
    allowed_phases = (Phase.VALIDATE,)
    destructive = False

    def __init__(self, status: str) -> None:
        self.status = status

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        return {"status": self.status, "target": target, "sender_receipt": "child_sandbox"}


def append(audit_path: Path, status: str) -> dict[str, Any]:
    now = time.time()
    with AuditLog(audit_path, "juice-shop-integrated") as audit:
        phase = Phase.VALIDATE
        token = ScopeToken("juice-shop-integrated", (), ("juice-shop.lab.test",), now - 1, now + 120, phase)
        action = Action("poc_catalog.validate", phase, requires_human_approval=True,
                        parameters={"poc_id": "POC-CSP-001", "path": "/"})
        guard = Guard({phase: {action.name}})
        guard.approve(action.name, "juice-shop.lab.test")
        harness = Harness(guard, audit, {action.name: cast(ToolAdapter, ReceiptAdapter(status))}, KillSwitch())
        output = harness.invoke("integrator", action, "juice-shop.lab.test", token)
        return {"result": output, "audit": audit.verify()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = append(args.audit, args.status)
    result["audit_file_verification"] = verify_file(args.audit)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
