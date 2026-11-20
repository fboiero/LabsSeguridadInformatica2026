"""Checkpoint de autorización inerte: sin red ni proveedor de IA."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from harness.audit import AuditLog
from harness.contracts import Action, Guard, Harness, KillSwitch, ScopeViolation
from harness.roe import TokenIssuer, fixture_roe_yaml, parse_roe
from harness.types import Phase, ScopeToken


class InertProbe:
    name = "fixture.observe"
    allowed_phases: tuple[Phase, ...] = (Phase.RECON,)
    destructive = False

    def __init__(self) -> None:
        self.calls = 0

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        self.calls += 1
        return {"synthetic": True}


def run_checkpoint(output: Path, *, approved_fixture: bool) -> dict[str, Any]:
    yaml_text = fixture_roe_yaml()
    output.mkdir(parents=True)
    roe = parse_roe(yaml_text)
    (output / "roe.yaml").write_text(yaml_text, encoding="utf-8")
    probe = InertProbe()
    decisions: list[dict[str, str]] = []
    result: dict[str, Any] = {"synthetic": True, "network_calls": 0, "model_calls": 0,
                              "state": "PENDING_HITL", "decisions": decisions, "fixture_calls": 0}
    if approved_fixture:
        issuer = TokenIssuer(roe, approved_fixture=True)
        token = issuer.issue(Phase.RECON)
        action = Action(probe.name, Phase.RECON)
        with AuditLog(output / "audit.db", roe.engagement_id) as audit:
            runner = Harness(Guard({Phase.RECON: {probe.name}}, issued_by=issuer.accepts),
                             audit, {probe.name: probe}, KillSwitch())
            for target in ("dvwa.lab.test", "other.lab.test"):
                try:
                    runner.invoke("operator-fixture", action, target, token)
                except ScopeViolation:
                    decision = "BLOCKED"
                else:
                    decision = "OK"
                decisions.append({"target": target, "result": decision, "audit_ref": audit.entries[-1]["hash"]})
            result.update(state="DEMONSTRATED_INERT", fixture_calls=probe.calls, audit=audit.verify())
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="Directorio nuevo de salida")
    parser.add_argument("--approve-fixture", action="store_true", help="Autoriza solo el contador inerte")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output debe ser nuevo")
    result = run_checkpoint(args.output, approved_fixture=args.approve_fixture)
    print(json.dumps(result, indent=2))
    return 0 if [row["result"] for row in result["decisions"]] == ["OK", "BLOCKED"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
