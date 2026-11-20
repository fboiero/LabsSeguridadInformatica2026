"""Demo integrada de 002–007; 004/005 usan fixtures y audit usa SQLite.

No aprueba por defecto. --approve acepta decisiones explícitas del operador;
para pruebas automatizadas se identifica al reviewer como prueba, no como revisión humana.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from harness.approvals import ApprovalStore
from harness.audit import AuditChainCorrupted, SqliteAuditLog, verify_file
from harness.contracts import Action, AuditLog, Harness, KillSwitch, Phase, ScopeToken
from harness.policy_loader import phase_allowlist
from harness.report_bundle import build_bundle, publish_bundle
from harness.reporting import Finding
from harness.roe import RoE, parse_roe
from harness.sandbox import DockerSender, FixtureSender
from harness.team_pipeline import PROVENANCE, run_team_pipeline
from harness.tokens import EngagementGuard, TokenIssuer
from harness.validation import ValidationRequest, validate_finding

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"


def verify_entries(entries: list[dict[str, Any]]) -> bool:
    prev = "GENESIS"
    for e in entries:
        body = {k: v for k, v in e.items() if k != "hash"}
        expected = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if e["prev"] != prev or e["hash"] != expected:
            return False
        prev = e["hash"]
    return True


class BundleAdapter:
    name = "report.render"
    allowed_phases: tuple[Phase, ...] = (Phase.REPORT,)
    destructive = False

    def __init__(
        self,
        engagement_id: str,
        findings: list[Finding],
        audit: AuditLog,
        mode: str,
        pipeline: dict[str, str] | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.findings = findings
        self.audit = audit
        self.mode = mode
        self.pipeline = pipeline or PROVENANCE

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        return build_bundle(
            self.engagement_id, self.findings, self.audit.entries, self.mode, pipeline=self.pipeline
        )


class ExportAdapter:
    name = "defectdojo.export"
    allowed_phases: tuple[Phase, ...] = (Phase.REPORT,)
    destructive = False

    def __init__(self, bundle: dict[str, Any], approvals: ApprovalStore, output: Path) -> None:
        self.bundle = bundle
        self.approvals = approvals
        self.output = output

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        publish_bundle(self.bundle, self.approvals, self.output)
        return {"status": "exported_local_json", "version": self.bundle["version"]}


def execute(
    roe_path: Path,
    output: Path,
    approvals: ApprovalStore,
    approve: tuple[str, ...] = (),
    reviewer: str = "",
    reason: str = "",
    delivery_bundle: Path | None = None,
    validation_mode: str = "fixture",
    network: str = "lab_lab",
    tools_mode: str = 'fixture',
) -> dict[str, Any]:
    roe = parse_roe(roe_path)
    output.mkdir(parents=True, exist_ok=True)
    engagement_key = hashlib.sha256(roe.engagement_id.encode()).hexdigest()
    db_path = output / ("audit-" + engagement_key + ".db")
    if db_path.exists() and not verify_file(str(db_path)):
        raise AuditChainCorrupted("bitácora SQLite alterada")
    audit = SqliteAuditLog(str(db_path))
    try:
        if any(e["engagement"] != roe.engagement_id for e in audit.entries):
            raise ValueError("bitácora de otro engagement")
        return _execute_with_audit(
            roe, output, approvals, audit, approve, reviewer, reason,
            delivery_bundle, validation_mode, network, tools_mode,
        )
    finally:
        audit.close()


def _execute_with_audit(
    roe: RoE,
    output: Path,
    approvals: ApprovalStore,
    audit: SqliteAuditLog,
    approve: tuple[str, ...],
    reviewer: str,
    reason: str,
    delivery_bundle: Path | None,
    validation_mode: str,
    network: str,
    tools_mode: str,
) -> dict[str, Any]:
    ks = KillSwitch()
    issuer = TokenIssuer(roe, audit, killswitch=ks)
    guard = EngagementGuard(roe.engagement_id, phase_allowlist())
    harness = Harness(guard, audit, {}, ks)
    target = "dvwa.lab.test"
    output.mkdir(parents=True, exist_ok=True)
    if delivery_bundle is not None:
        bundle = json.loads(delivery_bundle.read_text(encoding="utf-8"))
        if bundle["engagement_id"] != roe.engagement_id:
            raise ValueError("engagement ajeno")
    else:
        print(f"004/005: {tools_mode}; sin LLM vivo. Validación: {validation_mode}")
        pipeline = run_team_pipeline(harness, issuer, target, output, tools_mode, network)
        request = ValidationRequest(
            "F-CSP-001",
            target,
            "CWE-693",
            "POC-CSP-001",
            {"base_url": "http://dvwa.lab.test", "path": "/login.php"},
            validation_mode,
            roe.engagement_id,
        )
        if request.id in approve:
            approvals.decide(request.subject, "approve", reviewer, reason)
        token = issuer.issue(Phase.VALIDATE)
        factory = (
            FixtureSender
            if validation_mode == "fixture"
            else lambda: DockerSender(token.allowed_domains, token.allowed_cidrs, network)
        )
        validation = validate_finding(harness, token, request, approvals, factory)
        print("Loop C:", validation["status"])
        (output / "validation-evidence.json").write_text(
            json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        finding = Finding(
            request.id,
            "Ausencia de CSP (candidato manual; validación " + validation_mode + ")",
            target,
            request.cwe,
            VECTOR,
            "Definir y verificar Content-Security-Policy según la aplicación.",
            "validated" if validation["status"] == "validated" else "not_validated",
            tuple(validation["evidence_refs"]),
        )
        harness.tools["report.render"] = BundleAdapter(
            roe.engagement_id, [finding], audit, validation_mode, pipeline["provenance"]
        )
        bundle = harness.invoke(
            "reporting", Action("report.render", Phase.REPORT), target, issuer.issue(Phase.REPORT)
        )
        (output / "bundle-draft.json").write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    if "delivery" in approve:
        approvals.decide(bundle["subject"], "approve", reviewer, reason)
    approvals.pending(bundle["subject"], "Entrega del informe " + bundle["version"])
    harness.tools["defectdojo.export"] = ExportAdapter(bundle, approvals, output / "published")
    action = Action("defectdojo.export", Phase.REPORT, requires_human_approval=True)
    if approvals.approved(bundle["subject"]):
        guard.approve(action.name, target)
    delivery = harness.invoke("reporting", action, target, issuer.issue(Phase.REPORT))
    print("Entrega:", delivery["status"])
    if not audit.verify() or not verify_entries(audit.entries):
        raise ValueError("bitácora alterada")
    (output / "audit.json").write_text(
        json.dumps(audit.entries, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("Cadena SQLite y audit.json: OK")
    print("Bitácora SQLite:", audit.db_path)
    return {
        "bundle": bundle, "delivery": delivery, "audit": audit.entries,
        "audit_path": audit.db_path,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--roe", type=Path, required=True)
    ap.add_argument("--output", type=Path, default=Path(".demo-output"))
    ap.add_argument("--approvals", type=Path, default=Path(".demo-output/approvals.json"))
    ap.add_argument(
        "--approve", action="append", default=[], help="F-CSP-001 o delivery; nunca automático"
    )
    ap.add_argument("--reviewer", default="")
    ap.add_argument("--reason", default="")
    ap.add_argument("--deliver-bundle", type=Path)
    ap.add_argument("--validation-mode", choices=["fixture", "sandbox"], default="fixture")
    ap.add_argument("--network", default="lab_lab")
    ap.add_argument('--tools-mode', choices=['fixture', 'docker'], default='fixture')
    args = ap.parse_args()
    if args.approve and (not args.reviewer or not args.reason):
        ap.error("aprobación requiere --reviewer y --reason")
    approvals = ApprovalStore.load(args.approvals)
    try:
        execute(
            args.roe,
            args.output,
            approvals,
            tuple(args.approve),
            args.reviewer,
            args.reason,
            args.deliver_bundle,
            args.validation_mode,
            args.network,
            args.tools_mode,
        )
        approvals.save(args.approvals)
    except (ValueError, PermissionError, RuntimeError, AuditChainCorrupted) as exc:
        print(type(exc).__name__ + ": " + str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
