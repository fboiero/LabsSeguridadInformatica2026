"""Informe reproducible desde hallazgos y referencias de evidencia."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from hmac import compare_digest
from pathlib import Path
from typing import Any


class ReportError(ValueError):
    pass


_CVSS = re.compile(r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[NHL]/VI:[NHL]/VA:[NHL]/SC:[NHL]/SI:[NHL]/SA:[NHL]$")


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    status: str
    cwe: str
    cvss: str
    remediation: str
    evidence_refs: tuple[str, ...]
    epss: float | None = None


def report_digest(report: dict[str, Any]) -> str:
    content = {key: value for key, value in report.items() if key != "report_sha256"}
    return hashlib.sha256(json.dumps(content, sort_keys=True, allow_nan=False).encode()).hexdigest()


def verify_approval(report: dict[str, Any], approved_sha256: str | None) -> str:
    if report.get("publication") != "PENDING_HITL":
        raise ReportError("report_not_reviewable")
    if approved_sha256 is None or not re.fullmatch(r"[0-9a-f]{64}", approved_sha256):
        raise ReportError("reviewer_approval_required")
    try:
        digest = report_digest(report)
    except (TypeError, ValueError, RecursionError):
        raise ReportError("invalid_report_content") from None
    if report.get("report_sha256") != digest or not compare_digest(digest, approved_sha256):
        raise ReportError("approval_hash_mismatch")
    return digest


def _validate(finding: Finding, evidence: dict[str, Any]) -> None:
    for field in ("cwe", "cvss", "remediation"):
        if not getattr(finding, field):
            raise ReportError(f"missing_{field}")
    if not re.fullmatch(r"CWE-[1-9][0-9]{1,5}", finding.cwe):
        raise ReportError("invalid_cwe")
    if _CVSS.fullmatch(finding.cvss) is None:
        raise ReportError("invalid_cvss_v4")
    if finding.status not in {"validated", "not_validated"}:
        raise ReportError("invalid_validation_status")
    if not finding.evidence_refs or any(ref not in evidence for ref in finding.evidence_refs):
        raise ReportError("missing_evidence_reference")


def build_report(findings: list[Finding], evidence: dict[str, Any], *, engagement: str) -> dict[str, Any]:
    if not engagement or any("password" in json.dumps(asdict(item)).lower() for item in findings):
        raise ReportError("sensitive_or_missing_engagement")
    for finding in findings:
        _validate(finding, evidence)
    payload = {"engagement": engagement, "methodology": ["PTES", "NIST SP 800-115"],
               "findings": [asdict(item) for item in findings], "evidence_sha256":
               {key: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
                for key, value in evidence.items()}, "publication": "PENDING_HITL"}
    payload["report_sha256"] = report_digest(payload)
    return payload


def export_report(report: dict[str, Any], destination: Path, approved_sha256: str | None = None) -> dict[str, Any]:
    digest = verify_approval(report, approved_sha256)
    output = {"type": "PTaaS Grupo 10 Findings Import", "engagement": report["engagement"],
              "findings": report["findings"], "source_report_sha256": digest}
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2, ensure_ascii=True)
    return output
