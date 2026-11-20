"""Reporte PTES con procedencia y export Generic Findings Import, sin API externa."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from harness.approvals import ApprovalStore, subject_key
from harness.reporting import Finding, MissingField, render_report

BASE_VECTOR = re.compile(
    r"CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]"
)
SECRET = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|secret|token)\s*[=:]\s*\S+|Bearer\s+\S+|-----BEGIN .*PRIVATE KEY|FLAG\{"
)


def build_bundle(
    engagement_id: str, findings: list[Finding], entries: list[dict[str, Any]], mode: str
) -> dict[str, Any]:
    if mode not in {"fixture", "restricted_http_no_container", "sandbox"}:
        raise ValueError("modo desconocido")
    index = {e["hash"]: e for e in entries}
    lines = [
        "# Informe técnico PTES §7",
        "",
        "## Resumen ejecutivo",
        f"Engagement {engagement_id}: {len(findings)} hallazgos. Procedencia: {mode}.",
        "La severidad requiere revisión humana; no se calcula score CVSS numérico.",
        "",
        "## Alcance y metodología",
        "Solo laboratorio autorizado; tokens por fase, catálogo inerte y gate humano.",
        "## Límites",
        "Fixture: sin tráfico. Sender restringido: sin aislamiento por contenedor. No se evalúa un LLM en vivo.",
        "",
        "## Hallazgos",
    ]
    exports = []
    seen = set()
    for f in findings:
        if f.id in seen:
            raise ValueError("id duplicado")
        seen.add(f.id)
        if not BASE_VECTOR.fullmatch(f.cvss_v4_vector):
            raise MissingField(f"{f.id}: CVSS base inválido")
        if f.validation_status not in {"validated", "not_validated"}:
            raise ValueError("validation_status inválido")
        if f.epss is not None and not 0 <= f.epss <= 1:
            raise ValueError("EPSS inválido")
        if not f.evidence_refs or any(
            ref not in index
            or index[ref]["engagement"] != engagement_id
            or index[ref]["target"] != f.asset
            or (f.validation_status == "validated" and index[ref]["result"] != "OK")
            for ref in f.evidence_refs
        ):
            raise ValueError(f"{f.id}: evidencia ausente o ajena")
        if SECRET.search(json.dumps(asdict(f), ensure_ascii=False)):
            raise ValueError("datos sensibles en hallazgo")
        render_report(engagement_id, [f])  # mantiene validación del contrato original
        status = (
            (
                "validado sobre fixture"
                if mode == "fixture"
                else "validado con Sender restringido"
                if mode == "restricted_http_no_container"
                else "validado en sandbox"
            )
            if f.validation_status == "validated"
            else "no validado"
        )
        detail = f"{f.title}. Estado: {status}. Procedencia: {mode}. {f.cwe}. {f.cvss_v4_vector}. EPSS: {f.epss if f.epss is not None else 'unknown'}. Referencias: {', '.join(f.evidence_refs)}. Severidad Info provisional hasta valoración humana."
        lines += [
            f"### {f.id} — {f.title}",
            f"Activo: {f.asset}",
            detail,
            f"Remediación: {f.remediation}",
            "",
        ]
        exports.append(
            {
                "title": f.title,
                "severity": "Info",
                "description": detail,
                "mitigation": f.remediation,
                "cwe": int(f.cwe.split("-")[1]),
                "verified": f.validation_status == "validated" and mode != "fixture",
                "active": True,
            }
        )
    lines += [
        "## Conclusión y divulgación",
        "Priorizar revisión humana de los hallazgos. Divulgar únicamente al responsable del laboratorio; sin datos crudos ni secretos.",
    ]
    body = {
        "engagement_id": engagement_id,
        "mode": mode,
        "markdown": "\n".join(lines),
        "export": {"findings": exports},
    }
    if SECRET.search(json.dumps(body, ensure_ascii=False)):
        raise ValueError("datos sensibles en reporte")
    return {**body, "version": subject_key(body), "subject": subject_key(body)}


def publish_bundle(bundle: dict[str, Any], approvals: ApprovalStore, output: Path) -> None:
    body = {k: v for k, v in bundle.items() if k not in {"version", "subject"}}
    if subject_key(body) != bundle["version"] or bundle["subject"] != bundle["version"]:
        raise ValueError("informe alterado")
    if not approvals.approved(bundle["subject"]):
        raise PermissionError("PENDING_HITL: aprobación de entrega requerida")
    output.mkdir(parents=True, exist_ok=True)
    (output / "informe.md").write_text(bundle["markdown"], encoding="utf-8")
    (output / "defectdojo.json").write_text(
        json.dumps(bundle["export"], ensure_ascii=False, indent=2), encoding="utf-8"
    )
