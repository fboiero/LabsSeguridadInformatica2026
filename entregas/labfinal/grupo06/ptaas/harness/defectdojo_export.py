"""Exportación al formato de importación genérico de DefectDojo (change 007 · 2.5, P5).

Decisión del plan (6.5): se exporta un archivo JSON; DefectDojo real solo si sobra
tiempo. Antes de importarlo en una instancia real, verificar los nombres de campo
contra la documentación oficial de "Generic Findings Import" de la versión usada.

Reglas (design.md, decisión 6):
  - Solo se exporta un informe entregado; un informe DEMO nunca.
  - No salen cuerpos, encabezados, cookies, canario, nombres de personas ni rutas.
  - No se inventa severidad: sin fuente, va el valor mínimo con `severity-unknown`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.report_builder import DemoReport, Report, ReportFinding
from harness.reporting import DeliveryNotApproved
from harness.reporting_p3 import _epss

UNKNOWN_SEVERITY = "Info"   # valor mínimo del formato; siempre acompañado de la etiqueta


def to_findings(report: Report) -> list[dict[str, Any]]:
    return [_finding(report, f) for f in report.findings]


def _finding(report: Report, f: ReportFinding) -> dict[str, Any]:
    estado = f.status_label + (f" — {f.reason}" if f.reason and f.status != "validated" else "")
    description = "\n".join([
        f"Activo: {f.asset}",
        f"CWE: {f.cwe}",
        f"CVSS v4.0: {f.cvss_v4_vector}",
        f"EPSS: {_epss(f.epss)}",
        f"Estado: {estado}",
        f"Verificación: {f.poc_id} v{f.poc_version}" if f.poc_id else "Verificación: ninguna",
        "Severidad: no fue calculada (vector CVSS v4.0 sin puntaje en el contrato Finding).",
        "Referencias de bitácora: " + (", ".join(f.evidence_refs) or "unknown"),
        f"Informe: {report.engagement_id} v{report.version} · {report.report_hash}",
        f"Cabeza de la bitácora: {report.audit_head}",
    ])
    tags = ["ptaas", "severity-unknown",
            "validated" if f.status == "validated" else "not-validated"]
    return {
        "title": f.title,
        "description": description,
        "severity": UNKNOWN_SEVERITY,
        "mitigation": f.remediation,
        "cwe": int(f.cwe.split("-", 1)[1]),
        "unique_id_from_tool": f.stable_id,
        "active": True,
        "verified": f.status == "validated",
        "tags": tags,
    }


def export(report: Report, path: Path) -> Path:
    """Escribe el JSON de importación. Rechaza informes DEMO o no entregados."""
    if report.demo:
        raise DemoReport("el informe contiene etapas simuladas: no se exporta")
    if not report.delivered:
        raise DeliveryNotApproved("solo se exporta un informe entregado con aprobación registrada")
    path = Path(path)
    path.write_text(json.dumps({"findings": to_findings(report)}, ensure_ascii=False, indent=2)
                    + "\n", encoding="utf-8")
    return path
