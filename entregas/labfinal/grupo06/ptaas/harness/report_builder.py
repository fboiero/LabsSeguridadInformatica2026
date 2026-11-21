"""Informe final desde la bitácora (change 007 · 2.2 y 2.6, P5).

- El estado de validación de cada hallazgo sale del registro `validation.result`
  del loop C, no de lo que declare el `Finding` (design.md, decisión 1).
- Cada referencia de evidencia es el hash de una entrada de la bitácora, y la
  bitácora tiene que pasar `verify()` (decisión 2).
- El informe se identifica por `report_hash`; un cambio produce otra versión (3).
- La entrega exige una aprobación registrada por una persona para ese hash (4).
- Un dato sensible hace fallar la generación; no se redacta (5).
- Un informe con etapas `fixture` es DEMO: no se entrega ni se exporta (7).

Reusa las validaciones de P3 (`reporting_p3`) sin modificarlas.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from harness.reporting import DeliveryNotApproved, Finding, _check
from harness.reporting_p3 import _epss, _text, validate_cvss4

STAGE_VALUES = frozenset({"real", "fixture"})
LABEL_VALIDATED = "validado en sandbox"
LABEL_NOT_VALIDATED = "no validado"
LABEL_PENDING = "no validado (sin aprobación)"


class ReportError(ValueError):
    """El informe no se puede generar: se indica el hallazgo, la referencia o el dato."""


class SensitiveDataError(ReportError):
    """El contenido del informe coincide con un patrón de dato sensible."""


class DemoReport(DeliveryNotApproved):
    """El informe contiene etapas simuladas: no se entrega ni se exporta."""


# Patrones de datos sensibles (design.md, decisión 5). Ampliarlos requiere delta.
SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cookie de sesión", re.compile(
        r"(?i)\b(phpsessid|jsessionid|sessionid|session|sid|token)\s*=\s*[^\s;,]+|set-cookie\s*:")),
    ("token JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")),
    ("Authorization", re.compile(r"(?i)\bauthorization\s*:")),
    ("contraseña", re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[=:]\s*\S+")),
    ("clave privada", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("canario", re.compile(r"ptaas[0-9a-f]{8}")),
)


@dataclass(frozen=True)
class ReportFinding:
    id: str
    title: str
    asset: str
    cwe: str
    cvss_v4_vector: str
    epss: float | None
    remediation: str
    status: str                     # "validated" | "not_validated"
    status_label: str
    reason: str
    poc_id: str | None
    poc_version: str | None
    evidence_refs: tuple[str, ...]
    stable_id: str
    high_impact: bool
    merged_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Report:
    engagement_id: str
    version: int
    report_hash: str
    audit_head: str
    findings: tuple[ReportFinding, ...]
    stages: Mapping[str, str]
    demo: bool
    scope: Mapping[str, Any]
    markdown: str
    delivered: bool = False
    meta: Mapping[str, Any] = field(default_factory=dict)


# ---- Construcción ----------------------------------------------------------------


def build_report(engagement_id: str, findings: Sequence[Finding], *, evidence: Any,
                 scope: Mapping[str, Any] | None = None, stages: Mapping[str, str],
                 previous: Report | None = None) -> Report:
    scope = dict(scope or {})
    stages = _check_stages(stages)
    entries = _verified_entries(evidence)
    hashes = {e.hash for e in entries}
    audit_head = entries[-1].hash if entries else "GENESIS"

    built = []
    for f in findings:
        _check(f)
        validate_cvss4(f.cvss_v4_vector)
        _epss(f.epss)
        _check_sensitive(f.id, (f.id, f.title, f.asset, f.cwe, f.remediation))
        built.append(_from_log(f, entries, hashes))
    _check_sensitive("alcance", tuple(_flatten(scope)))

    merged = _merge_duplicates(built)
    demo = any(v == "fixture" for v in stages.values())
    canonical = {"engagement_id": engagement_id, "audit_head": audit_head,
                 "stages": dict(sorted(stages.items())), "scope": scope,
                 "findings": [asdict(f) for f in merged]}
    report_hash = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    version = 1 if previous is None else (
        previous.version if previous.report_hash == report_hash else previous.version + 1)
    markdown = _markdown(engagement_id, version, report_hash, audit_head, merged, stages,
                         demo, scope)
    return Report(engagement_id, version, report_hash, audit_head, tuple(merged), stages, demo,
                  scope, markdown)


def _check_stages(stages: Mapping[str, str]) -> dict[str, str]:
    if not stages:
        raise ReportError("falta declarar la procedencia de las etapas")
    bad = {k: v for k, v in stages.items() if v not in STAGE_VALUES}
    if bad:
        raise ReportError(f"procedencia inválida (solo real/fixture): {bad}")
    return dict(stages)


def _verified_entries(evidence: Any) -> list[Any]:
    result = evidence.verify()
    if not result.ok:
        raise ReportError(f"la bitácora no pasa la verificación: {result.motivo} "
                          f"(entrada {result.indice})")
    return list(evidence.entries())


def _flatten(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _flatten(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _flatten(v)]
    return [str(value)]


def _check_sensitive(where: str, texts: Sequence[str]) -> None:
    for text in texts:
        for label, pattern in SENSITIVE_PATTERNS:
            if pattern.search(text or ""):
                raise SensitiveDataError(f"{where}: dato sensible ({label})")


def _from_log(f: Finding, entries: Sequence[Any], hashes: set[str]) -> ReportFinding:
    for ref in f.evidence_refs:
        if ref not in hashes:
            raise ReportError(f"{f.id}: la referencia {ref} no existe en la bitácora")

    own = [e for e in entries if e.data.get("finding_id") == f.id
           and e.data.get("event") in ("validation.result", "sandbox.response")]
    results = [e for e in own if e.data.get("event") == "validation.result"]
    last = dict(results[-1].data) if results else None

    log_status = last["status"] if last else None
    reason = str(last.get("reason", "")) if last else "sin registro del loop C"
    # Revisión de P4 (007 · 1.3): el motivo viene de la bitácora y llega al informe y a la
    # exportación, así que pasa por el mismo filtro que los campos del hallazgo.
    _check_sensitive(f.id, (reason,))
    if f.validation_status == "validated" and log_status != "validated":
        raise ReportError(f"{f.id}: declarado validado sin respaldo en la bitácora")

    if log_status == "validated":
        status, label = "validated", LABEL_VALIDATED
    elif last is None or log_status == "PENDING_HITL" or reason == "sin aprobación":
        status, label = "not_validated", LABEL_PENDING
    else:
        status, label = "not_validated", LABEL_NOT_VALIDATED

    refs = list(dict.fromkeys([*f.evidence_refs, *(e.hash for e in own)]))
    # Una verificación solo cuenta si el loop C la encontró en el catálogo (tiene versión).
    # Sin ella, el hallazgo se identifica por su título: dos alertas distintas sin
    # verificación no se unifican (regresión de la corrida P5-recorrido-03).
    poc_version = last.get("poc_version") if last else None
    poc_id = last.get("poc_id") if last and poc_version else None
    key = f"{f.asset.strip().lower()}|{f.cwe}|{poc_id or ' '.join(f.title.lower().split())}"
    return ReportFinding(
        id=f.id, title=f.title, asset=f.asset, cwe=f.cwe, cvss_v4_vector=f.cvss_v4_vector,
        epss=f.epss, remediation=f.remediation, status=status, status_label=label,
        reason=reason, poc_id=poc_id, poc_version=poc_version,
        evidence_refs=tuple(refs), stable_id=hashlib.sha256(key.encode("utf-8")).hexdigest(),
        high_impact=bool(re.search(r"/V[CIA]:H(/|$)", f.cvss_v4_vector)))


def _merge_duplicates(findings: Sequence[ReportFinding]) -> list[ReportFinding]:
    """Une hallazgos con el mismo identificador estable. Solo queda "validado" si todos lo están."""
    groups: dict[str, list[ReportFinding]] = {}
    for f in findings:
        groups.setdefault(f.stable_id, []).append(f)
    out = []
    for group in groups.values():
        first = group[0]
        if len(group) == 1:
            out.append(first)
            continue
        refs = tuple(dict.fromkeys(r for f in group for r in f.evidence_refs))
        base = first if all(f.status == "validated" for f in group) else next(
            f for f in group if f.status != "validated")
        out.append(replace(base, id=first.id, evidence_refs=refs,
                           merged_ids=tuple(f.id for f in group[1:])))
    return out


# ---- Markdown ----------------------------------------------------------------------


def _markdown(engagement_id: str, version: int, report_hash: str, audit_head: str,
              findings: Sequence[ReportFinding], stages: Mapping[str, str], demo: bool,
              scope: Mapping[str, Any]) -> str:
    lines = [f"# Informe de pentest — {_text(engagement_id)}", ""]
    if demo:
        simuladas = ", ".join(k for k, v in sorted(stages.items()) if v == "fixture")
        lines += [(f"> **DEMO** — contiene etapas simuladas ({simuladas}). "
                   "No es un resultado de pentest y no se puede entregar ni exportar."), ""]
    lines += [f"- Versión: {version}", f"- Hash del informe: {report_hash}",
              f"- Cabeza de la bitácora: {audit_head}",
              "- Procedencia de las etapas: " + ", ".join(
                  f"{_text(k)}={v}" for k, v in sorted(stages.items())), ""]

    validated = sum(f.status == "validated" for f in findings)
    pendientes = [f for f in findings if f.status != "validated" and f.high_impact]
    lines += ["## Resumen ejecutivo",
              (f"Se documentan {len(findings)} hallazgos: {validated} validados en sandbox y "
               f"{len(findings) - validated} no validados, según la bitácora del engagement."),
              ("Este inventario no demuestra ausencia de vulnerabilidades fuera de la evidencia "
               "registrada.")]
    if pendientes:
        lines.append("Impacto alto, requiere validación: "
                     + ", ".join(_text(f.id) for f in pendientes) + ".")
    lines.append("")

    lines += ["## Alcance y RoE"]
    for key, label in [("assets", "Activos"), ("window", "Ventana"),
                       ("exclusions", "Exclusiones"), ("roe_ref", "Referencia RoE")]:
        lines.append(f"- {label}: {_text(scope.get(key, 'unknown'))}")
    lines += ["", "## Metodología",
              ("Estructura de presentación PTES §7. El estado de validación de cada hallazgo "
               "se toma de la bitácora del loop C; la estructura no acredita por sí sola "
               "ejecución completa de PTES, NIST SP 800-115 u OWASP WSTG.")]
    if scope.get("cvss_source"):
        lines.append(f"Vectores CVSS v4.0: {_text(scope['cvss_source'])}.")
    lines += ["",
              "## Hallazgos priorizados",
              "Orden: EPSS conocido descendente; unknown al final. No se infiere puntaje CVSS.", ""]
    for f in sorted(findings, key=lambda x: (x.epss is None, -(x.epss or 0), x.id)):
        estado = f.status_label + (f" — {_text(f.reason)}" if f.reason and
                                   f.status != "validated" else "")
        lines += [f"### {_text(f.id)} — {_text(f.title)}", f"- Activo: {_text(f.asset)}",
                  f"- {_text(f.cwe)} · {f.cvss_v4_vector} · EPSS: {_epss(f.epss)}",
                  "- Puntaje CVSS: unknown (no aportado por el contrato Finding)",
                  f"- Estado: {estado}"]
        if f.poc_id:
            lines.append(f"- Verificación: {_text(f.poc_id)} v{_text(f.poc_version)}")
        if f.merged_ids:
            lines.append("- Unificado con: " + ", ".join(_text(i) for i in f.merged_ids))
        lines += [f"- Remediación: {_text(f.remediation)}",
                  "- Evidencia (bitácora): " + (", ".join(f.evidence_refs) or "unknown"), ""]

    disclosure = dict(scope.get("disclosure") or {})
    lines += ["## Divulgación",
              "Manejo según ISO/IEC 29147; los datos ausentes en el RoE figuran como unknown.",
              f"- Receptor: {_text(disclosure.get('recipient', 'unknown'))}",
              f"- Canal: {_text(disclosure.get('channel', 'unknown'))}",
              f"- Fecha de entrega: {_text(disclosure.get('delivery_date', 'unknown'))}",
              f"- Plazo de remediación: {_text(disclosure.get('remediation_deadline', 'unknown'))}",
              "", "## Anexos",
              "- Inventario de activos: " + (", ".join(sorted({_text(f.asset) for f in findings}))
                                             or "unknown"),
              f"- Cabeza de la bitácora: {audit_head}"]
    return "\n".join(lines)


# ---- Entrega -------------------------------------------------------------------------


def deliver_report(report: Report, *, approvals: Any, evidence: Any) -> Report:
    """Entrega solo con una aprobación registrada por una persona para este `report_hash`."""
    base = {"event": "report.delivery", "engagement": report.engagement_id,
            "report_hash": report.report_hash, "version": report.version}
    if report.demo:
        evidence.append({**base, "result": "BLOCKED", "reason": "informe DEMO"})
        raise DemoReport("el informe contiene etapas simuladas: no se entrega")
    record = approvals.delivery_record(report.engagement_id, report.report_hash)
    if record is None:
        evidence.append({**base, "result": "PENDING_HITL"})
        raise DeliveryNotApproved("falta la aprobación registrada del Reviewer para este informe")
    evidence.append({**base, "result": "DELIVERED", "reviewer": record["reviewer"],
                     "reason": record["reason"]})
    return replace(report, delivered=True)
