"""Schemas de intercambio entre agentes + reglas deterministas (priorización, dedupe, escalado)."""
from __future__ import annotations

from dataclasses import dataclass, field


class SchemaError(ValueError): ...


@dataclass(frozen=True)
class Asset:
    id: str
    type: str
    address: str
    source_tool: str
    technologies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.source_tool:
            raise SchemaError("Asset requiere source_tool")


@dataclass
class CandidateFinding:
    id: str
    asset_id: str
    cwe: str = "unknown"
    cve: str | None = None
    epss: float | None = None
    attack_technique: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    confidence: str = "medium"
    cvss_v4_score: float | None = None

    def __post_init__(self) -> None:
        if not self.evidence_refs:
            raise SchemaError("CandidateFinding requiere evidence_refs")
        if self.epss is not None and not (0.0 <= self.epss <= 1.0):
            raise SchemaError("epss fuera de rango")
        if self.cvss_v4_score is not None and not (0.0 <= self.cvss_v4_score <= 10.0):
            raise SchemaError("cvss_v4_score fuera de rango")


@dataclass(frozen=True)
class PrioritizedVuln:
    finding_id: str
    status: str                  # confirmed | discarded | inconclusive
    rationale: str
    evidence_refs: tuple[str, ...] = ()
    cvss_v4_score: float | None = None
    priority: float | None = None

    def __post_init__(self) -> None:
        if self.status not in {"confirmed", "discarded", "inconclusive"}:
            raise SchemaError("status inválido")
        if not self.rationale.strip():
            raise SchemaError("PrioritizedVuln requiere rationale")
        if self.cvss_v4_score is not None and not (0.0 <= self.cvss_v4_score <= 10.0):
            raise SchemaError("cvss_v4_score fuera de rango")
        if self.priority is not None and not (0.0 <= self.priority <= 10.0):
            raise SchemaError("priority fuera de rango")


def dedupe(candidates: list[CandidateFinding]) -> list[CandidateFinding]:
    """Deduplica por (activo, CVE|CWE); fusiona evidencia."""
    merged: dict[tuple[str, str], CandidateFinding] = {}
    for c in candidates:
        key = (c.asset_id, c.cve or c.cwe)
        if key in merged:
            m = merged[key]
            m.evidence_refs = sorted(set(m.evidence_refs) | set(c.evidence_refs))
        else:
            merged[key] = CandidateFinding(**{**c.__dict__, "evidence_refs": list(c.evidence_refs)})
    return list(merged.values())


def priority_score(cvss_v4: float | None, epss: float | None,
                   asset_criticality: int | None) -> float | None:
    """Prioridad reproducible; si falta CVSS v4 no se fabrica un score."""
    if cvss_v4 is None or asset_criticality is None:
        return None
    if not (0 <= cvss_v4 <= 10) or not (1 <= asset_criticality <= 5):
        raise SchemaError("insumos fuera de rango")
    if epss is not None and not 0.0 <= epss <= 1.0:
        raise SchemaError("epss fuera de rango")
    e = 0.0 if epss is None else epss
    return round(0.6 * cvss_v4 + 2.5 * e + 0.25 * asset_criticality, 2)


class SchemaGate:
    """Tras 2 salidas inválidas consecutivas, escala a HITL (no reintenta más)."""

    def __init__(self, max_failures: int = 2):
        self.max_failures, self.failures = max_failures, 0

    def record(self, valid: bool) -> str:
        self.failures = 0 if valid else self.failures + 1
        return "PENDING_HITL" if self.failures >= self.max_failures else ("OK" if valid else "RETRY")
