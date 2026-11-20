"""Política determinista para Loop B (Change 005): no ejecuta herramientas.

El orquestador debe invocar ZAP/Nuclei exclusivamente mediante Harness.invoke.
Se conserva 'unknown' ante evidencia ausente o insuficiente.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ANALYZE = "ANALYZE"
    STOP_INCONCLUSIVE = "STOP_INCONCLUSIVE"
    STOP_COMPLETE = "STOP_COMPLETE"
    PENDING_HITL = "PENDING_HITL"


@dataclass(frozen=True)
class DetectionState:
    rounds_completed: int
    consecutive_no_evidence: int
    available_capabilities: frozenset[str]
    candidate_count: int
    evidence_count: int
    malformed_evidence: bool = False
    conflicting_evidence: bool = False
    max_rounds: int = 4


@dataclass(frozen=True)
class DetectionDecision:
    decision: Decision
    reason: str
    next_capability: str | None = None


_ALLOWED = ("zap.baseline_scan", "nuclei.safe_templates")


def decide_detection(state: DetectionState) -> DetectionDecision:
    """Decisión pura, sin redes, LLM, ejecución, ni aprobaciones implícitas.

    Rondas/contadores ingresados representan hechos ya auditados por el orquestador.
    El llamador debe actualizar contadores a partir de evidencia validada.
    """
    if (
        min(state.rounds_completed, state.consecutive_no_evidence,
            state.candidate_count, state.evidence_count) < 0
        or state.max_rounds < 1
        or state.rounds_completed > state.max_rounds
        or state.consecutive_no_evidence > state.rounds_completed
    ):
        return DetectionDecision(Decision.PENDING_HITL, "invalid_state")
    if state.malformed_evidence:
        return DetectionDecision(Decision.PENDING_HITL, "invalid_evidence_schema")
    if state.conflicting_evidence:
        return DetectionDecision(Decision.STOP_INCONCLUSIVE, "contradictory_evidence")
    if state.consecutive_no_evidence >= 2:
        return DetectionDecision(Decision.STOP_INCONCLUSIVE, "two_rounds_without_evidence")
    if state.rounds_completed >= state.max_rounds:
        return DetectionDecision(Decision.STOP_INCONCLUSIVE, "iteration_limit")
    # No clasificar como 'confirmed' un mero candidato; ni como hallazgo una alerta aislada.
    # Se permiten rondas extra solo cuando hay candidatos y herramientas habilitadas.
    if state.candidate_count == 0:
        return DetectionDecision(Decision.STOP_INCONCLUSIVE, "no_evidence_backed_candidates")
    if state.evidence_count > 0 and state.rounds_completed > 0:
        return DetectionDecision(Decision.STOP_COMPLETE, "analysis_evidence_collected")
    for capability in _ALLOWED:
        if capability in state.available_capabilities:
            return DetectionDecision(Decision.ANALYZE, "needs_analysis_evidence", capability)
    return DetectionDecision(Decision.STOP_INCONCLUSIVE, "no_approved_analyzers")
