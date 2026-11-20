"""Casos básicos para la política determinista de Loop B; sin red."""
from __future__ import annotations

import pytest

from harness.detection_loop_b import Decision, DetectionState, decide_detection


def state(**kwargs: object) -> DetectionState:
    defaults = {
        "rounds_completed": 0,
        "consecutive_no_evidence": 0,
        "available_capabilities": frozenset({"zap.baseline_scan"}),
        "candidate_count": 1,
        "evidence_count": 0,
    }
    defaults.update(kwargs)
    return DetectionState(**defaults)  # type: ignore[arg-type]


def test_solo_elige_zap_si_esta_habilitado() -> None:
    result = decide_detection(state())
    assert result.decision is Decision.ANALYZE
    assert result.next_capability == "zap.baseline_scan"


def test_elige_nuclei_si_zap_no_disponible() -> None:
    result = decide_detection(state(available_capabilities=frozenset({"nuclei.safe_templates"})))
    assert result.next_capability == "nuclei.safe_templates"


@pytest.mark.parametrize("capabilities", [frozenset(), frozenset({"arbitrary.tool"})])
def test_no_autoriza_capacidad_desconocida(capabilities: frozenset[str]) -> None:
    assert decide_detection(state(available_capabilities=capabilities)).decision is Decision.STOP_INCONCLUSIVE


def test_dos_rondas_sin_evidencia_detienen() -> None:
    result = decide_detection(state(rounds_completed=2, consecutive_no_evidence=2))
    assert result.decision is Decision.STOP_INCONCLUSIVE
    assert result.reason == "two_rounds_without_evidence"


def test_cuatro_rondas_detienen() -> None:
    assert decide_detection(state(rounds_completed=4)).reason == "iteration_limit"


def test_schema_invalido_escala_a_humano() -> None:
    assert decide_detection(state(malformed_evidence=True)).decision is Decision.PENDING_HITL


def test_contradiccion_es_inconclusa() -> None:
    assert decide_detection(state(conflicting_evidence=True)).reason == "contradictory_evidence"


def test_candidato_sin_evidencia_no_es_confirmacion() -> None:
    assert decide_detection(state(rounds_completed=1, evidence_count=0)).decision is Decision.ANALYZE


def test_evidencia_de_analisis_permite_cerrar_sin_confirmar_vulnerabilidad() -> None:
    assert decide_detection(state(rounds_completed=1, evidence_count=1)).decision is Decision.STOP_COMPLETE


def test_sin_candidatos_no_lanza_herramientas() -> None:
    assert decide_detection(state(candidate_count=0)).decision is Decision.STOP_INCONCLUSIVE


@pytest.mark.parametrize("changes", [
    {"rounds_completed": -1},
    {"consecutive_no_evidence": 2, "rounds_completed": 1},
    {"max_rounds": 0},
    {"evidence_count": -1},
    {"rounds_completed": 5},
])
def test_estado_invalido_va_a_humano(changes: dict[str, int]) -> None:
    assert decide_detection(state(**changes)).decision is Decision.PENDING_HITL
