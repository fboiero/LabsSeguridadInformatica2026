"""Loop B: coordinación sin acceso directo a herramientas o red.

La aprobación humana y el alcance los hace cumplir Harness.invoke.
No modifica el Loop A/B/C histórico de harness/loops.py.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from harness.contracts import Action, KillSwitchEngaged, Phase, ScopeToken, ScopeViolation
from harness.detection_loop_b import Decision, DetectionState, decide_detection

_CAPABILITIES = frozenset({"zap.baseline_scan", "nuclei.safe_templates"})


@dataclass(frozen=True)
class DetectionRun:
    status: str
    reason: str
    rounds: int
    evidence: tuple[dict[str, Any], ...]


def _evidence_from_output(capability: str, target: str, output: Any) -> list[dict[str, Any]]:
    """Analiza solo salidas de estructura reconocida; sin confirmar CVE."""
    if not isinstance(output, dict) or output.get("target") != target:
        raise ValueError("salida no corresponde al objetivo o esquema inválido")
    if capability == "zap.baseline_scan":
        if output.get("tool") != "zap" or output.get("format") != "json":
            raise ValueError("metadatos ZAP inválidos")
        alerts = output.get("alerts")
        if not isinstance(alerts, list) or not all(isinstance(a, dict) for a in alerts):
            raise ValueError("alertas ZAP inválidas")
        return [{"capability": capability, "target": target, "observation": a} for a in alerts]
    if capability == "nuclei.safe_templates":
        if output.get("tool") != "nuclei" or output.get("format") != "jsonl":
            raise ValueError("metadatos Nuclei inválidos")
        lines = output.get("lines")
        if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
            raise ValueError("líneas Nuclei inválidas")
        observations: list[dict[str, Any]] = []
        for line in lines:
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get("template-id"), str):
                raise TypeError("hallazgo Nuclei inválido")
            observations.append({"capability": capability, "target": target, "observation": item})
        return observations
    raise ValueError("capability desconocida")


def run_detection_p4(
    harness: Any,
    token: ScopeToken,
    target: str,
    *,
    candidate_count: int,
    capabilities: frozenset[str] = _CAPABILITIES,
    max_rounds: int = 4,
) -> DetectionRun:
    """Ejecuta como máximo una ronda por capability aprobada, mediante Harness.

    Cada ronda requiere aprobación explícita de Guard; no se crean aprobaciones.
    Cuando no queda una capability disponible, la ejecución termina inconclusa.
    No clasifica candidatos como vulnerabilidades confirmadas.
    """
    if token.phase != Phase.ANALYZE or not token.is_live():
        return DetectionRun("BLOCKED", "invalid_analyze_token", 0, ())
    if type(candidate_count) is not int or candidate_count < 0 or type(max_rounds) is not int or max_rounds < 1:
        return DetectionRun("PENDING_HITL", "invalid_state", 0, ())
    if not capabilities.issubset(_CAPABILITIES):
        return DetectionRun("PENDING_HITL", "unknown_capability", 0, ())

    attempted: set[str] = set()
    evidence: list[dict[str, Any]] = []
    rounds = 0
    no_evidence = 0
    while True:
        available = capabilities - attempted
        decision = decide_detection(DetectionState(
            rounds_completed=rounds,
            consecutive_no_evidence=no_evidence,
            available_capabilities=frozenset(available),
            candidate_count=candidate_count,
            evidence_count=len(evidence),
            max_rounds=max_rounds,
        ))
        if decision.decision != Decision.ANALYZE:
            return DetectionRun(decision.decision.value, decision.reason, rounds, tuple(evidence))
        capability = decision.next_capability
        if capability is None or capability not in available:
            return DetectionRun("PENDING_HITL", "invalid_decision", rounds, tuple(evidence))
        action = Action(capability, Phase.ANALYZE, requires_human_approval=True)
        try:
            result = harness.invoke("persona4", action, target, token)
        except KillSwitchEngaged:
            return DetectionRun("ABORTED", "kill_switch", rounds, tuple(evidence))
        except ScopeViolation:
            return DetectionRun("BLOCKED", "out_of_scope_or_unauthorized", rounds, tuple(evidence))
        if isinstance(result, dict) and result.get("status") == "PENDING_HITL":
            return DetectionRun("PENDING_HITL", "approval_required", rounds, tuple(evidence))
        rounds += 1
        attempted.add(capability)
        try:
            new = _evidence_from_output(capability, target, result)
        except (ValueError, TypeError, json.JSONDecodeError):
            return DetectionRun("PENDING_HITL", "invalid_evidence_schema", rounds, tuple(evidence))
        if new:
            evidence.extend(new)
            no_evidence = 0
        else:
            no_evidence += 1
