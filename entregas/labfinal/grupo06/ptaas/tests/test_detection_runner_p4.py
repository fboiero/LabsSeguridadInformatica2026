"""Integración offline: runners simulados; no hay red ni aprobaciones automáticas."""
from __future__ import annotations

import time
from typing import Any

from harness.contracts import Action, AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.detection_runner_p4 import run_detection_p4


class FakeAdapter:
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self, name: str, payload: dict[str, Any]) -> None:
        self.name = name
        self.payload = payload
        self.calls = 0

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        self.calls += 1
        return {**self.payload, "target": target}


def setup(*, approve: bool = False, outside: bool = False, zap: dict[str, Any] | None = None,
          nuclei: dict[str, Any] | None = None) -> tuple[Harness, ScopeToken, FakeAdapter, FakeAdapter]:
    now = time.time()
    token = ScopeToken("lab-p4", (), ("dvwa.lab.test",), now - 10, now + 60, Phase.ANALYZE)
    z = FakeAdapter("zap.baseline_scan", zap or {"tool": "zap", "format": "json", "alerts": []})
    n = FakeAdapter("nuclei.safe_templates", nuclei or {"tool": "nuclei", "format": "jsonl", "lines": []})
    guard = Guard({Phase.ANALYZE: {"zap.baseline_scan", "nuclei.safe_templates"}}, engagement_id="lab-p4")
    if approve:
        for capability in ("zap.baseline_scan", "nuclei.safe_templates"):
            guard.approve(capability, "example.com" if outside else "dvwa.lab.test")
    harness = Harness(guard, AuditLog(), {z.name: z, n.name: n}, KillSwitch())
    return harness, token, z, n


def test_sin_aprobacion_no_ejecuta() -> None:
    harness, token, z, n = setup()
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, out.rounds) == ("PENDING_HITL", 0)
    assert z.calls == n.calls == 0
    assert harness.audit.entries[-1]["result"] == "PENDING_HITL"


def test_fuera_alcance_bloqueado_aunque_aprobado_en_otro_objetivo() -> None:
    harness, token, z, n = setup(approve=True)
    out = run_detection_p4(harness, token, "example.com", candidate_count=1)
    assert (out.status, z.calls, n.calls) == ("BLOCKED", 0, 0)
    assert harness.audit.entries[-1]["result"] == "BLOCKED"


def test_sin_candidatos_no_llama_herramientas() -> None:
    harness, token, z, n = setup(approve=True)
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=0)
    assert out.status == "STOP_INCONCLUSIVE"
    assert z.calls == n.calls == 0


def test_dos_rondas_vacias_inconclusas() -> None:
    harness, token, z, n = setup(approve=True)
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, out.reason, out.rounds) == ("STOP_INCONCLUSIVE", "two_rounds_without_evidence", 2)
    assert z.calls == n.calls == 1
    assert len(harness.audit.entries) == 2


def test_evidencia_zap_no_confirma_automaticamente() -> None:
    harness, token, _z, n = setup(approve=True, zap={"tool": "zap", "format": "json", "alerts": [{"alert": "CSP Header Not Set"}]})
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, out.rounds, len(out.evidence)) == ("STOP_COMPLETE", 1, 1)
    assert n.calls == 0
    assert "confirmed" not in str(out).lower()


def test_malformed_output_solicita_revision() -> None:
    harness, token, z, n = setup(approve=True, zap={"tool": "zap", "format": "json", "alerts": "no-array"})
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, out.reason) == ("PENDING_HITL", "invalid_evidence_schema")
    assert z.calls == 1 and n.calls == 0


def test_capacidad_no_aprobada_no_se_ejecuta() -> None:
    harness, token, z, n = setup(approve=True)
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1,
                           capabilities=frozenset({"unknown.tool"}))
    assert out.status == "PENDING_HITL"
    assert z.calls == n.calls == 0


def test_kill_switch_impide_ejecucion() -> None:
    harness, token, z, n = setup(approve=True)
    harness.killswitch.engaged = True
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, z.calls, n.calls) == ("ABORTED", 0, 0)
    assert harness.audit.entries[-1]["result"] == "ABORTED"


def test_nuclei_jsonl_produce_observacion_sin_confirmacion() -> None:
    harness, token, _z, _n = setup(approve=True, nuclei={"tool": "nuclei", "format": "jsonl", "lines": ['{"template-id":"lab-header"}']})
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1)
    assert (out.status, out.rounds) == ("STOP_COMPLETE", 2)
    assert len(out.evidence) == 1


def test_maximo_una_ronda_con_tope_uno() -> None:
    harness, token, z, n = setup(approve=True)
    out = run_detection_p4(harness, token, "dvwa.lab.test", candidate_count=1, max_rounds=1)
    assert (out.status, out.reason, out.rounds) == ("STOP_INCONCLUSIVE", "iteration_limit", 1)
    assert z.calls == 1 and n.calls == 0
