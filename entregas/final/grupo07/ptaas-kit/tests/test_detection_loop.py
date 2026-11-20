import time

from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.detection_loop import DetectionLoop
from harness.policy_loader import phase_allowlist
from harness.schemas import CandidateFinding


class NoEvidenceAdapter:
    name = "fixture"
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self):
        self.calls = 0

    def run(self, action, target, token):
        self.calls += 1
        return {"alerts": [], "lines": []}


def test_dos_iteraciones_sin_evidencia_quedan_inconclusas():
    zap, nuclei = NoEvidenceAdapter(), NoEvidenceAdapter()
    audit = AuditLog()
    harness = Harness(Guard(phase_allowlist()), audit,
                      {"zap.baseline_scan": zap, "nuclei.safe_templates": nuclei}, KillSwitch())
    now = time.time()
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("lab.test",),
                       now - 5, now + 600, Phase.ANALYZE)
    finding = CandidateFinding("f1", "a1", cwe="CWE-22", cve="CVE-2021-41773",
                               evidence_refs=["nvd:CVE-2021-41773"])

    result = DetectionLoop(harness, max_iterations=4).analyze(finding, "dvwa.lab.test", token)

    assert result.status == "inconclusive"
    assert "sin ganancia de información" in result.rationale
    assert result.priority is None
    assert zap.calls == nuclei.calls == 2
    assert len(audit.entries) == 4


def test_evidencia_explicita_asociada_al_hallazgo_lo_confirma():
    class MatchingAdapter(NoEvidenceAdapter):
        def run(self, action, target, token):
            self.calls += 1
            return {"alerts": [{"finding_id": "f1", "id": "zap-1", "cwe": "CWE-22"}],
                    "lines": []}

    adapters = {"zap.baseline_scan": MatchingAdapter(),
                "nuclei.safe_templates": NoEvidenceAdapter()}
    harness = Harness(Guard(phase_allowlist()), AuditLog(), adapters, KillSwitch())
    now = time.time()
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("lab.test",),
                       now - 5, now + 600, Phase.ANALYZE)
    finding = CandidateFinding("f1", "a1", cwe="CWE-22", evidence_refs=["nvd:fixture"])

    result = DetectionLoop(harness).analyze(finding, "dvwa.lab.test", token)

    assert result.status == "confirmed"
    assert "zap:zap-1" in result.evidence_refs
