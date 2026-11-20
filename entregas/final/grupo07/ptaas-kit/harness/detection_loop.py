"""Loop B: analiza con ZAP baseline y Nuclei allow-listed, luego frena sin evidencia."""
from __future__ import annotations

import json

from harness.contracts import Action, Harness, Phase, ScopeToken
from harness.loops import decide_detection
from harness.policy_loader import load_policy
from harness.schemas import CandidateFinding, PrioritizedVuln, priority_score


class DetectionLoop:
    def __init__(self, harness: Harness, max_iterations: int | None = None):
        self.harness = harness
        configured = load_policy()["limits"]["max_loop_iterations"]["detection"]
        self.max_iterations = max_iterations or configured

    def analyze(self, finding: CandidateFinding, target: str, token: ScopeToken,
                asset_criticality: int | None = None) -> PrioritizedVuln:
        if token.phase != Phase.ANALYZE:
            raise ValueError("loop B requiere un token ANALYZE")
        known: set[str] = set()
        relevant_refs: set[str] = set()
        history: list[int] = []
        reason = "tope de iteraciones alcanzado"
        status = "inconclusive"

        for _iteration in range(1, self.max_iterations + 1):
            zap = self.harness.invoke(
                "vuln_analysis", Action("zap.baseline_scan", Phase.ANALYZE), target, token
            )
            nuclei = self.harness.invoke(
                "vuln_analysis", Action("nuclei.safe_templates", Phase.ANALYZE), target, token
            )
            current: set[str] = set()
            matched = False
            for alert in zap.get("alerts", []):
                reference = str(alert.get("id") or alert.get("alertRef") or
                                alert.get("alert") or "alert")
                current.add(f"zap:{reference}")
                matched = matched or alert.get("finding_id") == finding.id
            for line in nuclei.get("lines", []):
                result = json.loads(line)
                reference = str(result.get("template-id") or result.get("templateID") or "template")
                where = str(result.get("matched-at") or target)
                current.add(f"nuclei:{reference}@{where}")
                matched = matched or result.get("finding-id") == finding.id
            new_refs = current - known
            known.update(current)
            relevant_refs.update(current)
            history.append(len(new_refs))
            if matched:
                status = "confirmed"
                reason = "la herramienta aportó evidencia asociada explícitamente al candidato"
                break
            decision = decide_detection(history, self.max_iterations)
            if decision.decision == "stop":
                reason = decision.reason
                break

        cvss_v4 = finding.cvss_v4_score
        priority = priority_score(cvss_v4, finding.epss, asset_criticality)
        refs = tuple(sorted(set(finding.evidence_refs) | relevant_refs))
        return PrioritizedVuln(finding.id, status, reason, refs, cvss_v4, priority)
