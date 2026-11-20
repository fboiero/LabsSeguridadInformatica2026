import json

import pytest

from runtime.attack_pilot import PilotFixture, run_pilot
from runtime.providers import ProviderError


def test_pilot_decisions():
    result = run_pilot(PilotFixture())
    assert result["state"] == "PENDING_HITL"
    assert result["generation_attempts"] == 1 and result["model"] is None
    assert result["catalog"]["version"] == "17.1"
    assert [(r["status"], r["technique_id"]) for r in result["decisions"]] == [
        ("candidate", "T1110"), ("insufficient_evidence", None), ("insufficient_evidence", None),
    ]


@pytest.mark.parametrize("invalid", ["foreign_id", "foreign_evidence", "omit", "duplicate", "bandit", "single"])
def test_rejects_unsupported_decisions(invalid):
    class Bad(PilotFixture):
        def generate(self, prompt):
            response = json.loads(super().generate(prompt))
            rows = response["decisions"]
            if invalid == "foreign_id":
                rows[0]["technique_id"] = "T9999"
            elif invalid == "foreign_evidence":
                rows[0]["evidence_ids"] = ["evt-002"]
            elif invalid == "omit":
                rows.pop()
            elif invalid == "duplicate":
                rows[1] = rows[0]
            else:
                rows[2 if invalid == "bandit" else 1].update(status="candidate", technique_id="T1110")
            return json.dumps(response)

    result = run_pilot(Bad())
    assert result["reason"] == "invalid_agent_output"
    assert result["decisions"] == [] and result["generation_attempts"] == 1


def test_provider_failure_is_sanitized():
    class Broken(PilotFixture):
        def generate(self, prompt):
            raise ProviderError("SECRET_FIXTURE")

    result = run_pilot(Broken())
    assert result["state"] == "FAILED" and result["reason"] == "provider_error"
    assert "SECRET_FIXTURE" not in json.dumps(result)
