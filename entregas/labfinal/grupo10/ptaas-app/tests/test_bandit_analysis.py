import json

import pytest

from runtime.bandit_input import BanditInputError, load_report
from runtime.demo import run_demo
from runtime.providers import FixtureProvider


def sample_report(tmp_path):
    report = tmp_path / "bandit.json"
    report.write_text(json.dumps({"errors": [], "results": [{
        "test_id": "B603", "issue_severity": "LOW", "issue_confidence": "HIGH",
        "filename": "SECRET_PATH", "code": "SECRET_CODE", "issue_text": "SECRET_MESSAGE",
    }]}), encoding="utf-8")
    return report


def test_analysis_only_receives_metadata(tmp_path):
    class InspectProvider(FixtureProvider):
        def generate(self, prompt):
            assert "SECRET" not in prompt
            return super().generate(prompt)

    evidence = load_report(sample_report(tmp_path))
    result = run_demo(InspectProvider(), tmp_path / "audit.db", approved=True, bandit=evidence)
    assert result["agent_roles"][-2:] == ["analysis", "reporting"]
    assert result["model_calls"] == 6
    assert result["bandit_analysis"]["reviews"][0]["status"] == "inconclusive"
    assert result["bandit_analysis"]["reviews"][0]["id"] == "bandit-1"
    assert result["draft"]["findings"] == []


def test_analysis_rejects_unknown_ids(tmp_path):
    class InventedAlert(FixtureProvider):
        def generate(self, prompt):
            if json.loads(prompt)["agent"] == "analysis":
                return '{"reviews":[{"id":"bandit-999","status":"needs_review","recommendation":"Revisar"}]}'
            return super().generate(prompt)

    evidence = load_report(sample_report(tmp_path))
    result = run_demo(InventedAlert(), tmp_path / "audit.db", approved=True, bandit=evidence)
    assert result["reason"] == "invalid_agent_output"
    assert "bandit_analysis" not in result and "draft" not in result


def test_incomplete_bandit_report_rejected(tmp_path):
    report = tmp_path / "invalid.json"
    report.write_text('{"errors":[{}],"results":[]}', encoding="utf-8")
    with pytest.raises(BanditInputError, match="incomplete"):
        load_report(report)
