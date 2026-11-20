import json

import pytest

from runtime.evidence_quality import (
    QualityError,
    analyse,
    bandit_context,
    benchmarks,
    fixture_decisions,
    parse_status,
)


def test_status_extracts_only_closed_labels():
    text = '\x1b[32m\u2713\x1b[0m R1 SECRET\n  \u00b7 R2 SECRET\n  \u2713 R3 SECRET\n  \u00b7 R4\n2/4\n'
    assert parse_status(text) == ["registered", "not_registered", "registered", "not_registered"]
    with pytest.raises(QualityError):
        parse_status(text.replace("2/4", "4/4"))


@pytest.mark.parametrize("mutation", ["reference", "claim", "duplicate", "omit", "raw"])
def test_analysis_rejects_bad_outputs(mutation):
    class Provider:
        name = "test"

        def generate(self, prompt):
            cases = json.loads(prompt)["cases"]
            output = fixture_decisions(cases)
            if mutation == "reference":
                output[0]["refs"] = ["different"]
            elif mutation == "claim":
                output[0]["assessment"] = "historical_record_only"
            elif mutation == "duplicate":
                output[1] = output[0]
            elif mutation == "omit":
                output.pop()
            else:
                output[0]["extra"] = "SECRET"
            return json.dumps(output)

    cases = [{"id": "R1", "signal": "missing", "refs": []}, {"id": "R2", "signal": "missing", "refs": []}]
    result = analyse(cases, Provider(), "quality_astra")
    assert result["status"] == "rejected" and result["decisions"] == []
    assert "SECRET" not in json.dumps(result)


def test_context_is_closed_and_bound_to_bandit_bytes(tmp_path):
    path = tmp_path / "context.json"
    hash_value = "2" * 64
    context = {"report_sha256": hash_value, "labels": {"bandit-1": "test_assertion"}}
    path.write_text(json.dumps(context), encoding="utf-8")
    assert bandit_context(path, hash_value, {"bandit-1"}) == {"bandit-1": "test_assertion"}
    with pytest.raises(QualityError):
        bandit_context(path, "3" * 64, {"bandit-1"})
    context["labels"]["bandit-1"] = "SECRET"
    path.write_text(json.dumps(context), encoding="utf-8")
    with pytest.raises(QualityError):
        bandit_context(path, hash_value, {"bandit-1"})


def test_partial_credit_does_not_publish_partial_analysis():
    class Partial:
        name = "test"

        def generate(self, prompt):
            cases = json.loads(prompt)["cases"]
            return json.dumps(fixture_decisions(cases[:1]))

    cases = [{"id": "R1", "signal": "historical_status", "refs": ["status", "record-1"]},
             {"id": "R2", "signal": "conflicting", "refs": ["status", "record-2"]}]
    result = analyse(cases, Partial(), "quality_astra")
    assert result["status"] == "rejected"
    assert result["valid_case_ids"] == ["R1"] and result["decisions"] == []


def test_comparison_uses_the_same_cases():
    class Replay:
        name = "test"

        def generate(self, prompt):
            cases = json.loads(prompt)["cases"]
            observed.append(cases)
            return json.dumps(fixture_decisions(cases))

    observed = []
    cases = benchmarks()
    for role in ("quality_astra", "quality_sol", "quality_terra"):
        result = analyse(cases, Replay(), role)
        assert len(result["valid_case_ids"]) == 20 and result["latency_ms"] >= 0 and result["cost_usd"] is None
    assert observed == [cases, cases, cases]
