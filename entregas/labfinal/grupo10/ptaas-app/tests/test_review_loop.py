import json
from subprocess import CompletedProcess

import pytest

from runtime.review_loop import CASES, ReviewError, review, sandbox


class Decisions:
    name = "test"

    def __init__(self, *outputs):
        self.outputs = iter(outputs)
        self.inputs = []

    def generate(self, prompt):
        self.inputs.append(json.loads(prompt))
        return json.dumps(next(self.outputs))


def test_model_receives_new_evidence_between_rounds():
    agent = Decisions({"action": "request", "ref": "runtime"}, {"action": "finish", "ref": None})
    result = review("dvwa", agent)
    assert result["stop_reason"] == "agent_finished"
    assert agent.inputs[0]["seen"] == {"inventory": CASES["dvwa"]["inventory"]}
    assert agent.inputs[1]["seen"]["runtime"] == CASES["dvwa"]["runtime"]


@pytest.mark.parametrize(("outputs", "reason"), [
    ([{"action": "request", "ref": "inventory"}], "no_progress"),
    ([{"action": "request", "ref": "outside"}], "invalid_decision"),
    ([{"action": "escalate", "ref": None}], "agent_escalated"),
    ([{"action": "request", "ref": "runtime"}], "budget_exhausted"),
])
def test_stops_without_external_actions(outputs, reason):
    result = review("dvwa", Decisions(*outputs), max_rounds=1)
    assert result["state"] == "PENDING_HITL" and result["stop_reason"] == reason


def test_approval_is_bound_to_case_and_bytes(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Docker must not run without approval")

    monkeypatch.setattr("runtime.review_loop.subprocess.run", unexpected)
    result = review("dvwa")
    assert sandbox(result, None)["state"] == "PENDING_HITL"
    with pytest.raises(ReviewError):
        sandbox(result, "0" * 64)
    result["laboratory"] = "juice-shop"
    with pytest.raises(ReviewError):
        sandbox(result, result["approval_sha256"])


def test_docker_boundary_and_removal(monkeypatch):
    calls = []

    def fake(args, **kwargs):
        calls.append(args)
        stdout = '{"network_isolated":true,"checked":true}' if args[1] == "run" else ""
        return CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr("runtime.review_loop.subprocess.run", fake)
    result = review("dvwa")
    done = sandbox(result, result["approval_sha256"])
    assert done["container_removed"] and done["network_isolated"]
    assert calls[0][calls[0].index("--network") + 1] == "none"
    assert "--rm" in calls[0] and "--mount" not in calls[0]
    assert calls[1][:3] == ["docker", "ps", "-a"]
