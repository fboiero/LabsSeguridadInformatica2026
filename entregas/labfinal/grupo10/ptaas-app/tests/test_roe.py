from dataclasses import replace

import pytest

from harness.audit import AuditLog
from harness.contracts import Action, Guard, Harness, KillSwitch, ScopeViolation
from harness.roe import RoEError, TokenIssuer, parse_roe
from harness.types import Phase
from runtime.checkpoint import run_checkpoint

NOW = 1_767_225_600.0
RULES = """engagement_id: checkpoint-test
window_start: 2026-01-01T00:00:00Z
window_end: 2026-01-01T00:20:00Z
domains: [dvwa.lab.test]
cidrs: [10.20.0.0/24]
phases: [recon]
"""


@pytest.mark.parametrize(("old", "new"), [
    ("[dvwa.lab.test]", "[]\ncidrs: []"),  # duplicate key
    ("[10.20.0.0/24]", "[8.8.8.0/24]"),
    ("[10.20.0.0/24]", "[10.20.0.1/24]"),
    ("[10.20.0.0/24]", "[127.0.0.0/8]"),
    ("[10.20.0.0/24]", "[0.0.0.0/0]"),
    ("[dvwa.lab.test]", "[service.example.org]"),
    ("[dvwa.lab.test]", "['*.lab.test']"),
    ("[dvwa.lab.test]", "[dvwa.lab.test, dvwa.lab.test]"),
    ("[dvwa.lab.test]", "&dest [dvwa.lab.test]\nunknown: *dest"),
    ("00:20:00Z", "00:00:00Z"),
    ("00:20:00Z", "00:20:00+00:00"),
    ("[recon]", "[recon, recon]"),
    ("[recon]", "[invented]"),
])
def test_parser_rejects_bad_roe(old, new):
    with pytest.raises(RoEError):
        parse_roe(RULES.replace(old, new))


def test_parser_requires_scope():
    with pytest.raises(RoEError):
        parse_roe(RULES.replace("[dvwa.lab.test]", "[]").replace("[10.20.0.0/24]", "[]"))


def test_issuance_needs_operator_and_current_window():
    roe = parse_roe(RULES)
    for phase, approved, now in [(Phase.RECON, False, NOW), (Phase.VALIDATE, True, NOW),
                                 (Phase.RECON, True, NOW - 1), (Phase.RECON, True, roe.window_end)]:
        with pytest.raises(RoEError):
            TokenIssuer(roe, approved_fixture=approved, clock=lambda now=now: now).issue(phase)


def test_issuance_caps_ttl_and_uses_exclusive_end():
    roe = parse_roe(RULES)
    token = TokenIssuer(roe, approved_fixture=True, clock=lambda: NOW).issue(Phase.RECON)
    assert token.window_end == NOW + 300
    near_end = TokenIssuer(roe, approved_fixture=True, clock=lambda: roe.window_end - 1).issue(Phase.RECON)
    assert near_end.window_end == roe.window_end and not near_end.is_live(roe.window_end)


def test_checkpoint_bundle_no_approval_then_inert_run(tmp_path):
    no = run_checkpoint(tmp_path / "no", approved_fixture=False)
    assert no["state"] == "PENDING_HITL" and not (tmp_path / "no" / "audit.db").exists()
    yes = run_checkpoint(tmp_path / "yes", approved_fixture=True)
    assert [r["result"] for r in yes["decisions"]] == ["OK", "BLOCKED"]
    assert yes["fixture_calls"] == 1 and yes["audit"]["event_count"] == 3


def test_harness_only_trusts_one_live_issued_token(tmp_path, monkeypatch):
    monkeypatch.setattr("harness.types.time.time", lambda: NOW)
    issuer = TokenIssuer(parse_roe(RULES), approved_fixture=True, clock=lambda: NOW)
    previous = issuer.issue(Phase.RECON)
    token = issuer.issue(Phase.RECON)

    class Inert:
        name = "fixture.observe"
        allowed_phases = (Phase.RECON,)
        destructive = False
        calls = 0

        def run(self, action, target, token):
            self.calls += 1
            return {"synthetic": True}

    probe = Inert()
    action = Action(probe.name, Phase.RECON)
    with AuditLog(tmp_path / "audit.db", token.engagement_id) as audit:
        runner = Harness(Guard({Phase.RECON: {probe.name}}, issued_by=issuer.accepts),
                         audit, {probe.name: probe}, KillSwitch())
        assert runner.invoke("fixture", action, "dvwa.lab.test", token) == {"synthetic": True}
        for presented, host in [(replace(token), "dvwa.lab.test"), (previous, "dvwa.lab.test"),
                                (token, "child.dvwa.lab.test"), (token, "10.21.0.1")]:
            with pytest.raises(ScopeViolation):
                runner.invoke("fixture", action, host, presented)
        assert probe.calls == 1
        assert [event["result"] for event in audit.entries] == [None, "OK", *(["BLOCKED"] * 4)]
        assert audit.verify()["event_count"] == 6
