import time

import pytest

from harness.audit import AuditLog
from harness.contracts import Action, Guard, Harness, KillSwitch, Phase, ScopeToken


@pytest.fixture
def token():
    now = time.time()
    return ScopeToken("eng-test", (), ("dvwa.lab.test",), now - 5, now + 600, Phase.RECON)


@pytest.fixture
def action():
    return Action("httpx.probe", Phase.RECON)


class FakeAdapter:
    name = "httpx.probe"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, audit):
        self.audit = audit
        self.calls = 0
        self.fail = False

    def run(self, action, target, token):
        assert self.audit.entries[-1]["event"] == "ATTEMPT"
        self.calls += 1
        if self.fail:
            raise RuntimeError("SECRET_SYNTHETIC_PASSWORD")
        return {"simulated": True}


@pytest.fixture
def env(tmp_path, token):
    audit = AuditLog(tmp_path / "audit.db", token.engagement_id)
    adapter = FakeAdapter(audit)
    guard = Guard({Phase.RECON: {"httpx.probe"}})
    switch = KillSwitch()
    harness = Harness(guard, audit, {adapter.name: adapter}, switch)
    yield harness, audit, adapter, guard, switch
    audit.close()
