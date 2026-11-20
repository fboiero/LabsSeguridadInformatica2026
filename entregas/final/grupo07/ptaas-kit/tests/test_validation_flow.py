import copy

import pytest

from harness.approvals import ApprovalStore, subject_key
from harness.contracts import AuditLog, Harness, KillSwitch, Phase
from harness.policy_loader import phase_allowlist
from harness.sandbox import FixtureSender, RestrictedSender
from harness.tokens import EngagementGuard, TokenIssuer
from harness.validation import ValidationRequest, validate_finding
from tests.test_roe_tokens import roe_vigente


def setup():
    audit = AuditLog()
    h = Harness(EngagementGuard("eng-lab-001", phase_allowlist()), audit, {}, KillSwitch())
    token = TokenIssuer(roe_vigente(phases=["validate", "report"]), audit).issue(Phase.VALIDATE)
    request = ValidationRequest(
        "F-1",
        "dvwa.lab.test",
        "CWE-693",
        "POC-CSP-001",
        {"base_url": "http://dvwa.lab.test", "path": "/"},
    )
    return h, token, request, ApprovalStore()


def test_no_approval_never_creates_sender():
    h, t, r, a = setup()

    def forbidden():
        pytest.fail("sin gate no se crea sender")

    out = validate_finding(h, t, r, a, forbidden)
    assert out["status"] == "PENDING_HITL"
    assert h.audit.entries[-1]["result"] == "PENDING_HITL"


def test_approval_bound_to_parameters_and_finding():
    h, t, r, a = setup()
    a.decide(r.subject, "approve", "Fernando", "revisiÃ³n fixture")
    changed = copy.deepcopy(r)
    changed.params["path"] = "/otro"
    assert validate_finding(h, t, changed, a, FixtureSender)["status"] == "PENDING_HITL"
    assert not a.approved(subject_key({"otro": "hallazgo"}))


def test_expired_and_rejected_gate():
    a = ApprovalStore()
    a.decide("s", "approve", "Reviewer", "caso", ttl=-1)
    assert not a.approved("s")
    a.decide("s", "reject", "Reviewer", "rechazo")
    assert not a.approved("s")
    with pytest.raises(ValueError):
        a.decide("s", "approve", "", "")


def test_catalog_and_cwe_checked_before_sender():
    h, t, r, a = setup()
    r = ValidationRequest(r.id, r.asset, r.cwe, "POC-NEW", r.params)
    a.decide(r.subject, "approve", "Reviewer", "caso")
    assert validate_finding(h, t, r, a, FixtureSender)["status"] == "not_validated"


def test_success_records_selection_and_closes():
    h, t, r, a = setup()
    sender = FixtureSender()
    a.decide(r.subject, "approve", "Reviewer", "fixture explÃ­cita")
    out = validate_finding(h, t, r, a, lambda: sender)
    assert out["status"] == "validated" and out["mode"] == "fixture"
    assert out["attempts"] == 1 and sender.closed
    assert len(out["evidence_refs"]) == 1 and "POC-CSP-001" in h.audit.entries[-1]["agent"]


def test_failure_closes_and_records():
    h, t, r, a = setup()

    class Broken(FixtureSender):
        def __call__(self, *args):
            raise TimeoutError("fallÃ³")

    s = Broken()
    a.decide(r.subject, "approve", "Reviewer", "fixture")
    out = validate_finding(h, t, r, a, lambda: s)
    assert out["status"] == "not_validated" and s.closed
    assert h.audit.entries[-1]["result"] == "BLOCKED"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://dvwa.lab.test.evil.test",
        "http://user:pass@dvwa.lab.test",
        "file:///etc/passwd",
    ],
)
def test_sender_rejects_external_before_resolution(url):
    s = RestrictedSender(("dvwa.lab.test",), ("10.99.0.0/28",))
    with pytest.raises(ValueError):
        s("POC-CSP-001", {"base_url": url, "path": "/"})


def test_dns_external_no_connection(monkeypatch):
    monkeypatch.setattr(
        "harness.http_transport.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 80))],
    )
    s = RestrictedSender(("dvwa.lab.test",), ("10.99.0.0/28",))
    with pytest.raises(ValueError, match="DNS"):
        s("POC-CSP-001", {"base_url": "http://dvwa.lab.test", "path": "/"})


def test_sender_path_escape_and_closed():
    s = FixtureSender()
    s.close()
    with pytest.raises(ValueError):
        s("POC-CSP-001", {})
    s = RestrictedSender(("dvwa.lab.test",), ("10.99.0.0/28",))
    with pytest.raises(ValueError):
        s("POC-CSP-001", {"base_url": "http://dvwa.lab.test", "path": "//example.com"})


def test_loop_max_two_attempts():
    from harness.poc.catalog import ResponseRecord

    h, t, r, a = setup()
    calls = []

    class Protected(FixtureSender):
        def __call__(self, *args):
            calls.append(1)
            return ResponseRecord(200, {"Content-Security-Policy": "default-src 'self'"}, "")

    a.decide(r.subject, "approve", "Reviewer", "fixture")
    out = validate_finding(h, t, r, a, Protected)
    assert out["status"] == "not_validated" and out["attempts"] == 2 and len(calls) == 2


def test_execution_mode_bound_to_approval():
    h, t, r, a = setup()

    class Wrong(FixtureSender):
        mode = "sandbox"

    a.decide(r.subject, "approve", "Reviewer", "fixture")
    assert validate_finding(h, t, r, a, Wrong)["status"] == "not_validated"
    assert h.audit.entries[-1]["result"] == "BLOCKED"


def test_sender_redirect_no_follow(monkeypatch):
    monkeypatch.setattr(
        "harness.http_transport.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.99.0.2", 80))],
    )
    connections = []

    class Response:
        status = 302

    class Connection:
        def __init__(self, *a, **k):
            self.closed = False
            connections.append(self)

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            self.closed = True

    monkeypatch.setattr("harness.http_transport.http.client.HTTPConnection", Connection)
    s = RestrictedSender(("dvwa.lab.test",), ("10.99.0.0/28",))
    with pytest.raises(ValueError, match="redirecciones"):
        s("POC-CSP-001", {"base_url": "http://dvwa.lab.test", "path": "/"})
    assert len(connections) == 1 and connections[0].closed


def test_docker_rejects_noninternal_network(monkeypatch):
    import json
    from types import SimpleNamespace

    from harness.sandbox import DockerSender

    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(
            stdout=json.dumps(
                [{"Internal": False, "IPAM": {"Config": [{"Subnet": "10.99.0.0/28"}]}}]
            ),
            returncode=0,
        )

    monkeypatch.setattr("harness.sandbox.subprocess.run", run)
    with pytest.raises(ValueError, match="red Docker"):
        DockerSender(("dvwa.lab.test",), ("10.99.0.0/28",), "lab_lab")("POC-CSP-001", {})
    assert len(calls) == 1


def test_docker_cleanup_on_worker_failure(monkeypatch):
    import json
    from types import SimpleNamespace

    from harness.sandbox import DockerSender

    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[1] == "network":
            return SimpleNamespace(
                stdout=json.dumps(
                    [{"Internal": True, "IPAM": {"Config": [{"Subnet": "10.99.0.0/28"}]}}]
                ),
                returncode=0,
            )
        return SimpleNamespace(stdout="", returncode=1)

    monkeypatch.setattr("harness.sandbox.subprocess.run", run)
    sender = DockerSender(("dvwa.lab.test",), ("10.99.0.0/28",), "lab_lab")
    with pytest.raises(ValueError):
        sender("POC-CSP-001", {})
    assert calls[-1] == ["docker", "rm", "-f", sender.name]


def test_gate_cannot_be_reused_in_another_engagement():
    from dataclasses import replace

    h, t, r, a = setup()
    a.decide(r.subject, "approve", "Reviewer", "fixture")
    with pytest.raises(ValueError, match="engagement"):
        validate_finding(h, t, replace(r, engagement_id="other"), a, FixtureSender)
