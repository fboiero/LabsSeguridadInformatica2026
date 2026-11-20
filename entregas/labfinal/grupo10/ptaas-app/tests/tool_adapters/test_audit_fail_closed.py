import sqlite3
from dataclasses import replace

import pytest

from harness.audit import AuditLog, AuditRecoveryRequired, AuditUnavailable
from harness.contracts import Harness, KillSwitchEngaged, ToolExecutionError


def test_intento_confirmado_antes_de_ejecutar(env, token, action):
    harness, audit, adapter, _, _ = env
    assert harness.invoke("recon", action, "dvwa.lab.test", token) == {"simulated": True}
    assert adapter.calls == 1
    assert [entry["event"] for entry in audit.entries] == ["ATTEMPT", "DECISION"]
    assert audit.entries[-1]["result"] == "OK"
    assert len({entry["invocation_id"] for entry in audit.entries}) == 1


def test_no_se_puede_guardar_intento_no_ejecuta(env, token, action, monkeypatch):
    harness, audit, adapter, _, _ = env
    def fail():
        raise sqlite3.OperationalError("synthetic")
    monkeypatch.setattr(audit, "_commit", fail)
    with pytest.raises(AuditUnavailable):
        harness.invoke("recon", action, "dvwa.lab.test", token)
    assert adapter.calls == 0


def test_sin_aprobacion_no_ejecuta(env, token, action):
    harness, audit, adapter, _, _ = env
    result = harness.invoke("recon", replace(action, requires_human_approval=True), "dvwa.lab.test", token)
    assert result == {"status": "PENDING_HITL"}
    assert audit.entries[-1]["result"] == "PENDING_HITL"
    assert adapter.calls == 0


def test_kill_switch_primero(env, token, action):
    harness, audit, adapter, _, switch = env
    switch.engaged = True
    with pytest.raises(KillSwitchEngaged):
        harness.invoke("recon", action, "dvwa.lab.test", token)
    assert audit.entries[-1]["result"] == "ABORTED"
    assert adapter.calls == 0


def test_error_adaptador_se_registra_sin_reintento(env, token, action):
    harness, audit, adapter, _, _ = env
    adapter.fail = True
    with pytest.raises(ToolExecutionError):
        harness.invoke("recon", action, "dvwa.lab.test", token)
    assert adapter.calls == 1
    assert [entry["event"] for entry in audit.entries] == ["ATTEMPT", "TOOL_ERROR"]
    assert audit.entries[-1]["result"] is None


@pytest.mark.parametrize("tool_fails", [False, True])
def test_fallo_final_o_doble_suspende(env, token, action, monkeypatch, tool_fails):
    harness, audit, adapter, _, _ = env
    adapter.fail = tool_fails
    original_commit = audit._commit
    commits = 0
    def fail_terminal():
        nonlocal commits
        commits += 1
        if commits == 2:
            raise sqlite3.OperationalError("synthetic")
        original_commit()
    monkeypatch.setattr(audit, "_commit", fail_terminal)
    with pytest.raises(AuditUnavailable):
        harness.invoke("recon", action, "dvwa.lab.test", token)
    with pytest.raises(AuditUnavailable):
        harness.invoke("recon", action, "dvwa.lab.test", token)
    assert adapter.calls == 1
    assert [entry["event"] for entry in audit.entries] == ["ATTEMPT"]


def test_reinicio_con_intento_pendiente(env, token, action):
    _harness, audit, adapter, guard, switch = env
    audit.record_event("recon", action, "dvwa.lab.test", token, "ATTEMPT", "unresolved")
    path = audit.path
    audit.close()
    with AuditLog(path, token.engagement_id) as reopened, pytest.raises(AuditRecoveryRequired):
        Harness(guard, reopened, {adapter.name: adapter}, switch)
    assert adapter.calls == 0


@pytest.mark.parametrize("case", ["scope", "expired", "phase", "destructive", "missing_adapter"])
def test_controles_originales_se_conservan(env, token, action, case):
    from harness.contracts import Phase, ScopeViolation
    harness, audit, adapter, _, _ = env
    target = "dvwa.lab.test"
    if case == "scope":
        target = "outside.invalid"
    elif case == "expired":
        token = replace(token, window_end=0)
    elif case == "phase":
        action = replace(action, phase=Phase.ANALYZE)
    elif case == "destructive":
        action = replace(action, destructive=True)
    else:
        harness.tools.clear()
    with pytest.raises(ScopeViolation):
        harness.invoke("recon", action, target, token)
    assert adapter.calls == 0
    assert audit.entries[-1]["result"] == "BLOCKED"
