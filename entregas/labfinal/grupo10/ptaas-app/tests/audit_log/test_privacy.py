import json

import pytest

from harness.contracts import ScopeViolation, ToolExecutionError


def test_secreto_en_error_o_salida_no_se_persiste(env, token, action):
    harness, audit, adapter, _, _ = env
    adapter.fail = True
    with pytest.raises(ToolExecutionError) as error:
        harness.invoke("recon", action, "dvwa.lab.test", token)
    serialized = json.dumps(audit.entries) + str(error.value)
    assert "SECRET_SYNTHETIC_PASSWORD" not in serialized
    assert audit.entries[-1]["error_code"] == "adapter_failure"


def test_objetivo_invalido_con_credenciales(env, token, action):
    harness, audit, _, _, _ = env
    with pytest.raises(ScopeViolation) as error:
        harness.invoke("recon", action, "https://user:SECRET@dvwa.lab.test/", token)
    serialized = json.dumps(audit.entries) + str(error.value)
    assert "SECRET" not in serialized
    assert audit.entries[-1]["target"].startswith("invalid:")


def test_salida_exitosa_no_se_copia_a_bitacora(env, token, action, monkeypatch):
    harness, audit, adapter, _, _ = env
    monkeypatch.setattr(adapter, "run", lambda *args: {"body": "SECRET_SYNTHETIC_PASSWORD"})
    output = harness.invoke("recon", action, "dvwa.lab.test", token)
    assert "SECRET" in output["body"]
    assert "SECRET" not in json.dumps(audit.entries)
