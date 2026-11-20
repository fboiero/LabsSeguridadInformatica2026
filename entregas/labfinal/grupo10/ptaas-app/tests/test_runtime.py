import json

import pytest

from harness.audit import AuditLog
from runtime.demo import run_demo
from runtime.providers import FixtureProvider, OpenCodeProvider, ProviderError


def test_coordinacion_con_contextos_separados(tmp_path):
    provider = FixtureProvider()
    result = run_demo(provider, tmp_path / "audit.db", approved=True)
    assert result["agent_roles"] == ["orchestrator", "asset_discovery", "correlation", "reporting"]
    assert result["provider"] == "fixture"
    assert result["model_calls"] <= 6
    assert result["tool_calls"] == 1
    assert result["state"] == "PENDING_HITL"
    assert result["gate"] == "before_deliver"
    assert result["draft"]["simulated"] is True
    assert result["draft"]["findings"] == []
    with AuditLog(tmp_path / "audit.db", result["audit"]["engagement"]) as audit:
        assert audit.entries[-1]["action"] == "demo.pause"
        assert audit.entries[-1]["result"] == "PENDING_HITL"


def test_sin_aprobacion_cero_llamadas(tmp_path):
    provider = FixtureProvider()
    result = run_demo(provider, tmp_path / "audit.db", approved=False)
    assert result["state"] == "PENDING_HITL"
    assert result["model_calls"] == result["tool_calls"] == 0


class InvalidProvider(FixtureProvider):
    def generate(self, prompt):
        return "not-json SECRET_SYNTHETIC_PASSWORD"


def test_dos_invalidas_escalan_sin_filtrar(tmp_path):
    result = run_demo(InvalidProvider(), tmp_path / "audit.db", approved=True)
    assert result["state"] == "PENDING_HITL"
    assert result["model_calls"] == 2
    assert "SECRET" not in json.dumps(result)
    with AuditLog(tmp_path / "audit.db", result["audit"]["engagement"]) as audit:
        events = [event for event in audit.entries if event["action"] == "agent.invalid_output"]
    assert [event["result"] for event in events] == ["BLOCKED", "PENDING_HITL"]
    assert "SECRET" not in json.dumps(events)


class OutOfScopeProvider(FixtureProvider):
    def generate(self, prompt):
        data = json.loads(prompt)
        if data["agent"] == "asset_discovery":
            return json.dumps({"action": "httpx.probe", "target": "outside.invalid", "reason": "test"})
        return super().generate(prompt)


def test_propuesta_fuera_de_alcance_se_bloquea(tmp_path):
    result = run_demo(OutOfScopeProvider(), tmp_path / "audit.db", approved=True)
    assert result["state"] == "PENDING_HITL"
    assert result["tool_calls"] == 0
    assert result["reason"] == "scope_violation"


class InventedProvider(FixtureProvider):
    def generate(self, prompt):
        if json.loads(prompt)["agent"] == "correlation":
            return json.dumps({"candidates": [{"cve": "CVE-2099-9999"}], "reason": "invented"})
        return super().generate(prompt)


def test_candidato_sin_fuente_es_rechazado(tmp_path):
    result = run_demo(InventedProvider(), tmp_path / "audit.db", approved=True)
    assert result["state"] == "PENDING_HITL"
    assert "draft" not in result


def test_presupuesto_global_incluye_reintentos(tmp_path):
    result = run_demo(FixtureProvider(), tmp_path / "audit.db", approved=True, max_calls=1)
    assert result["state"] == "PENDING_HITL"
    assert result["model_calls"] == 1


class FailingProvider(FixtureProvider):
    def generate(self, prompt):
        if json.loads(prompt)["agent"] == "correlation":
            raise ProviderError("provider_unavailable SECRET_SYNTHETIC_PASSWORD")
        return super().generate(prompt)


def test_proveedor_no_disponible_persiste_resumen(monkeypatch, tmp_path):
    import sys

    from runtime.demo import main

    out = tmp_path / "run"
    monkeypatch.setattr(sys, "argv", ["demo", "--provider", "opencode", "--approve-fixture", "--output", str(out)])
    monkeypatch.setattr("runtime.demo.OpenCodeProvider", FailingProvider)
    assert main() == 2
    result = json.loads((out / "result.json").read_text(encoding="utf-8"))
    assert result["state"] == "FAILED" and result["reason"] == "provider_error"
    assert result["model_calls"] == 4
    assert result["agent_roles"] == ["orchestrator", "asset_discovery"]
    assert "SECRET" not in json.dumps(result)
    assert not (out / "draft.json").exists()
    with AuditLog(out / "audit.db", result["audit"]["engagement"]) as audit:
        assert audit.entries[-2]["action"] == "agent.provider_error"
        assert audit.entries[-2]["agent"] == "correlation"


def test_opencode_solo_generacion_stateless(monkeypatch, tmp_path):
    from subprocess import CompletedProcess
    calls = []
    executable = tmp_path / "opencode.exe"
    executable.touch()
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return CompletedProcess(argv, 0, '{"data":{"text":"{}"}}', "")
    monkeypatch.setattr("runtime.providers.subprocess.run", run)
    provider = OpenCodeProvider(executable=executable)
    assert provider.generate('{"agent":"analysis"}') == "{}"
    assert provider.generate('{"agent":"reporting"}') == "{}"
    assert provider.generate('{"agent":"orchestrator"}') == "{}"
    assert provider.generate('{"agent":"asset_discovery"}') == "{}"
    assert provider.generate('{"agent":"correlation"}') == "{}"
    assert provider.generate('{"agent":"attack_mapping"}') == "{}"
    argv, options = calls[0]
    assert argv[1:3] == ["api", "experimental.generate.text"]
    assert options["shell"] is False
    payload = json.loads(argv[-1])
    assert set(payload) == {"prompt", "model"}
    assert payload["model"] == {"providerID": "openai", "id": "gpt-6.2-astra"}
    assert [json.loads(call[0][-1])["model"]["id"] for call in calls] == [
        "gpt-6.2-astra", "gpt-6.2-sol", "gpt-6.2-sol", "gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.2-astra",
    ]


def test_opencode_no_expone_error_crudo(monkeypatch, tmp_path):
    from subprocess import CompletedProcess
    executable = tmp_path / "opencode.exe"
    executable.touch()
    monkeypatch.setattr(
        "runtime.providers.subprocess.run",
        lambda *args, **kwargs: CompletedProcess([], 1, "SECRET_STDOUT", "SECRET_STDERR"),
    )
    with pytest.raises(ProviderError) as error:
        OpenCodeProvider(executable=executable).generate('{"agent":"analysis"}')
    assert str(error.value) == "opencode_generation_failed (exit_code=1)"
