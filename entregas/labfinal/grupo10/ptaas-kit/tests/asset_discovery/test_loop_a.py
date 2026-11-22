"""Tests de integración del Loop A (`004-recon-loop-a`)."""
from __future__ import annotations

import json

from harness.adapters.common import RateLimiter
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase
from harness.engagement import Engagement, State
from harness.loop_a import AssetGraph, run_loop_a
from harness.policy_loader import phase_allowlist
from tests.conftest import make_token


def _build_harness(subfinder_outputs: dict[str, str], httpx_calls: list[str]):
    def sub_runner(argv, timeout):
        domain = argv[argv.index("-d") + 1]
        return subfinder_outputs.get(domain, "")

    def http_runner(argv, timeout):
        url = argv[argv.index("-u") + 1]
        httpx_calls.append(url)
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return json.dumps({
            "url": url,
            "host": host,
            "status_code": 200,
            "tech": ["Express"] if "juiceshop" in host else ["Apache", "PHP"],
        })

    guard = Guard(phase_allowlist())
    audit = AuditLog()
    ks = KillSwitch()
    adapters = {
        "subfinder.enum": SubfinderEnum(runner=sub_runner),
        "httpx.probe": HttpxProbe(runner=http_runner, rate_limiter=RateLimiter(rps=5), clock=lambda: 1.0),
    }
    return Harness(guard, audit, adapters, ks), audit


def test_loop_a_ordena_pasivo_antes_activo_deduplica_y_estabiliza():
    httpx_calls: list[str] = []
    harness, audit = _build_harness(
        {
            "dvwa.lab.test": '{"host":"dvwa.lab.test"}\n{"host":"dvwa.lab.test"}\n',
            "juiceshop.lab.test": '{"host":"juiceshop.lab.test"}\n',
        },
        httpx_calls,
    )
    eng = Engagement(roe_valid=True)
    eng.advance()
    eng.approve("first_active_action")
    eng.advance()
    assert eng.state == State.RECON

    token = make_token(phase=Phase.RECON, domains=("dvwa.lab.test", "juiceshop.lab.test"))
    result = run_loop_a(
        harness=harness,
        token=token,
        seed_domains=["dvwa.lab.test", "juiceshop.lab.test"],
        max_iterations=5,
    )

    assert result["stop_reason"] == "grafo estabilizado"
    assert len(result["assets"]) == 2
    # En iteración 1 sondea una vez cada host (sin duplicados); en iteración 2 no re-sondea.
    assert len(httpx_calls) == 2
    actions = [e["action"] for e in audit.entries if e["result"] == "OK"]
    assert actions[:2] == ["subfinder.enum", "subfinder.enum"]
    assert actions[2:] == ["httpx.probe", "httpx.probe"]
    assert all("evidence_ref" in e for e in audit.entries if e["result"] == "OK")
    assert audit.verify_chain()


def test_loop_a_registra_y_bloquea_descubrimiento_fuera_de_alcance():
    httpx_calls: list[str] = []
    harness, audit = _build_harness(
        {
            "dvwa.lab.test": (
                '{"host":"dvwa.lab.test"}\n'
                '{"host":"evil-dvwa.lab.test"}\n'
                '{"host":"cdn.tercero.org"}\n'
            ),
        },
        httpx_calls,
    )
    token = make_token(phase=Phase.RECON, domains=("dvwa.lab.test",))
    result = run_loop_a(
        harness=harness,
        token=token,
        seed_domains=["dvwa.lab.test"],
        max_iterations=5,
    )

    assert sorted(result["out_of_scope"]) == ["cdn.tercero.org", "evil-dvwa.lab.test"]
    assert all("dvwa.lab.test" in call for call in httpx_calls)
    assert not any("tercero.org" in call or "evil-dvwa" in call for call in httpx_calls)
    blocked_targets = {e["target"] for e in audit.entries if e["result"] == "BLOCKED"}
    assert {"cdn.tercero.org", "evil-dvwa.lab.test"} <= blocked_targets
    assert audit.verify_chain()


def test_loop_a_termina_por_tope_de_iteraciones():
    round_counter = [0]

    class DynamicSubfinder(SubfinderEnum):
        def run(self, action, target, token):
            round_counter[0] += 1
            host = f"s{round_counter[0]}.dvwa.lab.test"
            return {"tool": "subfinder", "target": target, "format": "jsonl", "hosts": [host]}

    guard = Guard(phase_allowlist())
    audit = AuditLog()
    harness = Harness(
        guard,
        audit,
        {
            "subfinder.enum": DynamicSubfinder(runner=lambda a, t: ""),
            "httpx.probe": HttpxProbe(
                runner=lambda a, t: json.dumps({"url": a[a.index("-u") + 1], "host": "s.dvwa.lab.test", "status_code": 200}),
                rate_limiter=RateLimiter(rps=10),
                clock=lambda: 1.0,
            ),
        },
        KillSwitch(),
    )
    token = make_token(phase=Phase.RECON, domains=("dvwa.lab.test",))
    result = run_loop_a(harness=harness, token=token, seed_domains=["dvwa.lab.test"], max_iterations=2)
    assert result["stop_reason"] == "tope de iteraciones alcanzado"
    assert len(result["snapshots"]) == 2
    assert isinstance(AssetGraph.from_dict({"assets": result["assets"], "out_of_scope": []}), AssetGraph)


def test_cli_run_loop_a_con_fixtures_genera_evidencia_verificable(tmp_path):
    from tools.run_loop_a import execute

    result = execute("fixture", tmp_path)
    assert result["audit_verified"] is True
    assert result["stop_reason"] == "grafo estabilizado"
    assert len(result["assets"]) == 2
    assert result["out_of_scope"] == ["cdn.tercero.org"]
    assert (tmp_path / "loop_a_result.json").exists()
    assert (tmp_path / "asset_graph.json").exists()
    assert (tmp_path / "audit_log.json").exists()
    assert "audit_verify=OK" in (tmp_path / "audit_verify.txt").read_text(encoding="utf-8")
