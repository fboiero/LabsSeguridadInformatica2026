import time

from harness.asset_graph import AssetGraph
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.policy_loader import phase_allowlist
from harness.recon_loop import ReconLoop


class FixtureAdapter:
    def __init__(self, name, output):
        self.name = name
        self.allowed_phases = (Phase.RECON,)
        self.destructive = False
        self.output = output
        self.calls = []

    def run(self, action, target, token):
        self.calls.append(target)
        if callable(self.output):
            return self.output(target)
        return self.output


def make_harness(subfinder, httpx):
    audit = AuditLog()
    harness = Harness(Guard(phase_allowlist()), audit,
                      {"subfinder.enum": subfinder, "httpx.probe": httpx}, KillSwitch())
    now = time.time()
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("lab.example.test",),
                       now - 5, now + 600, Phase.RECON)
    return harness, audit, token


def test_loop_a_se_estabiliza_y_deja_fuera_de_scope_sin_adapter_activo():
    subfinder = FixtureAdapter("subfinder.enum", {
        "hosts": ["dvwa.lab.example.test", "otro.example.org"]
    })
    httpx = FixtureAdapter("httpx.probe", lambda target: {
        "assets": [{"host": target, "technologies": ["Apache 2.4.49"]}]
    })
    harness, audit, token = make_harness(subfinder, httpx)
    graph = AssetGraph()

    result = ReconLoop(harness, graph, max_iterations=5).run("lab.example.test", token)

    assert result.reason == "grafo estabilizado"
    assert subfinder.calls == ["lab.example.test", "dvwa.lab.example.test"]
    assert httpx.calls == ["lab.example.test", "dvwa.lab.example.test"]
    assert graph.get_by_address("otro.example.org").in_scope is False
    assert any(entry["target"] == "otro.example.org" and entry["result"] == "BLOCKED"
               for entry in audit.entries)


def test_loop_a_se_detiene_por_tope():
    count = {"n": 0}

    def discover(_target):
        count["n"] += 1
        return {"hosts": [f"h{count['n']}.lab.example.test"]}

    subfinder = FixtureAdapter("subfinder.enum", discover)
    httpx = FixtureAdapter("httpx.probe", {"assets": []})
    harness, _audit, token = make_harness(subfinder, httpx)

    result = ReconLoop(harness, AssetGraph(), max_iterations=2).run("lab.example.test", token)

    assert result.reason == "tope de iteraciones alcanzado"
    assert result.iterations == 2
    assert len(subfinder.calls) == 2


def test_loop_a_no_sondea_dos_veces_el_mismo_descubrimiento():
    subfinder = FixtureAdapter("subfinder.enum", {"hosts": ["dvwa.lab.example.test"]})
    httpx = FixtureAdapter("httpx.probe", {"assets": []})
    harness, _audit, token = make_harness(subfinder, httpx)

    ReconLoop(harness, AssetGraph(), max_iterations=4).run("lab.example.test", token)

    assert httpx.calls == ["lab.example.test", "dvwa.lab.example.test"]
