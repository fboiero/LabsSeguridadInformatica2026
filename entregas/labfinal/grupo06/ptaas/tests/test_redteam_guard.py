"""Red team del guard — A1 a A10 de `docs/desafios-extension.md`.

Cada test es un intento adversarial. Se escribieron antes de las correcciones;
los que fallaron en rojo están marcados en `entrega/red-team.md` con su bypass.
"""
from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from harness.adapters.common import (
    InvalidTarget,
    RedirectPolicy,
    validate_parameters,
    validate_target,
)
from harness.contracts import (
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    Result,
    ScopeToken,
    ScopeViolation,
)
from harness.policy_loader import phase_allowlist
from harness.roe import RoEValidationError, parse
from tests.conftest import FakeAdapter, act, make_token


def _roe(cidrs=("10.99.0.0/24",), domains=("dvwa.lab.test",), **overrides):
    data = {
        "engagement_id": "eng-audit",
        "approver": "Responsable del laboratorio",
        "approval_ref": "ticket-AUDIT",
        "signed_at": "2026-11-11T09:00:00Z",
        "window": {"start": "2026-11-11T09:00:00Z", "end": "2026-11-11T18:00:00Z"},
        "scope": {"cidrs": list(cidrs), "domains": list(domains)},
        "exclusions": {"cidrs": [], "domains": []},
        "emergency_contacts": ["responsable-lab@example.test"],
    }
    data.update(overrides)
    return parse(data)


# A1 — hostname con mayúsculas, punto final o espacios


@pytest.mark.parametrize("target", [
    "DVWA.LAB.TEST",
    "dvwa.lab.test.",
    "  dvwa.lab.test  ",
    "DvWa.LaB.TeSt.",
])
def test_a1_hostname_se_normaliza_antes_de_decidir(env, target):
    h, *_ = env
    token = make_token(domains=("dvwa.lab.test",))
    assert h.invoke("recon", act("httpx.probe", Phase.RECON), target, token)["ok"]


# A2 — sufijo engañoso


@pytest.mark.parametrize("target", [
    "evil-lab.example.test",
    "notlab.example.test",
    "lab.example.test.evil.test",
    "example.test",
])
def test_a2_sufijo_enganoso_se_bloquea(env, target):
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), target, make_token())


# A3 — IPv6 y IPv4 mapeadas a IPv6


def test_a3_ipv4_mapeada_a_ipv6_se_evalua_contra_los_cidr_autorizados(env):
    h, *_ = env
    token = make_token()
    assert h.invoke("recon", act("httpx.probe", Phase.RECON), "::ffff:10.0.0.5", token)["ok"]
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "::ffff:10.0.1.5", token)


def test_a3_ipv6_se_evalua_contra_su_cidr(env):
    h, *_ = env
    token = make_token(cidrs=("fd00:abcd::/64",))
    assert h.invoke("recon", act("httpx.probe", Phase.RECON), "fd00:abcd::5", token)["ok"]
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "fd00:beef::5", token)


# A4 — hostname autorizado que resuelve a una IP fuera de alcance


def _harness_con_resolver(resolver):
    guard = Guard(phase_allowlist(), resolver=resolver)
    audit = AuditLog()
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}
    return Harness(guard, audit, adapters, KillSwitch()), audit


def test_a4_hostname_que_resuelve_fuera_de_alcance_se_bloquea():
    h, audit = _harness_con_resolver(lambda host: ["10.0.1.50"])
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", make_token())
    assert audit.entries[-1]["result"] == Result.BLOCKED.value


def test_a4_hostname_que_resuelve_dentro_de_alcance_se_permite():
    h, _ = _harness_con_resolver(lambda host: ["10.0.0.5", "10.0.0.6"])
    assert h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test",
                    make_token())["ok"]


def test_a4_si_una_sola_direccion_queda_fuera_se_bloquea():
    h, _ = _harness_con_resolver(lambda host: ["10.0.0.5", "10.0.1.50"])
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "app.lab.example.test", make_token())


# A5 — redirecciones HTTP hacia otro host


def test_a5_redireccion_al_mismo_host_relativa_se_permite():
    p = RedirectPolicy(allowed_domains=("dvwa.lab.test",))
    assert p.check("http://dvwa.lab.test/login", "/dashboard") == "http://dvwa.lab.test/dashboard"


@pytest.mark.parametrize("location", [
    "http://evil.example.test/",
    "//evil.example.test/x",
    "https://dvwa.lab.test.evil.example.test/",
    "http://usuario:clave@dvwa.lab.test/",
    "file:///etc/passwd",
])
def test_a5_redireccion_peligrosa_se_rechaza(location):
    p = RedirectPolicy(allowed_domains=("dvwa.lab.test",))
    with pytest.raises(InvalidTarget):
        p.check("http://dvwa.lab.test/", location)


def test_a5_redireccion_a_subdominio_autorizado_se_permite():
    p = RedirectPolicy(allowed_domains=("dvwa.lab.test",))
    assert p.check("http://dvwa.lab.test/", "http://app.dvwa.lab.test/x") == \
        "http://app.dvwa.lab.test/x"


# A6 — token reutilizado en otra fase o engagement


def test_a6_token_de_otra_fase_se_bloquea(env):
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("analysis", act("poc_catalog.run_parametrized", Phase.VALIDATE),
                 "10.0.0.5", make_token(phase=Phase.ANALYZE))


def test_a6_token_de_otro_engagement_se_bloquea():
    guard = Guard(phase_allowlist(), engagement_id="eng-1")
    audit = AuditLog()
    adapters = {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}
    h = Harness(guard, audit, adapters, KillSwitch())
    token = make_token()
    ajeno = ScopeToken("eng-2", token.allowed_cidrs, token.allowed_domains,
                       time.time() - 5, time.time() + 600, Phase.RECON)
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", ajeno)
    assert audit.entries[-1]["result"] == Result.BLOCKED.value


# A7 — ventanas con zonas horarias distintas


def test_a7_zonas_horarias_distintas_comparan_en_utc():
    a = _roe(window={"start": "2026-11-11T22:00:00-03:00",
                     "end": "2026-11-11T23:00:00-03:00"})
    b = _roe(window={"start": "2026-11-12T01:00:00Z",
                     "end": "2026-11-12T02:00:00Z"})
    assert a.window_start == b.window_start
    assert a.window_end == b.window_end


def test_a7_ventana_que_parece_valida_en_local_pero_es_invertida_en_utc():
    with pytest.raises(RoEValidationError, match="ventana"):
        _roe(window={"start": "2026-11-11T23:30:00-03:00",
                     "end": "2026-11-12T02:30:00Z"})


# A8 — CIDR demasiado amplio en el RoE


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "8.8.8.0/24", "::/0"])
def test_a8_cidr_amplio_o_publico_se_rechaza(cidr):
    with pytest.raises(RoEValidationError, match="CIDR"):
        _roe(cidrs=(cidr,), domains=())


# A9 — argumentos inyectados vía target o parameters


@pytest.mark.parametrize("target", [
    "10.0.0.5;id",
    "10.0.0.5 -A",
    "-iL /etc/hosts",
    "10.0.0.5\n--script=x",
    "$(id)",
])
def test_a9_target_con_argumentos_se_rechaza(target):
    with pytest.raises(InvalidTarget):
        validate_target(target)


@pytest.mark.parametrize("params", [
    {"--script": "vuln"},
    {"ports": "80; rm -rf /"},
    {"ports": "80 81"},
    {"rate": "5\n--script=x"},
    {"target": "-oN /tmp/x"},
])
def test_a9_parameters_con_argumentos_se_rechaza(params):
    with pytest.raises(InvalidTarget):
        validate_parameters(params)


def test_a9_parameters_inertes_se_aceptan():
    assert validate_parameters({"ports": "80,443", "rate": 5}) == {"ports": "80,443", "rate": "5"}


# A10 — escritura concurrente en la bitácora


def _verificar_cadena_contracts(entries: list[dict]) -> None:
    prev = "GENESIS"
    for e in entries:
        assert e["prev"] == prev
        body = {k: v for k, v in e.items() if k != "hash"}
        assert hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() == e["hash"]
        prev = e["hash"]


def test_a10_escritura_concurrente_conserva_la_cadena():
    audit = AuditLog()
    token = make_token()
    action = act("httpx.probe", Phase.RECON)

    def writer(i):
        for _ in range(25):
            audit.record(f"agent-{i}", action, "10.0.0.5", token, Result.OK)

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(writer, range(10)))

    assert len(audit.entries) == 250
    _verificar_cadena_contracts(audit.entries)
