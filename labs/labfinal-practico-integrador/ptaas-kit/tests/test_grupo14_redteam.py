"""Red-team del guard (grupo 14): cada test intenta un bypass y verifica el control.

Incluye un HALLAZGO real (el harness MVP no aplica los topes de iteración de
`policy.yaml`) y su CORRECCIÓN (`harness.limits.GuardedHarness`).
"""
import pytest

from harness.contracts import Phase, ScopeViolation
from harness.limits import GuardedHarness, LimitExceeded
from tests.conftest import act, make_token


# --- Intentos de evasión de alcance que DEBEN bloquearse ---

def test_sufijo_enganoso_no_entra_en_alcance(env, token):
    """'xlab.example.test' comparte el sufijo textual pero no es subdominio de
    'lab.example.test'. No debe pasar el chequeo de alcance."""
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "xlab.example.test", token)


def test_dominio_con_mayusculas_y_punto_final_se_normaliza(env, token):
    """Un subdominio legítimo en MAYÚSCULAS y con punto final (FQDN absoluto) debe
    normalizarse y entrar en alcance."""
    h, _, audit, _, adapters = env
    out = h.invoke("recon", act("httpx.probe", Phase.RECON), "APP.LAB.EXAMPLE.TEST.", token)
    assert out["ok"] and audit.entries[-1]["result"] == "OK"


def test_ip_de_otra_red_privada_se_bloquea(env, token):
    h, *_ = env
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "192.168.0.5", token)


# --- HALLAZGO: el harness MVP no aplica el tope de iteraciones de policy.yaml ---

def test_hallazgo_harness_mvp_no_aplica_tope_de_iteraciones(env, token):
    h, _, _, _, adapters = env
    for _ in range(50):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    # El MVP deja pasar las 50: ni rate_limit ni max_loop_iterations se hacen cumplir.
    assert adapters["httpx.probe"].calls.count("10.0.0.5") == 50


# --- CORRECCIÓN: GuardedHarness hace cumplir el tope y lo registra ---

def test_correccion_guarded_harness_bloquea_pasado_el_tope(env, token):
    h, _, audit, _, adapters = env
    g = GuardedHarness(h, max_iterations_per_target=3)
    for _ in range(3):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    with pytest.raises(LimitExceeded):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    assert adapters["httpx.probe"].calls.count("10.0.0.5") == 3   # la 4.a no corrió
    assert audit.entries[-1]["result"] == "BLOCKED"               # y quedó en bitácora


def test_guarded_harness_cuenta_por_objetivo(env, token):
    """El tope es por (acción, objetivo): otro objetivo tiene su propio contador."""
    h, *_ = env
    g = GuardedHarness(h, max_iterations_per_target=1)
    g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.6", token)  # distinto target: OK
    with pytest.raises(LimitExceeded):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
