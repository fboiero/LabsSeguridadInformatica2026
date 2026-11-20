"""Red-team del guard (grupo 14): cada test intenta un bypass y verifica el control.

Incluye la caracterización del hallazgo (loops consultivos, sin enforcement a nivel
harness) y la corrección (`harness.limits.GuardedHarness`: tope de iteración de loop
y tope de invocaciones por objetivo).
"""
import pytest

from harness.contracts import Phase, ScopeViolation
from harness.limits import GuardedHarness, InvocationLimit, LoopIterationLimit
from harness.policy_loader import load_policy
from tests.conftest import act

POLICY = load_policy()


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


# --- Caracterización del HALLAZGO: los loops son consultivos, sin enforcement ---

def test_caracterizacion_sin_enforcement_a_nivel_harness(env, token):
    """Estado ACTUAL (no deseado): sobre el Harness pelado, 50 invocaciones a un
    mismo objetivo pasan sin tope, porque decide_*() es consultivo y nada lo fuerza.
    Este test deberá actualizarse cuando el enforcement se integre al harness."""
    h, _, _, _, adapters = env
    for _ in range(50):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    assert adapters["httpx.probe"].calls.count("10.0.0.5") == 50


# --- CORRECCIÓN 1: tope de iteraciones de loop a nivel harness (fiel a la spec) ---

def test_guarded_harness_rechaza_iteracion_pasado_el_tope(env):
    h, *_ = env
    g = GuardedHarness(h, POLICY)
    cap = POLICY["limits"]["max_loop_iterations"]["validation"]   # = 2
    for _ in range(cap):
        g.begin_iteration("validation")
    with pytest.raises(LoopIterationLimit):
        g.begin_iteration("validation")


# --- CORRECCIÓN 2: tope de invocaciones por objetivo (defensa en profundidad) ---

def test_guarded_harness_bloquea_invocaciones_pasado_el_tope(env, token):
    h, _, audit, _, adapters = env
    g = GuardedHarness(h, POLICY, max_invocations_per_target=3)
    for _ in range(3):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    with pytest.raises(InvocationLimit):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    assert adapters["httpx.probe"].calls.count("10.0.0.5") == 3   # la 4.a no corrió
    assert audit.entries[-1]["result"] == "BLOCKED"               # y quedó en bitácora


def test_tope_de_invocaciones_es_por_objetivo(env, token):
    h, *_ = env
    g = GuardedHarness(h, POLICY, max_invocations_per_target=1)
    g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
    g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.6", token)  # otro target: OK
    with pytest.raises(InvocationLimit):
        g.invoke("recon", act("httpx.probe", Phase.RECON), "10.0.0.5", token)
