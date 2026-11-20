"""Spec asset-discovery — Requirement "Respeto del rate limit".

Scenario: ráfaga de sondeos
  GIVEN un límite de 5 rps por target
  WHEN el adaptador intenta emitir más de 5 solicitudes por segundo
  THEN el adaptador se auto-limita y no excede el umbral
"""
from harness.adapters.common import RateLimiter, rate_limiter_from_policy


def test_rafaga_supera_umbral_se_autolimita():
    rl = RateLimiter(rps=5)
    objetivo = "10.0.0.5"
    assert all(rl.allow(objetivo, now=0.0) for _ in range(5))   # 5 en el mismo segundo
    assert rl.allow(objetivo, now=0.0) is False                 # la 6ª se frena
    assert rl.allow(objetivo, now=1.01) is True                 # pasada la ventana, de nuevo


def test_el_limite_es_por_target():
    rl = RateLimiter(rps=5)
    for _ in range(5):
        rl.allow("10.0.0.5", now=0.0)
    assert rl.allow("10.0.0.6", now=0.0) is True                # otro target, su propio cubo


def test_el_tope_sale_de_policy():
    assert rate_limiter_from_policy().rps == 5
