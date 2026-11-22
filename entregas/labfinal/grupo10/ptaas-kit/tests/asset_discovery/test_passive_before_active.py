"""Spec asset-discovery — Requirement "Pasivo antes que activo".

Scenario: orden de técnicas
  GIVEN un dominio autorizado sin inventario previo
  WHEN comienza el relevamiento
  THEN las capabilities pasivas se ejecutan antes que las activas
"""
from harness.recon_order import ordered_recon, passive_before_active


def test_pasivas_se_ejecutan_antes_que_activas():
    orden = ordered_recon(["httpx.probe", "subfinder.enum", "nmap.service_scan"])
    assert orden[0] == "subfinder.enum"
    assert passive_before_active(orden)


def test_detecta_orden_invalido_activa_antes_de_pasiva():
    assert passive_before_active(["nmap.service_scan", "subfinder.enum"]) is False


def test_orden_estable_entre_activas():
    assert ordered_recon(["httpx.probe", "nmap.service_scan"]) == ["httpx.probe", "nmap.service_scan"]
