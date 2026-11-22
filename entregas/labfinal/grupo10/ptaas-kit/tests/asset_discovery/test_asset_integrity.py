"""Spec asset-discovery — Requirements nuevos (Scenario negativo de seguridad).

Requirement: "Deduplicación de activos descubiertos".
Scenario negativo: activo repetido
  GIVEN un activo ya presente en el inventario
  WHEN el recon lo vuelve a proponer (otra herramienta de origen)
  THEN no se incorpora dos veces y no se re-sondea

Requirement: "Dirección de activo obligatoria".
Scenario negativo: activo sin dirección
  GIVEN un activo propuesto sin `address`
  WHEN se intenta incorporarlo al grafo
  THEN se rechaza por schema inválido
"""
import pytest

from harness.schemas import Asset, SchemaError, dedupe_assets


def test_activo_repetido_no_se_incorpora_dos_veces():
    a1 = Asset("a1", "host", "10.0.0.5", source_tool="nmap.service_scan")
    a2 = Asset("a2", "host", "10.0.0.5", source_tool="httpx.probe")  # mismo (tipo, dirección)
    assert len(dedupe_assets([a1, a2])) == 1


def test_dedupe_conserva_activos_distintos():
    a1 = Asset("a1", "host", "10.0.0.5", source_tool="nmap.service_scan")
    a2 = Asset("a2", "host", "10.0.0.6", source_tool="nmap.service_scan")
    assert len(dedupe_assets([a1, a2])) == 2


def test_activo_sin_direccion_se_rechaza():
    with pytest.raises(SchemaError):
        Asset("a1", "host", "", source_tool="nmap.service_scan")
