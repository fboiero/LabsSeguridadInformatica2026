"""Change 005, tasks 2.3/2.4. Fixtures enteramente SINTÉTICOS; no hay escaneos."""
from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from harness.asset_graph import AssetGraph
from harness.correlator import correlate_assets
from harness.cwe_mapping import TaxonomyMapping, normalize_taxonomy
from harness.epss_snapshot import EPSSSnapshot
from harness.nvd_snapshot import NVDSnapshot

FAKE_CVE = "CVE-2099-0001"  # ID ficticio del test, no CVE publicado.


def fixtures() -> tuple[AssetGraph, NVDSnapshot, EPSSSnapshot]:
    graph = AssetGraph("eng-synthetic")
    graph.add({
        "type": "host", "address": "dvwa.lab.test", "source_tool": "fixture.recon",
        "technologies": ["fictional-app/1.0"],
    })
    nvd = NVDSnapshot(
        source="synthetic-test-fixture", retrieved_at=datetime(2026, 11, 18, tzinfo=UTC),
        snapshot_date=date(2026, 11, 18), sha256="a" * 64, status="current",
        records={FAKE_CVE: {"cve_id": FAKE_CVE, "product": "fictional-app",
                            "version": "1.0", "cwe": "unknown", "cvss_v4_score": None}},
    )
    epss = EPSSSnapshot(
        source="synthetic-test-fixture", retrieved_at=datetime(2026, 11, 18, tzinfo=UTC),
        snapshot_date=date(2026, 11, 18), sha256="b" * 64, status="current",
        records={FAKE_CVE: 0.2},
    )
    return graph, nvd, epss


def test_cwe_inexistente_permanece_unknown() -> None:
    assert normalize_taxonomy("unknown", {}) == ("unknown", None)
    assert normalize_taxonomy("CWE-9999", {}) == ("CWE-9999", None)


def test_attack_no_se_infiere_sin_fuente() -> None:
    with pytest.raises(ValueError, match="fuente"):
        TaxonomyMapping("CWE-9999", "T9999", "")
    assert normalize_taxonomy("CWE-9999", {})[1] is None


def test_mapeo_explicito_con_fuente() -> None:
    entry = TaxonomyMapping("CWE-9999", "T9999", "synthetic-test-fixture")
    assert normalize_taxonomy("CWE-9999", {"CWE-9999": entry}) == ("CWE-9999", "T9999")


def test_correlacion_exacta_devuelve_candidato_con_evidencia() -> None:
    graph, nvd, epss = fixtures()
    findings = correlate_assets(graph, nvd, epss)
    assert len(findings) == 1
    candidate = findings[0]
    assert candidate.cve == FAKE_CVE and candidate.epss == 0.2
    assert candidate.cwe == "unknown" and candidate.attack_technique is None
    assert any(ref.startswith("asset:") for ref in candidate.evidence_refs)
    assert any(ref.startswith("nvd:") for ref in candidate.evidence_refs)


def test_version_ambigua_no_crea_candidato() -> None:
    graph, nvd, epss = fixtures()
    asset = next(iter(graph.assets.values()))
    asset["technologies"] = ["fictional-app"]
    assert correlate_assets(graph, nvd, epss) == []


def test_snapshot_nvd_obsoleto_no_genera_candidatos() -> None:
    graph, nvd, epss = fixtures()
    object.__setattr__(nvd, "status", "stale")
    assert correlate_assets(graph, nvd, epss) == []


def test_snapshot_epss_obsoleto_no_inventa_probabilidad() -> None:
    graph, nvd, epss = fixtures()
    object.__setattr__(epss, "status", "stale")
    out = correlate_assets(graph, nvd, epss)
    assert len(out) == 1 and out[0].epss is None


def test_correlacion_no_inicia_sondeos(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def deny(*args: object, **kwargs: object) -> None:
        raise AssertionError("CORRELATE nunca debe contactar activos")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    graph, nvd, epss = fixtures()
    assert len(correlate_assets(graph, nvd, epss)) == 1
