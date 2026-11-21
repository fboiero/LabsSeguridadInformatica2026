"""Change 005 / task 2.1: pruebas del lector offline de snapshots NVD.

Datos exclusivamente sinteticos; ninguna CVE incluida representa un hallazgo real.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from harness.epss_snapshot import EPSSSnapshotError, load_epss_snapshot
from harness.nvd_snapshot import SnapshotError, load_nvd_snapshot

TEST_CVE = "CVE-2099-0001"  # Identificador FICTICIO de fixture; no es un hallazgo.


def write_synthetic_snapshot(path: Path, *, tamper: bool = False, snapshot_date: str = "2026-11-18") -> None:
    records = [
        {
            "cve_id": TEST_CVE,
            "product": "fictional-app",
            "version": "1.0",
            "cwe": "unknown",
            "cvss_v4_score": None,
        }
    ]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if tamper:
        records[0]["version"] = "2.0"  # alteracion posterior al hash
    document = {
        "schema_version": 1,
        "source": "synthetic-test-fixture",
        "retrieved_at": "2026-11-18T00:00:00Z",
        "snapshot_date": snapshot_date,
        "sha256": digest,
        "record_count": 1,
        "records": records,
    }
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


def test_nvd_snapshot_valido_se_lee_sin_red(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Un snapshot local verificable ofrece datos y procedencia, sin consultar Internet."""
    path = tmp_path / "nvd.json"
    write_synthetic_snapshot(path)

    def network_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("El lector offline no debe iniciar conexiones de red")

    import socket
    monkeypatch.setattr(socket, "create_connection", network_forbidden)
    monkeypatch.setattr(socket.socket, "connect", network_forbidden)

    snapshot = load_nvd_snapshot(
        path, now=datetime(2026, 11, 19, tzinfo=UTC), max_age_days=30
    )
    assert snapshot.status == "current"
    assert snapshot.lookup(TEST_CVE)["product"] == "fictional-app"
    assert snapshot.source == "synthetic-test-fixture"


def test_nvd_snapshot_alterado_se_rechaza(tmp_path: Path) -> None:
    path = tmp_path / "nvd.json"
    write_synthetic_snapshot(path, tamper=True)
    with pytest.raises(SnapshotError, match="(?i)(hash|integridad|sha256)"):
        load_nvd_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))


def test_nvd_cve_ausente_no_se_inventa(tmp_path: Path) -> None:
    path = tmp_path / "nvd.json"
    write_synthetic_snapshot(path)
    snapshot = load_nvd_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))
    assert snapshot.lookup("CVE-2099-9999") is None


def test_nvd_snapshot_desactualizado_se_identifica(tmp_path: Path) -> None:
    path = tmp_path / "nvd.json"
    write_synthetic_snapshot(path, snapshot_date="2026-01-01")
    snapshot = load_nvd_snapshot(
        path, now=datetime(2026, 11, 19, tzinfo=UTC), max_age_days=30
    )
    assert snapshot.status == "stale"

# Change 005 / task 2.2: EPSS offline (fixtures exclusivamente sinteticos).

def write_synthetic_epss_snapshot(
    path: Path, *, tamper: bool = False, snapshot_date: str = "2026-11-18",
    epss: float = 0.42,
) -> None:
    records = [{"cve_id": TEST_CVE, "epss": epss}]
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if tamper:
        records[0]["epss"] = 0.99
    payload = {
        "schema_version": 1,
        "source": "synthetic-test-fixture",
        "retrieved_at": "2026-11-18T00:00:00Z",
        "snapshot_date": snapshot_date,
        "sha256": digest,
        "record_count": len(records),
        "records": records,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_epss_snapshot_valido_y_sin_red(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    path = tmp_path / "epss.json"
    write_synthetic_epss_snapshot(path)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("EPSS offline no debe acceder a la red")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    snapshot = load_epss_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))
    assert snapshot.status == "current"
    assert snapshot.source == "synthetic-test-fixture"
    assert snapshot.lookup(TEST_CVE) == pytest.approx(0.42)


def test_epss_hash_alterado_se_rechaza(tmp_path: Path) -> None:
    path = tmp_path / "epss.json"
    write_synthetic_epss_snapshot(path, tamper=True)
    with pytest.raises(EPSSSnapshotError, match="(?i)(integridad|hash|sha256)"):
        load_epss_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))


def test_epss_cve_ausente_no_se_inventa(tmp_path: Path) -> None:
    path = tmp_path / "epss.json"
    write_synthetic_epss_snapshot(path)
    snapshot = load_epss_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))
    assert snapshot.lookup("CVE-2099-9999") is None


def test_epss_fuera_de_rango_se_rechaza(tmp_path: Path) -> None:
    path = tmp_path / "epss.json"
    write_synthetic_epss_snapshot(path, epss=1.5)
    with pytest.raises(EPSSSnapshotError, match="(?i)(epss|rango)"):
        load_epss_snapshot(path, now=datetime(2026, 11, 19, tzinfo=UTC))


def test_epss_snapshot_desactualizado(tmp_path: Path) -> None:
    path = tmp_path / "epss.json"
    write_synthetic_epss_snapshot(path, snapshot_date="2026-01-01")
    snapshot = load_epss_snapshot(
        path, now=datetime(2026, 11, 19, tzinfo=UTC), max_age_days=7
    )
    assert snapshot.status == "stale"
