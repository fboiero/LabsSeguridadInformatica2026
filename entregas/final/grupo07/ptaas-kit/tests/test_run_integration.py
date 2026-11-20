import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from harness.approvals import ApprovalStore
from harness.run import execute, verify_entries


@pytest.fixture
def roe(tmp_path):
    source = yaml.safe_load(Path("roe/roe-lab.example.yaml").read_text(encoding="utf-8"))
    now = datetime.now(UTC)
    source["window"] = {
        "start": (now - timedelta(hours=1)).isoformat(),
        "end": (now + timedelta(hours=1)).isoformat(),
    }
    source["approver"]["approved_at"] = (now - timedelta(hours=2)).isoformat()
    path = tmp_path / "roe.yaml"
    path.write_text(yaml.safe_dump(source), encoding="utf-8")
    return path


def test_single_command_without_gates_stays_pending(roe, tmp_path):
    out = execute(roe, tmp_path / "out", ApprovalStore())
    assert out["delivery"]["status"] == "PENDING_HITL"
    assert not (tmp_path / "out/published").exists()
    assert verify_entries(out["audit"])
    out["audit"][0]["result"] = "alterado"
    assert not verify_entries(out["audit"])


def test_explicit_fixture_gates_and_export(roe, tmp_path):
    out = execute(
        roe,
        tmp_path / "out",
        ApprovalStore(),
        ("F-CSP-001", "delivery"),
        "reviewer de prueba",
        "test fixture",
    )
    assert out["delivery"]["status"] == "exported_local_json"
    data = json.loads((tmp_path / "out/published/defectdojo.json").read_text(encoding="utf-8"))
    assert data["findings"][0]["verified"] is False
    assert "fixture" in data["findings"][0]["description"]


def test_integrates_team_loops_and_keeps_unknowns(roe, tmp_path):
    out = execute(roe, tmp_path / "integrated", ApprovalStore())
    stages = json.loads(
        (tmp_path / "integrated/pipeline-evidence.json").read_text(encoding="utf-8")
    )
    assert stages["recon"]["implementation"] == "harness.recon_loop.ReconLoop"
    assert stages["recon"]["iterations"] >= 1
    assert stages["correlation"]["candidates"] == []
    assert stages["analysis"]["status"] == "inconclusive"
    assert stages["validation_seed"]["origin"] == "manual_demo_seed"
    assert (tmp_path / "integrated/asset-graph.json").exists()
    names = {e["action"] for e in out["audit"]}
    assert {
        "subfinder.enum",
        "httpx.probe",
        "cve.lookup",
        "zap.baseline_scan",
        "nuclei.safe_templates",
    } <= names
    assert out["bundle"]["pipeline"]["analysis"] == "fixtures sintéticas con DetectionLoop (005)"


def test_demo_fixture_runners_never_execute_binaries(roe, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("la demo fixture no debe ejecutar herramientas ni conectar red")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    execute(roe, tmp_path / "offline", ApprovalStore())


def test_run_sqlite_survives_restart_and_appends(roe, tmp_path):
    from harness.audit import SqliteAuditLog, verify_file

    first = execute(roe, tmp_path / "persistent", ApprovalStore())
    db = Path(first["audit_path"])
    original = list(first["audit"])
    reopened = SqliteAuditLog(str(db))
    assert reopened.entries == original
    reopened.close()
    second = execute(roe, tmp_path / "persistent", ApprovalStore())
    assert second["audit_path"] == str(db)
    assert second["audit"][:len(original)] == original
    assert len(second["audit"]) > len(original)
    assert verify_file(str(db))
    assert second["delivery"]["status"] == "PENDING_HITL"


def test_run_corrupt_sqlite_stops_before_pipeline(roe, tmp_path, monkeypatch):
    from harness.audit import AuditChainCorrupted

    first = execute(roe, tmp_path / "corrupt", ApprovalStore())
    with sqlite3.connect(first["audit_path"]) as con:
        con.execute("DROP TRIGGER audit_no_update")
        con.execute("UPDATE audit SET target='alterado' WHERE seq=1")

    def forbidden(*args, **kwargs):
        pytest.fail("una bitácora corrupta no debe permitir acciones")

    monkeypatch.setattr("harness.run.run_team_pipeline", forbidden)
    with pytest.raises(AuditChainCorrupted):
        execute(roe, tmp_path / "corrupt", ApprovalStore())


def test_run_separates_engagement_databases(roe, tmp_path):
    first = execute(roe, tmp_path / "shared", ApprovalStore())
    data = yaml.safe_load(roe.read_text(encoding="utf-8"))
    data["engagement_id"] = "another-engagement"
    other = tmp_path / "other-roe.yaml"
    other.write_text(yaml.safe_dump(data), encoding="utf-8")
    second = execute(other, tmp_path / "shared", ApprovalStore())
    assert first["audit_path"] != second["audit_path"]
    assert {e["engagement"] for e in second["audit"]} == {"another-engagement"}


def test_run_closes_sqlite_when_pipeline_fails(roe, tmp_path, monkeypatch):
    from harness.audit import SqliteAuditLog

    closed = []
    original_close = SqliteAuditLog.close

    def close(audit):
        closed.append(audit.db_path)
        original_close(audit)

    def fail(*args, **kwargs):
        raise RuntimeError("pipeline falló")

    monkeypatch.setattr(SqliteAuditLog, "close", close)
    monkeypatch.setattr("harness.run.run_team_pipeline", fail)
    with pytest.raises(RuntimeError, match="pipeline falló"):
        execute(roe, tmp_path / "failure", ApprovalStore())
    assert len(closed) == 1
