import json
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
