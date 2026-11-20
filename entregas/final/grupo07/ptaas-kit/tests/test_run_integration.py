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
