import hashlib
import json
import os

import pytest

from runtime.phantomcorp_evidence import IntakeError, collect, write_draft


def record(milestone="R1"):
    return json.dumps({"version": 1, "lab": "phantomcorp", "milestone": milestone,
                       "source": "operator_review_note", "captured_at": "2026-11-18T18:00:00Z"}).encode()


def test_collect_fixed_names_and_no_hito_is_credited(tmp_path):
    raw = record()
    (tmp_path / "r1.json").write_bytes(raw)
    (tmp_path / "unrelated.json").write_bytes(b"SECRET")
    result = collect(tmp_path)
    assert result["state"] == "PENDING_HITL"
    rows = result["milestones"]
    assert [row["status"] for row in rows] == ["artifact_received", *(["missing"] * 3)]
    assert rows[0]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert rows[0]["source"] == "operator_review_note"
    assert rows[0]["captured_at"] == "2026-11-18T18:00:00Z"
    assert all(not row["credited"] for row in rows)
    assert "SECRET" not in json.dumps(result)


@pytest.mark.parametrize("raw", [record("R2"), b"{" * 5000, b"{{", b"\xff", b"[]",
                                  record().replace(b'"version": 1', b'"version": true'),
                                  record().replace(b'"version": 1', b'"version": 1, "version": 1'),
                                  record().replace(b'"version": 1', b'"version": 1, "raw": "SECRET"'),
                                  record().replace(b"2026-11-18", b"2026-02-30")])
def test_rejects_invalid_artifacts_without_echo(tmp_path, raw):
    (tmp_path / "r1.json").write_bytes(raw)
    result = collect(tmp_path)
    row = result["milestones"][0]
    assert row["status"] == "rejected" and "sha256" not in row
    assert "SECRET" not in json.dumps(result)


def test_hard_link_outside_staging_is_rejected(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    source = tmp_path / "other.json"
    source.write_bytes(record())
    os.link(source, stage / "r1.json")
    assert collect(stage)["milestones"][0]["status"] == "rejected"


def test_lab_export_requires_declared_original_reference(tmp_path):
    path = tmp_path / "r1.json"
    data = json.loads(record()) | {"source": "lab_export_metadata"}
    path.write_text(json.dumps(data), encoding="utf-8")
    assert collect(tmp_path)["milestones"][0]["status"] == "rejected"
    data["original_sha256"] = "a" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    row = collect(tmp_path)["milestones"][0]
    assert row["declared_original_sha256"] == "a" * 64 and not row["credited"]


def test_does_not_follow_symlink(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    source = tmp_path / "outside.json"
    source.write_bytes(record())
    try:
        (stage / "r1.json").symlink_to(source)
    except OSError:
        pytest.skip("symlinks not permitted on this host")
    assert collect(stage)["milestones"][0]["status"] == "rejected"


def test_output_must_be_new_and_outside_staging(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(IntakeError):
        write_draft(stage, stage / "report.json")
    output = tmp_path / "report.json"
    write_draft(stage, output)
    with pytest.raises(FileExistsError):
        write_draft(stage, output)
