import json
import shutil
from pathlib import Path

import pytest

from evals.run_evals import mutation_results
from runtime.evidence_demo import _FEEDS, _FILES, _SNAPSHOTS, build, main, snapshot_summary
from runtime.reporting import ReportError, verify_approval


def test_review_digest_binds_archived_receipt_bytes(tmp_path):
    runs = Path(__file__).resolve().parents[1] / "runs"
    for name in _FILES.values():
        shutil.copyfile(runs / name, tmp_path / name)
    report = build(tmp_path)
    assert report["findings"] == [] and report["exploitability"] == "not_assessed"
    assert report["tool_exit_codes"]["zap.baseline_scan"] == 3
    assert report["receipts"]["integrated"]["sha256"]
    approved = report["report_sha256"]
    assert verify_approval(report, approved) == approved
    with (tmp_path / _FILES["headers"]).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ReportError, match="hash_mismatch"):
        verify_approval(build(tmp_path), approved)


def test_contract_mutations_are_detected():
    results = mutation_results()
    assert len(results) == 3 and all(case["passed"] and case["detected_by"] for case in results)


def test_snapshot_summary_rejects_changed_data(tmp_path):
    for name in _FEEDS:
        shutil.copyfile(_SNAPSHOTS / name, tmp_path / name)
    assert all(item["records"] == 2 for item in snapshot_summary(tmp_path).values())
    path = tmp_path / "epss-snapshot.json"
    content = json.loads(path.read_bytes())
    content["data"]["CVE-2000-0001"] = 0.5
    path.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(ValueError, match="snapshot_digest_mismatch"):
        snapshot_summary(tmp_path)


def test_local_export_requires_exact_review_digest(tmp_path, monkeypatch):
    runs = Path(__file__).resolve().parents[1] / "runs"
    out = tmp_path / "generic.json"
    args = ["evidence_demo", "--runs", str(runs), "--export-empty", str(out)]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit) as blocked:
        main()
    assert blocked.value.code == 2 and not out.exists()
    monkeypatch.setattr("sys.argv", [*args, "--approve-sha256", build(runs)["report_sha256"]])
    assert main() == 0
    assert json.loads(out.read_text(encoding="utf-8"))["findings"] == []
    with pytest.raises(SystemExit):
        main()
