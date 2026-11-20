import pytest

from runtime.defectdojo import DefectDojoError, publish


def test_defectdojo_requires_external_instance_and_hitl(monkeypatch):
    monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
    with pytest.raises(DefectDojoError, match="missing"):
        publish({"engagement": "lab", "findings": [], "report_sha256": "x"}, token="secret")
    with pytest.raises(DefectDojoError, match="approval"):
        publish({"engagement": "lab", "findings": [], "report_sha256": "x"},
                base_url="http://dojo", token="secret", approved_sha256="wrong")


def test_modified_report_does_not_reach_network(tmp_path):
    from runtime.reporting import ReportError, build_report, export_report

    report = build_report([], {}, engagement="juice-shop")
    approved = report["report_sha256"]
    report["engagement"] = "changed"
    out = tmp_path / "out.json"
    with pytest.raises(ReportError, match="hash_mismatch"):
        export_report(report, out, approved)
    assert not out.exists()
    with pytest.raises(DefectDojoError, match="hash_mismatch"):
        publish(report, "https://dojo.invalid", "test", approved_sha256=approved,
                opener=lambda *_args, **_kwargs: pytest.fail("unexpected network call"))
