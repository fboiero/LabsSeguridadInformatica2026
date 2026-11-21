import io
import json
from email import policy
from email.parser import BytesParser

import pytest

from runtime.defectdojo import DefectDojoError, publish
from runtime.reporting import build_report


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


def test_publish_uses_multipart_and_safe_import_flags():
    report = build_report([], {}, engagement="juice-shop")

    class Response(io.BytesIO):
        status = 201

    def open_request(request, *, timeout):
        assert request.full_url == "http://127.0.0.1:18080/api/v2/import-scan/"
        assert request.get_header("Authorization") == "Token test"
        content_type = request.get_header("Content-type").encode()
        envelope = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + content_type + b"\r\n\r\n" + request.data)
        fields = {part.get_param("name", header="content-disposition"): part.get_content()
                  for part in envelope.iter_parts()}
        assert fields["engagement"] == "1"
        assert fields["scan_type"] == "Generic Findings Import"
        assert all(fields[name] == "false" for name in ("active", "verified", "close_old_findings", "push_to_jira"))
        assert json.loads(fields["file"])["findings"] == []
        return Response(b"{}")

    assert publish(report, "http://127.0.0.1:18080", "test", engagement_id=1,
                   approved_sha256=report["report_sha256"], opener=open_request)["status"] == 201
