import hashlib
import json

import pytest

from runtime.bandit_input import BanditInputError
from runtime.defensive_report import ReportError, create_draft, export_review


def evidence(tmp_path):
    path = tmp_path / "bandit.json"
    path.write_text(json.dumps({"errors": [], "results": [{
        "test_id": "B603", "issue_severity": "LOW", "issue_confidence": "HIGH",
        "code": "SECRET_RAW_CODE", "filename": "SECRET_PATH",
    }]}), encoding="utf-8")
    return path


def test_draft_sanitized_and_bound_to_report(tmp_path):
    source = evidence(tmp_path)
    draft = create_draft(source)
    report = json.loads(draft)
    assert report["state"] == "PENDING_HITL" and report["confirmed_findings"] == []
    assert report["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert report["alerts"][0]["id"] == "bandit-1"
    assert b"SECRET" not in draft


def test_incomplete_report_not_validated(tmp_path):
    source = tmp_path / "incomplete.json"
    source.write_text('{"results":[],"errors":[{}]}', encoding="utf-8")
    with pytest.raises(BanditInputError):
        create_draft(source)


@pytest.mark.parametrize("case", ["no_approval", "wrong_digest", "changed_draft", "changed_source"])
def test_export_fails_closed(tmp_path, case):
    source = evidence(tmp_path)
    draft_path = tmp_path / "draft.json"
    draft = create_draft(source)
    approval = hashlib.sha256(draft).hexdigest()
    if case == "changed_draft":
        draft += b"\n"
        approval = hashlib.sha256(draft).hexdigest()
    elif case == "changed_source":
        source.write_bytes(source.read_bytes() + b"\n")
    elif case == "no_approval":
        approval = ""
    else:
        approval = "0" * 64
    draft_path.write_bytes(draft)
    out = tmp_path / "export.json"
    with pytest.raises(ReportError):
        export_review(source, draft_path, approval, out)
    assert not out.exists()


def test_export_is_local_bound_and_no_overwrite(tmp_path):
    source = evidence(tmp_path)
    draft_path = tmp_path / "draft.json"
    draft = create_draft(source)
    draft_path.write_bytes(draft)
    approval = hashlib.sha256(draft).hexdigest()
    out = tmp_path / "export.json"
    export_review(source, draft_path, approval, out)
    exported = json.loads(out.read_bytes())
    assert exported["reviewed_draft_sha256"] == approval
    assert exported["publication"] == "not_published"
    with pytest.raises(FileExistsError):
        export_review(source, draft_path, approval, out)
