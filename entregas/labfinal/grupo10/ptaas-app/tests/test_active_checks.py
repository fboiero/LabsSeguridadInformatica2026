import pytest

from harness.poc.active import (
    ActiveCheckNotAuthorized,
    executable_active,
    load_active,
    run_active,
)
from harness.poc.catalog import ResponseRecord


def test_active_catalog_stays_pending_and_lab_only():
    entries = load_active()
    assert entries["PROPOSAL-AUTH-SQLI-001"]["review_status"] == "pending_teacher_review"
    assert all(entry["lab_only"] and entry["lab_targets"] == ["juice-shop"] for entry in entries.values())
    assert executable_active() == {}


def test_active_requires_explicit_session_authorization():
    active = load_active()
    sent = []
    with pytest.raises(ActiveCheckNotAuthorized):
        run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", False,
                   lambda *_: sent.append(1) or ResponseRecord(200, {}, "{}"))
    assert sent == []


def test_pending_teacher_review_blocks_traffic_even_with_operator_authorization():
    active = load_active()
    sent = []
    with pytest.raises(ActiveCheckNotAuthorized, match="teacher_review_required"):
        run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", True,
                   lambda *_: sent.append(1) or ResponseRecord(200, {}, "{}"))
    assert sent == []


def test_non_implementable_active_proposal_never_runs():
    active = load_active()
    with pytest.raises(ValueError):
        run_active(active, "PROPOSAL-DOM-XSS-001", "http://juice-shop.lab.test:3000", True,
                   lambda *_: pytest.fail("no debe enviar tráfico"))


def test_sqli_evaluator_only_checks_token_issuance():
    active = {key: dict(value, review_status="teacher_approved")
              for key, value in load_active().items() if value["implementable"]}

    def sender(poc_id, params, payload, method):
        assert poc_id == "PROPOSAL-AUTH-SQLI-001" and params == {"path": "/rest/user/login"}
        assert method == "POST"
        assert payload == {"email": "' OR 1=1--", "password": "not-a-real-password"}
        return ResponseRecord(200, {}, '{"authentication":{"token":"abcdef0123456789"}}')

    hit = run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", True, sender)
    assert hit.status == "validated" and hit.review_status == "teacher_approved"

    def rejected(poc_id, params, payload, method):
        return ResponseRecord(401, {}, '{"error":"Invalid email or password"}')

    miss = run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", True, rejected)
    assert miss.status == "not_validated"


def test_sqli_search_evaluator_uses_query_payload():
    active = {key: dict(value, review_status="teacher_approved")
              for key, value in load_active().items() if value["implementable"]}

    def sender(poc_id, params, payload, method):
        assert poc_id == "PROPOSAL-SQLI-SEARCH-001"
        assert params == {"path": "/rest/products/search"}
        assert method == "GET" and payload == {"q": "'"}
        return ResponseRecord(500, {}, '{"errors":[{"message":"SQLITE_ERROR: unrecognized token"}]}')

    hit = run_active(active, "PROPOSAL-SQLI-SEARCH-001", "http://juice-shop.lab.test:3000", True, sender)
    assert hit.status == "validated" and "motor SQL" in hit.detail

    def clean(poc_id, params, payload, method):
        return ResponseRecord(200, {}, '{"data":[{"name":"Apple"}]}')

    miss = run_active(active, "PROPOSAL-SQLI-SEARCH-001", "http://juice-shop.lab.test:3000", True, clean)
    assert miss.status == "not_validated"


def test_ftp_index_entries_are_described_without_downloading():
    from harness.poc.catalog import ftp_index_entries

    body = ('<title>Index of /ftp</title><a href="/ftp/acquisitions.md">acquisitions.md</a>'
            '<a href="/ftp/package.json.bak">package.json.bak</a><a href="/ftp/">..</a>')
    assert ftp_index_entries(body) == ("acquisitions.md", "package.json.bak")
    assert ftp_index_entries("") == ()

def test_run_header_review_blocks_pending_active_check(tmp_path, monkeypatch):
    from runtime import relevo

    monkeypatch.setattr(relevo.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("no debe enviar tráfico"))
    with pytest.raises(ValueError, match="consulta no habilitada"):
        relevo.run_header_review("PROPOSAL-AUTH-SQLI-001", tmp_path / "r.json", None,
                                 "/rest/user/login", True)


def test_run_header_review_blocks_active_without_authorization(tmp_path):
    from runtime import relevo

    with pytest.raises(ValueError):
        relevo.run_header_review("PROPOSAL-AUTH-SQLI-001", tmp_path / "r.json", None,
                                 "/rest/user/login", False)
