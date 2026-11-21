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
    assert set(executable_active()) == {"PROPOSAL-AUTH-SQLI-001", "PROPOSAL-SQLI-SEARCH-001"}


def test_active_requires_explicit_session_authorization():
    active = load_active()
    sent = []
    with pytest.raises(ActiveCheckNotAuthorized):
        run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", False,
                   lambda *_: sent.append(1) or ResponseRecord(200, {}, "{}"))
    assert sent == []


def test_non_implementable_active_proposal_never_runs():
    active = load_active()
    with pytest.raises(ValueError):
        run_active(active, "PROPOSAL-DOM-XSS-001", "http://juice-shop.lab.test:3000", True,
                   lambda *_: pytest.fail("no debe enviar tráfico"))


def test_sqli_evaluator_only_checks_token_issuance():
    active = load_active()

    def sender(poc_id, params, payload, method):
        assert poc_id == "PROPOSAL-AUTH-SQLI-001" and params == {"path": "/rest/user/login"}
        assert method == "POST"
        assert payload == {"email": "' OR 1=1--", "password": "not-a-real-password"}
        return ResponseRecord(200, {}, '{"authentication":{"token":"abcdef0123456789"}}')

    hit = run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", True, sender)
    assert hit.status == "validated" and hit.review_status == "pending_teacher_review"

    def rejected(poc_id, params, payload, method):
        return ResponseRecord(401, {}, '{"error":"Invalid email or password"}')

    miss = run_active(active, "PROPOSAL-AUTH-SQLI-001", "http://juice-shop.lab.test:3000", True, rejected)
    assert miss.status == "not_validated"


def test_sqli_search_evaluator_uses_query_payload():
    active = load_active()

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

def test_run_header_review_passes_active_switch_and_validates_receipt(tmp_path, monkeypatch):
    import json
    import subprocess

    from runtime import relevo

    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        receipt = args[args.index("-Output") + 1]
        with open(receipt, "w", encoding="utf-8") as handle:
            json.dump({"poc_id": "PROPOSAL-AUTH-SQLI-001", "status": "validated",
                       "detail": "sesión emitida sin credenciales válidas del laboratorio",
                       "parameters": {"path": "/rest/user/login"}, "http_status": 200,
                       "review_status": "pending_teacher_review",
                       "target_removed": True, "network_removed": True,
                       "observed_entries": []}, handle)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(relevo.subprocess, "run", fake_run)
    text = relevo.run_header_review("PROPOSAL-AUTH-SQLI-001", tmp_path / "r.json", None,
                                    "/rest/user/login", True)
    assert "-Active" in seen["args"]
    assert "POST /rest/user/login" in text and "pendiente de docente" in text


def test_run_header_review_blocks_active_without_authorization(tmp_path):
    from runtime import relevo

    with pytest.raises(ValueError):
        relevo.run_header_review("PROPOSAL-AUTH-SQLI-001", tmp_path / "r.json", None,
                                 "/rest/user/login", False)
