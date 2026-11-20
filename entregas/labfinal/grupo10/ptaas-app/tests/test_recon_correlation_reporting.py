import time

import pytest

from harness.audit import AuditLog
from harness.contracts import Guard, Harness
from harness.types import Phase, ScopeToken
from runtime.correlation import SafeTemplateScanner, SnapshotStore, correlate, detection_loop
from runtime.recon import Asset, AssetGraph, HttpxAdapter, SubfinderAdapter, run_loop
from runtime.reporting import Finding, ReportError, build_report, export_report


def harness_for(adapter, action, phase):
    now = time.time()
    token = ScopeToken("recon-test", (), ("juice-shop.lab.test",), now - 1, now + 60, phase)
    return Harness(Guard({phase: {action}}), AuditLog(), {action: adapter}, __import__("harness.contracts", fromlist=["KillSwitch"]).KillSwitch()), token


def test_recon_loop_stabilizes_and_never_probes_foreign_target():
    calls = []
    adapter = HttpxAdapter(lambda target: (calls.append(target) or Asset(target, 3000, 200, "httpx.probe")))
    harness, token = harness_for(adapter, "httpx.probe", Phase.RECON)
    result = run_loop(harness, token)
    assert result["stop_reason"] == "graph_stabilized" and result["rounds"] == 2
    assert calls == ["juice-shop.lab.test", "juice-shop.lab.test"]
    with pytest.raises(ValueError): SubfinderAdapter.argv("example.test")


def test_graph_rejects_out_of_scope_and_subfinder_filters():
    graph = AssetGraph()
    graph.reject("example.test")
    assert graph.out_of_scope == ["example.test"]
    assert SubfinderAdapter.parse("juice-shop.lab.test\nexample.test\n", {"juice-shop.lab.test"}) == ["juice-shop.lab.test"]


def test_correlation_requires_evidence_and_unknowns_are_null():
    store = SnapshotStore({"CVE-2026-1": {"cvss": None}}, {})
    result = correlate([{"id": "F-1", "title": "CSP", "cwe": "CWE-693", "cve": "CVE-404", "evidence_refs": ["e1"]}], store)
    assert result[0].nvd is None and result[0].epss is None
    with pytest.raises(ValueError): correlate([{"id": "F-2", "title": "x", "cwe": "CWE-693"}], store)


def test_analysis_allowlist_and_no_progress():
    with pytest.raises(ValueError): SafeTemplateScanner().argv("unknown", "juice-shop.lab.test")
    assert detection_loop([[{"id": "F-1"}], [{"id": "F-1"}]])["status"] == "inconclusive"


def test_reporting_requires_fields_status_and_hitl(tmp_path):
    finding = Finding("F-1", "CSP ausente", "validated", "CWE-693",
                      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                      "Configurar una política CSP restrictiva.", ("e1",), 0.1)
    report = build_report([finding], {"e1": {"http_status": 200}}, engagement="juice-shop")
    with pytest.raises(ReportError): export_report(report, tmp_path / "out.json")
    output = export_report(report, tmp_path / "out.json", report["report_sha256"])
    assert output["findings"][0]["status"] == "validated"
    with pytest.raises(ReportError): build_report([Finding("F", "x", "validated", "", finding.cvss, "fix", ("e1",))], {"e1": {}}, engagement="x")
