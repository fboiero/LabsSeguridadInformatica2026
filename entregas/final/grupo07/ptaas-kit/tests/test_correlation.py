import json
import time

from harness.adapters.feed_adapter import (
    CveLookup,
    CweMapLookup,
    EpssLookup,
    LookupAction,
    SnapshotStaleError,
)
from harness.contracts import (
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    ScopeToken,
    ScopeViolation,
)
from harness.correlation import Correlator
from harness.policy_loader import phase_allowlist
from harness.schemas import Asset


def make_harness():
    audit = AuditLog()
    adapters = {
        "cve.lookup": CveLookup(),
        "epss.lookup": EpssLookup(),
        "cwe.map": CweMapLookup(),
    }
    h = Harness(Guard(phase_allowlist()), audit, adapters, KillSwitch())
    now = time.time()
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("lab.test",),
                       now - 5, now + 600, Phase.CORRELATE)
    return h, audit, token


def test_correlacion_exacta_cita_asset_nvd_y_epss():
    harness, audit, token = make_harness()
    asset = Asset("a1", "host", "dvwa.lab.test", "httpx.probe", ("Apache 2.4.49",))

    findings = Correlator(harness).correlate([asset], token)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve == "CVE-2021-41773"
    assert finding.cwe == "CWE-22"
    assert finding.epss is not None and finding.epss > 0.99
    assert finding.cvss_v4_score is None
    assert any(ref.startswith("nvd:") for ref in finding.evidence_refs)
    assert any(ref.startswith("epss:") for ref in finding.evidence_refs)
    assert all(entry["result"] == "OK" for entry in audit.entries)


def test_correlacion_sin_match_no_inventa_cve_y_epss_falta_es_null():
    harness, _audit, token = make_harness()
    unknown = Asset("a2", "host", "dvwa.lab.test", "httpx.probe", ("Unknown 9.1",))
    assert Correlator(harness).correlate([unknown], token) == []

    cve = "CVE-2099-0001"
    result = harness.invoke("correlation", LookupAction("epss.lookup", Phase.CORRELATE,
                                                        query=cve),
                            "dvwa.lab.test", token)
    assert result["score"] is None


def test_lookup_no_acepta_atajo_fuera_de_scope():
    harness, audit, token = make_harness()

    try:
        harness.invoke("correlation", LookupAction("cve.lookup", Phase.CORRELATE,
                                                    "Apache 2.4.49"),
                       "outside.example.org", token)
    except ScopeViolation:
        pass

    assert audit.entries[-1]["result"] == "BLOCKED"


def test_snapshot_vencido_se_rechaza(tmp_path):
    (tmp_path / "nvd-snapshot.json").write_text(json.dumps({
        "version": 1, "as_of": "2000-01-01", "source_url": "https://example.test",
        "records": [],
    }), encoding="utf-8")
    now = time.time()
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("lab.test",),
                       now - 5, now + 600, Phase.CORRELATE)

    try:
        CveLookup(tmp_path).run(LookupAction("cve.lookup", Phase.CORRELATE,
                                             query="Apache 2.4.49"), "dvwa.lab.test", token)
    except SnapshotStaleError as error:
        assert "fuera de ventana" in str(error)
    else:
        raise AssertionError("el snapshot vencido debía rechazarse")
