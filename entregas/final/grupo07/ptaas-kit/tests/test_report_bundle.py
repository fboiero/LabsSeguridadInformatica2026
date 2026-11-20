from dataclasses import replace
import pytest
from harness.approvals import ApprovalStore
from harness.report_bundle import build_bundle, publish_bundle
from harness.contracts import AuditLog, Action, Phase, Result
from tests.test_reporting import f
from tests.test_roe_tokens import issuer_vigente

def bundle(**kw):
    audit=AuditLog();token=issuer_vigente(audit=audit).issue(Phase.RECON)
    e=audit.record('validation',Action('poc_catalog.run_parametrized',Phase.RECON),'dvwa.lab.test',token,Result.OK)
    finding=f(evidence_refs=(e['hash'],),**kw)
    return build_bundle('eng-lab-001',[finding],audit.entries,mode='fixture')

def test_bundle_traceability_and_provenance():
    b=bundle()
    assert 'fixture' in b['markdown'] and 'unknown' in b['markdown']
    assert 'Resumen ejecutivo' in b['markdown'] and 'PTES' in b['markdown']
    assert b['export']['findings'][0]['verified'] is False
    assert b['version']

def test_missing_ref_rejected():
    with pytest.raises(ValueError,match='evidencia'):
        build_bundle('eng-lab-001',[f(evidence_refs=('missing',))],[],mode='fixture')

@pytest.mark.parametrize('changes',[{'epss':2},{'validation_status':'inventado'},{'cvss_v4_vector':f().cvss_v4_vector+'/BAD:X'},{'title':'password=secreto'},{'remediation':'Bearer abcdefghijklmnop'}])
def test_reject_metrics_and_sensitive_fields(changes):
    with pytest.raises(ValueError):
        bundle(**changes)

def test_delivery_requires_exact_bundle_and_approval(tmp_path):
    b=bundle();a=ApprovalStore()
    with pytest.raises(PermissionError):publish_bundle(b,a,tmp_path)
    assert list(tmp_path.iterdir())==[]
    a.decide(b['subject'],'approve','Reviewer','reporte fixture')
    publish_bundle(b,a,tmp_path)
    assert (tmp_path/'defectdojo.json').exists()
    b['markdown']+='alterado'
    with pytest.raises(ValueError):publish_bundle(b,a,tmp_path)
