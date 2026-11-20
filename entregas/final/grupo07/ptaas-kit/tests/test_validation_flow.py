import copy
import time
import pytest
from harness.approvals import ApprovalStore, subject_key
from harness.validation import ValidationRequest, validate_finding
from harness.sandbox import FixtureSender, RestrictedSender
from harness.contracts import AuditLog, Harness, KillSwitch, Phase, ScopeViolation
from harness.policy_loader import phase_allowlist
from harness.tokens import EngagementGuard, TokenIssuer
from tests.test_roe_tokens import roe_vigente

def setup():
    audit=AuditLog()
    h=Harness(EngagementGuard('eng-lab-001',phase_allowlist()),audit,{},KillSwitch())
    token=TokenIssuer(roe_vigente(phases=['validate','report']),audit).issue(Phase.VALIDATE)
    request=ValidationRequest('F-1','dvwa.lab.test','CWE-693','POC-CSP-001',{'base_url':'http://dvwa.lab.test','path':'/'})
    return h,token,request,ApprovalStore()

def test_no_approval_never_creates_sender():
    h,t,r,a=setup()
    def forbidden():
        pytest.fail('sin gate no se crea sender')
    out=validate_finding(h,t,r,a,forbidden)
    assert out['status']=='PENDING_HITL'
    assert h.audit.entries[-1]['result']=='PENDING_HITL'

def test_approval_bound_to_parameters_and_finding():
    h,t,r,a=setup()
    a.decide(r.subject,'approve','Fernando','revisiÃ³n fixture')
    changed=copy.deepcopy(r)
    changed.params['path']='/otro'
    assert validate_finding(h,t,changed,a,FixtureSender)['status']=='PENDING_HITL'
    assert not a.approved(subject_key({'otro':'hallazgo'}))

def test_expired_and_rejected_gate():
    a=ApprovalStore()
    a.decide('s','approve','Reviewer','caso',ttl=-1)
    assert not a.approved('s')
    a.decide('s','reject','Reviewer','rechazo')
    assert not a.approved('s')
    with pytest.raises(ValueError):
        a.decide('s','approve','','')

def test_catalog_and_cwe_checked_before_sender():
    h,t,r,a=setup()
    r=ValidationRequest(r.id,r.asset,r.cwe,'POC-NEW',r.params)
    a.decide(r.subject,'approve','Reviewer','caso')
    assert validate_finding(h,t,r,a,FixtureSender)['status']=='not_validated'

def test_success_records_selection_and_closes():
    h,t,r,a=setup();sender=FixtureSender()
    a.decide(r.subject,'approve','Reviewer','fixture explÃ­cita')
    out=validate_finding(h,t,r,a,lambda:sender)
    assert out['status']=='validated' and out['mode']=='fixture'
    assert out['attempts']==1 and sender.closed
    assert len(out['evidence_refs'])==1 and 'POC-CSP-001' in h.audit.entries[-1]['agent']

def test_failure_closes_and_records():
    h,t,r,a=setup()
    class Broken(FixtureSender):
        def __call__(self,*args):
            raise TimeoutError('fallÃ³')
    s=Broken();a.decide(r.subject,'approve','Reviewer','fixture')
    out=validate_finding(h,t,r,a,lambda:s)
    assert out['status']=='not_validated' and s.closed
    assert h.audit.entries[-1]['result']=='BLOCKED'

@pytest.mark.parametrize('url',['http://example.com','http://dvwa.lab.test.evil.test','http://user:pass@dvwa.lab.test','file:///etc/passwd'])
def test_sender_rejects_external_before_resolution(url):
    s=RestrictedSender(('dvwa.lab.test',),('10.99.0.0/28',))
    with pytest.raises(ValueError):
        s('POC-CSP-001',{'base_url':url,'path':'/'})

def test_dns_external_no_connection(monkeypatch):
    monkeypatch.setattr('harness.http_transport.socket.getaddrinfo',lambda *a,**k:[(2,1,6,'',('8.8.8.8',80))])
    s=RestrictedSender(('dvwa.lab.test',),('10.99.0.0/28',))
    with pytest.raises(ValueError,match='DNS'):
        s('POC-CSP-001',{'base_url':'http://dvwa.lab.test','path':'/'})

def test_sender_path_escape_and_closed():
    s=FixtureSender();s.close()
    with pytest.raises(ValueError):
        s('POC-CSP-001',{})
    s=RestrictedSender(('dvwa.lab.test',),('10.99.0.0/28',))
    with pytest.raises(ValueError):
        s('POC-CSP-001',{'base_url':'http://dvwa.lab.test','path':'//example.com'})
