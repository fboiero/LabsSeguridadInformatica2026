import importlib
from dataclasses import replace
import pytest
from harness.reporting import Finding, deliver, DeliveryNotApproved

VECTOR = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'

def module():
    return importlib.import_module('harness.reporting_p3')

def finding(epss=None):
    return Finding('F1', 'Configuración de prueba', 'dvwa.lab.test', 'CWE-16', VECTOR,
                   'Revisar configuración', 'not_validated', ('audit:1',), epss)

@pytest.mark.parametrize('suffix', ['', '/E:P', '/MSI:S/MSA:S/S:P/AU:Y/R:U/V:C/RE:H/U:Red'])
def test_valid_vectors(suffix):
    assert module().validate_cvss4(VECTOR + suffix) == VECTOR + suffix

@pytest.mark.parametrize('vector', [VECTOR + '/AV:N', VECTOR + '/ZZ:X', VECTOR + '/E:BAD',
                                  VECTOR.replace('/AT:N', ''), VECTOR.replace('4.0', '3.1'),
                                  VECTOR + '/', VECTOR + '/MSI:X/MSI:S'])
def test_invalid_vector(vector):
    with pytest.raises(ValueError, match='CVSS'):
        module().validate_cvss4(vector)

@pytest.mark.parametrize('epss,label', [(None, 'unknown'), (0, '0%'), (0.25, '25%')])
def test_epss_alongside_vector(epss, label):
    report = module().render_report('eng', [finding(epss)])
    assert VECTOR in report['markdown'] and 'EPSS: ' + label in report['markdown']
    assert report['delivered'] is False

@pytest.mark.parametrize('epss', [-0.1, 1.1, float('nan'), float('inf'), True, '0.5'])
def test_invalid_epss(epss):
    with pytest.raises(ValueError, match='EPSS'):
        module().render_report('eng', [finding(epss)])

def test_ptes_structure_and_evidence():
    report = module().render_report('eng', [finding()], scope={'assets': ['dvwa.lab.test']})
    md = report['markdown']
    for section in ['Resumen ejecutivo', 'Alcance y RoE', 'Metodología', 'Hallazgos priorizados', 'Anexos']:
        assert section in md
    assert 'audit:1' in md and 'no validado' in md
    with pytest.raises(DeliveryNotApproved):
        deliver(report, False)

def test_empty_report_does_not_claim_safety():
    md = module().render_report('eng', [])['markdown']
    assert 'unknown' in md
    assert 'no demuestra ausencia de vulnerabilidades' in md

def test_existing_required_fields_preserved():
    with pytest.raises(ValueError):
        module().render_report('eng', [replace(finding(), cwe='')])
