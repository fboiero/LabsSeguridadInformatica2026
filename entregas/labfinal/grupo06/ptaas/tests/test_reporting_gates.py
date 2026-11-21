"""Change 007 · gates 3.1 y 3.3: informe incompleto y entrega sin aprobación.

Estos tests verifican comportamiento que ya existe en `harness/reporting.py`;
se agregan como evidencia explícita de los gates de P2 sin tocar el módulo
(propiedad de P5). Si alguno falla, se avisa antes de modificar reporting.py.
"""
import pytest

from harness.reporting import DeliveryNotApproved, Finding, MissingField, deliver, render_report

VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


def finding(**overrides):
    base = {"id": "F-7", "title": "Cabecera ausente", "asset": "dvwa.lab.test",
            "cwe": "CWE-693", "cvss_v4_vector": VEC,
            "remediation": "Agregar la cabecera", "validation_status": "validated"}
    return Finding(**{**base, **overrides})


@pytest.mark.parametrize("campo,valor,esperado", [
    ("cwe", "", "CWE"),
    ("cwe", "unknown", "CWE"),
    ("cvss_v4_vector", "", "CVSS"),
    ("cvss_v4_vector", "CVSS:3.1/AV:N", "CVSS"),
    ("remediation", "   ", "remediación"),
])
def test_gate_3_1_hallazgo_incompleto_falla_indicando_el_campo(campo, valor, esperado):
    with pytest.raises(MissingField) as error:
        render_report("eng-7", [finding(**{campo: valor})])
    assert "F-7" in str(error.value)
    assert esperado in str(error.value)


def test_gate_3_1_un_hallazgo_incompleto_no_genera_informe_parcial():
    with pytest.raises(MissingField):
        render_report("eng-7", [finding(), finding(id="F-8", cwe="")])


def test_gate_3_3_entrega_sin_aprobacion_se_rechaza_y_queda_en_reporte():
    report = render_report("eng-7", [finding()])
    with pytest.raises(DeliveryNotApproved, match="aprobación"):
        deliver(report, reviewer_approved=False)
    assert report["delivered"] is False


def test_gate_3_3_entrega_con_aprobacion_humana_se_marca_entregada():
    report = render_report("eng-7", [finding()])
    assert deliver(report, reviewer_approved=True)["delivered"] is True
