"""Change 005 · 3.3 (cierre por P5): Nuclei a través de Harness.invoke.

Regresión: el adaptador real `NucleiSafeTemplates` exigía una URL, pero el Guard del
harness evalúa un host. Con un host fallaba la validación de URL del adaptador; con
una URL el Guard la bloqueaba. Los tests del loop B usaban un adaptador falso y no lo
detectaban. El adaptador ahora recibe el host del lab y arma la URL, como ZAP.
"""
import time

import pytest

from harness.adapters.common import InvalidTarget
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.contracts import (
    Action,
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    Phase,
    ScopeToken,
    ScopeViolation,
)
from harness.policy_loader import phase_allowlist

ENG = "p5-nuclei"


def token():
    now = time.time()
    return ScopeToken(ENG, ("10.99.0.0/24",), ("dvwa.lab.test", "juiceshop.lab.test"),
                      now - 5, now + 60, Phase.ANALYZE)


def harness(runner, approved=("dvwa.lab.test",)):
    guard = Guard(phase_allowlist(), engagement_id=ENG,
                  approvals={f"nuclei.safe_templates@{h}" for h in approved})
    return Harness(guard, AuditLog(), {"nuclei.safe_templates": NucleiSafeTemplates(runner)},
                   KillSwitch())


ACTION = Action("nuclei.safe_templates", Phase.ANALYZE, requires_human_approval=True)


def test_nuclei_corre_por_el_harness_con_un_host_del_lab():
    calls = []

    def runner(argv, timeout):
        calls.append(argv)
        return '{"template-id": "p4-security-header-csp", "host": "http://dvwa.lab.test/"}\n'

    h = harness(runner)
    out = h.invoke("analysis", ACTION, "dvwa.lab.test", token())
    assert out["tool"] == "nuclei" and len(out["lines"]) == 1
    assert calls[0][calls[0].index("-u") + 1] == "http://dvwa.lab.test/"
    assert calls[0][calls[0].index("-t") + 1] == "templates/allowlist"
    assert h.audit.entries[-1]["result"] == "OK"


def test_juice_shop_usa_su_puerto_del_lab():
    from harness.adapters.nuclei_adapter import target_url
    assert target_url("juiceshop.lab.test") == "http://juiceshop.lab.test:3000/"


def test_host_fuera_del_lab_no_construye_url():
    from harness.adapters.nuclei_adapter import target_url
    with pytest.raises(InvalidTarget):
        target_url("example.com")


def test_sin_aprobacion_humana_queda_pendiente_y_no_ejecuta():
    calls = []
    h = harness(lambda argv, t: calls.append(argv) or "", approved=())
    out = h.invoke("analysis", ACTION, "dvwa.lab.test", token())
    assert out["status"] == "PENDING_HITL" and calls == []


# ---- Allow-list verificable: MANIFEST.md con hash y segunda aprobación humana -------

TEMPLATE = "id: t1\ninfo:\n  name: x\n  severity: info\n  tags: headers\n"


def allowlist(tmp_path, *, approver="Martin Beccereca (P5)", proposer="Maria Belen Benito (P4)",
              digest=None, extra_file=False, crlf=False):
    import hashlib
    d = tmp_path / "allowlist"
    d.mkdir()
    body = TEMPLATE.replace("\n", "\r\n") if crlf else TEMPLATE
    (d / "t1.yaml").write_bytes(body.encode("utf-8"))
    if extra_file:
        (d / "t2.yaml").write_text(TEMPLATE, encoding="utf-8")
    sha = digest or hashlib.sha256(TEMPLATE.encode("utf-8")).hexdigest()
    (d / "MANIFEST.md").write_text(
        "| Archivo | SHA-256 | Propuso | Segunda aprobación | Fecha |\n|---|---|---|---|---|\n"
        f"| t1.yaml | {sha} | {proposer} | {approver} | 2026-11-19 |\n", encoding="utf-8")
    return d


def nal():
    import importlib
    return importlib.import_module("harness.nuclei_allowlist")


def test_allowlist_aprobada_se_acepta(tmp_path):
    rows = nal().verify_allowlist(allowlist(tmp_path))
    assert [r["archivo"] for r in rows] == ["t1.yaml"]


def test_hash_con_crlf_de_git_en_windows_se_acepta(tmp_path):
    nal().verify_allowlist(allowlist(tmp_path, crlf=True))


def test_template_modificado_despues_de_aprobar_se_rechaza(tmp_path):
    with pytest.raises(nal().AllowlistError, match="hash"):
        nal().verify_allowlist(allowlist(tmp_path, digest="0" * 64))


def test_template_sin_fila_en_el_manifiesto_se_rechaza(tmp_path):
    with pytest.raises(nal().AllowlistError, match="t2.yaml"):
        nal().verify_allowlist(allowlist(tmp_path, extra_file=True))


@pytest.mark.parametrize("approver", ["", "Pendiente", "security-reviewer"])
def test_sin_segunda_aprobacion_humana_se_rechaza(tmp_path, approver):
    with pytest.raises(nal().AllowlistError):
        nal().verify_allowlist(allowlist(tmp_path, approver=approver))


def test_quien_propone_no_puede_ser_la_segunda_aprobacion(tmp_path):
    with pytest.raises(nal().AllowlistError, match="otra persona"):
        nal().verify_allowlist(allowlist(tmp_path, approver="Maria Belen Benito (P4)"))


def test_allowlist_vacia_se_rechaza(tmp_path):
    (tmp_path / "vacia").mkdir()
    with pytest.raises(nal().AllowlistError):
        nal().verify_allowlist(tmp_path / "vacia")


def test_host_fuera_de_alcance_lo_bloquea_el_guard():
    calls = []
    h = harness(lambda argv, t: calls.append(argv) or "", approved=("example.com",))
    with pytest.raises(ScopeViolation):
        h.invoke("analysis", ACTION, "example.com", token())
    assert calls == []
