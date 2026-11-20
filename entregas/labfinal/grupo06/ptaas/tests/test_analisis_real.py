"""Scenarios del change 008: análisis real (loop B de P4 con ZAP) en el recorrido.

Delta: openspec/changes/008-analisis-real-en-recorrido/specs/reporting/spec.md

El ZAP falso devuelve el reporte REAL que P4 obtuvo contra DVWA
(evidencia/zap/zap-dvwa-baseline.json). Para Juice Shop devuelve un reporte sin
alertas, armado para el test. Las aprobaciones son precondiciones simuladas de cada
Scenario (la persona en otra terminal); el recorrido nunca aprueba nada.
"""
import importlib
import json
from pathlib import Path

import pytest

from harness.audit import InMemoryAuditStore
from tests.test_reporting_e2e import Bridges, cli

ROOT = Path(__file__).resolve().parent.parent
ZAP_DVWA = ROOT / "evidencia" / "zap" / "zap-dvwa-baseline.json"
ENG = "p5-zap"
HDR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
LOW = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


def api(module):
    return importlib.import_module("harness." + module)


def dvwa_alerts():
    data = json.loads(ZAP_DVWA.read_text(encoding="utf-8"))
    sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
    return [a for s in sites for a in s["alerts"]]


def mapping_yaml(path, *, approved_by="Persona de prueba", vector=HDR, extra=""):
    lines = [f'approved_by: "{approved_by}"' if approved_by is not None else "",
             'approved_at: "2026-11-19"',
             "plugins:",
             '  "10020": {poc_id: POC-HDR-001, cvss_v4_vector: "' + vector + '", '
             'rationale: "clickjacking"}',
             '  "10038": {poc_id: POC-CSP-001, cvss_v4_vector: "' + HDR + '", rationale: "csp"}',
             '  "10036": {poc_id: null, cvss_v4_vector: "' + LOW + '", rationale: "banner"}',
             extra]
    path.write_text("\n".join(x for x in lines if x) + "\n", encoding="utf-8")
    return path


# ---- Tabla de mapeo aprobada por una persona -------------------------------------


def test_tabla_sin_aprobacion_se_rechaza(tmp_path):
    za = api("zap_analysis")
    with pytest.raises(za.ZapMappingError):
        za.load_mapping(mapping_yaml(tmp_path / "m.yaml", approved_by=None))


def test_tabla_aprobada_por_agente_se_rechaza(tmp_path):
    za = api("zap_analysis")
    with pytest.raises(za.ZapMappingError, match="humana"):
        za.load_mapping(mapping_yaml(tmp_path / "m.yaml", approved_by="security-reviewer"))


def test_vector_invalido_se_rechaza_indicando_el_plugin(tmp_path):
    za = api("zap_analysis")
    with pytest.raises(za.ZapMappingError, match="10020"):
        za.load_mapping(mapping_yaml(tmp_path / "m.yaml", vector="CVSS:3.1/AV:N"))


def test_tabla_real_del_repo_tiene_vectores_validos():
    za = api("zap_analysis")
    m = za.load_mapping(ROOT / "harness" / "zap_mapping.yaml", require_approval=False)
    assert {"10020", "10038", "10010", "10054"} <= set(m.entries)


# ---- Alertas → hallazgos ---------------------------------------------------------------


def test_alerta_mapeada_genera_hallazgo_con_datos_de_zap(tmp_path):
    za = api("zap_analysis")
    m = za.load_mapping(mapping_yaml(tmp_path / "m.yaml"))
    cands, _ = za.findings_from_alerts("dvwa.lab.test", dvwa_alerts(), m)
    f = next(c for c in cands if c["pluginid"] == "10020")
    assert f["cwe"] == "CWE-1021"
    assert f["cvss_v4_vector"] == HDR
    assert f["poc_id"] == "POC-HDR-001"
    assert f["asset"] == "dvwa.lab.test"
    assert f["path"].startswith("/") and "?" not in f["path"]
    assert "<" not in f["remediation"] and f["remediation"]
    assert f["title"] == "Missing Anti-clickjacking Header"


def test_alerta_sin_mapeo_se_descarta_con_el_plugin(tmp_path):
    za = api("zap_analysis")
    m = za.load_mapping(mapping_yaml(tmp_path / "m.yaml"))
    cands, descartadas = za.findings_from_alerts("dvwa.lab.test", dvwa_alerts(), m)
    assert all(c["pluginid"] != "10021" for c in cands)        # riesgo 1, sin mapeo
    assert any(d["pluginid"] == "10021" and d["reason"] for d in descartadas)


def test_alerta_informativa_no_genera_hallazgo(tmp_path):
    # 10027 es riesgo 0 pero trae CWE (615) y remediación: solo la regla de riesgo la
    # puede excluir (con 10111, sin CWE, el test pasaba por otra regla; ver M33).
    za = api("zap_analysis")
    m = za.load_mapping(mapping_yaml(tmp_path / "m.yaml",
                                     extra='  "10027": {poc_id: null, cvss_v4_vector: "'
                                           + LOW + '", rationale: "info"}'))
    cands, descartadas = za.findings_from_alerts("dvwa.lab.test", dvwa_alerts(), m)
    assert all(c["pluginid"] != "10027" for c in cands)        # riesgo 0
    assert all(d["pluginid"] != "10027" for d in descartadas)  # ni siquiera se descarta


def test_alerta_mapeada_sin_verificacion_del_catalogo(tmp_path):
    za = api("zap_analysis")
    m = za.load_mapping(mapping_yaml(tmp_path / "m.yaml"))
    cands, _ = za.findings_from_alerts("dvwa.lab.test", dvwa_alerts(), m)
    banner = next(c for c in cands if c["pluginid"] == "10036")
    assert banner["poc_id"] is None


def _sin_verificacion(ev, fid):
    """validation.result tal como lo escribe el loop C para una alerta sin verificación."""
    ev.append({"event": "validation.result", "engagement": ENG, "finding_id": fid,
               "poc_id": "NINGUNA", "poc_version": None, "catalog_version": "0.1.0",
               "params_hash": "h-" + fid, "status": "not_validated",
               "reason": "fuera del catálogo", "attempts": 0})


def test_alertas_distintas_sin_verificacion_no_se_unifican():
    # Regresión de la corrida P5-recorrido-03: 10009 y 10036 (ambas CWE-497, sin
    # verificación en el catálogo) se unificaron como si fueran el mismo hallazgo.
    from harness.reporting import Finding
    rb = api("report_builder")
    ev = InMemoryAuditStore()
    _sin_verificacion(ev, "DVWA-ZAP-10009")
    _sin_verificacion(ev, "DVWA-ZAP-10036")
    fs = [Finding("DVWA-ZAP-10009", "In Page Banner Information Leak", "dvwa.lab.test",
                  "CWE-497", LOW, "Configurar el servidor", "not_validated"),
          Finding("DVWA-ZAP-10036", "Server Leaks Version Information", "dvwa.lab.test",
                  "CWE-497", LOW, "Suprimir el header Server", "not_validated")]
    report = rb.build_report(ENG, fs, evidence=ev, stages={"recon": "real", "analysis": "real",
                                                          "validation": "real"})
    assert {f.id for f in report.findings} == {"DVWA-ZAP-10009", "DVWA-ZAP-10036"}


def test_hallazgo_sin_verificacion_no_muestra_un_poc_inexistente():
    from harness.reporting import Finding
    rb = api("report_builder")
    ev = InMemoryAuditStore()
    _sin_verificacion(ev, "DVWA-ZAP-10021")
    f = Finding("DVWA-ZAP-10021", "X-Content-Type-Options Header Missing", "dvwa.lab.test",
                "CWE-693", LOW, "Enviar X-Content-Type-Options: nosniff", "not_validated")
    report = rb.build_report(ENG, [f], evidence=ev, stages={"recon": "real", "analysis": "real",
                                                           "validation": "real"})
    assert report.findings[0].poc_id is None
    assert "NINGUNA" not in report.markdown and "vNone" not in report.markdown


def test_instancia_fuera_del_objetivo_se_rechaza(tmp_path):
    za = api("zap_analysis")
    alerts = dvwa_alerts()
    alerts[0] = {**alerts[0], "instances": [{"uri": "http://example.com/"}]}
    with pytest.raises(za.ZapScopeError):
        za.check_report_scope("dvwa.lab.test", alerts)


# ---- Recorrido con análisis real ---------------------------------------------------------


def roe_yaml(path, phases=("recon", "analyze", "validate")):
    from datetime import UTC, datetime, timedelta
    now = datetime.now(UTC)
    path.write_text("\n".join([
        f"engagement_id: {ENG}",
        'approver: "Integrante del grupo (Reviewer)"',
        'approval_ref: "acta-lab-002"',
        f'signed_at: "{(now - timedelta(minutes=5)).isoformat()}"',
        "window:",
        f'  start: "{(now - timedelta(minutes=1)).isoformat()}"',
        f'  end: "{(now + timedelta(hours=2)).isoformat()}"',
        "scope:",
        '  cidrs: ["10.99.0.0/24"]',
        '  domains: ["dvwa.lab.test", "juiceshop.lab.test"]',
        "exclusions: {}",
        'emergency_contacts: ["Responsable del laboratorio"]',
        "authorized_phases: [" + ", ".join(f'"{p}"' for p in phases) + "]"]) + "\n",
        encoding="utf-8")
    return path


class ZapFake:
    def __init__(self, foreign=False):
        self.calls, self.foreign = [], foreign

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        url = argv[argv.index("-t") + 1]
        if "dvwa" in url:
            data = json.loads(ZAP_DVWA.read_text(encoding="utf-8"))
            if self.foreign:
                site = data["site"][0] if isinstance(data["site"], list) else data["site"]
                site["alerts"][0]["instances"] = [{"uri": "http://example.com/"}]
            return json.dumps(data)
        return json.dumps({"site": [{"@host": "juiceshop.lab.test", "alerts": []}]})


class Humano:
    def __init__(self, approvals, output, *, gates=("first_active_action", "active_analysis"),
                 delivery=True):
        self.approvals, self.output, self.gates, self.delivery = approvals, output, gates, delivery
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s
        base = ["--store", str(self.approvals)]
        for gate in self.gates:
            cli(base + ["approve-gate", ENG, gate, "--reviewer", "Ana Revisora",
                        "--reason", "autorizado"], audit=InMemoryAuditStore())
        store = api("validation").ApprovalStore(self.approvals, audit=InMemoryAuditStore())
        for fid, _ in store.pending():
            cli(base + ["approve", fid, "--reviewer", "Ana Revisora", "--reason", "en alcance"],
                audit=InMemoryAuditStore())
        rj = self.output / "report.json"
        if self.delivery and rj.exists():
            h = json.loads(rj.read_text(encoding="utf-8"))["report_hash"]
            cli(base + ["approve-delivery", ENG, "--report-hash", h, "--reviewer", "Ana Revisora",
                        "--reason", "revisado"], audit=InMemoryAuditStore())


def run_real(tmp_path, *, humano=None, roe=None, zap=None, wait_s=30):
    pl = api("pipeline")
    za = api("zap_analysis")
    output = tmp_path / "corrida"
    approvals = tmp_path / "approvals.json"
    br = Bridges()
    zap = zap or ZapFake()
    humano = humano or Humano(approvals, output)
    cfg = pl.PipelineConfig(roe_path=roe or roe_yaml(tmp_path / "roe.yaml"),
                            approvals_path=approvals, output_dir=output,
                            analysis=za.ZapAnalysis(mapping_yaml(tmp_path / "m.yaml")),
                            wait_s=wait_s, poll_s=1)
    result = pl.run(cfg, bridges=pl.Bridges(httpx=br.httpx, subfinder=br.subfinder,
                                            resolver=br.resolver, sandbox_runtime=br.runtime,
                                            zap=zap),
                    sleep=humano.sleep, clock=humano.clock)
    return result, zap, br, output


def test_sin_aprobacion_del_analisis_activo_no_corre_zap(tmp_path):
    output = tmp_path / "corrida"
    humano = Humano(tmp_path / "approvals.json", output, gates=("first_active_action",))
    result, zap, br, output = run_real(tmp_path, humano=humano)
    assert result.status == "PENDING_HITL" and result.exit_code != 0
    assert zap.calls == [] and br.runtime.created == []
    audit = json.loads((output / "harness-audit.json").read_text(encoding="utf-8"))
    assert any(e["result"] == "PENDING_HITL" and e["phase"] == "analyze"
               for e in audit["entries"])


def test_roe_sin_fase_de_analisis_no_corre_zap(tmp_path):
    roe = roe_yaml(tmp_path / "roe.yaml", phases=("recon", "validate"))
    result, zap, _, _ = run_real(tmp_path, roe=roe)
    assert result.status == "ABORTED" and result.exit_code != 0
    assert zap.calls == []


def test_reporte_de_zap_fuera_del_objetivo_aborta(tmp_path):
    result, _, br, _ = run_real(tmp_path, zap=ZapFake(foreign=True))
    assert result.status == "ABORTED" and result.exit_code != 0
    assert br.runtime.created == []


def test_recorrido_con_analisis_real_entrega_y_exporta(tmp_path):
    result, zap, _, output = run_real(tmp_path)
    assert result.status == "DELIVERED" and result.exit_code == 0
    assert result.report.demo is False and result.report.stages["analysis"] == "real"
    assert len(zap.calls) == 2                       # una vez por activo relevado
    ids = {f.id for f in result.report.findings}
    assert "DVWA-ZAP-10020" in ids and "DVWA-ZAP-10038" in ids
    assert (output / "defectdojo.json").exists()
    md = (output / "report.md").read_text(encoding="utf-8")
    assert "asignado por el analista" in md
    evidencia = json.loads((output / "evidence.json").read_text(encoding="utf-8"))
    assert any(e["data"].get("event") == "analysis.discarded" and e["data"].get("pluginid")
               for e in evidencia["entries"])
    verificacion = api("pipeline").verify_outputs(output)
    assert all(v.ok for v in verificacion.values())


def test_cli_acepta_el_gate_de_analisis_activo(tmp_path):
    path = tmp_path / "a.json"
    rc = cli(["--store", str(path), "approve-gate", ENG, "active_analysis",
              "--reviewer", "Ana", "--reason", "ZAP baseline autorizado"], audit=InMemoryAuditStore())
    store = api("validation").ApprovalStore(path, audit=InMemoryAuditStore())
    assert rc == 0 and store.gate_approved(ENG, "active_analysis")
