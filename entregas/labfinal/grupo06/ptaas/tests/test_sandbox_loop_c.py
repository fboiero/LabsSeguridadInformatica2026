"""Scenarios del change 006: sandbox efímero, Sender aislado y loop C.

Deltas: openspec/changes/006-sandbox-validation-loop-c/specs/{validation,poc-catalog}/spec.md
Diseño: openspec/changes/006-sandbox-validation-loop-c/design.md

Los tests unitarios usan un `FakeRuntime` en lugar de Docker. Las pruebas de
aislamiento real (red y destrucción) corren solo con PTAAS_SANDBOX_DOCKER=1 y el
lab levantado; ver tools/p3_lab/README.md.

Las aprobaciones que aparecen acá son precondiciones simuladas de cada Scenario:
prueban el control, no representan una aprobación humana real.
"""
import hashlib
import importlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from harness.audit import InMemoryAuditStore
from harness.contracts import (
    AuditLog,
    Guard,
    Harness,
    KillSwitch,
    KillSwitchEngaged,
    Phase,
    ScopeToken,
    ScopeViolation,
)
from harness.poc.catalog import (
    InvalidCatalog,
    ParameterError,
    load_catalog,
    run_parametrized,
    validate_entries,
)
from harness.policy_loader import phase_allowlist

ENG = "p5-test"
NETWORK = "ptaas-p3_lab"
LAB = ("dvwa.lab.test", "juiceshop.lab.test")
BASE = {"base_url": "http://dvwa.lab.test", "path": "/"}
CAPABILITY = "poc_catalog.run_parametrized"


def api(module):
    return importlib.import_module("harness." + module)


# ---- Fakes y armado ----------------------------------------------------------


def ok_response(status=200, headers=None, body="<html></html>", set_cookies=()):
    return {"status": status, "headers": dict(headers or {}), "body": body,
            "set_cookies": list(set_cookies)}


class FakeRuntime:
    """Runtime de contenedores en memoria. Registra cada operación en `events`."""

    def __init__(self, response=None, raise_on_run=None, fail_remove=False, leftovers=()):
        self.response = response if response is not None else ok_response()
        self.raise_on_run = raise_on_run
        self.fail_remove = fail_remove
        self.created = []
        self.removed = []
        self.events = []
        self.alive = {name: {"ptaas.engagement": ENG} for name in leftovers}

    def run(self, spec):
        self.created.append(spec)
        self.alive[spec.name] = dict(spec.labels)
        self.events.append(("run", spec.name))
        if self.raise_on_run is not None:
            raise self.raise_on_run
        if callable(self.response):
            return self.response(spec)
        return self.response

    def remove(self, name):
        self.events.append(("remove", name))
        if self.fail_remove:
            raise RuntimeError("docker rm falló")
        self.alive.pop(name, None)
        self.removed.append(name)

    def list_labeled(self, key, value):
        return [n for n, labels in self.alive.items() if labels.get(key) == value]


def make_token(phase=Phase.VALIDATE, domains=LAB, start=None, end=None):
    now = time.time()
    return ScopeToken(ENG, ("10.99.0.0/24",), domains,
                      now - 5 if start is None else start,
                      now + 600 if end is None else end, phase)


def setup(runtime=None, *, token=None, limits=None):
    sb = api("sandbox")
    runtime = runtime or FakeRuntime()
    audit = AuditLog()
    evidence = InMemoryAuditStore()
    adapter = sb.SandboxAdapter(runtime=runtime, network=NETWORK, engagement_id=ENG,
                                limits=limits or sb.SandboxLimits(), audit=audit)
    harness = Harness(Guard(phase_allowlist(), engagement_id=ENG), audit,
                      {CAPABILITY: adapter}, KillSwitch())
    token = token or make_token()
    sender = sb.SandboxSender(harness, token, adapter, evidence=evidence, lab_domains=LAB)
    return sb, harness, token, sender, runtime, evidence


def request(finding="F1", poc="POC-HDR-001", params=None):
    return api("validation").ValidationRequest(finding, poc, dict(params or BASE))


def approved_store(tmp_path, *reqs, evidence=None):
    val = api("validation")
    store = val.ApprovalStore(tmp_path / "approvals.json", audit=evidence or InMemoryAuditStore())
    for r in reqs:
        store.request(r.finding_id, r.poc_id, r.params)
        store.approve(r.finding_id, r.poc_id, val.params_hash(r.params),
                      reviewer="Integrante de prueba", reason="precondición del Scenario")
    return store


def run_loop(harness, token, sender, reqs, store, evidence, catalog=None, **kw):
    val = api("validation")
    return val.run_validation_loop(harness, token, reqs, approvals=store, sender=sender,
                                   catalog=catalog or val.FrozenCatalog.load(),
                                   evidence=evidence, **kw)


def all_audit_text(harness, evidence):
    return json.dumps(harness.audit.entries) + json.dumps([dict(e.data) for e in evidence.entries()])


# ---- Requirement: un sandbox por verificación, destruido siempre ---------------


def test_verificacion_finalizada_destruye_el_contenedor(tmp_path):
    _, h, tok, sender, rt, ev = setup(FakeRuntime(ok_response(headers={})))
    req = request()
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "validated"
    # Un "validated" se confirma con un segundo intento (design.md, decisión 5):
    # lo que importa acá es que cada contenedor creado se destruyó.
    assert rt.created and rt.removed == [s.name for s in rt.created]
    assert rt.list_labeled("ptaas.engagement", ENG) == []


def test_un_contenedor_distinto_por_verificacion(tmp_path):
    _, h, tok, sender, rt, ev = setup()
    reqs = [request("F1", "POC-HDR-001"), request("F2", "POC-CSP-001")]
    run_loop(h, tok, sender, reqs, approved_store(tmp_path, *reqs), ev)
    names = [s.name for s in rt.created]
    assert len(names) == len(set(names)) >= 2


def test_fallo_del_runtime_destruye_igual_y_no_valida(tmp_path):
    _, h, tok, sender, rt, ev = setup(FakeRuntime(raise_on_run=RuntimeError("se cayó")))
    req = request()
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "not_validated"
    assert rt.created and rt.removed == [s.name for s in rt.created]


def test_evaluador_que_falla_deja_el_hallazgo_no_validado(tmp_path, monkeypatch):
    catalog_mod = importlib.import_module("harness.poc.catalog")

    def roto(_):
        raise ValueError("evaluador roto")

    monkeypatch.setitem(catalog_mod.EVALUATORS, "header_missing_frame_protection", roto)
    _, h, tok, sender, rt, ev = setup()
    req = request()
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "not_validated"
    assert rt.list_labeled("ptaas.engagement", ENG) == []


def test_si_la_destruccion_falla_se_aborta_y_no_sigue(tmp_path):
    sb, h, tok, sender, rt, ev = setup(FakeRuntime(fail_remove=True))
    reqs = [request("F1", "POC-HDR-001"), request("F2", "POC-CSP-001")]
    with pytest.raises(sb.SandboxAborted):
        run_loop(h, tok, sender, reqs, approved_store(tmp_path, *reqs), ev)
    assert len(rt.created) == 1
    assert any(e["result"] == "ABORTED" for e in h.audit.entries)


def test_contenedor_huerfano_se_elimina_antes_de_empezar(tmp_path):
    _, h, tok, sender, rt, ev = setup(FakeRuntime(leftovers=("ptaas-sbx-viejo",)))
    req = request()
    run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert rt.events[0] == ("remove", "ptaas-sbx-viejo")
    assert any("ptaas-sbx-viejo" in json.dumps(dict(e.data)) for e in ev.entries())


def test_argv_de_docker_endurecido():
    sb = api("sandbox")
    spec = sb.ContainerSpec.for_request(network=NETWORK, engagement_id=ENG,
                                        url="http://dvwa.lab.test/", limits=sb.SandboxLimits())
    argv = sb.docker_argv(spec)
    assert argv[:2] == ["docker", "run"]
    for flag in ("--rm", "--read-only", "--network", NETWORK, "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges", "--memory", "128m",
                 "--pids-limit", "64", "--label", f"ptaas.engagement={ENG}"):
        assert flag in argv
    assert not any(a in ("-v", "--volume", "--mount", "--privileged", "-e", "--env")
                   for a in argv)
    assert all(isinstance(a, str) for a in argv)


# ---- Requirement: el sandbox no sale del laboratorio ---------------------------


def test_objetivo_fuera_del_lab_se_rechaza_antes_del_contenedor():
    # El token incluye example.com a propósito (RoE mal configurado): el que tiene
    # que frenarlo es la segunda barrera del Sender, no el Guard.
    tok = make_token(domains=LAB + ("example.com",))
    _, h, _, sender, rt, _ = setup(token=tok)
    with pytest.raises(ScopeViolation):
        sender("POC-HDR-001", {"base_url": "http://example.com", "path": "/"})
    assert rt.created == []
    assert h.audit.entries[-1]["result"] == "BLOCKED"


@pytest.mark.parametrize("base_url", ["file:///etc/passwd", "gopher://dvwa.lab.test",
                                      "ftp://dvwa.lab.test", "http://", "dvwa.lab.test"])
def test_esquema_o_url_no_permitidos(base_url):
    _, _, _, sender, rt, _ = setup()
    with pytest.raises(ScopeViolation):
        sender("POC-HDR-001", {"base_url": base_url, "path": "/"})
    assert rt.created == []


def test_objetivo_del_lab_devuelve_respuesta():
    _, _, _, sender, rt, _ = setup(FakeRuntime(ok_response(status=200)))
    resp = sender("POC-HDR-001", {"base_url": "http://dvwa.lab.test", "path": "/login.php"})
    assert resp.status == 200
    assert rt.created[0].url == "http://dvwa.lab.test/login.php"
    assert rt.created[0].network == NETWORK


@pytest.mark.skipif(os.environ.get("PTAAS_SANDBOX_DOCKER") != "1",
                    reason="requiere Docker y el lab levantado (PTAAS_SANDBOX_DOCKER=1)")
def test_real_sandbox_se_destruye_aunque_docker_falle():
    """Observación 2 de P1 (006 · 1.3): la destrucción tras un fallo se probaba solo con
    FakeRuntime. Acá falla un `docker run` real (imagen inexistente, --pull never) y se
    comprueba con Docker que no quedó ningún contenedor con la etiqueta del engagement."""
    import uuid

    from harness.contracts import Action
    sb = api("sandbox")
    runtime = sb.DockerRuntime()
    eng = f"p5-real-{uuid.uuid4().hex[:8]}"
    adapter = sb.SandboxAdapter(runtime=runtime, network=NETWORK, engagement_id=eng,
                                limits=sb.SandboxLimits(), audit=AuditLog(),
                                image="ptaas-imagen-que-no-existe:0")
    adapter.prepare("http://dvwa.lab.test/")
    with pytest.raises(RuntimeError):
        adapter.run(Action(CAPABILITY, Phase.VALIDATE), "dvwa.lab.test",
                    make_token())
    assert runtime.list_labeled("ptaas.engagement", eng) == []


@pytest.mark.skipif(os.environ.get("PTAAS_SANDBOX_DOCKER") != "1",
                    reason="requiere Docker y el lab levantado (PTAAS_SANDBOX_DOCKER=1)")
def test_real_sandbox_no_alcanza_internet():
    sb = api("sandbox")
    assert sb.DockerRuntime().probe_egress(NETWORK, ("1.1.1.1", 80)) is False


# ---- Requirement: el envío pasa por el harness ----------------------------------


def test_token_de_otra_fase_bloquea_sin_contenedor():
    _, h, _, sender, rt, _ = setup(token=make_token(phase=Phase.ANALYZE))
    with pytest.raises(ScopeViolation):
        sender("POC-HDR-001", dict(BASE))
    assert rt.created == []
    assert h.audit.entries[-1]["result"] == "BLOCKED"


def test_kill_switch_aborta_sin_contenedor():
    _, h, _, sender, rt, _ = setup()
    h.killswitch.engaged = True
    with pytest.raises(KillSwitchEngaged):
        sender("POC-HDR-001", dict(BASE))
    assert rt.created == []
    assert h.audit.entries[-1]["result"] == "ABORTED"


# ---- Requirement: límites de la verificación -------------------------------------


def test_timeout_deja_no_validado_y_destruye(tmp_path):
    sb = api("sandbox")
    _, h, tok, sender, rt, ev = setup(FakeRuntime(raise_on_run=sb.SandboxTimeout("10 s")))
    req = request()
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "not_validated"
    assert out["F1"].reason == "timeout"
    assert rt.removed


def test_respuesta_grande_se_trunca_y_se_marca():
    sb = api("sandbox")
    limits = sb.SandboxLimits(max_body_bytes=1024)
    _, _, _, sender, _, ev = setup(FakeRuntime(ok_response(body="A" * 5000)), limits=limits)
    resp = sender("POC-HDR-001", dict(BASE))
    assert len(resp.body) == 1024
    assert ev.entries()[-1].data["truncated"] is True


def test_no_sigue_redirecciones_en_la_especificacion():
    _, _, _, sender, rt, _ = setup(FakeRuntime(ok_response(
        status=302, headers={"Location": "http://example.com/"})))
    resp = sender("POC-HDR-001", dict(BASE))
    assert resp.status == 302
    assert rt.created[0].follow_redirects is False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()
        elif self.path == "/grande":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"B" * 4096)
        elif self.path == "/lento":
            time.sleep(2)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("X-Prueba", "1")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_fetch_del_contenedor_no_sigue_redireccion(local_server):
    out = api("sandbox").fetch(local_server + "/redir", timeout_s=5, max_body_bytes=1024)
    assert out["status"] == 302
    assert out["headers"]["Location"] == "http://example.com/"


def test_fetch_del_contenedor_trunca(local_server):
    out = api("sandbox").fetch(local_server + "/grande", timeout_s=5, max_body_bytes=100)
    assert len(out["body"]) == 100
    assert out["truncated"] is True


def test_fetch_del_contenedor_respeta_timeout(local_server):
    sb = api("sandbox")
    with pytest.raises(sb.SandboxTimeout):
        sb.fetch(local_server + "/lento", timeout_s=0.5, max_body_bytes=1024)


def test_limites_se_leen_de_un_perfil(tmp_path):
    sb = api("sandbox")
    perfil = tmp_path / "profiles.yaml"
    perfil.write_text("sandbox:\n  timeout_s: 7\n  container_timeout_s: 20\n"
                      "  max_body_bytes: 2048\n", encoding="utf-8")
    limits = sb.load_limits(perfil)
    assert (limits.timeout_s, limits.container_timeout_s, limits.max_body_bytes) == (7, 20, 2048)


def test_limites_por_defecto_del_design():
    limits = api("sandbox").SandboxLimits()
    assert (limits.timeout_s, limits.container_timeout_s, limits.max_body_bytes) == \
        (10, 30, 1024 * 1024)


# ---- Requirement: la aprobación cubre la verificación y sus parámetros ----------


def test_sin_aprobacion_queda_pendiente_y_no_envia(tmp_path):
    val = api("validation")
    _, h, tok, sender, rt, ev = setup()
    store = val.ApprovalStore(tmp_path / "a.json", audit=ev)
    out = run_loop(h, tok, sender, [request()], store, ev)
    assert out["F1"].status == "PENDING_HITL"
    assert rt.created == []


def test_parametros_cambiados_despues_de_aprobar(tmp_path):
    _, h, tok, sender, rt, ev = setup()
    store = approved_store(tmp_path, request(params={**BASE, "path": "/"}))
    out = run_loop(h, tok, sender, [request(params={**BASE, "path": "/admin"})], store, ev)
    assert out["F1"].status == "PENDING_HITL"
    assert rt.created == []


def test_otra_verificacion_que_la_aprobada(tmp_path):
    _, h, tok, sender, rt, ev = setup()
    store = approved_store(tmp_path, request(poc="POC-HDR-001"))
    out = run_loop(h, tok, sender, [request(poc="POC-CSP-001")], store, ev)
    assert out["F1"].status == "PENDING_HITL"
    assert rt.created == []


def test_aprobacion_rechazada(tmp_path):
    val = api("validation")
    _, h, tok, sender, rt, ev = setup()
    req = request()
    store = val.ApprovalStore(tmp_path / "a.json", audit=ev)
    store.request(req.finding_id, req.poc_id, req.params)
    store.reject(req.finding_id, reviewer="Integrante de prueba", reason="fuera de interés")
    out = run_loop(h, tok, sender, [req], store, ev)
    assert out["F1"].status == "not_validated"
    assert out["F1"].reason == "rechazado"
    assert rt.created == []


def test_verificacion_fuera_del_catalogo(tmp_path):
    _, h, tok, sender, rt, ev = setup()
    req = request(poc="POC-EXPLOIT-999")
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "not_validated"
    assert rt.created == []


# ---- Requirement: sin respuesta del Reviewer no se valida ----------------------


def test_token_vencido_sin_aprobacion_queda_no_validado(tmp_path):
    val = api("validation")
    now = time.time()
    _, h, tok, sender, rt, ev = setup(token=make_token(start=now - 600, end=now - 1))
    store = val.ApprovalStore(tmp_path / "a.json", audit=ev)
    out = run_loop(h, tok, sender, [request()], store, ev)
    assert out["F1"].status == "not_validated"
    assert out["F1"].reason == "sin aprobación"
    assert rt.created == []


# ---- Requirement: resultados consistentes ----------------------------------------


def test_intentos_contradictorios_no_validan(tmp_path):
    respuestas = iter([ok_response(headers={}),                         # vulnerable
                       ok_response(headers={"X-Frame-Options": "DENY"})])  # no vulnerable
    _, h, tok, sender, _, ev = setup(FakeRuntime(lambda spec: next(respuestas)))
    req = request()
    out = run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert out["F1"].status == "not_validated"
    assert out["F1"].reason == "inconsistente"


def test_intentos_no_superan_el_maximo_de_policy(tmp_path):
    _, h, tok, sender, rt, ev = setup(FakeRuntime(ok_response(headers={})))
    req = request()
    run_loop(h, tok, sender, [req], approved_store(tmp_path, req), ev)
    assert len(rt.created) <= 2


# ---- Requirement: evidencia por referencia, no por contenido -------------------


def test_bitacora_guarda_hash_y_no_el_cuerpo(tmp_path):
    cuerpo = "<html>cuerpo-unico-del-objetivo-7f3a</html>"
    _, h, tok, sender, _, ev = setup(FakeRuntime(ok_response(body=cuerpo)))
    req = request()
    run_loop(h, tok, sender, [req], approved_store(tmp_path, req, evidence=ev), ev)
    registros = [dict(e.data) for e in ev.entries() if "body_sha256" in e.data]
    assert registros
    r = registros[0]
    assert r["body_sha256"] == hashlib.sha256(cuerpo.encode()).hexdigest()
    assert r["body_len"] == len(cuerpo.encode())
    assert r["poc_id"] == "POC-HDR-001" and r["poc_version"] == "1.0.0"
    assert r["catalog_version"] == "0.1.0"
    assert r["truncated"] is False
    assert "cuerpo-unico-del-objetivo-7f3a" not in all_audit_text(h, ev)
    assert ev.verify().ok


def test_decision_del_reviewer_queda_en_bitacora(tmp_path):
    val = api("validation")
    ev = InMemoryAuditStore()
    req = request()
    store = val.ApprovalStore(tmp_path / "a.json", audit=ev)
    store.request(req.finding_id, req.poc_id, req.params)
    store.approve(req.finding_id, req.poc_id, val.params_hash(req.params),
                  reviewer="Ana Revisora", reason="alcance confirmado")
    d = next(dict(e.data) for e in ev.entries() if dict(e.data).get("decision") == "approved")
    assert d["reviewer"] == "Ana Revisora"
    assert d["reason"] == "alcance confirmado"
    assert d["params_hash"] == val.params_hash(req.params)
    assert "ts" in d


def test_params_hash_es_canonico():
    val = api("validation")
    a = val.params_hash({"base_url": "http://dvwa.lab.test", "path": "/"})
    b = val.params_hash({"path": "/", "base_url": "http://dvwa.lab.test"})
    c = val.params_hash({"path": "/x", "base_url": "http://dvwa.lab.test"})
    assert a == b != c


# ---- Requirement: CLI de aprobación con responsable y motivo -------------------


def cli(argv, **kw):
    try:
        return api("validation_cli").main(argv, **kw)
    except SystemExit as e:
        return e.code


def pending_store(tmp_path, ev):
    val = api("validation")
    path = tmp_path / "approvals.json"
    store = val.ApprovalStore(path, audit=ev)
    store.request("F1", "POC-HDR-001", dict(BASE))
    store.request("F2", "POC-CSP-001", {**BASE, "path": "/login.php"})
    store.request("F3", "POC-COOKIE-001", dict(BASE))
    store.approve("F3", "POC-COOKIE-001", val.params_hash(BASE),
                  reviewer="Integrante de prueba", reason="precondición del Scenario")
    return path


def test_cli_aprobar_sin_motivo_falla(tmp_path):
    val = api("validation")
    ev = InMemoryAuditStore()
    path = pending_store(tmp_path, ev)
    rc = cli(["--store", str(path), "approve", "F1", "--reviewer", "Ana"], audit=ev)
    assert rc != 0
    assert val.ApprovalStore(path, audit=ev).status("F1") == "PENDING_HITL"


def test_cli_aprobar_sin_reviewer_falla(tmp_path):
    val = api("validation")
    ev = InMemoryAuditStore()
    path = pending_store(tmp_path, ev)
    rc = cli(["--store", str(path), "approve", "F1", "--reason", "ok"], audit=ev)
    assert rc != 0
    assert val.ApprovalStore(path, audit=ev).status("F1") == "PENDING_HITL"


def test_cli_lista_solo_pendientes(tmp_path, capsys):
    ev = InMemoryAuditStore()
    path = pending_store(tmp_path, ev)
    assert cli(["--store", str(path), "list"], audit=ev) == 0
    out = capsys.readouterr().out
    assert "F1" in out and "POC-HDR-001" in out
    assert "F2" in out and "/login.php" in out
    assert "F3" not in out


def test_cli_aprobar_con_reviewer_y_motivo(tmp_path):
    val = api("validation")
    ev = InMemoryAuditStore()
    path = pending_store(tmp_path, ev)
    rc = cli(["--store", str(path), "approve", "F1", "--reviewer", "Ana", "--reason", "ok"],
             audit=ev)
    assert rc == 0
    assert val.ApprovalStore(path, audit=ev).status("F1") == "approved"


# ---- poc-catalog: ningún agente aprueba una entrada -----------------------------


def _entrada(**kw):
    base = {"id": "POC-NUEVA-001", "version": "1.0.0", "title": "t", "cwe": "CWE-693",
            "kind": "inert_check", "method": "GET", "parameters": ["base_url", "path"],
            "evaluator": "header_missing_csp", "lab_targets": ["dvwa"], "lab_only": True,
            "approved_by": "Integrante del grupo", "approved_at": "2026-11-18"}
    return {**base, **kw}


@pytest.mark.parametrize("agente", ["security-reviewer", "spec-author", "harness-engineer",
                                    "tool-adapter-dev", "orchestrator", "claude", "opencode"])
def test_entrada_aprobada_por_un_agente_se_rechaza(agente):
    with pytest.raises(InvalidCatalog):
        validate_entries([_entrada(approved_by=agente)])


def test_entrada_aprobada_por_una_persona_se_acepta():
    assert "POC-NUEVA-001" in validate_entries([_entrada()])


# ---- poc-catalog: el catálogo no cambia durante el loop C ----------------------


def test_catalogo_congelado_es_inmutable():
    cat = api("validation").FrozenCatalog.load()
    assert cat.version == "0.1.0"
    with pytest.raises(TypeError):
        cat.entries["POC-NUEVA-001"] = _entrada()


def test_entrada_agregada_al_archivo_durante_el_loop_no_se_usa(tmp_path):
    val = api("validation")
    origen = importlib.import_module("harness.poc.catalog")._CATALOG
    copia = tmp_path / "catalog.yaml"
    copia.write_text(origen.read_text(encoding="utf-8"), encoding="utf-8")
    cat = val.FrozenCatalog.load(copia)

    def agrega_entrada(spec):
        texto = copia.read_text(encoding="utf-8")
        if "POC-NUEVA-001" not in texto:
            copia.write_text(texto + "\n  - id: POC-NUEVA-001\n    version: \"1.0.0\"\n"
                             "    title: t\n    cwe: CWE-693\n    kind: inert_check\n"
                             "    method: GET\n    parameters: [base_url, path]\n"
                             "    evaluator: header_missing_csp\n    lab_targets: [dvwa]\n"
                             "    lab_only: true\n    approved_by: Persona\n"
                             "    approved_at: \"2026-11-18\"\n", encoding="utf-8")
        return ok_response()

    _, h, tok, sender, _, ev = setup(FakeRuntime(agrega_entrada))
    reqs = [request("F1", "POC-HDR-001"), request("F2", "POC-NUEVA-001")]
    out = run_loop(h, tok, sender, reqs, approved_store(tmp_path, *reqs), ev, catalog=cat)
    assert out["F2"].status == "not_validated"


# ---- poc-catalog: los parámetros no cambian el objetivo -------------------------


@pytest.fixture(scope="module")
def cat():
    return load_catalog()


def registrando(enviado):
    """Sender falso que anota lo enviado y devuelve una respuesta inocua."""
    from harness.poc.catalog import ResponseRecord

    def sender(poc_id, params):
        enviado.append(params)
        return ResponseRecord(200, {"X-Frame-Options": "DENY"}, "", canary=params.get("canary"))

    return sender


@pytest.mark.parametrize("path", ["//example.com/", "http://example.com/", "/../../etc/passwd",
                                  "/a/../../b", "login.php", ""])
def test_path_que_cambia_el_objetivo_se_rechaza(cat, path):
    enviado = []
    with pytest.raises(ParameterError):
        run_parametrized(cat, "POC-HDR-001", {**BASE, "path": path}, True,
                         registrando(enviado))
    assert enviado == []


@pytest.mark.parametrize("nombre", ["q&admin=1", "q=1", "q#x", "q y", "../q", ""])
def test_param_name_con_caracteres_especiales_se_rechaza(cat, nombre):
    enviado = []
    with pytest.raises(ParameterError):
        run_parametrized(cat, "POC-REFLECT-001", {**BASE, "param_name": nombre}, True,
                         registrando(enviado))
    assert enviado == []


def test_parametros_validos_llegan_tal_cual(cat):
    from harness.poc.catalog import ResponseRecord
    enviado = []

    def sender(i, p):
        enviado.append(p)
        return ResponseRecord(200, {"X-Frame-Options": "DENY"}, "")

    run_parametrized(cat, "POC-HDR-001", {**BASE, "path": "/login.php"}, True, sender)
    assert enviado == [{**BASE, "path": "/login.php"}]
