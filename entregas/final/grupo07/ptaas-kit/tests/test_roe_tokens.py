"""Scenarios del change 003 (delta de `authorization`): RoE y emisión de tokens.

Incluye los tests adversariales A6, A7 y A8 de docs/desafios-extension.md.
"""
import copy
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from harness.contracts import (AuditLog, Harness, KillSwitch, KillSwitchEngaged, Phase,
                               Result, ScopeViolation)
from harness.policy_loader import load_policy, phase_allowlist
from harness.roe import RoEError, parse_roe
from harness.tokens import EngagementGuard, TokenIssuer, TokenRejected
from tests.conftest import FakeAdapter, act

ROOT = Path(__file__).resolve().parent.parent
LAB = {"cidrs": ("10.99.0.0/24",), "domains": ("dvwa.lab.test", "juiceshop.lab.test")}

BASE = {
    "engagement_id": "eng-lab-001",
    "scope": {"cidrs": ["10.99.0.0/28"], "domains": ["dvwa.lab.test", "juiceshop.lab.test"]},
    "exclusions": {"cidrs": ["10.99.0.5/32"], "domains": []},
    "window": {"start": "2026-11-20T09:00:00-03:00", "end": "2026-11-20T18:00:00-03:00"},
    "phases": ["recon", "correlate", "analyze"],
    "emergency_contacts": [{"name": "Docente", "channel": "canal de la cátedra"}],
    "approver": {"name": "Reviewer", "role": "reviewer",
                 "approved_at": "2026-11-20T08:30:00-03:00"},
}
# 10:00 en Argentina = 13:00 UTC, dentro de la ventana
NOW = datetime(2026, 11, 20, 13, 0, tzinfo=timezone.utc).timestamp()


def roe_dict(**cambios):
    d = copy.deepcopy(BASE)
    for clave, valor in cambios.items():
        d[clave] = valor
    return d


def roe_vigente(**cambios):
    """RoE cuya ventana incluye el reloj real: lo necesitan los tests que pasan por
    Harness.invoke, que valida la vigencia con time.time()."""
    ahora = datetime.now(timezone.utc)
    w = {"start": (ahora - timedelta(hours=1)).isoformat(),
         "end": (ahora + timedelta(hours=8)).isoformat()}
    ap = {"name": "Reviewer", "role": "reviewer",
          "approved_at": (ahora - timedelta(hours=2)).isoformat()}
    return parse_roe(roe_dict(window=w, approver=ap, **cambios), LAB)


def issuer_vigente(roe=None, audit=None, ks=None):
    return TokenIssuer(roe or roe_vigente(), audit or AuditLog(), killswitch=ks)


def issuer(roe=None, now=NOW, audit=None, ks=None):
    roe = roe or parse_roe(roe_dict(), LAB)
    return TokenIssuer(roe, audit or AuditLog(), killswitch=ks, clock=lambda: now)


# ----------------------------------------------------------------- parser: RoE válido

def test_roe_valido_se_parsea_con_ventana_en_utc_y_huella():
    roe = parse_roe(roe_dict(), LAB)
    assert roe.engagement_id == "eng-lab-001"
    assert roe.window_start == datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc).timestamp()
    assert roe.phases == (Phase.RECON, Phase.CORRELATE, Phase.ANALYZE)
    assert len(roe.fingerprint) == 64


def test_roe_de_ejemplo_del_repositorio_es_valido():
    roe = parse_roe(ROOT / "roe" / "roe-lab.example.yaml")
    assert roe.authorizes(Phase.VALIDATE)


# ----------------------------------------------------------------- parser: rechazos (2.1)

def test_roe_sin_alcance_se_rechaza():
    with pytest.raises(RoEError, match="alcance está vacío"):
        parse_roe(roe_dict(scope={"cidrs": [], "domains": []}), LAB)


def test_roe_con_campo_obligatorio_faltante_se_rechaza():
    d = roe_dict()
    del d["approver"]
    with pytest.raises(RoEError, match="approver"):
        parse_roe(d, LAB)


def test_roe_con_ventana_invertida_se_rechaza():
    w = {"start": "2026-11-20T18:00:00-03:00", "end": "2026-11-20T09:00:00-03:00"}
    with pytest.raises(RoEError, match="invertida"):
        parse_roe(roe_dict(window=w), LAB)


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "0.0.0.0/0", "10.99.0.0/16", "192.168.1.0/24"])
def test_a8_cidr_amplio_o_fuera_del_lab_se_rechaza(cidr):
    with pytest.raises(RoEError, match="excede el alcance"):
        parse_roe(roe_dict(scope={"cidrs": [cidr], "domains": []}), LAB)


def test_dominio_que_no_es_del_lab_se_rechaza():
    with pytest.raises(RoEError, match="no es un host del laboratorio"):
        parse_roe(roe_dict(scope={"cidrs": [], "domains": ["example.com"]}), LAB)


def test_exclusion_que_anula_todo_el_alcance_se_rechaza():
    d = roe_dict(scope={"cidrs": ["10.99.0.0/28"], "domains": []},
                 exclusions={"cidrs": ["10.99.0.0/24"], "domains": []})
    with pytest.raises(RoEError, match="anulan todo el alcance"):
        parse_roe(d, LAB)


def test_aprobador_sin_rol_reviewer_se_rechaza():
    ap = {"name": "Alguien", "role": "operador", "approved_at": "2026-11-20T08:30:00-03:00"}
    with pytest.raises(RoEError, match="reviewer"):
        parse_roe(roe_dict(approver=ap), LAB)


def test_fase_desconocida_se_rechaza():
    with pytest.raises(RoEError, match="fase desconocida"):
        parse_roe(roe_dict(phases=["recon", "exploit"]), LAB)


# ----------------------------------------------------------------- A7: zonas horarias

def test_a7_fecha_sin_zona_horaria_se_rechaza():
    w = {"start": "2026-11-20T09:00:00", "end": "2026-11-20T18:00:00-03:00"}
    with pytest.raises(RoEError, match="zona horaria"):
        parse_roe(roe_dict(window=w), LAB)


def test_a7_misma_ventana_en_distintas_zonas_horarias_es_identica():
    arg = parse_roe(roe_dict(), LAB)
    utc = parse_roe(roe_dict(window={"start": "2026-11-20T12:00:00Z",
                                     "end": "2026-11-20T21:00:00+00:00"}), LAB)
    assert (arg.window_start, arg.window_end) == (utc.window_start, utc.window_end)


def test_a7_borde_de_ventana_se_decide_en_utc():
    # 18:30 en Argentina (21:30 UTC) ya está fuera, aunque "18" parezca dentro en UTC-0
    fuera = datetime(2026, 11, 20, 21, 30, tzinfo=timezone.utc).timestamp()
    with pytest.raises(TokenRejected, match="fuera de la ventana"):
        issuer(now=fuera).issue(Phase.RECON)


# ----------------------------------------------------------------- emisor (3.1–3.4)

def test_roe_valido_emite_token_solo_de_la_fase_pedida_y_registra():
    audit = AuditLog()
    tok = issuer(audit=audit).issue(Phase.RECON)
    assert tok.phase is Phase.RECON and tok.engagement_id == "eng-lab-001"
    assert tok.is_live(NOW)
    assert tok.window_end - tok.window_start == 60 * 60            # TTL recon = 60 min
    ultimo = audit.entries[-1]
    assert (ultimo["action"], ultimo["result"], ultimo["phase"]) == ("token.issue", "OK", "recon")


def test_ttl_sale_de_policy_y_no_supera_el_fin_del_roe():
    ttl = load_policy()["phases"]["correlate"]["token_ttl_minutes"]
    assert issuer().issue(Phase.CORRELATE).window_end == NOW + ttl * 60
    casi_fin = datetime(2026, 11, 20, 20, 50, tzinfo=timezone.utc).timestamp()  # 10' antes del fin
    tok = issuer(now=casi_fin).issue(Phase.RECON)
    assert tok.window_end == parse_roe(roe_dict(), LAB).window_end


def test_fase_no_autorizada_se_rechaza_y_queda_registrada():
    audit = AuditLog()
    with pytest.raises(TokenRejected, match="no autoriza la fase 'validate'"):
        issuer(audit=audit).issue(Phase.VALIDATE)
    ultimo = audit.entries[-1]
    assert (ultimo["action"], ultimo["result"], ultimo["phase"]) == ("token.issue", "BLOCKED", "validate")


def test_exclusiones_prevalecen_sobre_el_alcance_en_el_guard():
    audit = AuditLog()
    tok = issuer_vigente(audit=audit).issue(Phase.RECON)
    assert "10.99.0.5/32" not in tok.allowed_cidrs
    httpx = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(EngagementGuard("eng-lab-001", phase_allowlist()), audit, {"httpx.probe": httpx},
                KillSwitch())
    h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.4", tok)        # en alcance
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "10.99.0.5", tok)    # excluida
    assert httpx.calls == ["10.99.0.4"] and audit.entries[-1]["result"] == "BLOCKED"


def test_dominio_excluido_no_llega_al_token():
    roe = parse_roe(roe_dict(exclusions={"cidrs": [], "domains": ["juiceshop.lab.test"]}), LAB)
    assert issuer(roe=roe).issue(Phase.RECON).allowed_domains == ("dvwa.lab.test",)


def test_token_vencido_no_se_renueva_solo():
    iss = issuer()
    tok = iss.issue(Phase.RECON)
    despues = tok.window_end + 1
    assert not tok.is_live(despues)                       # sigue vencido
    assert not hasattr(iss, "renew")                      # no existe renovación automática
    otro = TokenIssuer(iss.roe, iss.audit, clock=lambda: despues).issue(Phase.RECON)
    assert otro is not tok and otro.window_start == despues   # uno nuevo, pedido y registrado
    assert [e["result"] for e in iss.audit.entries] == ["OK", "OK"]


# ----------------------------------------------------------------- A6: reutilización

def test_a6_token_reutilizado_en_otra_fase_se_bloquea_y_registra():
    audit = AuditLog()
    tok = issuer_vigente(audit=audit).issue(Phase.RECON)
    zap = FakeAdapter("zap.baseline_scan", (Phase.ANALYZE,))
    h = Harness(EngagementGuard("eng-lab-001", phase_allowlist()), audit,
                {"zap.baseline_scan": zap}, KillSwitch())
    with pytest.raises(ScopeViolation):
        h.invoke("analysis", act("zap.baseline_scan", Phase.ANALYZE), "dvwa.lab.test", tok)
    assert zap.calls == [] and audit.entries[-1]["result"] == "BLOCKED"


def test_a6_token_de_otro_engagement_se_bloquea_y_registra():
    audit = AuditLog()
    tok_ajeno = issuer_vigente(roe=roe_vigente(engagement_id="eng-otro"), audit=audit).issue(Phase.RECON)
    httpx = FakeAdapter("httpx.probe", (Phase.RECON,))
    h = Harness(EngagementGuard("eng-lab-001", phase_allowlist()), audit,
                {"httpx.probe": httpx}, KillSwitch())
    with pytest.raises(ScopeViolation):
        h.invoke("recon", act("httpx.probe", Phase.RECON), "dvwa.lab.test", tok_ajeno)
    assert httpx.calls == [] and audit.entries[-1]["engagement"] == "eng-otro"
    assert audit.entries[-1]["result"] == "BLOCKED"


# ----------------------------------------------------------------- revocación

def test_revocar_el_roe_frena_emisiones_y_activa_el_kill_switch():
    audit, ks = AuditLog(), KillSwitch()
    iss = issuer_vigente(audit=audit, ks=ks)
    tok = iss.issue(Phase.RECON)
    iss.revoke()
    assert ks.engaged and audit.entries[-1]["result"] == "ABORTED"
    with pytest.raises(TokenRejected, match="revocado"):
        iss.issue(Phase.RECON)
    h = Harness(EngagementGuard("eng-lab-001", phase_allowlist()), audit,
                {"httpx.probe": FakeAdapter("httpx.probe", (Phase.RECON,))}, ks)
    with pytest.raises(KillSwitchEngaged):              # el token ya emitido tampoco sirve
        h.invoke("recon", act("httpx.probe", Phase.RECON), "dvwa.lab.test", tok)


# ----------------------------------------------------------------- 2.4: único constructor

def test_solo_el_emisor_crea_scope_tokens():
    """Ninguna ruta de producción construye ScopeToken fuera de harness/tokens.py."""
    patron = re.compile(r"\bScopeToken\s*\(")
    infractores = []
    for archivo in ROOT.rglob("*.py"):
        rel = archivo.relative_to(ROOT).as_posix()
        if rel.startswith(("tests/", ".venv/")) or rel == "harness/tokens.py":
            continue
        for n, linea in enumerate(archivo.read_text(encoding="utf-8").splitlines(), 1):
            codigo = linea.split("#", 1)[0]
            if patron.search(codigo) and not codigo.lstrip().startswith("class "):
                infractores.append(f"{rel}:{n}")
    assert infractores == [], f"ScopeToken creado fuera del emisor: {infractores}"
