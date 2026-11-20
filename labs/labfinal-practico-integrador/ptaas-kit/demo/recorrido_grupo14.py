"""Demo de recorrido PTaaS de punta a punta (grupo 14) — un solo comando.

    python demo/recorrido_grupo14.py

Ejecuta el engagement completo CREATED -> ... -> DELIVERED con el harness real:
guard determinista, scope token por fase, gates HITL, tope de iteraciones
(GuardedHarness), loops con parada, reporte con CWE+CVSS v4 y bitácora
hash-encadenada verificada al final.

Usa adaptadores INERTES SIMULADOS (no hay escaneo real contra terceros en esta
sesión, por las reglas del proyecto). La salida simula el laboratorio aislado.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness.contracts import (Action, AuditLog, Guard, Harness, KillSwitch,
                                Phase, Result, ScopeToken, evidence_ref)
from harness.engagement import Engagement, State
from harness.limits import GuardedHarness
from harness.loops import decide_recon
from harness.policy_loader import load_policy, phase_allowlist
from harness.reporting import Finding, deliver, render_report

TARGET = "10.0.0.5"          # host del laboratorio aislado
CIDRS = ("10.0.0.0/24",)
DOMAINS = ("lab.example.test",)


class InertSimAdapter:
    """Adaptador inerte: devuelve salida simulada, nunca toca la red."""

    def __init__(self, name, phases, payload):
        self.name, self.allowed_phases, self.destructive = name, phases, False
        self.payload, self.calls = payload, []

    def run(self, action, target, token):
        self.calls.append(target)
        return {"ok": True, "target": target, **self.payload}


def token_for(phase: Phase) -> ScopeToken:
    now = time.time()
    return ScopeToken("eng-grupo14", CIDRS, DOMAINS, now - 5, now + 600, phase)


def verify_chain(entries) -> bool:
    prev = "GENESIS"
    for e in entries:
        body = {k: v for k, v in e.items() if k != "hash"}
        if body["prev"] != prev:
            return False
        if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != e["hash"]:
            return False
        prev = e["hash"]
    return True


def step(msg):
    print(f"  -> {msg}")


def main() -> int:
    policy = load_policy()
    max_recon = policy["limits"]["max_loop_iterations"]["recon"]

    adapters = {
        "httpx.probe": InertSimAdapter("httpx.probe", (Phase.RECON,), {"status": 200}),
        "nmap.service_scan": InertSimAdapter("nmap.service_scan", (Phase.RECON,),
                                             {"ports": [80], "service": "http"}),
        "zap.baseline_scan": InertSimAdapter("zap.baseline_scan", (Phase.ANALYZE,),
                                             {"alerts": ["sqli-candidate"]}),
        "poc_catalog.run_parametrized": InertSimAdapter("poc_catalog.run_parametrized",
                                                        (Phase.VALIDATE,), {"reproduced": True}),
    }
    guard = Guard(phase_allowlist(policy))
    audit = AuditLog()
    ks = KillSwitch()
    h = Harness(guard, audit, adapters, ks)
    # change 008: enforcement de topes a nivel harness (iteración de loop + por objetivo)
    g = GuardedHarness(h, policy, max_invocations_per_target=10)

    eng = Engagement(roe_valid=True)
    print("== PTaaS — recorrido grupo 14 (laboratorio aislado, adaptadores inertes) ==\n")

    # 1. Autorización (RoE) + gate antes de la primera acción activa
    print("[1] Autorización")
    eng.advance()                               # CREATED -> AUTHORIZED (RoE válido)
    eng.approve("first_active_action")          # gate HITL
    eng.advance()                               # AUTHORIZED -> RECON
    step(f"estado = {eng.state.value}")

    # 2. Loop A — relevamiento acotado (para por grafo estable antes del tope)
    print("[2] Recon (loop A, tope de iteraciones =", max_recon, ")")
    t = token_for(Phase.RECON)
    for i, nuevos in enumerate([2, 1, 0], start=1):
        g.begin_iteration("recon")              # el harness rechaza si se pasa del tope
        g.invoke("recon", Action("httpx.probe", Phase.RECON), TARGET, t)
        g.invoke("recon", Action("nmap.service_scan", Phase.RECON), TARGET, t)
        d = decide_recon(i, nuevos, max_recon)
        step(f"iter {i}: {nuevos} activos nuevos -> {d.decision} ({d.reason})")
        if d.decision == "stop":
            break

    # 3. Correlación (solo datos, no toca activos) + referencia de evidencia inerte
    print("[3] Correlación")
    eng.advance()                               # RECON -> CORRELATE
    ev = evidence_ref("respuesta HTTP 200 con form de login en /portal", uri="loot://ev/001")
    step(f"evidencia citada por referencia: {ev['evidence'][:23]}… ({ev['bytes']} bytes)")

    # 4. Análisis
    print("[4] Análisis")
    eng.advance()                               # CORRELATE -> ANALYZE
    h.invoke("analysis", Action("zap.baseline_scan", Phase.ANALYZE), TARGET, token_for(Phase.ANALYZE))
    step("zap.baseline_scan -> candidato SQLi")

    # 5. Validación en sandbox con gate HITL (por engagement y por acción)
    print("[5] Validación (gate HITL)")
    eng.approve("before_validate")
    eng.advance()                               # ANALYZE -> VALIDATE
    tv = token_for(Phase.VALIDATE)
    av = Action("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=True)
    out = h.invoke("validation", av, TARGET, tv)
    step(f"sin aprobación -> {out['status']}")
    guard.approve(av.name, TARGET)              # aprueba el Reviewer
    h.invoke("validation", av, TARGET, tv)
    step("con aprobación -> PoC del catálogo reproducido en sandbox")

    # 6. Reporte (exige CWE + CVSS v4 + remediación)
    print("[6] Reporte")
    eng.advance()                               # VALIDATE -> REPORT
    finding = Finding(
        id="H-01", title="SQLi con bypass de autenticación", asset=TARGET,
        cwe="CWE-89",
        cvss_v4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        remediation="Consultas parametrizadas; nunca concatenar entrada en SQL.",
        validation_status="validated", evidence_refs=(ev["evidence"],),
    )
    report = render_report("eng-grupo14", [finding])
    step(f"informe generado con {len(report['findings'])} hallazgo(s)")

    # 7. Entrega (gate HITL del Reviewer)
    print("[7] Entrega")
    eng.approve("before_deliver")
    eng.advance()                               # REPORT -> DELIVERED
    report = deliver(report, reviewer_approved=True)
    step(f"estado = {eng.state.value} · delivered = {report['delivered']}")

    # 8. Cierre: verificación de la bitácora
    print("\n== Bitácora ==")
    tally: dict[str, int] = {}
    for e in audit.entries:
        tally[e["result"]] = tally.get(e["result"], 0) + 1
    print("  registros:", len(audit.entries), "·", tally)
    print("  cadena de hashes íntegra:", verify_chain(audit.entries))

    ok = eng.state == State.DELIVERED and verify_chain(audit.entries) and report["delivered"]
    print("\nRESULTADO:", "OK — recorrido completo" if ok else "FALLO")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
