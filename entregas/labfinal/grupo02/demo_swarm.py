#!/usr/bin/env python3
"""Demo del swarm en modo golden (sin API key) — grupo 02.

Muestra el recorrido de los agentes encadenados sobre un caso real del
engagement (phantomcorp). Cada agente devuelve una salida representativa que se
VALIDA contra los schemas del harness: si un agente inventara un dato (p. ej. un
candidato sin evidencia), el schema lo rechazaría acá mismo.

La ejecución con un modelo real (modo live) es el siguiente paso; este runner
demuestra que los contratos entre agentes cierran de punta a punta.

    python3 demo_swarm.py
"""
from __future__ import annotations

from harness.schemas import (Asset, CandidateFinding, PrioritizedVuln, dedupe,
                             priority_score)


def paso(titulo: str) -> None:
    print(f"\n{'='*64}\n  {titulo}\n{'='*64}")


def discovery_agent() -> list[Asset]:
    """Agente Discovery → inventaría activos en alcance (schema Asset)."""
    return [
        Asset(id="asset-1", type="web_service", address="phantomcorp",
              source_tool="httpx", technologies=("PhantomClientes/2.0",)),
    ]


def analysis_agent(assets: list[Asset]) -> tuple[list[CandidateFinding], list[PrioritizedVuln]]:
    """Agente Analysis → candidatos (con evidencia) y vulnerabilidades priorizadas."""
    candidatos = [
        CandidateFinding(id="cand-1", asset_id="asset-1", cwe="CWE-78",
                         attack_technique="T1190", evidence_refs=["audit:142"],
                         confidence="high"),
        CandidateFinding(id="cand-2", asset_id="asset-1", cwe="CWE-200",
                         evidence_refs=["audit:118"], confidence="high"),
    ]
    candidatos = dedupe(candidatos)
    vulns = [
        PrioritizedVuln(finding_id="cand-1", status="confirmed",
                        rationale="RCE confirmado: /api/reporte ejecutó 'id' y devolvió uid=0(root)",
                        evidence_refs=("audit:142", "audit:143"), cvss_v4_score=9.3),
        PrioritizedVuln(finding_id="cand-2", status="confirmed",
                        rationale="backup /backup/rrhh.conf accesible sin auth; filtra el token de API",
                        evidence_refs=("audit:118",), cvss_v4_score=8.7),
    ]
    return candidatos, vulns


def validation_agent(vuln: PrioritizedVuln) -> dict:
    """Agente Validation → elige UNA verificación del catálogo, con gate humano."""
    return {"poc_id": "POC-REFLECT-001",
            "params": {"path": "/api/reporte", "marker": "cnry-7f3a"},
            "requires_human_approval": True}


def main() -> None:
    paso("1. DISCOVERY — inventario de activos en alcance")
    assets = discovery_agent()
    for a in assets:
        print(f"  [OK schema Asset] {a.id}  {a.address}  ({a.source_tool})  {a.technologies}")

    paso("2. ANALYSIS — candidatos (cada uno con evidencia) y priorización")
    candidatos, vulns = analysis_agent(assets)
    for c in candidatos:
        print(f"  [OK schema CandidateFinding] {c.id}  {c.cwe}  evidencia={c.evidence_refs}")
    for v in vulns:
        p = priority_score(v.cvss_v4_score, epss=None, asset_criticality=5)
        print(f"  [OK schema PrioritizedVuln] {v.finding_id}  {v.status}  CVSS={v.cvss_v4_score}  prioridad={p}")
        print(f"      rationale: {v.rationale}")

    paso("3. VALIDATION — verificación inerte del catálogo (requiere gate humano)")
    eleccion = validation_agent(vulns[0])
    print(f"  PoC elegido: {eleccion['poc_id']}  params={eleccion['params']}")
    print(f"  requires_human_approval = {eleccion['requires_human_approval']}  -> queda PENDING_HITL")

    paso("4. REPORTING — se redacta desde la evidencia registrada (no se inventa)")
    print("  El agente Reporting consolidaría estos hallazgos citando evidencia por")
    print("  referencia (audit:142, audit:118), con CWE + CVSS v4 + remediación.")

    print("\nTodos los contratos de schema cerraron. Cero datos inventados "
          "(cada candidato trae evidencia).")

    paso("5. EL CONTROL EN ACCIÓN — un agente que INVENTA es rechazado")
    print("  Si el agente Analysis intentara devolver un candidato SIN evidencia")
    print("  (un hallazgo 'alucinado'), el schema lo rechaza antes de propagarse:")
    try:
        CandidateFinding(id="cand-falso", asset_id="asset-1", cwe="CWE-89",
                         evidence_refs=[])  # sin evidencia: dato inventado
        print("  [!!] ERROR: se aceptó un candidato sin evidencia (esto NO debería pasar)")
    except Exception as e:
        print(f"  [OK — RECHAZADO] {type(e).__name__}: {e}")
    print("\n  'El agente propone, el harness dispone': el modelo puede equivocarse,")
    print("  el control no se lo permite.")


if __name__ == "__main__":
    main()
