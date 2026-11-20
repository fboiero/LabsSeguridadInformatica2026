"""Integra 004/005 con sus adaptadores reales y runners de fixtures, sin red."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from harness.adapters.common import Runner
from harness.adapters.feed_adapter import CveLookup, CweMapLookup, EpssLookup
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.adapters.zap_adapter import ZapBaselineScan
from harness.contracts import Harness, Phase, ToolAdapter
from harness.correlation import Correlator
from harness.detection_loop import DetectionLoop
from harness.recon_loop import ReconLoop
from harness.schemas import CandidateFinding
from harness.tokens import TokenIssuer

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
PROVENANCE = {
    "recon": "fixtures sintéticas con ReconLoop (004)",
    "correlation": "snapshots offline con Correlator (005)",
    "analysis": "fixtures sintéticas con DetectionLoop (005)",
    "validation_seed": "candidato CSP manual para demo, sin CVE inferida",
    "audit": "SQLite persistente (002) + export JSON; verificable con harness.audit verify",
}


def fixture_runner(argv: list[str], timeout_s: int) -> str:
    """Solo interpreta argv de adaptadores conocidos. Nunca lanza binarios."""
    binary = Path(argv[0]).name
    if binary == "subfinder":
        return (FIXTURES / "004/subfinder.jsonl").read_text(encoding="utf-8")
    if binary == "httpx":
        return (FIXTURES / "004/httpx.jsonl").read_text(encoding="utf-8")
    if binary == "nuclei":
        return (FIXTURES / "005/nuclei.jsonl").read_text(encoding="utf-8")
    if binary == "zap-baseline.py":
        report = Path(argv[argv.index("-J") + 1])
        report.write_text(
            (FIXTURES / "005/zap-baseline.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        return ""
    raise ValueError("runner fixture no reconoce " + binary)


def run_team_pipeline(
    harness: Harness, issuer: TokenIssuer, target: str, output: Path,
    tools_mode: str = 'fixture', network: str = 'lab_lab',
) -> dict[str, Any]:
    if tools_mode not in {'fixture', 'docker'}:
        raise ValueError('modo de herramientas inválido')
    runner: Runner = fixture_runner
    provenance = dict(PROVENANCE)
    zap_profile = None
    if tools_mode == 'docker':
        from harness.adapters.common import load_profiles
        from harness.docker_runner import DockerToolRunner
        runner = DockerToolRunner(output, network)
        zap_profile = dict(load_profiles()['zap'], report_dir=str(output.resolve()))
        provenance.update(recon='Docker real con ReconLoop (004)',
                          analysis='Docker real con DetectionLoop (005)')
    harness.tools.update(
        {
            "subfinder.enum": cast(ToolAdapter, SubfinderEnum(runner=runner)),
            "httpx.probe": cast(ToolAdapter, HttpxProbe(runner=runner)),
            "cve.lookup": cast(ToolAdapter, CveLookup()),
            "epss.lookup": cast(ToolAdapter, EpssLookup()),
            "cwe.map": cast(ToolAdapter, CweMapLookup()),
            "zap.baseline_scan": cast(ToolAdapter, ZapBaselineScan(runner=runner, profile=zap_profile)),
            "nuclei.safe_templates": cast(ToolAdapter, NucleiSafeTemplates(runner=runner)),
        }
    )
    recon = ReconLoop(harness).run(target, issuer.issue(Phase.RECON), output / "asset-graph.json")
    assets = [node.asset for node in recon.graph.nodes if node.in_scope]
    candidates = Correlator(harness).correlate(assets, issuer.issue(Phase.CORRELATE))
    # Las fixtures no incluyen versión exacta y sus alertas no afirman ausencia
    # de CSP. Se conserva la semilla manual de 006; no se inventa una detección.
    node = recon.graph.get_by_address(target)
    if node is None:
        raise ValueError("objetivo ausente del grafo")
    seed = CandidateFinding(
        "F-CSP-001",
        node.asset.id,
        cwe="CWE-693",
        evidence_refs=["manual-demo-seed:CSP:requiere-validación"],
    )
    analysis = DetectionLoop(harness).analyze(seed, target, issuer.issue(Phase.ANALYZE))
    result = {
        "provenance": {
            **provenance,
            "correlation_result": f"{len(candidates)} coincidencias CVE",
            "analysis_result": analysis.status,
        },
        "recon": {
            "implementation": "harness.recon_loop.ReconLoop",
            "iterations": recon.iterations,
            "reason": recon.reason,
            "assets": [asdict(a) for a in assets],
        },
        "correlation": {
            "candidates": [asdict(c) for c in candidates],
            "reason": "sin match exacto; no se fabrica CVE"
            if not candidates
            else "coincidencias offline",
        },
        "analysis": asdict(analysis),
        "validation_seed": {"origin": "manual_demo_seed", "candidate": asdict(seed)},
    }
    (output / "pipeline-evidence.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Loop A (004, {tools_mode}):", recon.reason)
    print("Correlación (005, offline):", len(candidates), "coincidencias CVE")
    print(f"Loop B (005, {tools_mode}):", analysis.status, "—", analysis.rationale)
    print("Validación: candidato manual CSP; no se atribuye a una alerta de ZAP/Nuclei.")
    return result
