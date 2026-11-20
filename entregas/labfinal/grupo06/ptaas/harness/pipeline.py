"""Recorrido de un comando (change 007 · 3.5, P5).

    python -m harness.pipeline run --roe <roe.yaml> --approvals <aprobaciones.json> --output <dir nuevo> --analysis-fixture lab/analysis-fixture.json
    python -m harness.pipeline verify <dir>

RoE → recon (loop A, P3) → análisis → validación (loop C, 006) → informe → entrega.

Gates humanos: el comando ESPERA decisiones que una persona registra con
`python -m harness.validation_cli` en otra terminal. Nunca aprueba nada:
  1. `approve-gate <engagement> first_active_action` antes del primer sondeo;
  2. `approve <hallazgo>` por cada hallazgo antes de validarlo;
  3. `approve-delivery <engagement> --report-hash <hash>` antes de entregar.

Dónde corre cada cosa: el comando corre en el host (donde está Docker, que necesita
el sandbox). httpx y subfinder corren DENTRO del runner del lab con
`docker exec`, usando los adaptadores de P3 sin cambios; el host no alcanza la red
interna. Mientras no exista el change 005, el análisis es `fixture` y el informe
sale DEMO: no se entrega ni se exporta.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml

from harness import roe as roe_mod
from harness import tokens
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.subfinder_adapter import NoPassiveSources, SubfinderEnum
from harness.adapters.zap_adapter import ZapBaseline
from harness.asset_graph import AssetGraph
from harness.audit import (
    Entry,
    PersistentAuditLog,
    SQLiteAuditStore,
    VerifyResult,
    verificar_cadena,
)
from harness.contracts import Guard, Harness, KillSwitch, Phase, Result, ToolAdapter
from harness.defectdojo_export import export as export_defectdojo
from harness.loops import run_recon
from harness.poc.catalog import ParameterError
from harness.policy_loader import phase_allowlist
from harness.recon_lab import export_audit, verify_audit
from harness.report_builder import DemoReport, Report, build_report, deliver_report
from harness.reporting import DeliveryNotApproved, Finding
from harness.sandbox import (
    CAPABILITY,
    DEFAULT_IMAGE,
    DEFAULT_NETWORK,
    DockerRuntime,
    SandboxAborted,
    SandboxAdapter,
    SandboxSender,
    load_limits,
)
from harness.validation import (
    PENDING,
    ApprovalStore,
    FrozenCatalog,
    ValidationRequest,
    run_validation_loop,
)
from harness.zap_analysis import NO_POC, AnalysisBlocked, ZapAnalysis

DEFAULT_RUNNER = "ptaas-p3-runner-1"
# Imagen de ZAP fijada por P4 (tools/run_zap_lab_p4.py). Se usa con --pull never.
ZAP_IMAGE = ("ghcr.io/zaproxy/zaproxy@sha256:"
             "9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af")
_PROFILES = Path(__file__).resolve().parent / "profiles.yaml"
# Puerto fijo de cada objetivo del lab (P3 detectó que Juice Shop escucha en 3000).
LAB_PORTS = {"juiceshop.lab.test": 3000}
CANDIDATE_KEYS = {"id", "title", "asset", "cwe", "cvss_v4_vector", "remediation", "poc_id", "path"}


# ---- Configuración y resultado ----------------------------------------------------------


@dataclass(frozen=True)
class PipelineConfig:
    roe_path: Path
    approvals_path: Path
    output_dir: Path
    analysis: Any
    wait_s: float = 900
    poll_s: float = 5
    sandbox_network: str = DEFAULT_NETWORK
    sandbox_image: str = DEFAULT_IMAGE


@dataclass(frozen=True)
class Bridges:
    httpx: Callable[[list[str], int], str]
    subfinder: Callable[[list[str], int], str]
    resolver: Callable[[str], list[str]]
    sandbox_runtime: Any
    zap: Callable[[list[str], int], str] | None = None   # change 008


@dataclass
class PipelineResult:
    status: str            # ABORTED | PENDING_HITL | REPORT | DEMO | DELIVERED
    exit_code: int
    message: str = ""
    report: Report | None = None
    output: Path | None = None
    stages: dict[str, str] = field(default_factory=dict)


# ---- Análisis -----------------------------------------------------------------------------


class FixtureAnalysis:
    """Análisis simulado mientras no exista el change 005. Se declara `fixture`."""

    provenance = "fixture"

    def __init__(self, path: Path):
        self.path = Path(path)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.candidates = list(data["candidates"])

    def propose(self, assets: set[str]) -> list[dict[str, Any]]:
        return [dict(c) for c in self.candidates]


# ---- Puentes reales hacia el runner del lab --------------------------------------------------

_BRIDGE = (
    "import json, sys\n"
    "from harness.adapters import httpx_adapter, subfinder_adapter\n"
    "kind, argv, timeout = sys.argv[1], json.loads(sys.argv[2]), int(sys.argv[3])\n"
    "try:\n"
    "    if kind == 'httpx':\n"
    "        out = httpx_adapter._execute(argv, timeout)\n"
    "    else:\n"
    "        out = subfinder_adapter.OfflineSubfinderRunner()(argv, timeout)\n"
    "except subfinder_adapter.NoPassiveSources:\n"
    "    sys.exit(3)\n"
    "sys.stdout.write(out)\n"
)

_RESOLVE = (
    "import socket, sys\n"
    "print('\\n'.join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 80, "
    "type=socket.SOCK_STREAM)})))\n"
)


def real_bridges(container: str = DEFAULT_RUNNER, network: str = DEFAULT_NETWORK) -> Bridges:
    """httpx/subfinder corren dentro del runner con los adaptadores de P3; argv fijo, sin shell."""

    def in_runner(kind: str, argv: list[str], timeout: int) -> str:
        cmd = ["docker", "exec", "-w", "/work", "-e", "PYTHONPATH=/work", container,
               "python", "-c", _BRIDGE, kind, json.dumps(argv), str(int(timeout))]
        proc = subprocess.run(cmd, shell=False, capture_output=True, text=True,
                              timeout=timeout + 30, check=False)
        if kind == "subfinder" and proc.returncode == 3:
            raise NoPassiveSources()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd[:6], proc.stdout, proc.stderr)
        return proc.stdout

    def resolver(host: str) -> list[str]:
        proc = subprocess.run(["docker", "exec", container, "python", "-I", "-c", _RESOLVE, host],
                              shell=False, capture_output=True, text=True, timeout=30,
                              check=False)
        if proc.returncode != 0:
            raise OSError(f"no se pudo resolver {host} desde el runner")
        return [line for line in proc.stdout.split() if line]

    return Bridges(httpx=lambda a, t: in_runner("httpx", a, t),
                   subfinder=lambda a, t: in_runner("subfinder", a, t),
                   resolver=resolver, sandbox_runtime=DockerRuntime(),
                   zap=zap_bridge(network))


def zap_bridge(network: str = DEFAULT_NETWORK,
               image: str = ZAP_IMAGE) -> Callable[[list[str], int], str]:
    """ZAP baseline en un contenedor efímero en la red interna del lab (change 008).

    Recibe el argv fijo del adaptador de P4 (`build_argv`). Verifica antes que la red
    sea `internal`, no descarga imágenes (`--pull never`) y no guarda el reporte crudo:
    lo devuelve al adaptador y se borra con el directorio temporal.
    """
    import tempfile

    def run_zap(argv: list[str], timeout: int) -> str:
        info = subprocess.run(["docker", "network", "inspect", network], shell=False,
                              capture_output=True, text=True, timeout=30, check=False)
        if info.returncode != 0 or json.loads(info.stdout)[0].get("Internal") is not True:
            raise OSError(f"la red {network} no existe o no es interna: no se ejecuta ZAP")
        if argv[0] != "zap-baseline.py" or argv[-2:] != ["-J", "/dev/stdout"]:
            raise ValueError("argv de ZAP inesperado")
        with tempfile.TemporaryDirectory(prefix="ptaas-zap-") as work:
            cmd = ["docker", "run", "--rm", "--pull", "never", "--network", network,
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--mount", f"type=bind,src={work},dst=/zap/wrk",
                   "--entrypoint", "zap-baseline.py", image, *argv[1:-1], "report.json"]
            proc = subprocess.run(cmd, shell=False, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout + 60,
                                  check=False)
            report = Path(work) / "report.json"
            if not report.is_file():
                raise OSError(f"ZAP no generó el reporte (exit {proc.returncode})")
            data = json.loads(report.read_text(encoding="utf-8"))
        if isinstance(data.get("site"), dict):
            data["site"] = [data["site"]]
        return json.dumps(data)

    return run_zap


# ---- Recorrido ----------------------------------------------------------------------------------


def run(cfg: PipelineConfig, *, bridges: Bridges | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = print) -> PipelineResult:
    out = Path(cfg.output_dir)
    if out.exists():
        return PipelineResult("ABORTED", 2, f"el directorio de salida ya existe: {out}")
    try:
        roe = roe_mod.load(cfg.roe_path)
    except roe_mod.RoEValidationError as exc:
        return PipelineResult("ABORTED", 2, f"RoE inválido: {exc}")

    out.mkdir(parents=True)
    bridges = bridges or real_bridges()
    eng = roe.engagement_id
    stages = {"recon": "real", "analysis": str(cfg.analysis.provenance), "validation": "real"}
    # Change 002: las dos bitácoras se persisten en SQLite (un archivo por engagement).
    harness_audit = PersistentAuditLog(out / "harness-audit.db", eng)
    evidence = SQLiteAuditStore(out / "evidence.db", eng)
    result = PipelineResult("ABORTED", 2, output=out, stages=stages)
    started = datetime.now(UTC).isoformat()

    def store() -> ApprovalStore:
        # Se relee en cada consulta: las decisiones las escribe una persona desde otra terminal.
        return ApprovalStore(cfg.approvals_path, audit=evidence)

    def wait_for(predicate: Callable[[], bool]) -> bool:
        start = clock()
        while True:
            if predicate():
                return True
            if clock() - start >= cfg.wait_s:
                return False
            sleep(cfg.poll_s)

    def cli_hint(args: str) -> str:
        return (f"python -m harness.validation_cli --store {cfg.approvals_path} {args} "
                f"--reviewer \"<nombre>\" --reason \"<motivo>\"")

    try:
        evidence.append({"event": "pipeline.start", "engagement": eng, "stages": stages,
                         "roe_approval_hash": roe.approval_hash})
        seeds = list(roe.scope_domains)

        # 1. Gate antes de la primera acción activa.
        log("[gate] esperando aprobación humana de la primera acción activa:\n  "
            + cli_hint(f"approve-gate {eng} first_active_action"))
        if not wait_for(lambda: store().gate_approved(eng, "first_active_action")):
            harness_audit.record_decision("orchestrator", "recon.first_active_action",
                                          ",".join(seeds), eng, Phase.RECON.value,
                                          Result.PENDING_HITL)
            evidence.append({"event": "gate.pending", "engagement": eng,
                             "gate": "first_active_action"})
            result = PipelineResult("PENDING_HITL", 3, "sin aprobación de la primera acción activa",
                                    output=out, stages=stages)
            return result
        gate = store().gate_record(eng, "first_active_action") or {}
        evidence.append({"event": "hitl.decision.observed", "engagement": eng,
                         "gate": "first_active_action", "reviewer": gate.get("reviewer"),
                         "reason": gate.get("reason"), "decided_at": gate.get("ts")})

        # 2. Recon real (loop A de P3) con las aprobaciones del gate materializadas.
        recon_token = tokens.issue(roe, Phase.RECON, audit=harness_audit, agent="orchestrator")
        guard = Guard(phase_allowlist(), approvals={f"httpx.probe@{h}" for h in seeds},
                      engagement_id=eng, resolver=bridges.resolver)
        recon_harness = Harness(guard, harness_audit, {
            "subfinder.enum": cast(ToolAdapter, SubfinderEnum(runner=bridges.subfinder)),
            "httpx.probe": cast(ToolAdapter, HttpxProbe(runner=bridges.httpx)),
        }, KillSwitch())
        graph = AssetGraph(eng)
        # run_recon (loop A de P3) no tiene anotaciones de tipos; no se modifica.
        run_recon(recon_harness, recon_token, seeds, graph,  # type: ignore[no-untyped-call]
                  checkpoint=out / "graph.json")
        assets = {str(a["address"]) for a in graph.assets.values()}
        evidence.append({"event": "stage.recon", "engagement": eng, "status": graph.status,
                         "reason": graph.stop_reason, "assets": sorted(assets)})
        if graph.status != "STOPPED":
            result = PipelineResult("ABORTED", 2, f"recon terminó en {graph.status}: "
                                    f"{graph.stop_reason}", output=out, stages=stages)
            return result

        # 3. Análisis: solo candidatos sobre activos relevados.
        catalog = FrozenCatalog.load()
        findings: list[Finding] = []
        requests: list[ValidationRequest] = []
        if getattr(cfg.analysis, "requires_harness", False):
            # Change 008: análisis real (loop B de P4 con ZAP) con gate humano propio.
            log("[gate] esperando aprobación humana del análisis activo (ZAP baseline):\n  "
                + cli_hint(f"approve-gate {eng} active_analysis"))
            if not wait_for(lambda: store().gate_approved(eng, "active_analysis")):
                harness_audit.record_decision("orchestrator", "analysis.active_analysis",
                                              ",".join(sorted(assets)), eng,
                                              Phase.ANALYZE.value, Result.PENDING_HITL)
                evidence.append({"event": "gate.pending", "engagement": eng,
                                 "gate": "active_analysis"})
                result = PipelineResult("PENDING_HITL", 3, "sin aprobación del análisis activo",
                                        output=out, stages=stages)
                return result
            gate = store().gate_record(eng, "active_analysis") or {}
            evidence.append({"event": "hitl.decision.observed", "engagement": eng,
                             "gate": "active_analysis", "reviewer": gate.get("reviewer"),
                             "reason": gate.get("reason"), "decided_at": gate.get("ts")})
            if bridges.zap is None:
                raise ValueError("falta el puente de ZAP para el análisis real")
            analyze_token = tokens.issue(roe, Phase.ANALYZE, audit=harness_audit,
                                         agent="orchestrator")
            zap_guard = Guard(phase_allowlist(),
                              approvals={f"zap.baseline_scan@{h}" for h in assets},
                              engagement_id=eng, resolver=bridges.resolver)
            zap_harness = Harness(zap_guard, harness_audit, {
                "zap.baseline_scan": cast(ToolAdapter, ZapBaseline(runner=bridges.zap,
                                                                   timeout_s=600)),
            }, KillSwitch())
            try:
                proposals = cfg.analysis.run(zap_harness, analyze_token, assets,
                                             evidence=evidence)
            except AnalysisBlocked as exc:
                status = "PENDING_HITL" if exc.status == "PENDING_HITL" else "ABORTED"
                result = PipelineResult(status, 3 if status == "PENDING_HITL" else 2,
                                        f"análisis: {exc}", output=out, stages=stages)
                return result
            cvss_source = cfg.analysis.cvss_source()
        else:
            proposals = cfg.analysis.propose(assets)
            cvss_source = None
        for cand in proposals:
            missing = CANDIDATE_KEYS - set(cand)
            if missing:
                raise ValueError(f"candidato {cand.get('id', '?')}: faltan {sorted(missing)}")
            if cand["asset"] not in assets:
                harness_audit.record_decision("analysis", "analysis.candidate", cand["asset"],
                                              eng, "analyze", Result.BLOCKED)
                evidence.append({"event": "analysis.discarded", "engagement": eng,
                                 "finding_id": cand["id"], "asset": cand["asset"],
                                 "reason": "activo no relevado por el recon"})
                continue
            findings.append(Finding(cand["id"], cand["title"], cand["asset"], cand["cwe"],
                                    cand["cvss_v4_vector"], cand["remediation"],
                                    "not_validated", (), cand.get("epss")))
            requests.append(ValidationRequest(cand["id"], cand["poc_id"] or NO_POC,
                                              _params(cand, catalog)))
        evidence.append({"event": "stage.analysis", "engagement": eng,
                         "provenance": stages["analysis"], "findings": [f.id for f in findings]})

        # 4. Validación: registrar propuestas, esperar decisiones, correr el loop C.
        if requests:
            # Solo se pide aprobación para lo que tiene verificación en el catálogo; el
            # resto lo deja el loop C como "no validado (fuera del catálogo)".
            to_approve = [r for r in requests if r.poc_id in catalog.entries]
            pending_store = store()
            for req in to_approve:
                pending_store.request(req.finding_id, req.poc_id, req.params)
            log("[gate] hallazgos pendientes de aprobación (aprobar o rechazar cada uno):\n  "
                + f"python -m harness.validation_cli --store {cfg.approvals_path} list\n  "
                + cli_hint("approve <hallazgo>"))
            wait_for(lambda: all(store().status(r.finding_id) != PENDING for r in to_approve))
            validate_token = tokens.issue(roe, Phase.VALIDATE, audit=harness_audit,
                                          agent="orchestrator")
            adapter = SandboxAdapter(runtime=bridges.sandbox_runtime,
                                     network=cfg.sandbox_network, engagement_id=eng,
                                     limits=load_limits(), audit=harness_audit,
                                     image=cfg.sandbox_image)
            val_harness = Harness(Guard(phase_allowlist(), engagement_id=eng,
                                        resolver=bridges.resolver),
                                  harness_audit, {CAPABILITY: adapter}, KillSwitch())
            sender = SandboxSender(val_harness, validate_token, adapter, evidence=evidence,
                                   lab_domains=_lab_domains())
            run_validation_loop(val_harness, validate_token, requests, approvals=store(),
                                sender=sender, catalog=catalog, evidence=evidence)

        # 5. Informe desde la bitácora.
        scope = _scope(roe, assets)
        if cvss_source:
            scope["cvss_source"] = cvss_source
        report = build_report(eng, findings, evidence=evidence, stages=stages, scope=scope)
        (out / "report.md").write_text(report.markdown + "\n", encoding="utf-8")
        _write_report_json(out / "report.json", report)
        log(f"[informe] versión {report.version} · hash {report.report_hash}"
            + (" · DEMO" if report.demo else ""))

        # 6. Entrega con aprobación registrada para este hash.
        if report.demo:
            try:
                deliver_report(report, approvals=store(), evidence=evidence)
            except DemoReport as exc:
                result = PipelineResult("DEMO", 0, str(exc), report=report, output=out,
                                        stages=stages)
            return result
        log("[gate] esperando aprobación humana de la entrega:\n  "
            + cli_hint(f"approve-delivery {eng} --report-hash {report.report_hash}"))
        wait_for(lambda: store().delivery_approved(eng, report.report_hash))
        try:
            delivered = deliver_report(report, approvals=store(), evidence=evidence)
        except DeliveryNotApproved as exc:
            result = PipelineResult("REPORT", 3, str(exc), report=report, output=out,
                                    stages=stages)
            return result
        export_defectdojo(delivered, out / "defectdojo.json")
        _write_report_json(out / "report.json", delivered)
        result = PipelineResult("DELIVERED", 0, "informe entregado y exportado",
                                report=delivered, output=out, stages=stages)
        return result
    except (SandboxAborted, ParameterError, ValueError, OSError) as exc:
        result = PipelineResult("ABORTED", 2, f"{type(exc).__name__}: {exc}", output=out,
                                stages=stages)
        return result
    finally:
        evidence.append({"event": "pipeline.end", "engagement": eng, "status": result.status,
                         "message": result.message})
        export_audit(harness_audit, out / "harness-audit.json")
        _export_evidence(evidence, out / "evidence.json")
        # Ancla de cabeza (diseño 002): se guarda fuera de cada archivo, en el manifiesto.
        anchors = {"harness-audit.db": harness_audit.store.anchor(),
                   "evidence.db": evidence.anchor()}
        harness_audit.close()
        evidence.close()
        _write_manifest(out, eng, stages, result, started, anchors)
        log(f"[fin] {result.status}: {result.message}")


def _params(cand: Mapping[str, Any], catalog: FrozenCatalog) -> dict[str, str]:
    entry = catalog.entries.get(cand["poc_id"])
    port = LAB_PORTS.get(cand["asset"])
    base_url = f"http://{cand['asset']}" + (f":{port}" if port else "")
    params = {"base_url": base_url, "path": str(cand["path"])}
    if entry is not None and "param_name" in entry["parameters"]:
        params["param_name"] = str(cand.get("param_name", ""))
    return params


def _lab_domains() -> tuple[str, ...]:
    data = yaml.safe_load(_PROFILES.read_text(encoding="utf-8"))
    return tuple(data["targets"]["lab_only_domains"])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat()


def _scope(roe: Any, assets: set[str]) -> dict[str, Any]:
    exclusions = [*roe.excluded_cidrs, *roe.excluded_domains]
    return {"assets": ", ".join(sorted(assets)) or "ninguno",
            "window": f"{_iso(roe.window_start)} – {_iso(roe.window_end)}",
            "exclusions": ", ".join(exclusions) or "ninguna",
            "roe_ref": roe.approval_ref,
            "disclosure": {"recipient": roe.emergency_contacts[0] if roe.emergency_contacts
                           else "unknown"}}


def _write_report_json(path: Path, report: Report) -> None:
    data = {"engagement_id": report.engagement_id, "version": report.version,
            "report_hash": report.report_hash, "audit_head": report.audit_head,
            "demo": report.demo, "delivered": report.delivered, "stages": dict(report.stages),
            "findings": [{"id": f.id, "status": f.status, "status_label": f.status_label,
                          "stable_id": f.stable_id, "evidence_refs": list(f.evidence_refs)}
                         for f in report.findings]}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _export_evidence(evidence: Any, path: Path) -> None:
    entries = evidence.entries()
    payload = {"count": len(entries), "head": entries[-1].hash if entries else "GENESIS",
               "entries": [{"seq": e.seq, "prev": e.prev, "hash": e.hash, "data": dict(e.data)}
                           for e in entries]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def verify_evidence(path: Path) -> VerifyResult:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        rows = payload["entries"]
        if payload["count"] != len(rows) or payload["head"] != (
                rows[-1]["hash"] if rows else "GENESIS"):
            return VerifyResult(False, "conteo o anclaje final diferente")
        return verificar_cadena([Entry(r["seq"], r["prev"], r["hash"], r["data"]) for r in rows])
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return VerifyResult(False, type(exc).__name__)


def verify_outputs(output: Path) -> dict[str, VerifyResult]:
    """Verifica las exportaciones JSON y, si están, las bitácoras SQLite contra su ancla."""
    output = Path(output)
    results = {"harness-audit.json": verify_audit(output / "harness-audit.json"),
               "evidence.json": verify_evidence(output / "evidence.json")}
    manifest_path = output / "manifest.json"
    anchors = {}
    if manifest_path.is_file():
        anchors = json.loads(manifest_path.read_text(encoding="utf-8")).get("anchors", {})
    for name in ("harness-audit.db", "evidence.db"):
        if not (output / name).is_file():
            continue                      # los .db no se versionan (.gitignore)
        store = SQLiteAuditStore.open_existing(output / name)
        try:
            anchor = anchors.get(name)
            results[name] = (store.verify_anchor(anchor["count"], anchor["head"]) if anchor
                             else VerifyResult(False, "sin ancla en el manifiesto"))
        finally:
            store.close()
    return results


def _write_manifest(out: Path, eng: str, stages: Mapping[str, str], result: PipelineResult,
                    started: str, anchors: Mapping[str, tuple[int, str]]) -> None:
    files = {}
    for p in sorted(out.iterdir()):
        if p.is_file() and p.name != "manifest.json":
            files[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {"engagement_id": eng, "status": result.status, "message": result.message,
                "stages": dict(stages), "started_at": started,
                "finished_at": datetime.now(UTC).isoformat(),
                "report_hash": result.report.report_hash if result.report else None,
                "anchors": {k: {"count": c, "head": h} for k, (c, h) in anchors.items()},
                "files_sha256": files}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8")


# ---- CLI -----------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m harness.pipeline",
                                description="Recorrido PTaaS de un comando contra el lab")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--roe", type=Path, required=True)
    r.add_argument("--approvals", type=Path, required=True,
                   help="archivo de aprobaciones (usar uno nuevo por engagement)")
    r.add_argument("--output", type=Path, required=True, help="directorio NUEVO de salida")
    r.add_argument("--analysis", choices=["zap", "fixture"], default="zap",
                   help="zap: loop B de P4 con ZAP baseline (real); fixture: simulado (DEMO)")
    r.add_argument("--analysis-fixture", type=Path, default=Path("lab/analysis-fixture.json"),
                   help="archivo del análisis simulado (solo con --analysis fixture)")
    r.add_argument("--wait", type=float, default=900, help="segundos de espera por cada gate")
    r.add_argument("--runner", default=DEFAULT_RUNNER)
    r.add_argument("--network", default=DEFAULT_NETWORK)
    v = sub.add_parser("verify")
    v.add_argument("output", type=Path)
    args = p.parse_args(argv)

    if args.command == "verify":
        results = verify_outputs(args.output)
        for name, res in results.items():
            print(json.dumps({"file": name, "ok": res.ok, "reason": res.motivo},
                             ensure_ascii=False))
        return 0 if all(res.ok for res in results.values()) else 1

    analysis: Any = (ZapAnalysis() if args.analysis == "zap"
                     else FixtureAnalysis(args.analysis_fixture))
    cfg = PipelineConfig(roe_path=args.roe, approvals_path=args.approvals,
                         output_dir=args.output, analysis=analysis,
                         wait_s=args.wait, sandbox_network=args.network)
    outcome = run(cfg, bridges=real_bridges(args.runner, args.network))
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
