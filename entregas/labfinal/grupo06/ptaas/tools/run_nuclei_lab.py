"""Corrida de nuclei.safe_templates contra el laboratorio (cierre de 005 · 3.3, P5).

    python tools/run_nuclei_lab.py --roe roe-p5.yaml --approvals <aprobaciones.json> \
        --output entrega/evidencia/salidas/P5-nuclei-01 --image projectdiscovery/nuclei:v3.11.1

Controles, en orden:
  1. RoE válido con la fase `analyze` (token de corta vida, auditado).
  2. Gate humano `active_analysis` aprobado con la CLI para ese engagement.
  3. Allow-list verificada contra MANIFEST.md (hash + segunda aprobación humana).
  4. Red del lab `internal: true`; imagen local (`--pull never`), digest registrado.
  5. Cada ejecución pasa por Harness.invoke; bitácora persistente (SQLite) + JSON.
  6. Se guarda una versión sanitizada de los hallazgos (sin request/response crudos).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import roe as roe_mod
from harness import tokens
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.audit import PersistentAuditLog
from harness.contracts import Action, Guard, Harness, KillSwitch, Phase
from harness.nuclei_allowlist import ALLOWLIST_DIR, verify_allowlist
from harness.policy_loader import phase_allowlist
from harness.recon_lab import export_audit
from harness.validation import ApprovalStore

TARGETS = ("dvwa.lab.test", "juiceshop.lab.test")
SAFE_KEYS = ("template-id", "host", "matched-at", "type", "timestamp", "matcher-status")


def sanitize(line: str) -> dict[str, object]:
    item = json.loads(line)
    info = item.get("info") or {}
    out: dict[str, object] = {k: item[k] for k in SAFE_KEYS if k in item}
    out["name"] = info.get("name")
    out["severity"] = info.get("severity")
    return out


def docker_runner(network: str, image: str):
    def run(argv: list[str], timeout: int) -> str:
        info = subprocess.run(["docker", "network", "inspect", network], capture_output=True,
                              text=True, timeout=30, check=False)
        if info.returncode != 0 or json.loads(info.stdout)[0].get("Internal") is not True:
            raise OSError(f"la red {network} no existe o no es interna")
        if argv[0] != "nuclei" or argv[argv.index("-t") + 1] != "templates/allowlist":
            raise ValueError("argv de Nuclei inesperado")
        cmd = ["docker", "run", "--rm", "--pull", "never", "--network", network,
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--tmpfs", "/root:rw,size=64m", "-w", "/work",
               "--mount", f"type=bind,src={ALLOWLIST_DIR},dst=/work/templates/allowlist,readonly",
               image, *argv[1:]]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout + 60, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"nuclei terminó con código {proc.returncode}: "
                               f"{proc.stderr.strip()[-300:]}")
        return proc.stdout
    return run


def image_digest(image: str) -> str:
    proc = subprocess.run(["docker", "image", "inspect", image, "--format",
                           "{{json .RepoDigests}}"], capture_output=True, text=True,
                          timeout=30, check=False)
    if proc.returncode != 0:
        raise OSError(f"la imagen {image} no está descargada (docker pull {image})")
    digests = json.loads(proc.stdout or "[]")
    return digests[0] if digests else image


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roe", type=Path, required=True)
    ap.add_argument("--approvals", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True, help="directorio NUEVO")
    ap.add_argument("--image", required=True, help="imagen local de Nuclei (p. ej. v3.11.1)")
    ap.add_argument("--network", default="ptaas-p3_lab")
    args = ap.parse_args()

    if args.output.exists():
        print(f"el directorio de salida ya existe: {args.output}")
        return 2
    roe = roe_mod.load(args.roe)
    eng = roe.engagement_id
    approvals = ApprovalStore(args.approvals, audit=None)
    gate = approvals.gate_record(eng, "active_analysis")
    if gate is None:
        print("falta la aprobación humana del análisis activo:\n  python -m harness.validation_cli "
              f"--store {args.approvals} approve-gate {eng} active_analysis "
              '--reviewer "<nombre>" --reason "<motivo>"')
        return 3
    templates = verify_allowlist()
    digest = image_digest(args.image)

    args.output.mkdir(parents=True)
    audit = PersistentAuditLog(args.output / "nuclei-audit.db", eng)
    findings: list[dict[str, object]] = []
    status = "ERROR"
    try:
        token = tokens.issue(roe, Phase.ANALYZE, audit=audit, agent="orchestrator")
        guard = Guard(phase_allowlist(), engagement_id=eng,
                      approvals={f"nuclei.safe_templates@{h}" for h in TARGETS})
        harness = Harness(guard, audit, {
            "nuclei.safe_templates": NucleiSafeTemplates(docker_runner(args.network, digest)),
        }, KillSwitch())
        action = Action("nuclei.safe_templates", Phase.ANALYZE, requires_human_approval=True)
        for host in TARGETS:
            out = harness.invoke("analysis", action, host, token)
            for line in out.get("lines", []):
                findings.append({"target": host, **sanitize(line)})
        status = "OK"
    finally:
        count, head = audit.store.anchor()
        export_audit(audit, args.output / "nuclei-audit.json")
        audit.close()
        (args.output / "nuclei-findings.json").write_text(
            json.dumps(findings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        manifest = {"engagement_id": eng, "status": status, "image": digest,
                    "network": args.network,
                    "gate_active_analysis": {"reviewer": gate["reviewer"], "reason": gate["reason"]},
                    "templates": [{"archivo": t["archivo"], "sha256": t["sha256"],
                                   "propuso": t["propuso"], "aprobo": t["aprobo"]}
                                  for t in templates],
                    "audit_anchor": {"count": count, "head": head},
                    "findings": len(findings)}
        (args.output / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "findings": len(findings),
                      "by_template": sorted({str(f.get('template-id')) for f in findings})},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
