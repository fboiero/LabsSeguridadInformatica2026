r"""Corrida de ZAP baseline autorizada en el laboratorio aislado (Change 005, P4).

Uso desde ptaas (PowerShell):
  .\.venv\Scripts\python.exe tools/run_zap_lab_p4.py
  .\.venv\Scripts\python.exe tools/run_zap_lab_p4.py --approved

La primera invocación devuelve PENDING_HITL, sin ejecutar Docker/ZAP.
Usar --approved solo cuando la aprobación humana requerida esté documentada.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from harness.adapters.zap_adapter import ZapBaseline, build_argv
from harness.contracts import (
    Action, AuditLog, Guard, Harness, KillSwitch, Phase, Result, ScopeToken,
)

IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
NETWORK = "lab_lab"
TARGET = "dvwa.lab.test"
ENGAGEMENT = "labfinal-grupo06"


def docker_json(*args: str) -> Any:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=20, check=True)
    return json.loads(proc.stdout)


def check_isolated_lab() -> None:
    network = docker_json("network", "inspect", NETWORK)[0]
    if network.get("Internal") is not True:
        raise RuntimeError("La red del laboratorio no es interna")
    for name in ("lab-runner-1", "lab-dvwa-1", "lab-juiceshop-1"):
        state = docker_json("inspect", name)[0]
        if set(state["NetworkSettings"]["Networks"]) != {NETWORK}:
            raise RuntimeError(f"Redes fuera del laboratorio en {name}")
        if not state["State"]["Running"]:
            raise RuntimeError(f"Contenedor detenido: {name}")


def check_report_scope(report: dict[str, Any]) -> None:
    """Rechaza reportes que mencionan sitios ajenos, pero no controla el spider."""
    sites = report.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        raise ValueError("Formato site no válido")
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("Entrada site no válida")
        name = site.get("@name", site.get("@host", ""))
        host = urlsplit(name).hostname if "://" in str(name) else str(name)
        if host and host.lower() != TARGET:
            raise ValueError("El reporte incluye un sitio fuera del objetivo permitido")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved", action="store_true",
                        help="Usar solo con autorización humana documentada")
    args = parser.parse_args()
    evidence = Path("evidencia/zap").resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    report_file = evidence / "zap-dvwa-baseline.json"
    log_file = evidence / "zap-dvwa-baseline.log"
    audit_file = evidence / "zap-dvwa-audit.json"

    now = time.time()
    token = ScopeToken(
        engagement_id=ENGAGEMENT,
        allowed_cidrs=(),
        allowed_domains=(TARGET,),
        window_start=now - 30,
        window_end=now + 600,
        phase=Phase.ANALYZE,
    )
    audit = AuditLog()
    guard = Guard({Phase.ANALYZE: {"zap.baseline_scan"}}, engagement_id=ENGAGEMENT)
    action = Action("zap.baseline_scan", Phase.ANALYZE,
                    requires_human_approval=True)

    def docker_runner(argv: list[str], timeout_s: int) -> str:
        check_isolated_lab()
        if argv != build_argv(TARGET):
            raise ValueError("argv no coincide con el perfil fijo del laboratorio")
        report_file.unlink(missing_ok=True)
        # Sustituye solo el destino del reporte, manteniendo el resto fijo.
        cmd = [
            "docker", "run", "--rm", "--pull", "never",
            "--network", NETWORK,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,src={evidence},dst=/zap/wrk",
            "--entrypoint", "zap-baseline.py", IMAGE,
            *argv[1:-1], "zap-dvwa-baseline.json",
        ]
        # argv termina en ['-J', '/dev/stdout']: se reemplaza por nombre de archivo.
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout_s, check=False)
        log_file.write_text(proc.stdout + "\n--- STDERR ---\n" + proc.stderr,
                            encoding="utf-8")
        if not report_file.is_file():
            raise RuntimeError(f"ZAP no generó JSON (exit={proc.returncode}); revisar log")
        data = json.loads(report_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise TypeError("Reporte JSON no es objeto")
        check_report_scope(data)
        if proc.returncode != 0:
            raise RuntimeError(f"ZAP exit={proc.returncode}; revisar log y reporte")
        # Normaliza variantes de site objeto/lista para el parser actual de ZapBaseline.
        if isinstance(data.get("site"), dict):
            data["site"] = [data["site"]]
        return json.dumps(data)

    harness = Harness(guard, audit, {"zap.baseline_scan": ZapBaseline(
        runner=docker_runner, timeout_s=450)}, KillSwitch())
    if args.approved:
        guard.approve("zap.baseline_scan", TARGET)

    try:
        result = harness.invoke("persona4", action, TARGET, token)
        print("Resultado:", result.get("status", "OK"))
        if "alerts" in result:
            print("Alertas (no validadas):", len(result["alerts"]))
    except Exception as exc:
        # Harness registra denegaciones; el adaptador puede fallar antes del OK.
        if not audit.entries or audit.entries[-1]["result"] not in {
            Result.BLOCKED.value, Result.PENDING_HITL.value, Result.ABORTED.value,
        }:
            audit.record("persona4", action, TARGET, token, Result.ABORTED)
        print(f"ERROR: {type(exc).__name__}: {exc}")
        return_code = 1
    else:
        return_code = 0
    finally:
        audit_file.write_text(json.dumps(audit.entries, indent=2), encoding="utf-8")
        print("Auditoría:", audit_file)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
