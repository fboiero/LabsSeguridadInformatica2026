"""Change 005 · Control ESTÁTICO de propuestas Nuclei, sin ejecutar herramientas.

Ejecutar desde ptaas: python -m tools.p4_preflight_005
No aprueba templates, no realiza escaneos y no archiva deltas.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROPOSALS = Path("templates/proposed_p4")
EVIDENCE = Path("entrega/evidencia/salidas/p4-template-preflight.json")

# Aceptar únicamente estas cinco propuestas conocidas; ninguna DSL inyectada.
EXPECTED: dict[str, tuple[str, str, str]] = {
    "p4-login-form-visible.yaml": (
        "panel", "{{BaseURL}}/login.php", 'contains(tolower(body), "<form")'
    ),
    "p4-security-header-csp.yaml": (
        "misconfig", "{{BaseURL}}/", '!contains(tolower(all_headers), "content-security-policy:")'
    ),
    "p4-security-header-x-content-type-options.yaml": (
        "headers", "{{BaseURL}}/", '!contains(tolower(all_headers), "x-content-type-options:")'
    ),
    "p4-security-header-x-frame-options.yaml": (
        "headers", "{{BaseURL}}/", '!contains(tolower(all_headers), "x-frame-options:")'
    ),
    "p4-server-header-present.yaml": (
        "tech", "{{BaseURL}}/", 'contains(tolower(all_headers), "server:")'
    ),
}


class PreflightError(ValueError):
    """El archivo propuesto no supera la validación conservadora."""


def _check(condition: bool, reason: str) -> None:
    if not condition:
        raise PreflightError(reason)


def review_one(path: Path) -> dict[str, str]:
    """Verifica contenido inerte exacto; NO sustituye revisión humana."""
    _check(path.name in EXPECTED, f"template fuera de lista: {path.name}")
    _check(path.is_file() and not path.is_symlink(), f"archivo inválido: {path.name}")
    tag, endpoint, expression = EXPECTED[path.name]
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    _check(isinstance(data, dict) and set(data) == {"id", "info", "http"}, "esquema raíz inesperado")
    _check(data["id"] == path.stem, "id no coincide con archivo")
    info = data["info"]
    _check(isinstance(info, dict), "info inválida")
    _check(info.get("severity") == "info" and info.get("tags") == tag, "severidad o tag no esperado")
    _check(isinstance(info.get("name"), str) and bool(info["name"].strip()), "name ausente")
    _check(isinstance(info.get("author"), str) and bool(info["author"].strip()), "author ausente")
    reqs = data["http"]
    _check(type(reqs) is list and len(reqs) == 1 and isinstance(reqs[0], dict), "cantidad http inválida")
    req = reqs[0]
    _check(set(req) == {"method", "path", "redirects", "max-redirects", "matchers-condition", "matchers"}, "opción http no autorizada")
    _check(req["method"] == "GET", "solo GET")
    _check(req["path"] == [endpoint], "endpoint distinto al previsto")
    _check(req["redirects"] is False and type(req["max-redirects"]) is int and req["max-redirects"] == 0, "redirecciones habilitadas")
    _check(req["matchers-condition"] == "and", "matchers-condition inesperada")
    _check(req["matchers"] == [
        {"type": "status", "status": [200]},
        {"type": "dsl", "dsl": [expression]},
    ], "matchers distintos a lo revisable")
    return {
        "archivo": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "metodo": "GET",
        "ruta": endpoint,
        "estado": "APTO_PARA_REVISION_HUMANA_NO_APROBADO",
    }


def run_preflight(root: Path = ROOT) -> dict[str, Any]:
    folder = root / PROPOSALS
    _check(folder.is_dir(), "no existe carpeta de propuestas")
    found = {p.name for p in folder.iterdir() if p.suffix in {".yaml", ".yml"}}
    _check(found == set(EXPECTED), f"propuestas distintas a las cinco previstas: {sorted(found)}")
    # Actualizado por P5 (2026-11-19): una propuesta puede estar en la allow-list solo
    # si su aprobación verifica contra MANIFEST.md (hash + segunda aprobación humana).
    copied = list((root / "templates/allowlist").glob("p4-*.yaml"))
    aprobacion = "PENDIENTE"
    if copied:
        from harness.nuclei_allowlist import AllowlistError, verify_allowlist
        try:
            verify_allowlist(root / "templates/allowlist")
        except AllowlistError as exc:
            raise PreflightError(f"propuesta copiada a allowlist sin aprobación válida: {exc}") from exc
        aprobacion = "APROBADA"
    records = [review_one(folder / name) for name in sorted(EXPECTED)]
    return {
        "change": "005-correlation-analysis-loop-b",
        "evaluado_en_utc": datetime.now(UTC).isoformat(),
        "tipo": "revision_estatica_sin_red_sin_ejecucion",
        "aprobacion_humana": aprobacion,
        "escaneo_real": "NO_REALIZADO",
        "templates": records,
        "cantidad": len(records),
    }


def main() -> int:
    try:
        report = run_preflight(ROOT)
    except (PreflightError, yaml.YAMLError, OSError, TypeError, KeyError) as exc:
        print(f"FAIL preflight P4: {exc}")
        return 1
    out = ROOT / EVIDENCE
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: {len(report['templates'])} templates revisados ESTÁTICAMENTE")
    print("NO APROBADOS; NO se ejecutó Nuclei, ZAP ni ningún escaneo")
    for record in report["templates"]:
        print(f"  {record['archivo']}  sha256={record['sha256']}")
    print(f"Informe: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
