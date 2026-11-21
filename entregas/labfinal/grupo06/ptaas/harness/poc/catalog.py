"""Catálogo de verificaciones inertes: carga, validación y ejecución parametrizada.

El agente de validación SOLO elige un id del catálogo y completa parámetros
declarados. No puede agregar parámetros, ni pasar código, ni usar ids ajenos.
La verificación se evalúa sobre una respuesta ya obtenida (`ResponseRecord`),
lo que permite probarla offline con fixtures.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

_CATALOG = Path(__file__).resolve().parent / "catalog.yaml"
_REQUIRED = {"id", "version", "title", "cwe", "kind", "method", "parameters",
             "evaluator", "lab_only", "approved_by", "approved_at"}

# Change 006: ningún agente aprueba una entrada (I8 + gates humanos).
# Subagentes del kit y herramientas de IA que usa el grupo.
AGENT_APPROVERS = frozenset({
    "spec-author", "harness-engineer", "tool-adapter-dev", "security-reviewer",
    "orchestrator", "claude", "claude-code", "opencode", "agent", "agente",
})

# Change 006: los parámetros no pueden cambiar el objetivo.
# path: ruta que empieza con una sola "/", sin esquema, host, query ni fragmento.
_PATH_RE = re.compile(r"^/(?!/)[A-Za-z0-9._~%/-]*$")
# param_name: identificador simple, sin separadores de query.
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


class NotInCatalog(Exception): ...
class InvalidCatalog(Exception): ...
class ParameterError(Exception): ...
class ApprovalRequired(Exception): ...


@dataclass(frozen=True)
class ResponseRecord:
    status: int
    headers: dict[str, str]
    body: str
    set_cookies: tuple[str, ...] = ()
    canary: str | None = None     # canario enviado (solo POC-REFLECT-001)


@dataclass(frozen=True)
class Evidence:
    poc_id: str
    poc_version: str
    status: str                   # "validated" | "not_validated"
    detail: str
    parameters: dict = field(default_factory=dict)


def load_catalog(path: Path = _CATALOG) -> dict[str, dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return validate_entries(data["entries"])


def validate_entries(entries: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in entries:
        missing = _REQUIRED - e.keys()
        if missing:
            raise InvalidCatalog(f"{e.get('id', '?')}: faltan campos {sorted(missing)}")
        if e["kind"] != "inert_check":
            raise InvalidCatalog(f"{e['id']}: solo se admiten verificaciones 'inert_check'")
        if e["lab_only"] is not True:
            raise InvalidCatalog(f"{e['id']}: debe ser lab_only")
        if not e["approved_by"] or not e["approved_at"]:
            raise InvalidCatalog(f"{e['id']}: sin aprobación registrada")
        if str(e["approved_by"]).strip().lower() in AGENT_APPROVERS:
            raise InvalidCatalog(f"{e['id']}: la aprobación debe ser humana, no de un agente")
        if e["id"] in out:
            raise InvalidCatalog(f"id duplicado: {e['id']}")
        out[e["id"]] = e
    return out


# ---- Evaluadores: funciones puras sobre la respuesta observada -----------------

def _header(r: ResponseRecord, name: str) -> str | None:
    for k, v in r.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def header_missing_frame_protection(r: ResponseRecord) -> tuple[bool, str]:
    xfo = _header(r, "X-Frame-Options")
    csp = _header(r, "Content-Security-Policy") or ""
    ok = bool(xfo) or "frame-ancestors" in csp.lower()
    return (not ok, "sin X-Frame-Options ni frame-ancestors" if not ok else "protección presente")


def header_missing_csp(r: ResponseRecord) -> tuple[bool, str]:
    missing = not _header(r, "Content-Security-Policy")
    return (missing, "sin Content-Security-Policy" if missing else "CSP presente")


def cookie_flags_missing(r: ResponseRecord) -> tuple[bool, str]:
    problems = []
    for c in r.set_cookies:
        low = c.lower()
        miss = [f for f in ("secure", "httponly", "samesite") if f not in low]
        if miss:
            problems.append(f"{c.split('=')[0]} sin {','.join(miss)}")
    return (bool(problems), "; ".join(problems) if problems else "flags correctos")


def directory_listing_enabled(r: ResponseRecord) -> tuple[bool, str]:
    hit = r.status == 200 and re.search(r"<title>\s*index of /", r.body, re.I) is not None
    return (hit, "listado de directorio visible" if hit else "sin listado")


def input_reflected_unencoded(r: ResponseRecord) -> tuple[bool, str]:
    if not r.canary:
        return (False, "sin canario enviado")
    # Vulnerable si los caracteres especiales del canario aparecen SIN codificar.
    hit = r.canary in r.body
    return (hit, "canario reflejado sin codificar" if hit else "canario ausente o codificado")


def verbose_error_disclosure(r: ResponseRecord) -> tuple[bool, str]:
    sigs = [r"stack trace", r"traceback \(most recent call", r"at [\w.$]+\(.+\.(java|js|py|php):\d+",
            r"fatal error:.*on line \d+", r"sqlstate\[", r"you have an error in your sql syntax"]
    found = [s for s in sigs if re.search(s, r.body, re.I)]
    return (bool(found), f"firmas de error: {len(found)}" if found else "sin divulgación")


EVALUATORS: dict[str, Callable[[ResponseRecord], tuple[bool, str]]] = {
    "header_missing_frame_protection": header_missing_frame_protection,
    "header_missing_csp": header_missing_csp,
    "cookie_flags_missing": cookie_flags_missing,
    "directory_listing_enabled": directory_listing_enabled,
    "input_reflected_unencoded": input_reflected_unencoded,
    "verbose_error_disclosure": verbose_error_disclosure,
}


def new_canary() -> str:
    """Canario inerte: identificador único + caracteres especiales, sin marcado ejecutable."""
    return f"ptaas{secrets.token_hex(4)}\"'<>"


# ---- Ejecución parametrizada ---------------------------------------------------

Sender = Callable[[str, dict], ResponseRecord]   # lo provee el sandbox (fuera del kit)


def _check_target_params(params: dict) -> None:
    """Rechaza parámetros que cambiarían el host o la ruta aprobados (change 006)."""
    path = params.get("path")
    if path is not None and (not _PATH_RE.match(path) or ".." in path.split("/")):
        raise ParameterError("path debe empezar con una sola '/', sin host, query ni '..'")
    name = params.get("param_name")
    if name is not None and not _PARAM_NAME_RE.match(name):
        raise ParameterError("param_name debe ser un identificador simple")


def run_parametrized(catalog: dict[str, dict], poc_id: str, params: dict,
                     approved: bool, sender: Sender) -> Evidence:
    entry = catalog.get(poc_id)
    if entry is None:
        raise NotInCatalog(poc_id)
    if not approved:
        raise ApprovalRequired(f"{poc_id} requiere aprobación del Reviewer")
    declared = set(entry["parameters"])
    if set(params) != declared:
        raise ParameterError(f"parámetros esperados {sorted(declared)}, recibidos {sorted(params)}")
    for k, v in params.items():
        if not isinstance(v, str) or len(v) > 512 or re.search(r"[\r\n\x00]", v):
            raise ParameterError(f"valor inválido para {k}")
    _check_target_params(params)
    send_params = dict(params)
    if entry["evaluator"] == "input_reflected_unencoded":
        send_params["canary"] = new_canary()
    response = sender(poc_id, send_params)
    vulnerable, detail = EVALUATORS[entry["evaluator"]](response)
    return Evidence(poc_id, entry["version"], "validated" if vulnerable else "not_validated",
                    detail, params)
