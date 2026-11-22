"""Catálogo docente de comprobaciones inertes y parametrización estricta."""
from __future__ import annotations

import html
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_PATH = Path(__file__).with_name("catalog.yaml")
_REQUIRED = {"id", "version", "title", "cwe", "kind", "method", "parameters", "evaluator", "lab_targets", "lab_only", "approved_by", "approved_at"}


class NotInCatalog(Exception): pass
class InvalidCatalog(Exception): pass
class ParameterError(ValueError): pass
class ApprovalRequired(Exception): pass


_ALLOWED_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/?%\-]*$")


def validate_target_path(path: str) -> str:
    """Solo rutas relativas simples dentro del host autorizado."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 512:
        raise ParameterError("path_invalid")
    lowered = path.lower()
    if (path.startswith("//") or "\\" in path or ".." in path or "%2e" in lowered
            or re.search(r"[\r\n\x00]", path) or not _ALLOWED_PATH.fullmatch(path)):
        raise ParameterError("path_invalid")
    return path


@dataclass(frozen=True)
class ResponseRecord:
    status: int
    headers: dict[str, str]
    body: str
    set_cookies: tuple[str, ...] = ()
    canary: str | None = None


@dataclass(frozen=True)
class Evidence:
    poc_id: str
    poc_version: str
    status: str
    detail: str
    parameters: dict[str, str]
    http_status: int
    observed: tuple[str, ...] = ()


def validate_entries(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if _REQUIRED - entry.keys() or entry.get("kind") != "inert_check" or entry.get("lab_only") is not True:
            raise InvalidCatalog("invalid_or_non_inert_entry")
        if not entry.get("approved_by") or not entry.get("approved_at") or entry["id"] in result:
            raise InvalidCatalog("approval_or_duplicate_entry")
        if entry["method"] != "GET" or not set(entry["lab_targets"]) <= {"dvwa", "juice-shop"}:
            raise InvalidCatalog("catalog_target_or_method")
        result[entry["id"]] = entry
    return result


def load_catalog(path: Path = _PATH) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return validate_entries(data["entries"])


def _header(record: ResponseRecord, name: str) -> str | None:
    return next((value for key, value in record.headers.items() if key.lower() == name.lower()), None)


def _evaluate(name: str, record: ResponseRecord) -> tuple[bool, str]:
    if name == "header_missing_csp":
        missing = _header(record, "Content-Security-Policy") is None
        return missing, "CSP ausente" if missing else "CSP presente"
    if name == "header_missing_frame_protection":
        csp = _header(record, "Content-Security-Policy") or ""
        missing = _header(record, "X-Frame-Options") is None and "frame-ancestors" not in csp.lower()
        return missing, "protección contra framing ausente" if missing else "cabecera de protección contra framing observada"
    if name == "cookie_flags_missing":
        if not record.set_cookies:
            return False, "sin Set-Cookie en esta respuesta; no aplica evaluar atributos"
        missing_flags: set[str] = set()
        for cookie in record.set_cookies:
            attributes = {part.partition('=')[0].strip().lower() for part in cookie.split(';')[1:]}
            missing_flags.update({'secure', 'httponly', 'samesite'} - attributes)
        return (bool(missing_flags), "atributos ausentes en al menos una cookie: " + ', '.join(sorted(missing_flags))
                if missing_flags else "atributos presentes en las cookies observadas")
    if name == "directory_listing_enabled":
        hit = record.status == 200 and re.search(r"<title>\s*index of /", record.body, re.IGNORECASE) is not None
        return hit, "listado visible" if hit else "no se observó la firma de listado en esta respuesta"
    if name == "input_reflected_unencoded":
        return bool(record.canary and record.canary in record.body and html.escape(record.canary) not in record.body), "canario reflejado"
    if name == "verbose_error_disclosure":
        hit = bool(re.search(r"fatal error|stack trace|traceback|sqlstate", record.body, re.IGNORECASE))
        return hit, "firma de error detallado" if hit else "sin firma"
    if name == "ftp_directory_listing":
        hit = record.status == 200 and re.search(
            r"index of /ftp|href=[\"']?/ftp/|acquisitions\.md|package\.json\.bak", record.body, re.IGNORECASE) is not None
        return hit, "listado de /ftp visible" if hit else "sin listado de /ftp"
    if name == "admin_configuration_public":
        hit = record.status == 200 and '"config"' in record.body and ('"server"' in record.body or '"challenges"' in record.body)
        return hit, "configuración de aplicación expuesta" if hit else "configuración no expuesta"
    if name == "metrics_public":
        hit = record.status == 200 and ("# HELP" in record.body or "# TYPE" in record.body)
        return hit, "métricas públicas" if hit else "sin métricas públicas"
    if name == "api_docs_public":
        hit = record.status == 200 and re.search(r"swagger|openapi|api-docs", record.body, re.IGNORECASE) is not None
        return hit, "documentación de API pública" if hit else "sin documentación de API"
    if name == "captcha_answer_public":
        hit = record.status == 200 and '"answer"' in record.body and '"captcha"' in record.body
        return hit, "respuesta CAPTCHA expuesta" if hit else "sin respuesta CAPTCHA"
    if name == "public_products_json":
        hit = record.status == 200 and '"name"' in record.body and '"price"' in record.body
        return hit, "productos accesibles sin autenticación" if hit else "sin productos accesibles"
    if name == "public_reviews_json":
        hit = record.status == 200 and '"message"' in record.body and '"author"' in record.body
        return hit, "reseñas accesibles sin autenticación" if hit else "sin reseñas accesibles"
    if name == "admin_route_unauthenticated":
        hit = record.status == 200
        return hit, "ruta administrativa sin autenticación" if hit else "ruta administrativa protegida"
    if name == "public_challenges_json":
        hit = record.status == 200 and '"challenges"' in record.body and '"name"' in record.body
        return hit, "catálogo de retos público" if hit else "sin catálogo público"
    if name == "client_bundle_admin_markers":
        hit = record.status == 200 and re.search(
            r"administration|customer feedback|/api/users|/api/feedback", record.body, re.IGNORECASE
        ) is not None
        return hit, "marcadores de funciones administrativas en el bundle público" if hit else "sin marcadores administrativos observables"
    raise InvalidCatalog("unknown_evaluator")


def ftp_index_entries(body: str, limit: int = 20) -> tuple[str, ...]:
    """Nombres que el propio índice de /ftp ya expone. No descarga ni abre archivos."""
    names: list[str] = []
    for href in re.findall(r'href=["\']?([^"\'>\s]+)', body, re.IGNORECASE):
        candidate = href.split("?")[0].rstrip("/")
        if not candidate.startswith("/ftp/"):
            continue
        name = candidate.rsplit("/", 1)[-1]
        if not name or name in names:
            continue
        names.append(name)
        if len(names) >= limit:
            break
    return tuple(names)


def new_canary() -> str:
    return f"ptaas{secrets.token_hex(4)}\"'<>"


def run_parametrized(catalog: dict[str, dict[str, Any]], poc_id: str, params: dict[str, str], approved: bool,
                     sender: Callable[[str, dict[str, str]], ResponseRecord]) -> Evidence:
    entry = catalog.get(poc_id)
    if entry is None: raise NotInCatalog(poc_id)
    if not approved: raise ApprovalRequired(poc_id)
    if set(params) != set(entry["parameters"]): raise ParameterError("parameters_mismatch")
    if any(not isinstance(value, str) or len(value) > 512 or re.search(r"[\r\n\x00]", value) for value in params.values()):
        raise ParameterError("parameter_value_invalid")
    if "path" in params:
        validate_target_path(params["path"])
    sent = dict(params)
    if entry["evaluator"] == "input_reflected_unencoded": sent["canary"] = new_canary()
    record = sender(poc_id, sent)
    valid, detail = _evaluate(entry["evaluator"], record)
    observed = ftp_index_entries(record.body) if valid and entry["evaluator"] == "ftp_directory_listing" else ()
    return Evidence(poc_id, entry["version"], "validated" if valid else "not_validated", detail, params, record.status, observed)
