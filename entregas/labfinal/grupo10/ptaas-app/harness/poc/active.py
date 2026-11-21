"""Comprobaciones activas derivadas de las propuestas, acotadas al laboratorio.

No registran aprobación docente. Cada ejecución exige que la persona que opera
habilite las comprobaciones activas en esa sesión, y el recibo conserva el
estado `pending_teacher_review`.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .catalog import NotInCatalog, ParameterError, ResponseRecord, validate_target_path

_PATH = Path(__file__).with_name("active.yaml")

# Cargas fijas: el modelo no puede aportar ni modificar el cuerpo de la petición.
BODY_PAYLOADS: dict[str, dict[str, str]] = {
    "login_sqli_bypass": {"email": "' OR 1=1--", "password": "not-a-real-password"},
}
QUERY_PAYLOADS: dict[str, dict[str, str]] = {
    "search_sqli_error": {"q": "'"},
}
PAYLOADS: dict[str, Any] = {**BODY_PAYLOADS, **QUERY_PAYLOADS}
_REQUIRED = {"id", "version", "title", "cwe", "kind", "method", "evaluator", "lab_targets",
             "lab_only", "review_status", "implementable", "reason"}


class ActiveCheckNotAuthorized(Exception):
    pass


class InvalidActiveCatalog(Exception):
    pass


@dataclass(frozen=True)
class ActiveResult:
    poc_id: str
    poc_version: str
    status: str
    detail: str
    parameters: dict[str, str]
    http_status: int
    review_status: str


def validate_active_entries(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if _REQUIRED - entry.keys():
            raise InvalidActiveCatalog("missing_fields")
        if entry["kind"] != "active_check" or entry["lab_only"] is not True:
            raise InvalidActiveCatalog("active_requires_lab_only")
        if not set(entry["lab_targets"]) <= {"juice-shop"}:
            raise InvalidActiveCatalog("active_target_not_allowed")
        if entry["review_status"] != "pending_teacher_review":
            # Sin una revisión registrada no se puede afirmar otra cosa.
            raise InvalidActiveCatalog("review_status_must_stay_pending")
        if entry["id"] in result:
            raise InvalidActiveCatalog("duplicate_active_entry")
        if entry["implementable"]:
            method = entry["method"]
            payload = entry.get("payload")
            allowed = BODY_PAYLOADS if method == "POST" else QUERY_PAYLOADS if method == "GET" else {}
            if payload not in allowed:
                raise InvalidActiveCatalog("implementable_requires_fixed_payload")
            validate_target_path(entry["path"])
        result[entry["id"]] = entry
    return result


def load_active(path: Path = _PATH) -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data.get("review_status") != "pending_teacher_review":
        raise InvalidActiveCatalog("catalog_review_status")
    if data.get("authorization") != "operator_session":
        raise InvalidActiveCatalog("authorization_must_be_operator_session")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise InvalidActiveCatalog("entries_missing")
    return validate_active_entries(entries)


def executable_active(path: Path = _PATH) -> dict[str, dict[str, Any]]:
    return {key: value for key, value in load_active(path).items() if value["implementable"]}


def _evaluate(name: str, record: ResponseRecord) -> tuple[bool, str]:
    if name == "auth_bypass_token_issued":
        token = re.search(r'"token"\s*:\s*"[^"]{8,}"', record.body) is not None
        hit = record.status == 200 and token and '"authentication"' in record.body
        return hit, ("sesión emitida sin credenciales válidas del laboratorio" if hit
                     else "sin emisión de sesión ante la carga de prueba")
    if name == "sql_error_disclosed":
        hit = re.search(r"sqlite_error|sql syntax|sequelizedatabaseerror|unrecognized token",
                        record.body, re.IGNORECASE) is not None
        return hit, ("error del motor SQL expuesto ante la comilla de prueba" if hit
                     else "sin firma de error SQL en esta respuesta")
    raise InvalidActiveCatalog("unknown_active_evaluator")


def run_active(active: dict[str, dict[str, Any]], poc_id: str, base_url: str, authorized: bool,
               sender: Callable[[str, dict[str, str], dict[str, str], str], ResponseRecord]) -> ActiveResult:
    entry = active.get(poc_id)
    if entry is None:
        raise NotInCatalog(poc_id)
    if not entry["implementable"]:
        raise ParameterError("active_check_not_implementable")
    if not authorized:
        raise ActiveCheckNotAuthorized(poc_id)
    if entry["method"] not in {"GET", "POST"}:
        raise ParameterError("active_method_not_allowed")
    payload = PAYLOADS[str(entry["payload"])]
    path = validate_target_path(entry["path"])
    record = sender(poc_id, {"path": path}, dict(payload), entry["method"])
    valid, detail = _evaluate(entry["evaluator"], record)
    return ActiveResult(poc_id, entry["version"], "validated" if valid else "not_validated",
                        detail, {"path": path, "base_url": base_url}, record.status,
                        entry["review_status"])


def active_summary(path: Path = _PATH) -> str:
    """Texto corto para el prompt: qué se puede ejecutar y qué solo se declara."""
    entries = load_active(path)
    runnable = [entry["title"] for entry in entries.values() if entry["implementable"]]
    declared = [f"{entry['title']} ({entry.get('requires', entry.get('covered_by', 'sin adaptador'))})"
                for entry in entries.values() if not entry["implementable"]]
    return ("Activas ejecutables en el laboratorio: " + "; ".join(runnable) +
            ". Declaradas pero sin adaptador: " + "; ".join(declared) + ".")
