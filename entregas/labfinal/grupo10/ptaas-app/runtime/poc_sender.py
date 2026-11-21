"""Sender HTTP de solo lectura para comprobaciones inert_check del catálogo."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, cast

from harness.audit import AuditLog
from harness.contracts import Guard, Harness, ScopeViolation, ToolExecutionError
from harness.poc.active import (
    ActiveCheckNotAuthorized,
    ActiveResult,
    executable_active,
    load_active,
    run_active,
)
from harness.poc.catalog import (
    NotInCatalog,
    ResponseRecord,
    load_catalog,
    run_parametrized,
    validate_target_path,
)
from harness.types import Action, Phase, ScopeToken, ToolAdapter


def send_factory(base_url: str) -> Any:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname != "juice-shop.lab.test" or parsed.port != 3000:
        raise ValueError("sender_scope_is_juice_shop_internal")

    def sender(poc_id: str, params: dict[str, str], payload: dict[str, str] | None = None,
               method: str = "GET") -> ResponseRecord:
        entry_path = validate_target_path(params["path"])
        if payload is not None and method == "POST":
            url = base_url.rstrip("/") + entry_path
            body = json.dumps(payload, ensure_ascii=True).encode()
            request = urllib.request.Request(url, data=body, method="POST",
                                             headers={"Content-Type": "application/json"})
            return _read(request, None)
        query = dict(payload or {})
        if "param_name" in params:
            query[params["param_name"]] = params.get("canary", "")
        url = base_url.rstrip("/") + entry_path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, method="GET")
        return _read(request, params.get("canary"))

    def _read(request: urllib.request.Request, canary: str | None) -> ResponseRecord:
        for attempt in range(15):
            try:
                with urllib.request.urlopen(request, timeout=2) as response:
                    body = response.read(65537).decode("utf-8", "replace")
                    headers = {key: value for key, value in response.headers.items()}
                    cookies = tuple(response.headers.get_all("Set-Cookie") or ())
                    return ResponseRecord(response.status, headers, body, cookies, canary)
            except urllib.error.HTTPError as error:
                return ResponseRecord(error.code, dict(error.headers.items()), error.read(65537).decode("utf-8", "replace"),
                                      tuple(error.headers.get_all("Set-Cookie") or ()), canary)
            except urllib.error.URLError:
                if attempt == 14:
                    raise
                time.sleep(1)
        raise RuntimeError("sender_retry_exhausted")
    return sender


class CatalogAdapter:
    """Adapter fijo: el único tráfico posible sale del catálogo aprobado."""

    name = "poc_catalog"
    allowed_phases = (Phase.VALIDATE,)
    destructive = False

    def __init__(self, catalog: dict[str, dict[str, Any]], sender: Any) -> None:
        self.catalog = catalog
        self.sender = sender

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if action.parameters is None:
            raise ValueError("poc_parameters_missing")
        poc_id = action.parameters.get("poc_id")
        if poc_id is None:
            raise ValueError("poc_id_missing")
        params = {key: value for key, value in action.parameters.items() if key != "poc_id"}
        evidence = run_parametrized(self.catalog, poc_id, params, True, self.sender)
        return {
            "poc_id": evidence.poc_id,
            "version": evidence.poc_version,
            "status": evidence.status,
            "detail": evidence.detail,
            "parameters": evidence.parameters,
            "http_status": evidence.http_status,
            "observed_entries": list(evidence.observed),
        }


class ActiveAdapter:
    """Comprobaciones activas con carga fija; exigen autorización de la sesión."""

    name = "poc_catalog"
    allowed_phases = (Phase.VALIDATE,)
    destructive = True

    def __init__(self, active: dict[str, dict[str, Any]], sender: Any, authorized: bool) -> None:
        self.active = active
        self.sender = sender
        self.authorized = authorized

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if action.parameters is None:
            raise ValueError("poc_parameters_missing")
        poc_id = action.parameters.get("poc_id")
        base_url = action.parameters.get("base_url")
        if not isinstance(poc_id, str) or not isinstance(base_url, str):
            raise ValueError("poc_parameters_missing")  # noqa: TRY004 - contrato uniforme del adaptador
        result: ActiveResult = run_active(self.active, poc_id, base_url, self.authorized, self.sender)
        return {
            "poc_id": result.poc_id,
            "version": result.poc_version,
            "status": result.status,
            "detail": result.detail,
            "parameters": result.parameters,
            "http_status": result.http_status,
            "review_status": result.review_status,
            "observed_entries": [],
        }


def run_check(poc_id: str, base_url: str, params: dict[str, str], approved: bool,
              audit_path: str | None = None, active_authorized: bool = False) -> dict[str, Any]:
    catalog = load_catalog()
    active = executable_active()
    is_active = poc_id in load_active()
    engagement = "juice-shop-poc-sandbox"
    now = time.time()
    token = ScopeToken(engagement, (), ("juice-shop.lab.test",), now - 1, now + 300, Phase.VALIDATE)
    action = Action(
        "poc_catalog.validate", Phase.VALIDATE, requires_human_approval=True,
        parameters={"poc_id": poc_id, **params, "base_url": base_url},
    )
    audit = AuditLog(audit_path, engagement) if audit_path else AuditLog()
    guard = Guard({Phase.VALIDATE: {"poc_catalog.validate"}})
    adapter = (ActiveAdapter(active, send_factory(base_url), active_authorized) if is_active
               else CatalogAdapter(catalog, send_factory(base_url)))
    tools: dict[str, ToolAdapter] = {"poc_catalog.validate": cast(ToolAdapter, adapter)}
    harness = Harness(guard, audit, tools, __import__("harness.contracts", fromlist=["KillSwitch"]).KillSwitch())
    if approved:
        guard.approve(action.name, "juice-shop.lab.test")
    try:
        output = harness.invoke("reviewer", action, "juice-shop.lab.test", token)
    except ScopeViolation:
        raise ValueError("sender_scope_blocked") from None
    except ToolExecutionError:
        raise
    result: dict[str, Any] = {
        "state": output.get("status", "DOCUMENTED"),
        "poc_id": poc_id,
        "response_scope": "juice-shop.lab.test:3000",
        "audit": audit.verify(),
        "network": "internal_only",
        "confirmed_findings": [],
    }
    if output.get("status") == "PENDING_HITL":
        return result
    result.update(output)
    result["response_hash"] = hashlib.sha256(str(output["detail"]).encode()).hexdigest()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--poc-id", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--param-name")
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--active", action="store_true", help="Autoriza comprobaciones activas en esta corrida")
    parser.add_argument("--audit-path")
    args = parser.parse_args()
    params = {"path": args.path}
    if args.param_name is not None:
        params["param_name"] = args.param_name
    try:
        result = run_check(args.poc_id, args.base_url, params, args.approve, args.audit_path, args.active)
    except (ValueError, OSError, KeyError, NotInCatalog, ActiveCheckNotAuthorized) as error:
        print(json.dumps({"state": "FAILED", "reason": type(error).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
