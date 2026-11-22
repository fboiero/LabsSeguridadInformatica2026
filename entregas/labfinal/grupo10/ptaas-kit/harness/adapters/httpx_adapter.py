"""Adaptador httpx.probe: sondeo HTTP activo acotado con RateLimiter y salida JSONL."""
from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from harness.adapters.common import (
    AdapterOutputError,
    RateLimiter,
    RateLimitExceeded,
    Runner,
    ToolExecutionError,
    default_runner,
    rate_limiter_from_policy,
    validate_target,
    validate_url,
)
from harness.contracts import Action, Phase, ScopeToken


def _to_probe_url(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith(("http://", "https://")):
        return validate_url(cleaned)
    host = validate_target(cleaned.rstrip("."))
    return validate_url(f"http://{host}")


def build_argv(target: str) -> list[str]:
    """Construye argv fijo para httpx sin interpolar opciones arbitrarias."""
    url = _to_probe_url(target)
    return ["httpx", "-u", url, "-silent", "-json"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def stdlib_http_runner(argv: list[str], timeout_s: int) -> str:
    """Runner Python stdlib (sin shell) para el contenedor `runner` sin binario Go `httpx`."""
    url = argv[argv.index("-u") + 1]
    validated = validate_url(url)
    host = validated.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(validated, method="GET", headers={"User-Agent": "PTaaS-Grupo10-Recon/1.0"})
    try:
        with opener.open(req, timeout=min(timeout_s, 10)) as resp:
            status = resp.status
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
    except urllib.error.HTTPError as err:
        status = err.code
        server = err.headers.get("Server", "") if err.headers else ""
        powered = err.headers.get("X-Powered-By", "") if err.headers else ""
    tech = [t for t in (server, powered) if t]
    return json.dumps({"url": validated, "host": host, "status_code": status, "tech": tech})


class HttpxProbe:
    name = "httpx.probe"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(
        self,
        runner: Runner = default_runner,
        rate_limiter: RateLimiter | None = None,
        clock: Callable[[], float] = time.monotonic,
        timeout_s: int = 30,
    ):
        self._runner = runner
        self._rate_limiter = rate_limiter or rate_limiter_from_policy()
        self._clock = clock
        self._timeout_s = timeout_s

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        argv = build_argv(target)
        rate_key = target.strip().lower().rstrip(".")
        if not self._rate_limiter.allow(rate_key, self._clock()):
            raise RateLimitExceeded(f"rate limit excedido para {rate_key}")

        try:
            raw = self._runner(argv, self._timeout_s)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            raise ToolExecutionError(f"error ejecutando httpx: {type(exc).__name__}") from exc

        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if not lines:
            raise AdapterOutputError("salida vacía en httpx.probe")
        try:
            record = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise AdapterOutputError("salida JSON inválida en httpx.probe") from exc

        if not isinstance(record, dict) or "status_code" not in record:
            raise AdapterOutputError("registro sin status_code en httpx.probe")

        tech_raw = record.get("tech") or []
        tech = [str(item) for item in tech_raw] if isinstance(tech_raw, list) else []
        return {
            "tool": "httpx",
            "target": target,
            "url": str(record.get("url", argv[argv.index("-u") + 1])),
            "host": str(record.get("host", rate_key)),
            "status_code": int(record["status_code"]),
            "tech": tech,
        }
