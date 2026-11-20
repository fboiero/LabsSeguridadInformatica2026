"""Sandbox efímero de validación (change 006).

Un contenedor por verificación, en la red interna del laboratorio, que hace UNA
solicitud GET sin seguir redirecciones y se destruye siempre.

Piezas:
  - `SandboxLimits` / `load_limits`: límites de `profiles.yaml` (sección `sandbox`).
  - `ContainerSpec` / `docker_argv`: argv fijo y endurecido, sin shell ni volúmenes.
  - `fetch`: lo que corre adentro del contenedor (solo stdlib).
  - `SandboxAdapter`: ToolAdapter que crea y destruye el contenedor.
  - `SandboxSender`: implementa `Sender` del catálogo; valida el objetivo y
    envía a través de `Harness.invoke`.
  - `DockerRuntime`: runtime real. Los tests usan un runtime falso.

Decisiones: openspec/changes/006-sandbox-validation-loop-c/design.md
"""
from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import yaml

from harness.contracts import Action, AuditLog, Harness, Phase, Result, ScopeToken, ScopeViolation
from harness.poc.catalog import ResponseRecord

CAPABILITY = "poc_catalog.run_parametrized"
ENGAGEMENT_LABEL = "ptaas.engagement"
DEFAULT_IMAGE = "ptaas-p3-runner:20261113"
DEFAULT_NETWORK = "ptaas-p3_lab"
_PROFILES = Path(__file__).resolve().parent / "profiles.yaml"


class SandboxTimeout(Exception):
    """La solicitud o el contenedor superaron el tiempo máximo."""


class SandboxAborted(Exception):
    """No se pudo destruir el contenedor: el loop C no debe continuar."""


# ---- Límites --------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxLimits:
    timeout_s: float = 10
    container_timeout_s: float = 30
    max_body_bytes: int = 1024 * 1024
    memory: str = "128m"
    cpus: str = "0.5"
    pids_limit: int = 64


def load_limits(path: Path = _PROFILES) -> SandboxLimits:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    section = data.get("sandbox") or {}
    known = {f for f in SandboxLimits.__dataclass_fields__}
    return SandboxLimits(**{k: v for k, v in section.items() if k in known})


def load_sandbox_profile(path: Path = _PROFILES) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    section = data.get("sandbox") or {}
    return {"image": section.get("image", DEFAULT_IMAGE),
            "network": section.get("network", DEFAULT_NETWORK)}


# ---- Lo que corre adentro del contenedor ---------------------------------------


def _fetch_raw(url: str, timeout_s: float, max_body_bytes: int) -> dict[str, object]:
    """Una solicitud GET, sin redirecciones. Solo stdlib: se copia al contenedor."""
    import http.client
    from urllib.parse import urlsplit as _split

    parts = _split(url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(parts.hostname or "", parts.port, timeout=timeout_s)
    try:
        conn.request("GET", target, headers={"User-Agent": "ptaas-sandbox/006"})
        resp = conn.getresponse()
        raw = resp.read(max_body_bytes + 1)
        truncated = len(raw) > max_body_bytes
        raw = raw[:max_body_bytes]
        headers = {k: v for k, v in resp.getheaders() if k.lower() != "set-cookie"}
        cookies = resp.headers.get_all("Set-Cookie") or []
        return {"status": resp.status, "headers": headers,
                "body": raw.decode("utf-8", errors="replace"),
                "set_cookies": list(cookies), "truncated": truncated}
    except TimeoutError:
        return {"error": "timeout"}
    except OSError as exc:
        return {"error": f"connection: {type(exc).__name__}"}
    finally:
        conn.close()


def fetch(url: str, *, timeout_s: float, max_body_bytes: int) -> dict[str, object]:
    out = _fetch_raw(url, timeout_s, max_body_bytes)
    if out.get("error") == "timeout":
        raise SandboxTimeout(url)
    if "error" in out:
        raise OSError(out["error"])
    return out


_CONTAINER_SCRIPT = (
    inspect.getsource(_fetch_raw)
    + "\nimport json, sys\n"
    + "print(json.dumps(_fetch_raw(sys.argv[1], float(sys.argv[2]), int(sys.argv[3]))))\n"
)


# ---- Especificación del contenedor ---------------------------------------------


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    network: str
    url: str
    image: str
    limits: SandboxLimits
    labels: Mapping[str, str] = field(default_factory=dict)
    follow_redirects: bool = False

    @classmethod
    def for_request(cls, *, network: str, engagement_id: str, url: str,
                    limits: SandboxLimits, image: str = DEFAULT_IMAGE) -> ContainerSpec:
        name = f"ptaas-sbx-{engagement_id}-{uuid.uuid4().hex[:8]}"
        return cls(name=name, network=network, url=url, image=image, limits=limits,
                   labels={ENGAGEMENT_LABEL: engagement_id})


def docker_argv(spec: ContainerSpec) -> list[str]:
    """argv fijo: sin shell, sin volúmenes, sin variables del host, sin privilegios."""
    argv = ["docker", "run", "--rm", "--name", spec.name,
            "--network", spec.network,
            "--read-only", "--tmpfs", "/tmp:size=8m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", spec.limits.memory, "--cpus", spec.limits.cpus,
            "--pids-limit", str(spec.limits.pids_limit)]
    for key, value in spec.labels.items():
        argv += ["--label", f"{key}={value}"]
    argv += [spec.image, "python", "-I", "-c", _CONTAINER_SCRIPT,
             spec.url, str(spec.limits.timeout_s), str(spec.limits.max_body_bytes)]
    return argv


# ---- Runtimes -------------------------------------------------------------------


class ContainerRuntime(Protocol):
    def run(self, spec: ContainerSpec) -> dict[str, Any]: ...
    def remove(self, name: str) -> None: ...
    def list_labeled(self, key: str, value: str) -> list[str]: ...


class DockerRuntime:
    """Runtime real. Solo lo usa `SandboxAdapter`, que se invoca por `Harness.invoke`."""

    def run(self, spec: ContainerSpec) -> dict[str, Any]:
        try:
            proc = subprocess.run(docker_argv(spec), capture_output=True, text=True,
                                  timeout=spec.limits.container_timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise SandboxTimeout(spec.name) from exc
        if proc.returncode != 0:
            raise RuntimeError(f"docker run falló ({proc.returncode})")
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        if out.get("error") == "timeout":
            raise SandboxTimeout(spec.url)
        if "error" in out:
            raise RuntimeError(out["error"])
        return dict(out)

    def remove(self, name: str) -> None:
        proc = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True,
                              timeout=30, check=False)
        # Con --rm el contenedor suele desaparecer solo: eso cuenta como destruido.
        if proc.returncode != 0 and "No such container" not in proc.stderr:
            raise RuntimeError(f"docker rm falló para {name}")

    def list_labeled(self, key: str, value: str) -> list[str]:
        proc = subprocess.run(["docker", "ps", "-a", "--filter", f"label={key}={value}",
                               "--format", "{{.Names}}"],
                              capture_output=True, text=True, timeout=30, check=True)
        return [n for n in proc.stdout.split() if n]

    def probe_egress(self, network: str, addr: tuple[str, int],
                     image: str = DEFAULT_IMAGE) -> bool:
        """Prueba de aislamiento (3.3): True si desde la red del sandbox se alcanza `addr`."""
        script = ("import socket, sys\n"
                  "try:\n"
                  f"    socket.create_connection(({addr[0]!r}, {int(addr[1])}), timeout=5)\n"
                  "    print('CONNECTED')\n"
                  "except OSError:\n"
                  "    print('BLOCKED')\n")
        proc = subprocess.run(["docker", "run", "--rm", "--network", network, "--read-only",
                               "--cap-drop", "ALL", image, "python", "-I", "-c", script],
                              capture_output=True, text=True, timeout=60, check=False)
        return "CONNECTED" in proc.stdout


# ---- ToolAdapter ------------------------------------------------------------------


class SandboxAdapter:
    """Crea un contenedor por verificación y lo destruye en `finally`."""

    name: str = CAPABILITY
    allowed_phases: tuple[Phase, ...] = (Phase.VALIDATE,)
    destructive: bool = False

    def __init__(self, *, runtime: ContainerRuntime, network: str, engagement_id: str,
                 limits: SandboxLimits, audit: AuditLog, image: str = DEFAULT_IMAGE):
        self.runtime, self.network, self.engagement_id = runtime, network, engagement_id
        self.limits, self.audit, self.image = limits, audit, image
        self._pending_url: str | None = None

    def prepare(self, url: str) -> None:
        self._pending_url = url

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        url, self._pending_url = self._pending_url, None
        if url is None:
            raise ScopeViolation("solicitud de sandbox sin preparar")
        spec = ContainerSpec.for_request(network=self.network, engagement_id=self.engagement_id,
                                         url=url, limits=self.limits, image=self.image)
        try:
            raw = dict(self.runtime.run(spec))
        finally:
            self._destroy(spec.name, action, target, token)
        return self._bounded(raw)

    def cleanup_orphans(self) -> list[str]:
        removed = []
        for name in self.runtime.list_labeled(ENGAGEMENT_LABEL, self.engagement_id):
            self.runtime.remove(name)
            removed.append(name)
        return removed

    def _destroy(self, name: str, action: Action, target: str, token: ScopeToken) -> None:
        try:
            self.runtime.remove(name)
        except Exception as exc:
            self.audit.record("sandbox", action, target, token, Result.ABORTED)
            raise SandboxAborted(f"no se pudo destruir {name}") from exc

    def _bounded(self, raw: dict[str, Any]) -> dict[str, Any]:
        body = str(raw.get("body", ""))
        data = body.encode("utf-8")
        truncated = bool(raw.get("truncated", False))
        if len(data) > self.limits.max_body_bytes:
            data = data[: self.limits.max_body_bytes]
            body = data.decode("utf-8", errors="ignore")
            truncated = True
        return {"status": int(raw["status"]), "headers": dict(raw.get("headers") or {}),
                "body": body, "set_cookies": list(raw.get("set_cookies") or []),
                "truncated": truncated}


# ---- Sender ------------------------------------------------------------------------


class SandboxSender:
    """Implementa `Sender` del catálogo: valida el objetivo y envía vía `Harness.invoke`."""

    def __init__(self, harness: Harness, token: ScopeToken, adapter: SandboxAdapter, *,
                 evidence: Any, lab_domains: tuple[str, ...], agent: str = "validation-agent"):
        self.harness, self.token, self.adapter = harness, token, adapter
        self.evidence, self.lab_domains, self.agent = evidence, tuple(lab_domains), agent
        self._context: dict[str, Any] = {}

    def annotate(self, **fields: Any) -> None:
        """Contexto que el loop C agrega a la evidencia (hallazgo, versiones, intento)."""
        self._context = dict(fields)

    def __call__(self, poc_id: str, params: dict[str, Any]) -> ResponseRecord:
        host = self._lab_host(str(params.get("base_url", "")))
        url = self._url(params)
        self.adapter.prepare(url)
        out = self.harness.invoke(self.agent, Action(CAPABILITY, Phase.VALIDATE), host,
                                  self.token)
        body = str(out["body"])
        record = {"event": "sandbox.response", "engagement": self.token.engagement_id,
                  **self._context, "poc_id": poc_id,
                  "params": {k: v for k, v in params.items() if k != "canary"},
                  "http_status": out["status"],
                  "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                  "body_len": len(body.encode("utf-8")), "truncated": out["truncated"]}
        self.evidence.append(record)
        return ResponseRecord(out["status"], out["headers"], body,
                              tuple(out["set_cookies"]), canary=params.get("canary"))

    def _lab_host(self, base_url: str) -> str:
        parts = urlsplit(base_url)
        host = (parts.hostname or "").rstrip(".").lower()
        ok = (parts.scheme in ("http", "https") and host
              and any(host == d or host.endswith("." + d) for d in self.lab_domains)
              and not parts.username and not parts.password)
        if not ok:
            self.harness.audit.record_decision(self.agent, CAPABILITY, base_url or "<vacío>",
                                               self.token.engagement_id,
                                               self.token.phase.value, Result.BLOCKED)
            raise ScopeViolation(f"objetivo fuera del laboratorio: {base_url!r}")
        return host

    @staticmethod
    def _url(params: dict[str, Any]) -> str:
        url = str(params["base_url"]).rstrip("/") + str(params.get("path", "/"))
        if "param_name" in params and "canary" in params:
            url += f"?{params['param_name']}={quote(str(params['canary']), safe='')}"
        return url
