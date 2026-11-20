"""Nuclei GET-only: ejecuta archivos exactos de un manifiesto con SHA-256."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from harness.adapters.common import (
    Runner,
    default_runner,
    load_profiles,
    validate_target,
    validate_url,
)
from harness.contracts import Action, Phase, ScopeToken

_FORBIDDEN_TEMPLATE = re.compile(r"interactsh|\bheadless\b|\bjavascript\b|\bcode:\s*true", re.IGNORECASE)


def _template_files(profile: dict[str, Any]) -> list[str]:
    root = Path(profile["templates_dir"]).resolve()
    manifest_path = Path(profile.get("manifest_path", root / "manifest.json"))
    if not manifest_path.is_absolute():
        manifest_path = Path.cwd() / manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or not isinstance(manifest.get("templates"), list):
        raise ValueError("manifest de Nuclei inválido")
    files: list[str] = []
    for entry in manifest["templates"]:
        relative = Path(entry["path"])
        template_path = (root / relative).resolve()
        if not template_path.is_relative_to(root):
            raise ValueError("template fuera de la allow-list")
        if entry.get("methods") != ["GET"]:
            raise ValueError("solo se permiten templates con método GET")
        raw = template_path.read_text(encoding="utf-8")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if digest != entry.get("sha256"):
            raise ValueError(f"SHA-256 no coincide para {relative.as_posix()}")
        if _FORBIDDEN_TEMPLATE.search(raw):
            raise ValueError(f"template con característica prohibida: {relative.as_posix()}")
        template = yaml.safe_load(raw)
        requests = template.get("http") if isinstance(template, dict) else None
        if not isinstance(template, dict) or set(template) != {"id", "info", "http"}:
            raise ValueError("se permiten solo templates HTTP declarativos")
        info = template.get("info")
        if not isinstance(info, dict) or info.get("severity") not in {"info", "low"}:
            raise ValueError("se permiten severidades info o low")
        if not isinstance(requests, list) or not requests:
            raise ValueError("cada template debe declarar solicitudes HTTP GET")
        for request in requests:
            allowed_keys = {"method", "path", "matchers", "matchers-condition"}
            method = request.get("method", "GET") if isinstance(request, dict) else None
            if (not isinstance(request, dict) or set(request) - allowed_keys or
                    not isinstance(method, str) or method.upper() != "GET"):
                raise ValueError("template fuera del perfil GET de bajo impacto")
        files.append(str(Path(profile["templates_dir"]) / relative))
    if not files:
        raise ValueError("allow-list de Nuclei vacía")
    return files


def build_argv(url: str, profile: dict[str, Any] | None = None) -> list[str]:
    p = profile or load_profiles()["nuclei"]
    if url.startswith(("http://", "https://")):
        target = validate_url(url)
    else:
        target = "http://" + validate_target(url)
    files = _template_files(p)
    argv = [p["binary"], "-u", target]
    for template in files:
        argv.extend(("-t", template))
    argv.extend(("-tags", ",".join(p["include_tags"]),
                 "-etags", ",".join(p["exclude_tags"]),
                 "-rate-limit", str(p["rate_limit_rps"]), *p["fixed_args"]))
    overlap = set(p["include_tags"]) & set(p["exclude_tags"])
    if overlap:
        raise ValueError(f"tags incluidas y excluidas a la vez: {sorted(overlap)}")
    return argv


class NucleiSafeTemplates:
    name = "nuclei.safe_templates"
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self, runner: Runner = default_runner,
                 profile: dict[str, Any] | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["nuclei"]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if target.startswith(("http://", "https://")):
            target_url = validate_url(target)
            host = urlsplit(target_url).hostname
            if host is None:
                raise ValueError("URL de Nuclei sin hostname")
        else:
            host = validate_target(target)
            target_url = "http://" + host
        raw = self._runner(build_argv(target_url, self._profile), self._profile["timeout_s"])
        lines = [line for line in raw.splitlines() if line.strip()]
        for line in lines:
            if not isinstance(json.loads(line), dict):
                raise TypeError("salida JSONL de Nuclei inválida")
        return {"tool": "nuclei", "target": host, "format": "jsonl", "lines": lines}
