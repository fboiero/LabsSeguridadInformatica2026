"""Adaptador nuclei.safe_templates: solo templates curados y tags permitidos."""
from __future__ import annotations

from harness.adapters.common import (
    InvalidTarget,
    Runner,
    default_runner,
    load_profiles,
    validate_target,
    validate_url,
)
from harness.contracts import Action, Phase, ScopeToken

# Cierre de 005 · 3.3 (P5): el Guard del harness evalúa un HOST, así que el adaptador
# recibe el host del laboratorio y arma la URL, igual que ZapBaseline.
_LAB_URLS = {"dvwa.lab.test": "http://dvwa.lab.test/",
             "juiceshop.lab.test": "http://juiceshop.lab.test:3000/"}


def target_url(host: str) -> str:
    host = validate_target(host)
    if host not in _LAB_URLS:
        raise InvalidTarget("Nuclei solo admite hosts exactos del laboratorio")
    return _LAB_URLS[host]


def build_argv(url: str, profile: dict | None = None) -> list[str]:
    p = profile or load_profiles()["nuclei"]
    if p.get("templates_dir") != "templates/allowlist":
        raise ValueError("allow-list Nuclei: directorio no autorizado")
    safe_args = (
        "-jsonl",
        "-silent",
        "-ni",
        "-duc",
        "-disable-update-check",
    )
    fixed_args = p.get("fixed_args")
    if not isinstance(fixed_args, list) or tuple(fixed_args) != safe_args:
        raise ValueError("allow-list Nuclei: argumentos no autorizados")
    u = validate_url(url)
    argv = [
        p["binary"], "-u", u,
        "-t", p["templates_dir"],
        "-tags", ",".join(p["include_tags"]),
        "-etags", ",".join(p["exclude_tags"]),
        "-rate-limit", str(p["rate_limit_rps"]),
        *p["fixed_args"],
    ]
    # Invariante: ninguna etiqueta incluida puede estar también excluida o ser intrusiva.
    overlap = set(p["include_tags"]) & set(p["exclude_tags"])
    if overlap:
        raise ValueError(f"tags incluidas y excluidas a la vez: {sorted(overlap)}")
    return argv


class NucleiSafeTemplates:
    name = "nuclei.safe_templates"
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self, runner: Runner = default_runner, profile: dict | None = None):
        self._runner = runner
        self._profile = profile or load_profiles()["nuclei"]

    def run(self, action: Action, target: str, token: ScopeToken) -> dict:
        if action.name != self.name or action.phase != Phase.ANALYZE:
            raise PermissionError("fase o capability Nuclei no autorizada")
        # Por Harness.invoke llega el host del lab; se conserva la URL por compatibilidad.
        url = target if target.startswith(("http://", "https://")) else target_url(target)
        argv = build_argv(url, self._profile)
        raw = self._runner(argv, self._profile["timeout_s"])
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        return {"tool": "nuclei", "target": target, "format": "jsonl", "lines": lines}
