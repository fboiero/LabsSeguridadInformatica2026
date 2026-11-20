"""Adaptador de ZAP baseline: sólo targets de laboratorio y argv controlado.

La entrada por Harness.invoke es obligatoria en el orquestador para auditar decisiones.
La ejecución real requiere un runner ZAP aislado que devuelva JSON verificado.
"""
from __future__ import annotations

import json
from typing import Any

from harness.adapters.common import InvalidTarget, Runner, default_runner, validate_target
from harness.contracts import Action, Guard, Phase, ScopeToken

_LAB_HOSTS = frozenset({"dvwa.lab.test", "juiceshop.lab.test"})


def build_argv(host: str) -> list[str]:
    """Construye el comando baseline con parámetros fijos, sin shell ni flags del agente."""
    host = validate_target(host)
    if host not in _LAB_HOSTS:
        raise InvalidTarget("ZAP solo admite hosts exactos del laboratorio")
    suffix = ":3000" if host == "juiceshop.lab.test" else ""
    return [
        "zap-baseline.py", "-t", f"http://{host}{suffix}/",
        "-m", "1", "-T", "3", "-I", "-J", "/dev/stdout",
    ]


class ZapBaseline:
    name = "zap.baseline_scan"
    allowed_phases = (Phase.ANALYZE,)
    destructive = False

    def __init__(self, runner: Runner = default_runner, timeout_s: int = 300) -> None:
        if type(timeout_s) is not int or timeout_s < 1 or timeout_s > 600:
            raise ValueError("timeout ZAP inválido")
        self._runner = runner
        self._timeout_s = timeout_s

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        if action.name != self.name or action.phase != Phase.ANALYZE or token.phase != Phase.ANALYZE:
            raise PermissionError("fase o capability ZAP no autorizada")
        argv = build_argv(target)
        if not token.is_live() or not Guard._in_scope(target, token):
            raise PermissionError("token vencido o target fuera de alcance")
        raw = self._runner(argv, self._timeout_s)
        try:
            report = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("salida JSON ZAP inválida") from exc
        if not isinstance(report, dict):
            raise TypeError("esquema de alertas ZAP inválido")
        # La salida JSON nativa de ZAP agrupa las alertas dentro de "site".
        if isinstance(report.get("alerts"), list):
            alerts = report["alerts"]
        elif isinstance(report.get("site"), list):
            alerts = []
            for site in report["site"]:
                if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
                    raise TypeError("esquema de alertas ZAP inválido")
                alerts.extend(site.get("alerts", []))
        else:
            raise TypeError("esquema de alertas ZAP inválido")
        return {"tool": "zap", "target": target, "format": "json", "alerts": alerts}
