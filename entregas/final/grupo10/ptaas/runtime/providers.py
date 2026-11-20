"""Generación real vía OpenCode o fixtures explícitos para tests offline."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Protocol


class ProviderError(RuntimeError):
    pass


ROLE_MODELS = {
    "orchestrator": "gpt-6.2-sol",
    "asset_discovery": "gpt-6.1-terra",
    "correlation": "gpt-6.1-terra",
    "analysis": "gpt-6.2-astra",
    "validation": "gpt-5.6-luna",
    "reporting": "gpt-6.2-sol",
    "attack_mapping": "gpt-6.2-astra",
    "quality_astra": "gpt-6.2-astra",
    "quality_sol": "gpt-6.2-sol",
    "quality_terra": "gpt-6.1-terra",
}


class ModelProvider(Protocol):
    name: str

    def generate(self, prompt: str) -> str: ...


def _find_executable() -> Path:
    configured = os.environ.get("PTAAS_OPENCODE_EXE")
    found = configured or shutil.which("opencode")
    if not found:
        raise ProviderError("opencode_not_found")
    executable = Path(found)
    if executable.suffix.lower() in {".cmd", ".bat"}:
        # Resolver el launcher instalado, no enviar prompts a cmd.exe ni a un shell.
        executable = executable.parent / "node_modules" / "@opencode" / "cli" / "bin" / "opencode.exe"
    if not executable.is_file() or executable.suffix.lower() in {".cmd", ".bat"}:
        raise ProviderError("set_PTAAS_OPENCODE_EXE_to_native_executable")
    return executable


class OpenCodeProvider:
    """API stateless: no sesiones de programación, tools, MCPs ni lectura de auth.json."""

    name = "opencode"

    def __init__(self, executable: Path | None = None, *, timeout: float = 120):
        self.executable = executable or _find_executable()
        if self.executable.suffix.lower() in {".cmd", ".bat"}:
            raise ProviderError("native_executable_required")
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        if len(prompt) > 20000:
            raise ProviderError("prompt_limit_exceeded")
        try:
            role = json.loads(prompt)["agent"]
        except (ValueError, TypeError, KeyError):
            raise ProviderError("invalid_agent_request") from None
        if not isinstance(role, str) or role not in ROLE_MODELS:
            raise ProviderError("unknown_model_role")
        payload = json.dumps({
            "prompt": prompt, "model": {"providerID": "openai", "id": ROLE_MODELS[role]},
        }, ensure_ascii=True)
        try:
            response = subprocess.run(
                [str(self.executable), "api", "experimental.generate.text", "--data", payload],
                check=False, shell=False, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            raise ProviderError("opencode_unavailable_or_timeout") from None
        if response.returncode != 0:
            raise ProviderError("opencode_generation_failed")
        if len(response.stdout) > 65536:
            raise ProviderError("response_limit_exceeded")
        try:
            result = json.loads(response.stdout)
            text = result["data"]["text"]
            if not isinstance(text, str) or len(text) > 32000:
                raise ValueError
            return text
        except (ValueError, TypeError, KeyError):
            raise ProviderError("opencode_invalid_response") from None


class FixtureProvider:
    """No llama a un modelo. Su nombre se conserva en resultados y evaluaciones."""

    name = "fixture"

    def generate(self, prompt: str) -> str:
        request = json.loads(prompt)
        role, data = request["agent"], request["input"]
        if role == "orchestrator":
            result = {
                "agents": ["asset_discovery", "correlation", "reporting"],
                "max_iterations": 2, "needs_human": None,
            }
        elif role == "asset_discovery":
            result = {
                "action": "stop" if data["visited_targets"] else "httpx.probe",
                "target": "dvwa.lab.test", "reason": "fixture inventory decision",
            }
        elif role == "correlation":
            result = {"candidates": [], "reason": "No vulnerability feed supplied; no CVE invented."}
        elif role == "analysis":
            result = {"reviews": [
                {"id": alert["id"], "status": "inconclusive",
                 "recommendation": "Revisar la alerta y el contexto en el informe local."}
                for alert in data["alerts"]
            ]}
        elif role == "validation":
            result = {"destino": "Vos", "motivo": "La comprobación del catálogo requiere aprobación humana.",
                      "resultado": "Propuesta de validación del catálogo; pendiente de aprobación humana."}
        elif role == "reporting":
            result = {
                "simulated": True, "status": "draft",
                "conclusion": "coordination_only_not_a_pentest",
                "executive_summary": "Demostracion de coordinacion con evidencia sintetica.",
                "assets": [asset["address"] for asset in data["assets"]],
                "findings": [], "limitations": ["Herramienta simulada; no se ejecuto un pentest."],
                "evidence_refs": data["evidence_refs"],
            }
        else:
            raise ProviderError("unsupported_fixture_role")
        return json.dumps(result)
