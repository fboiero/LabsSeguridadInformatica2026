"""Piloto de solo lectura con un extracto versionado y tres casos sintéticos fijos."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError

from .providers import ROLE_MODELS, FixtureProvider, ModelProvider, OpenCodeProvider, ProviderError
from .schemas import StrictModel

_ROLE = "attack_mapping"
_CATALOG = {
    "matrix": "Enterprise ATT&CK", "version": "17.1", "format": "STIX 2.1 (extracto normalizado)",
    "source": "https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-17.1.json",
    "techniques": [{"id": "T1110", "name": "Brute Force", "object_version": "2.7",
                    "stix_id": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd",
                    "url": "https://attack.mitre.org/techniques/T1110/"}],
}
_CASES = (
    {"case_id": "auth_series", "evidence_ids": ["evt-001"], "kind": "auth_failure_summary",
     "failures": 18, "window_seconds": 60, "same_source_and_account": True},
    {"case_id": "auth_single", "evidence_ids": ["evt-002"], "kind": "auth_failure_summary", "failures": 1},
    {"case_id": "bandit_only", "evidence_ids": ["artifact-003"], "kind": "static_alert_without_telemetry"},
)
_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "attack_mapping.md"
_Note = Annotated[str, Field(min_length=1, max_length=350)]


class Decision(StrictModel):
    case_id: Literal["auth_series", "auth_single", "bandit_only"]
    status: Literal["candidate", "insufficient_evidence"]
    technique_id: Literal["T1110"] | None
    evidence_ids: list[str] = Field(min_length=1, max_length=1)
    rationale: _Note
    missing_evidence: _Note


class PilotResponse(StrictModel):
    decisions: list[Decision] = Field(min_length=3, max_length=3)


def fixture_response() -> str:
    return json.dumps({"decisions": [
        {"case_id": "auth_series", "status": "candidate", "technique_id": "T1110",
         "evidence_ids": ["evt-001"], "rationale": "Serie repetida compatible, no concluyente.",
         "missing_evidence": "Revisar contexto de autenticación y actividad legítima esperada."},
        {"case_id": "auth_single", "status": "insufficient_evidence", "technique_id": None,
         "evidence_ids": ["evt-002"], "rationale": "Un fallo aislado no indica un patrón.",
         "missing_evidence": "Más eventos comparables en la misma ventana."},
        {"case_id": "bandit_only", "status": "insufficient_evidence", "technique_id": None,
         "evidence_ids": ["artifact-003"], "rationale": "Una alerta estática no observa conductas.",
         "missing_evidence": "Telemetría de ejecución o autenticación pertinente."},
    ]})


class PilotFixture(FixtureProvider):
    def generate(self, prompt: str) -> str:
        return fixture_response()


def run_pilot(provider: ModelProvider) -> dict[str, Any]:
    result: dict[str, Any] = {
        "provider": provider.name, "model": f"openai/{ROLE_MODELS[_ROLE]}" if provider.name == "opencode" else None,
        "state": "PENDING_HITL", "gate": "review_attack_mapping", "synthetic": True,
        "tool_calls": 0, "generation_attempts": 1, "catalog": _CATALOG, "cases": _CASES, "decisions": [],
    }
    request = json.dumps({"agent": _ROLE, "instructions": _PROMPT.read_text(encoding="utf-8"),
                          "input": {"cases": _CASES, "catalog": _CATALOG}})
    try:
        raw = provider.generate(request)
    except ProviderError:
        result.update(state="FAILED", gate=None, reason="provider_error")
        return result
    try:
        rows = PilotResponse.model_validate_json(raw).decisions
        by_case = {row.case_id: row for row in rows}
        known = {case["case_id"] for case in _CASES}
        if set(by_case) != known:
            raise ValueError
        for row in rows:
            case = next(case for case in _CASES if case["case_id"] == row.case_id)
            if row.evidence_ids != case["evidence_ids"]:
                raise ValueError
            if row.status == "candidate":
                if row.case_id != "auth_series" or row.technique_id != "T1110":
                    raise ValueError
            elif row.technique_id is not None:
                raise ValueError
        result["decisions"] = [row.model_dump() for row in rows]
    except (ValidationError, ValueError):
        result["reason"] = "invalid_agent_output"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", required=True, choices=("fixture", "opencode"))
    parser.add_argument("--output", required=True, type=Path, help="Directorio nuevo")
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    try:
        provider: ModelProvider = OpenCodeProvider() if args.provider == "opencode" else PilotFixture()
    except ProviderError:
        result: dict[str, Any] = {"provider": args.provider, "state": "FAILED", "reason": "provider_error",
                                  "generation_attempts": 0, "decisions": []}
    else:
        result = run_pilot(provider)
    (args.output / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{result['state']}: {len(result['decisions'])} decisiones; {result['generation_attempts']} intento(s)")
    return 0 if result["decisions"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
