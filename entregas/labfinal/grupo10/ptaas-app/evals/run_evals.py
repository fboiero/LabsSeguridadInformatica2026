"""Eval de contratos: salidas golden y negativas. No llama a modelos reales."""
from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any

from pydantic import ValidationError

from runtime.demo import AgentRunner
from runtime.providers import FixtureProvider
from runtime.schemas import (
    BanditAnalysis,
    CorrelationResult,
    DemoReport,
    EngagementPlan,
    ReconDecision,
    StrictModel,
)

ProvenanceCheck = Callable[[StrictModel, dict[str, Any]], None]


def run(check: ProvenanceCheck = AgentRunner._check_provenance) -> list[dict[str, Any]]:
    schema_by_role: dict[str, type[StrictModel]] = {
        "orchestrator": EngagementPlan, "asset_discovery": ReconDecision,
        "correlation": CorrelationResult, "reporting": DemoReport, "analysis": BanditAnalysis,
    }
    inputs: dict[str, dict[str, Any]] = {
        "orchestrator": {}, "asset_discovery": {"visited_targets": []},
        "correlation": {},
        "analysis": {"alerts": [{"id": "bandit-1", "rule": "B603", "severity": "LOW", "confidence": "HIGH"}]},
        "reporting": {"assets": [{"address": "dvwa.lab.test"}], "evidence_refs": ["a" * 64]},
    }
    invalid = {
        "orchestrator": {"agents": ["asset_discovery", "correlation", "reporting"],
                         "max_iterations": 99, "needs_human": None},
        "asset_discovery": {"action": "shell", "target": "dvwa.lab.test", "reason": "invalid"},
        "correlation": {"candidates": [{"cve": "CVE-2099-9999"}], "reason": "invented"},
        "analysis": {"reviews": [{"id": "bandit-999", "status": "inconclusive", "recommendation": "Revisar"}]},
        "reporting": {"simulated": False, "status": "delivered"},
    }
    results = []
    provider = FixtureProvider()
    for role, schema in schema_by_role.items():
        golden = provider.generate(json.dumps({"agent": role, "input": inputs[role]}))
        valid_output = json.loads(golden)
        extras: dict[str, list[tuple[str, dict[str, Any], bool]]] = {
            "orchestrator": [
                ("wrong-order", {**valid_output, "agents": ["reporting", "correlation", "asset_discovery"]}, False),
                ("hitl-request", {**valid_output, "needs_human": "Revisar el alcance"}, True),
            ],
            "asset_discovery": [
                ("stop", {**valid_output, "action": "stop"}, True),
                ("extra-field", {**valid_output, "raw_command": "INVALID"}, False),
            ],
            "correlation": [
                ("reason-required", {**valid_output, "reason": ""}, False),
                ("no-extra-feed", {**valid_output, "feed_url": "synthetic"}, False),
            ],
            "analysis": [
                ("duplicate-id", {"reviews": [valid_output["reviews"][0]] * 2}, False),
                ("missing-id", {"reviews": []}, False),
            ] if role == "analysis" else [],
            "reporting": [
                ("foreign-evidence", {**valid_output, "evidence_refs": ["b" * 64]}, False),
                ("invented-cve-in-prose", {**valid_output, "executive_summary": "CVE-2099-12345"}, False),
                ("omitted-asset", {**valid_output, "assets": []}, False),
            ],
        }
        for label, response, expected in [
            ("golden", golden, True), ("negative", json.dumps(invalid[role]), False),
            *((name, json.dumps(value), expected) for name, value, expected in extras[role]),
        ]:
            try:
                output = schema.model_validate_json(response)
                check(output, inputs[role])
                valid = True
            except (ValidationError, ValueError):
                valid = False
            results.append({"case": f"{role}-{label}", "passed": valid == expected,
                            "expected_valid": expected, "actual_valid": valid})
    return results


def mutation_results() -> list[dict[str, Any]]:
    baseline = {case["case"] for case in run() if case["passed"]}
    mutations: dict[str, type[StrictModel]] = {
        "skip_plan_order": EngagementPlan,
        "skip_analysis_provenance": BanditAnalysis,
        "skip_report_provenance": DemoReport,
    }
    results = []
    for name, model in mutations.items():
        def mutated(value: StrictModel, data: dict[str, Any], model: type[StrictModel] = model) -> None:
            if not isinstance(value, model):
                AgentRunner._check_provenance(value, data)

        detected = [case["case"] for case in run(mutated)
                    if case["case"] in baseline and not case["passed"]]
        results.append({"case": name, "passed": bool(detected), "detected_by": detected})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("golden", "mutation"), default="golden")
    args = parser.parse_args()
    if args.mode == "mutation" and not all(item["passed"] for item in run()):
        print("FAIL baseline; no se evalúan mutaciones")
        return 1
    results = run() if args.mode == "golden" else mutation_results()
    for result in results:
        suffix = " — " + ", ".join(result["detected_by"]) if args.mode == "mutation" else ""
        print(("PASS " if result["passed"] else "FAIL ") + result["case"] + suffix)
    print(f"{sum(item['passed'] for item in results)}/{len(results)} casos; proveedor fixture, sin IA real")
    return 0 if all(item["passed"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
