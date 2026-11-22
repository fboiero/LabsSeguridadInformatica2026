"""Análisis defensivo de registros históricos y generación de un paquete local."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

from .bandit_input import load_report
from .providers import ROLE_MODELS, ModelProvider, OpenCodeProvider, ProviderError

_COMMIT = "bf8f68159a0e9e4e601862e5ae003af62e705fda"
_BASE = "entregas/labfinal/grupo10"
_HITOS = ("R1", "R2", "R3", "R4")
_ROLES = ("quality_astra", "quality_sol", "quality_terra")
_LABELS = {
    "test_assertion": "Comprobar que el assert se limita a pruebas y no aplica una política de seguridad.",
    "audit_internal_assertion": "Revisar si la precondición de SQLite debe ser una comprobación explícita incluso con Python -O.",
    "process_import": "Revisar las rutas de ejecución y la frontera entre entradas y procesos.",
    "stateless_process_boundary": "Verificar que el ejecutable sea de confianza, que no se use shell y que haya timeout.",
    "unknown": "Revisar la función y los controles locales antes de concluir.",
}
_SIGNALS = {"historical_status": "historical_record_only", "missing": "insufficient_evidence",
            "conflicting": "insufficient_evidence", "synthetic": "synthetic_only"}
_ASSESSMENTS = {"historical_record_only", "insufficient_evidence", "synthetic_only", "context_review_required"}


class QualityError(ValueError):
    pass


def parse_status(text: str) -> list[str]:
    rows: dict[str, str] = {}
    totals: list[int] = []
    for line in re.sub(r"\x1b\[[0-9;]*m", "", text).splitlines():
        if hit := re.match(r"^\s*([✓✔·])\s+(R[1-4])\b", line):
            if hit[2] in rows:
                raise QualityError("duplicate_status")
            rows[hit[2]] = "not_registered" if hit[1] == "·" else "registered"
        totals.extend(int(value) for value in re.findall(r"(?<!\d)([0-4])\s*/\s*4\b", line))
    if set(rows) != set(_HITOS) or totals != [sum(value == "registered" for value in rows.values())]:
        raise QualityError("status_missing_or_inconsistent")
    return [rows[key] for key in _HITOS]


def _git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "--no-replace-objects", "--no-lazy-fetch", *args], cwd=repo, shell=False,
                              capture_output=True, check=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        raise QualityError("local_git_evidence_unavailable") from None


def historical_cases(repo: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    status_path = f"{_BASE}/evidencia/16_status_despues.txt"
    obj = f"{_COMMIT}:{status_path}"
    if int(_git(repo, "cat-file", "-s", obj)) > 16_384:
        raise QualityError("historical_status_too_large")
    raw = _git(repo, "cat-file", "blob", obj)
    statuses = parse_status(raw.decode("utf-8-sig"))
    inventory = {}
    refs = {"status": status_path, "report": f"{_BASE}/informe.md"}
    refs.update({f"record-{number}": f"{_BASE}/evidencia/{number + 11:02d}_submit_r{number}.txt"
                 for number in range(1, 5)})
    for key, name in refs.items():
        oid = _git(repo, "rev-parse", "--verify", f"{_COMMIT}:{name}").decode("ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{40}", oid) or _git(repo, "cat-file", "-t", oid).strip() != b"blob":
            raise QualityError("invalid_git_reference")
        inventory[key] = {"path": name, "blob": oid, "review": "indexed_only" if key != "status" else "status_parsed"}
    cases = []
    for number, (key, status) in enumerate(zip(_HITOS, statuses, strict=True), 1):
        ref = f"record-{number}"
        oid = inventory[ref]["blob"]
        if int(_git(repo, "cat-file", "-s", oid)) > 16_384:
            raise QualityError("historical_record_too_large")
        receipt = _git(repo, "cat-file", "blob", oid)
        parsed = re.sub(r"\x1b\[[0-9;]*m", "", receipt.decode("utf-8-sig"))
        acknowledged = bool(re.search(rf"\breto {key} resuelto\b", parsed, re.IGNORECASE))
        inventory[ref].update(review="receipt_marker_parsed", sha256=hashlib.sha256(receipt).hexdigest())
        signal = "historical_status" if status == "registered" and acknowledged else (
            "conflicting" if (status == "registered") != acknowledged else "missing"
        )
        cases.append({"id": key, "signal": signal, "refs": ["status", ref]})
    return cases, {"commit": _COMMIT, "status_sha256": hashlib.sha256(raw).hexdigest(), "artifacts": inventory}


def bandit_context(path: Path, digest: str, known: set[str]) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            raise QualityError("context_limit")
        data = json.loads(raw, object_pairs_hook=_unique)
    except (OSError, ValueError, RecursionError):
        raise QualityError("invalid_context") from None
    if not isinstance(data, dict) or set(data) != {"report_sha256", "labels"} or data["report_sha256"] != digest:
        raise QualityError("context_hash_or_fields")
    labels = data["labels"]
    if not isinstance(labels, dict) or not set(labels) <= known or any(
        not isinstance(label, str) or label not in _LABELS for label in labels.values()
    ):
        raise QualityError("context_labels")
    return {key: str(value) for key, value in labels.items()}


def fixture_decisions(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": row["id"], "refs": row["refs"],
             "assessment": _SIGNALS.get(row["signal"], "context_review_required")} for row in cases]


def analyse(cases: list[dict[str, Any]], provider: ModelProvider | None, role: str) -> dict[str, Any]:
    model = None if provider is None else f"openai/{ROLE_MODELS[role]}"
    result: dict[str, Any] = {"model_requested": model, "provider": provider.name if provider else "fixture",
                              "decisions": [], "status": "rejected", "cost_usd": None, "valid_case_ids": []}
    start = perf_counter()
    try:
        if provider is None:
            rows = fixture_decisions(cases)
        else:
            request = json.dumps({"agent": role, "cases": cases, "instructions": (
                "Classify defensive evidence. Return a JSON array only, one object per case: id, refs (exact copies), "
                "assessment. historical_status => historical_record_only (not an independent finding); "
                "missing or conflicting => insufficient_evidence; synthetic => synthetic_only; "
                "bandit alert => context_review_required. Never add facts or fields."
            )}, ensure_ascii=True)
            rows = json.loads(provider.generate(request), object_pairs_hook=_unique)
        expected = {row["id"]: row for row in fixture_decisions(cases)}
        if not isinstance(rows, list) or len(rows) > 2 * len(expected):
            raise QualityError("case_count")
        seen = set()
        valid = set()
        ambiguous = set()
        invalid = False
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] not in expected:
                invalid = True
                continue
            key = row["id"]
            if key in seen:
                ambiguous.add(key)
            elif row == expected[key] and row["assessment"] in _ASSESSMENTS:
                valid.add(key)
            seen.add(key)
        result["valid_case_ids"] = sorted(valid - ambiguous)
        if not invalid and len(result["valid_case_ids"]) == len(expected):
            result.update(decisions=rows, status="accepted")
    except ProviderError:
        result["status"] = "provider_error"
    except (ValueError, RecursionError):
        pass
    result["latency_ms"] = round((perf_counter() - start) * 1000)
    return result


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if key in fields:
            raise QualityError("duplicate_json_field")
        fields[key] = value
    return fields


def benchmarks() -> list[dict[str, Any]]:
    return [{"id": f"eval-{number}-{signal}", "signal": signal,
             "refs": [] if signal == "missing" else [f"fixture-{number}"]}
            for number in range(1, 5) for signal in (*_SIGNALS, "bandit")]


def bundle(repo: Path, output: Path, *, bandit: Path | None = None, context: Path | None = None,
           provider: ModelProvider | None = None, compare: bool = False) -> dict[str, Any]:
    cases, provenance = historical_cases(repo)
    alerts: list[dict[str, Any]] = []
    if context is not None and bandit is None:
        raise QualityError("context_requires_bandit")
    if bandit is not None:
        evidence = load_report(bandit)
        labels = bandit_context(context, evidence.source_sha256, {row["id"] for row in evidence.alerts}) if context else {}
        provenance["bandit"] = {"sha256": evidence.source_sha256, "total": evidence.total_alerts}
        for alert in evidence.alerts:
            label = labels.get(alert["id"], "unknown")
            alerts.append({**alert, "context": label, "next_step": _LABELS[label]})
            cases.append({"id": alert["id"], "signal": "bandit", "refs": [alert["id"]],
                          "rule": alert["rule"], "severity": alert["severity"], "confidence": alert["confidence"],
                          "context": label})
    output.mkdir(parents=True)
    review = analyse(cases, provider, _ROLES[0])
    benchmark = benchmarks()
    evaluations = []
    for role in (_ROLES if compare and provider is not None else _ROLES[:1]):
        run = analyse(benchmark, provider if compare else None, role)
        passed = set(run["valid_case_ids"])
        evaluations.append({**run, "passed": len(passed), "total": len(benchmark),
                            "cases": [{"id": row["id"], "passed": row["id"] in passed} for row in benchmark]})
    report = {"state": "PENDING_HITL", "provenance": provenance, "cases": cases, "alerts": alerts,
              "review": review, "evaluations": evaluations, "confirmed_findings": [],
              "reviewer_checklist": ["Cotejar las referencias con los originales.", "Separar estado historico de prueba tecnica.",
                                     "No confirmar alertas estaticas sin contexto suficiente.", "Registrar conformidad humana por separado."]}
    (output / "decisiones.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    matrix = ["# PhantomCorp — borrador pendiente de revisión", "", "Sin ejecución contra el laboratorio.", "",
              "| Hito | Evidencia disponible | Alcance |", "|---|---|---|"]
    for row in cases[:4]:
        observed = "Estado y comprobante coinciden" if row["signal"] == "historical_status" else "Evidencia insuficiente"
        cited = ", ".join(f"`{ref}`" for ref in row["refs"])
        matrix.append(f"| {row['id']} | {observed} ({cited}) | No confirma el hallazgo técnico |")
    matrix += ["", "Se leyeron marcadores del estado y de los comprobantes históricos. El informe solo se indexó.",
               f"Validación del análisis: `{review['status']}`. Confirmados: 0.", "", "## Bandit"]
    matrix += [f"- {row['id']} ({row['rule']}): {row['next_step']}" for row in alerts]
    matrix += ["", "## Evaluaciones (clasificación cerrada; no miden detección)"]
    matrix += [f"- {row['model_requested'] or 'fixture'}: {row['passed']}/{row['total']}, {row['latency_ms']} ms."
               for row in evaluations]
    matrix += ["", "## Revisión pendiente", *(f"- [ ] {item}" for item in report["reviewer_checklist"])]
    (output / "LEEME.md").write_text("\n".join(matrix) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bandit", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--live", action="store_true", help="Autoriza enviar solo categorías; una generación")
    parser.add_argument("--compare", action="store_true", help="Añade tres generaciones sintéticas con --live")
    args = parser.parse_args()
    if args.compare and not args.live:
        parser.error("--compare requiere --live")
    try:
        provider = OpenCodeProvider() if args.live else None
        result = bundle(args.repo, args.output, bandit=args.bandit, context=args.context,
                        provider=provider, compare=args.compare)
    except (ValueError, OSError, ProviderError) as error:
        print(f"bundle_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    print(f"{result['state']}: {result['review']['status']}")
    return 0 if result["review"]["status"] == "accepted" and all(
        row["status"] == "accepted" for row in result["evaluations"]
    ) else 3


if __name__ == "__main__":
    raise SystemExit(main())
