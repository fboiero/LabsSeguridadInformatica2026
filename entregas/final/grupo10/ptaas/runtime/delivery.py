"""Validación documental y exportación local; sin dependencias ni herramientas externas."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

_LIMIT = 256_000
_ASSESSMENTS = {"historical_status": "historical_record_only", "missing": "insufficient_evidence",
                "conflicting": "insufficient_evidence", "bandit": "context_review_required"}


class DeliveryError(ValueError):
    pass


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryError("duplicate_key")
        result[key] = value
    return result


def _verify(raw: bytes) -> int:
    data = json.loads(raw, object_pairs_hook=_unique)
    if data["state"] != "PENDING_HITL" or data["confirmed_findings"] != [] or data["review"]["status"] != "accepted":
        raise DeliveryError("not_reviewable")
    cases = data["cases"]
    decisions = data["review"]["decisions"]
    provenance = data["provenance"]
    if not re.fullmatch(r"[0-9a-f]{40}", provenance["commit"]):
        raise DeliveryError("invalid_commit")
    if not isinstance(cases, list) or not 4 <= len(cases) <= 24 or not isinstance(decisions, list):
        raise DeliveryError("case_count")
    expected = {}
    historical = set()
    for item in cases:
        key, refs, signal = item["id"], item["refs"], item["signal"]
        if key in expected:
            raise DeliveryError("duplicate_case")
        if re.fullmatch(r"R[1-4]", key):
            historical.add(key)
            if refs != ["status", f"record-{key[1]}"] or signal not in ("historical_status", "missing", "conflicting"):
                raise DeliveryError("historical_reference_mismatch")
            if any(not re.fullmatch(r"[0-9a-f]{40}", provenance["artifacts"][ref]["blob"]) for ref in refs):
                raise DeliveryError("invalid_blob")
        elif not (re.fullmatch(r"bandit-[1-9][0-9]{0,5}", key) and refs == [key] and signal == "bandit"):
            raise DeliveryError("case_not_allowed")
        expected[key] = {"id": key, "refs": refs, "assessment": _ASSESSMENTS[signal]}
    if historical != {"R1", "R2", "R3", "R4"} or len(decisions) != len(expected):
        raise DeliveryError("missing_case")
    for item in decisions:
        if item != expected.pop(item["id"], None):
            raise DeliveryError("unsupported_decision")
    return len(cases)


def validate(raw: bytes, draft: bytes, *, approved_sha256: str | None = None) -> dict[str, Any]:
    if not raw or not draft or max(len(raw), len(draft)) > _LIMIT:
        raise DeliveryError("document_size")
    try:
        count = _verify(raw)
        draft.decode("utf-8")
    except (ValueError, AttributeError, KeyError, TypeError, RecursionError) as error:
        if isinstance(error, DeliveryError):
            raise
        raise DeliveryError("invalid_document") from None
    parts = [hashlib.sha256(value).hexdigest() for value in (raw, draft)]
    digest = hashlib.sha256(":".join(parts).encode("ascii")).hexdigest()
    result: dict[str, Any] = {"state": "PENDING_HITL", "review_sha256": digest, "validated_cases": count,
                              "decisions_sha256": parts[0], "draft_sha256": parts[1], "publication": "not_published"}
    if approved_sha256 is not None:
        if approved_sha256 != digest:
            raise DeliveryError("approval_hash_mismatch")
        result.update(state="EXPORTED_LOCAL", generic_import={"type": "PTaaS Grupo 10 Evidence Review",
                      "description": "Revision documental. Sin hallazgos tecnicos confirmados por este flujo.",
                      "findings": []})
    return result


def _read(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(_LIMIT + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decisions", type=Path)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--approve-sha256")
    args = parser.parse_args()
    try:
        output = validate(_read(args.decisions), _read(args.draft), approved_sha256=args.approve_sha256)
    except (OSError, DeliveryError) as error:
        print(f"delivery_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
