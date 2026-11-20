import json

import pytest

from runtime.delivery import DeliveryError, validate


def package():
    cases = [{"id": f"R{n}", "signal": "historical_status", "refs": ["status", f"record-{n}"]} for n in range(1, 5)]
    records = {key: {"blob": "a" * 40} for case in cases for key in case["refs"]}
    return {"state": "PENDING_HITL", "confirmed_findings": [], "cases": cases,
            "provenance": {"artifacts": records, "commit": "b" * 40},
            "review": {"status": "accepted", "decisions": [
                {"id": row["id"], "refs": row["refs"], "assessment": "historical_record_only"} for row in cases
            ]}}


def test_sandbox_document_contract():
    result = validate(json.dumps(package()).encode(), b"reviewable draft")
    assert result["state"] == "PENDING_HITL" and result["validated_cases"] == 4
    assert "generic_import" not in result


@pytest.mark.parametrize("changed", ["claim", "crossed", "duplicate", "rejected", "confirmed", "source"])
def test_delivery_blocks_unsupported_decisions(changed):
    report = package()
    decisions = report["review"]["decisions"]
    if changed == "claim":
        decisions[0]["assessment"] = "confirmed"
    elif changed == "crossed":
        decisions[0]["refs"] = ["status", "record-2"]
    elif changed == "duplicate":
        decisions[1] = decisions[0]
    elif changed == "rejected":
        report["review"]["status"] = "rejected"
    elif changed == "source":
        del report["provenance"]["artifacts"]["record-1"]
    else:
        report["confirmed_findings"] = [{"id": "invented"}]
    with pytest.raises(DeliveryError):
        validate(json.dumps(report).encode(), b"draft")


def test_approval_gate_and_format():
    raw, draft = json.dumps(package()).encode(), b"draft"
    check = validate(raw, draft)
    for wrong in ("", "0" * 64):
        with pytest.raises(DeliveryError):
            validate(raw, draft, approved_sha256=wrong)
    with pytest.raises(DeliveryError):
        validate(raw, b"changed", approved_sha256=check["review_sha256"])
    result = validate(raw, draft, approved_sha256=check["review_sha256"])
    assert result["state"] == "EXPORTED_LOCAL"
    assert result["generic_import"]["findings"] == []
    assert result["publication"] == "not_published"
