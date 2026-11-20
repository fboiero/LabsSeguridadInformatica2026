import pytest

from harness.contracts import ToolExecutionError
from runtime.poc_sender import run_check


def test_sender_gate_does_not_send():
    result = run_check("POC-HDR-001", "http://juice-shop.lab.test:3000", {"path": "/"}, False)
    assert result["state"] == "PENDING_HITL" and result["audit"]["event_count"] == 1


def test_sender_scope_is_strict():
    with pytest.raises(ValueError, match="internal"):
        run_check("POC-HDR-001", "http://example.test:3000", {"path": "/"}, True)


def test_sender_requires_catalog_parameters():
    with pytest.raises(ToolExecutionError):
        run_check("POC-REFLECT-001", "http://juice-shop.lab.test:3000", {"path": "/"}, True)
