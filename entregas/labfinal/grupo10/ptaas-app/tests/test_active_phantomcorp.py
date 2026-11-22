import json

import pytest

from runtime.active_phantomcorp import ActivePhantomCorp, run_active


def test_four_fixed_steps_and_sanitized_evidence(tmp_path):
    class Lab(ActivePhantomCorp):
        def request(self, step, **kwargs):
            self.calls += 1
            bodies = {
                "R1": "FLAG{final_recon_portal}",
                "R2": "Bienvenido admin FLAG{final_sqli_foothold}",
                "R3": "API_TOKEN=x FLAG{final_token_looted}",
                "R4": "clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}",
            }
            return 200, bodies[step]

    target = Lab("http://phantomcorp.test")
    result = run_active(target, tmp_path / "run", approved=True)
    assert result["state"] == "PENDING_HITL"
    assert [row["milestone"] for row in result["evidence"]] == ["R1", "R2", "R3", "R4"]
    assert result["requests"] == 4
    assert "FLAG{" not in json.dumps(result) and "API_TOKEN" not in json.dumps(result)
    assert result["evidence"][3]["summary"] == "clientes: 48210 registros (nombre, DNI, tarjeta). [redacted]"


def test_no_approval_does_not_contact_target(tmp_path):
    target = ActivePhantomCorp("http://phantomcorp.test")
    result = run_active(target, tmp_path / "run", approved=False)
    assert result["state"] == "PENDING_HITL" and result["requests"] == 0


def test_unapproved_command_is_rejected(tmp_path):
    target = ActivePhantomCorp("http://phantomcorp.test")
    result = run_active(target, tmp_path / "run", approved=True, r4_command="cat /etc/passwd")
    assert result["state"] == "FAILED" and result["reason"] == "command_not_in_catalog"
    assert result["requests"] == 3


def test_unexpected_marker_stops_chain(tmp_path):
    class Broken(ActivePhantomCorp):
        def request(self, step, **kwargs):
            self.calls += 1
            if step == "R2":
                return 401, "unexpected"
            return super().request(step, **kwargs)

    result = run_active(Broken("http://phantomcorp.test"), tmp_path / "run", approved=True)
    assert result["state"] == "FAILED" and result["reason"] in {"unexpected_response_R2", "adapter_failure"}
    assert result["requests"] == 2 and all(row["milestone"] != "R2" for row in result["evidence"])


def test_target_outside_scope_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="target_must_be_phantomcorp"):
        ActivePhantomCorp("http://example.test")
