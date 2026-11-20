import json
import sqlite3
import subprocess
import sys

import pytest

from harness.audit import AuditIntegrityError, AuditLog, AuditUnavailable
from harness.contracts import Result


def test_recuperacion_entre_procesos(tmp_path, token, action):
    path = tmp_path / "audit.db"
    with AuditLog(path, token.engagement_id) as log:
        original = log.record("recon", action, "dvwa.lab.test", token, Result.OK)
    script = (
        "from harness.audit import AuditLog; import sys,json; "
        "a=AuditLog(sys.argv[1],sys.argv[2]); print(json.dumps(a.entries)); a.close()"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", script, str(path), token.engagement_id],
        check=True, capture_output=True, text=True,
    )
    assert json.loads(result.stdout) == [original]


def test_commit_fallido_sin_fallback(tmp_path, token, action, monkeypatch):
    with AuditLog(tmp_path / "audit.db", token.engagement_id) as log:
        def fail_commit():
            raise sqlite3.OperationalError("SECRET_SYNTHETIC_PASSWORD")
        monkeypatch.setattr(log, "_commit", fail_commit)
        with pytest.raises(AuditUnavailable) as error:
            log.record("recon", action, "dvwa.lab.test", token, Result.OK)
        assert "SECRET" not in str(error.value)
        assert log.entries == []


def test_archivos_independientes(tmp_path, token, action):
    from dataclasses import replace
    other = replace(token, engagement_id="eng-other")
    for name, current in (("a", token), ("b", other)):
        with AuditLog(tmp_path / f"{name}.db", current.engagement_id) as log:
            log.record("recon", action, "dvwa.lab.test", current, Result.OK)
            assert {entry["engagement"] for entry in log.entries} == {current.engagement_id}
            assert log.entries[0]["prev"] == "GENESIS"


def test_identidad_incompatible(tmp_path, token, action):
    from dataclasses import replace
    path = tmp_path / "audit.db"
    with AuditLog(path, token.engagement_id) as log:
        original = log.record("recon", action, "dvwa.lab.test", token, Result.OK)
        with pytest.raises(AuditIntegrityError):
            log.record("recon", action, "dvwa.lab.test", replace(token, engagement_id="other"), Result.OK)
        assert log.entries == [original]
    with pytest.raises(AuditIntegrityError):
        AuditLog(path, "other")
