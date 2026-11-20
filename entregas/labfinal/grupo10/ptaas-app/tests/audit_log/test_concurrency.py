import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from harness.audit import AuditLog, AuditUnavailable, verify_file
from harness.contracts import Result


def test_dos_escritores_sin_perdidas(tmp_path, token, action):
    path = tmp_path / "audit.db"
    AuditLog(path, token.engagement_id).close()
    def write(_):
        with AuditLog(path, token.engagement_id) as log:
            for _ in range(10):
                log.record("recon", action, "dvwa.lab.test", token, Result.OK)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(write, range(2)))
    assert verify_file(path)["event_count"] == 20


def test_bloqueo_persistente_acotado(tmp_path, token, action):
    path = tmp_path / "audit.db"
    with AuditLog(path, token.engagement_id, timeout=0.01) as log:
        with sqlite3.connect(path) as lock:
            lock.execute("BEGIN IMMEDIATE")
            with pytest.raises(AuditUnavailable):
                log.record("recon", action, "dvwa.lab.test", token, Result.OK)
        assert log.entries == []
