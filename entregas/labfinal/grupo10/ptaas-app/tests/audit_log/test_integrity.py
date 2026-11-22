import sqlite3
import subprocess
import sys

import pytest

from harness.audit import AuditIntegrityError, AuditLog, verify_file
from harness.contracts import Result


def tamper(path, sql):
    """Simula control administrativo; no es la API de la aplicación."""
    with sqlite3.connect(path) as connection:
        triggers = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
        ).fetchall()
        for name, _ in triggers:
            assert name.replace("_", "").isalnum()
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute(sql)
        for _, create_sql in triggers:
            connection.execute(create_sql)


@pytest.fixture
def filled(tmp_path, token, action):
    path = tmp_path / "audit.db"
    with AuditLog(path, token.engagement_id) as log:
        for _ in range(4):
            log.record("recon", action, "dvwa.lab.test", token, Result.OK)
    return path


def test_modificacion_de_registro_intermedio(filled, token):
    tamper(filled, "UPDATE events SET body = replace(body, 'dvwa.lab.test', 'changed.test') WHERE seq=2")
    with pytest.raises(AuditIntegrityError):
        AuditLog(filled, token.engagement_id)


def test_borrado_intermedio(filled):
    tamper(filled, "DELETE FROM events WHERE seq=2")
    with pytest.raises(AuditIntegrityError):
        verify_file(filled)


def test_archivo_ausente_no_se_crea(tmp_path):
    path = tmp_path / "missing.db"
    result = subprocess.run(
        [sys.executable, "-B", "-m", "harness.audit", "verify", str(path)],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert not path.exists()


def test_truncamiento_final_declara_limite(filled):
    tamper(filled, "DELETE FROM events WHERE seq=4")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "harness.audit", "verify", str(filled)],
        check=False, capture_output=True, text=True, encoding="utf-8",
    )
    assert result.returncode == 0
    assert "sin anclaje externo" in result.stdout
    assert verify_file(filled)["event_count"] == 3


def test_corrupcion_desde_comando_no_se_repara(filled):
    tamper(filled, "UPDATE events SET hash='bad' WHERE seq=2")
    before = filled.read_bytes()
    result = subprocess.run(
        [sys.executable, "-B", "-m", "harness.audit", "verify", str(filled)],
        check=False, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert filled.read_bytes() == before


@pytest.mark.parametrize("statement", [
    "UPDATE events SET hash='bad' WHERE seq=1", "DELETE FROM events WHERE seq=1",
])
def test_edicion_y_borrado_sql_rechazados(filled, statement):
    before = verify_file(filled)
    with sqlite3.connect(filled) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(statement)
    assert verify_file(filled) == before
