"""Spec audit-log — Requirement "Sin datos sensibles en claro".

Scenario: evidencia grande
  GIVEN una evidencia con contenido del objetivo
  WHEN se registra la acción
  THEN la bitácora guarda una referencia, no el contenido

Requirement nuevo: "Evidencia verificable contra su referencia".
Scenario negativo: contenido alterado
  GIVEN una evidencia registrada por su referencia
  WHEN se presenta un contenido alterado
  THEN la verificación de la referencia falla
"""
import json

from harness.contracts import Action, AuditLog, Phase, Result
from tests.conftest import make_token

EVIDENCIA = (
    "DUMP cliente -> tarjeta=4111111111111111 pass=hunter2 cookie=SESSION=abc "
    + "X" * 5000
)


def test_evidencia_grande_guarda_referencia_no_el_contenido():
    audit = AuditLog()
    entry = audit.record("recon", Action("httpx.probe", Phase.RECON),
                         "10.0.0.5", make_token(), Result.OK, evidence=EVIDENCIA)
    serializado = json.dumps(audit.entries)
    assert EVIDENCIA not in serializado
    assert "4111111111111111" not in serializado and "hunter2" not in serializado
    assert entry["evidence_ref"].startswith("sha256:")
    assert AuditLog.evidence_matches(entry["evidence_ref"], EVIDENCIA)


def test_sin_evidencia_no_agrega_campo():
    audit = AuditLog()
    entry = audit.record("recon", Action("httpx.probe", Phase.RECON),
                         "10.0.0.5", make_token(), Result.OK)
    assert "evidence_ref" not in entry


def test_referencia_no_coincide_si_el_contenido_fue_alterado():
    audit = AuditLog()
    entry = audit.record("recon", Action("httpx.probe", Phase.RECON),
                         "10.0.0.5", make_token(), Result.OK, evidence="contenido-original")
    assert not AuditLog.evidence_matches(entry["evidence_ref"], "contenido-ALTERADO")
