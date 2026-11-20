"""Scenario faltante de `audit-log`: "Sin datos sensibles en claro" (grupo 14).

Spec (openspec/specs/audit-log/spec.md):
  Requirement: Sin datos sensibles en claro
  Scenario: evidencia grande
    GIVEN una evidencia con contenido del objetivo
    WHEN se registra la acción
    THEN la bitácora guarda una referencia, no el contenido

Verificamos el control `evidence_ref`: la bitácora cita la evidencia por digest,
nunca credenciales ni datos del cliente.
"""
import json
import re

from harness.contracts import Action, AuditLog, Phase, Result, evidence_ref
from tests.conftest import make_token

SECRETO = "API_TOKEN=phantom-api-7c1e"
DATOS_CLIENTE = "clientes: 48210 registros (nombre, DNI, tarjeta)"


def test_evidence_ref_guarda_digest_no_contenido():
    ref = evidence_ref(SECRETO + "\n" + DATOS_CLIENTE, uri="loot://ev/001")
    blob = json.dumps(ref)
    assert "phantom-api-7c1e" not in blob      # no filtra el token
    assert "48210" not in blob                 # no filtra datos del cliente
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", ref["evidence"])
    assert ref["bytes"] == len((SECRETO + "\n" + DATOS_CLIENTE).encode())
    assert ref["uri"] == "loot://ev/001"


def test_evidence_ref_es_estable_y_distingue_contenido():
    assert evidence_ref("x") == evidence_ref("x")
    assert evidence_ref("x")["evidence"] != evidence_ref("y")["evidence"]


def test_bitacora_del_harness_no_contiene_contenido_sensible():
    a = AuditLog()
    a.record("recon", Action("httpx.probe", Phase.RECON), "10.0.0.5", make_token(), Result.OK)
    blob = json.dumps(a.entries)
    # La bitácora solo lleva metadatos + hash encadenado: ningún campo de contenido.
    assert "phantom-api-7c1e" not in blob and "48210" not in blob
    assert set(a.entries[-1]) == {
        "ts", "engagement", "agent", "action", "target", "phase", "result", "prev", "hash"
    }
