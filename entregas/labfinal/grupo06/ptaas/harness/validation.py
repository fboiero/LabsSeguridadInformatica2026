"""Loop C de validación (change 006): aprobación por hallazgo, catálogo congelado y
orquestación de intentos con `decide_validation`.

Reglas (design.md, decisiones 5 a 7):
  - Sin aprobación de una persona para (hallazgo, verificación, hash de parámetros)
    no se envía nada: el hallazgo queda PENDING_HITL.
  - Nada se aprueba ni se rechaza solo. Si el token vence sin aprobación, el
    hallazgo queda "not_validated" con motivo "sin aprobación".
  - "validated" solo si todos los intentos dan "validated".
  - El catálogo se carga una vez y no cambia durante el loop.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

from harness.contracts import Harness, KillSwitchEngaged, Result, ScopeToken, ScopeViolation
from harness.loops import decide_validation
from harness.poc import catalog as catalog_mod
from harness.poc.catalog import ParameterError, run_parametrized, validate_entries
from harness.policy_loader import load_policy
from harness.sandbox import CAPABILITY, SandboxAborted, SandboxSender, SandboxTimeout

PENDING = "PENDING_HITL"
# Gates de engagement que se aprueban por la CLI. La validación es por hallazgo y la
# entrega por hash del informe: tienen sus propios comandos.
KNOWN_GATES = frozenset({"first_active_action", "active_analysis"})
APPROVED = "approved"
REJECTED = "rejected"


def params_hash(params: Mapping[str, Any]) -> str:
    canonical = json.dumps(dict(params), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ValidationRequest:
    finding_id: str
    poc_id: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Outcome:
    status: str                 # "validated" | "not_validated" | "PENDING_HITL"
    reason: str = ""
    attempts: int = 0


# ---- Catálogo congelado ------------------------------------------------------------


@dataclass(frozen=True)
class FrozenCatalog:
    version: str
    entries: Mapping[str, Mapping[str, Any]]

    @classmethod
    def load(cls, path: Path | None = None) -> FrozenCatalog:
        path = path or catalog_mod._CATALOG
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = validate_entries(copy.deepcopy(data["entries"]))
        frozen = {k: MappingProxyType(dict(v)) for k, v in entries.items()}
        return cls(str(data.get("catalog_version", "unknown")), MappingProxyType(frozen))


# ---- Aprobaciones -------------------------------------------------------------------


class ApprovalStore:
    """Decisiones del Reviewer por hallazgo, persistidas en JSON y registradas en bitácora.

    Ningún código del agente llama a `approve`/`reject`: lo hace una persona por la CLI.
    """

    def __init__(self, path: Path, *, audit: Any):
        self.path, self.audit = Path(path), audit
        self._data: dict[str, dict[str, Any]] = {}
        self._deliveries: dict[str, dict[str, Any]] = {}
        self._gates: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._data = raw.get("findings", {})
            self._deliveries = raw.get("deliveries", {})
            self._gates = raw.get("gates", {})

    def _save(self) -> None:
        self.path.write_text(json.dumps({"findings": self._data, "deliveries": self._deliveries,
                                         "gates": self._gates}, indent=2, sort_keys=True),
                             encoding="utf-8")

    # ---- Gates del engagement (change 007 · 3.5) ----

    def approve_gate(self, engagement_id: str, gate: str, *, reviewer: str, reason: str) -> None:
        if gate not in KNOWN_GATES:
            raise ValueError(f"gate desconocido: {gate}")
        if not reviewer or not reviewer.strip():
            raise ValueError("falta el Reviewer")
        if not reason or not reason.strip():
            raise ValueError("falta el motivo")
        ts = time.time()
        record = {"engagement_id": engagement_id, "gate": gate, "reviewer": reviewer.strip(),
                  "reason": reason.strip(), "ts": ts}
        self._gates[f"{engagement_id}:{gate}"] = record
        self._save()
        self.audit.append({"event": "hitl.decision", "decision": "gate_approved", **record})

    def gate_record(self, engagement_id: str, gate: str) -> dict[str, Any] | None:
        return self._gates.get(f"{engagement_id}:{gate}")

    def gate_approved(self, engagement_id: str, gate: str) -> bool:
        return self.gate_record(engagement_id, gate) is not None

    # ---- Entrega del informe (change 007 · 2.6) ----

    def approve_delivery(self, engagement_id: str, report_hash: str, *,
                         reviewer: str, reason: str) -> None:
        """Aprobación de entrega ligada al hash exacto del informe."""
        if not reviewer or not reviewer.strip():
            raise ValueError("falta el Reviewer")
        if not reason or not reason.strip():
            raise ValueError("falta el motivo")
        if not re.fullmatch(r"[0-9a-f]{64}", report_hash or ""):
            raise ValueError("report_hash inválido")
        ts = time.time()
        record = {"engagement_id": engagement_id, "report_hash": report_hash,
                  "reviewer": reviewer.strip(), "reason": reason.strip(), "ts": ts}
        self._deliveries[f"{engagement_id}:{report_hash}"] = record
        self._save()
        self.audit.append({"event": "hitl.decision", "decision": "delivery_approved", **record})

    def delivery_record(self, engagement_id: str, report_hash: str) -> dict[str, Any] | None:
        return self._deliveries.get(f"{engagement_id}:{report_hash}")

    def delivery_approved(self, engagement_id: str, report_hash: str) -> bool:
        return self.delivery_record(engagement_id, report_hash) is not None

    def request(self, finding_id: str, poc_id: str, params: Mapping[str, Any]) -> None:
        """Registra una propuesta. Si cambia la verificación o los parámetros, vuelve a pendiente."""
        h = params_hash(params)
        cur = self._data.get(finding_id)
        if cur and cur["poc_id"] == poc_id and cur["params_hash"] == h:
            return
        if cur and cur["status"] == REJECTED:
            return
        self._data[finding_id] = {"poc_id": poc_id, "params": dict(params), "params_hash": h,
                                  "status": PENDING}
        self._save()

    def approve(self, finding_id: str, poc_id: str, approved_hash: str, *,
                reviewer: str, reason: str) -> None:
        self._decide(finding_id, APPROVED, reviewer, reason, poc_id=poc_id,
                     approved_hash=approved_hash)

    def approve_pending(self, finding_id: str, *, reviewer: str, reason: str) -> None:
        """Aprueba exactamente la propuesta pendiente que se mostró en `list`."""
        cur = self._require(finding_id)
        self.approve(finding_id, cur["poc_id"], cur["params_hash"],
                     reviewer=reviewer, reason=reason)

    def reject(self, finding_id: str, *, reviewer: str, reason: str) -> None:
        self._decide(finding_id, REJECTED, reviewer, reason)

    def status(self, finding_id: str) -> str:
        return str(self._data.get(finding_id, {}).get("status", PENDING))

    def pending(self) -> list[tuple[str, dict[str, Any]]]:
        return [(k, v) for k, v in sorted(self._data.items()) if v["status"] == PENDING]

    def is_approved(self, finding_id: str, poc_id: str, h: str) -> bool:
        cur = self._data.get(finding_id)
        return bool(cur and cur["status"] == APPROVED and cur.get("approved_poc_id") == poc_id
                    and cur.get("approved_hash") == h)

    def _require(self, finding_id: str) -> dict[str, Any]:
        if finding_id not in self._data:
            raise KeyError(f"hallazgo sin propuesta registrada: {finding_id}")
        return self._data[finding_id]

    def _decide(self, finding_id: str, decision: str, reviewer: str, reason: str, *,
                poc_id: str | None = None, approved_hash: str | None = None) -> None:
        if not reviewer or not reviewer.strip():
            raise ValueError("falta el Reviewer")
        if not reason or not reason.strip():
            raise ValueError("falta el motivo")
        cur = self._require(finding_id)
        ts = time.time()
        cur.update({"status": decision, "reviewer": reviewer.strip(),
                    "reason": reason.strip(), "ts": ts})
        if decision == APPROVED:
            cur.update({"approved_poc_id": poc_id, "approved_hash": approved_hash})
        self._save()
        self.audit.append({"event": "hitl.decision", "decision": decision,
                           "finding_id": finding_id, "poc_id": poc_id or cur["poc_id"],
                           "params_hash": approved_hash or cur["params_hash"],
                           "reviewer": reviewer.strip(), "reason": reason.strip(), "ts": ts})


# ---- Loop C ---------------------------------------------------------------------------


def _max_attempts() -> int:
    return int(load_policy()["limits"]["max_loop_iterations"]["validation"])


def run_validation_loop(harness: Harness, token: ScopeToken, requests: list[ValidationRequest],
                        *, approvals: ApprovalStore, sender: SandboxSender,
                        catalog: FrozenCatalog, evidence: Any,
                        max_attempts: int | None = None,
                        agent: str = "validation-agent") -> dict[str, Outcome]:
    limit = max_attempts or _max_attempts()
    for name in sender.adapter.cleanup_orphans():
        evidence.append({"event": "sandbox.orphan_removed", "engagement": token.engagement_id,
                         "container": name})

    results: dict[str, Outcome] = {}
    for req in requests:
        outcome = _validate_one(harness, token, req, approvals, sender, catalog, limit, agent)
        results[req.finding_id] = outcome
        entry = catalog.entries.get(req.poc_id)
        evidence.append({"event": "validation.result", "engagement": token.engagement_id,
                         "finding_id": req.finding_id, "poc_id": req.poc_id,
                         "poc_version": entry["version"] if entry else None,
                         "catalog_version": catalog.version,
                         "params_hash": params_hash(req.params), "status": outcome.status,
                         "reason": outcome.reason, "attempts": outcome.attempts})
    return results


def _validate_one(harness: Harness, token: ScopeToken, req: ValidationRequest,
                  approvals: ApprovalStore, sender: SandboxSender, catalog: FrozenCatalog,
                  limit: int, agent: str) -> Outcome:
    if approvals.status(req.finding_id) == REJECTED:
        return Outcome("not_validated", "rechazado")
    entry = catalog.entries.get(req.poc_id)
    if entry is None:
        return Outcome("not_validated", "fuera del catálogo")

    h = params_hash(req.params)
    if not approvals.is_approved(req.finding_id, req.poc_id, h):
        approvals.request(req.finding_id, req.poc_id, req.params)
        harness.audit.record_decision(agent, CAPABILITY, str(req.params.get("base_url", "")),
                                      token.engagement_id, token.phase.value,
                                      Result.PENDING_HITL)
        if token.is_live():
            return Outcome(PENDING, "esperando aprobación del Reviewer")
        return Outcome("not_validated", "sin aprobación")

    statuses: list[str] = []
    while decide_validation(len(statuses), len(set(statuses)) > 1, limit).decision == "continue":
        sender.annotate(finding_id=req.finding_id, poc_version=entry["version"],
                        catalog_version=catalog.version, attempt=len(statuses) + 1)
        try:
            ev = run_parametrized({k: dict(v) for k, v in catalog.entries.items()}, req.poc_id,
                                  dict(req.params),
                                  True, sender)
        except (SandboxAborted, KillSwitchEngaged):
            raise
        except SandboxTimeout:
            return Outcome("not_validated", "timeout", len(statuses) + 1)
        except ScopeViolation:
            return Outcome("not_validated", "bloqueado por el harness", len(statuses) + 1)
        except ParameterError:
            return Outcome("not_validated", "parámetros inválidos", len(statuses) + 1)
        # Captura amplia a propósito: cualquier fallo del runtime o del evaluador deja el
        # hallazgo "no validado" (falla cerrado). SandboxAborted y el kill switch ya se
        # re-lanzaron arriba.
        except Exception as exc:  # noqa: BLE001
            return Outcome("not_validated", f"error: {type(exc).__name__}", len(statuses) + 1)
        statuses.append(ev.status)

    if len(set(statuses)) > 1:
        return Outcome("not_validated", "inconsistente", len(statuses))
    if statuses and statuses[0] == "validated":
        return Outcome("validated", "confirmado en todos los intentos", len(statuses))
    return Outcome("not_validated", "no se observó la debilidad", len(statuses))
