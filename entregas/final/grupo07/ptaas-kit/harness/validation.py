"""Loop C con aprobación por hallazgo, catálogo y Harness como única puerta."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from harness.approvals import ApprovalStore, subject_key
from harness.contracts import Action, Harness, Phase, Result, ScopeToken
from harness.loops import decide_validation
from harness.poc.catalog import NotInCatalog, ParameterError, load_catalog, run_parametrized


@dataclass(frozen=True)
class ValidationRequest:
    id: str
    asset: str
    cwe: str
    poc_id: str
    params: dict[str, str]
    execution_mode: str = "fixture"
    engagement_id: str = "eng-lab-001"

    @property
    def subject(self) -> str:
        return subject_key(asdict(self))


class ValidationAdapter:
    name = "poc_catalog.run_parametrized"
    allowed_phases: tuple[Phase, ...] = (Phase.VALIDATE,)
    destructive = False

    def __init__(
        self, request: ValidationRequest, factory: Callable[[], Any], catalog: dict[str, Any]
    ) -> None:
        self.request = request
        self.factory = factory
        self.catalog = catalog

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        sender = self.factory()
        try:
            if sender.mode != self.request.execution_mode:
                raise ValueError("modo de ejecución difiere del aprobado")
            evidence = run_parametrized(
                self.catalog, self.request.poc_id, self.request.params, True, sender
            )
            return {**asdict(evidence), "mode": sender.mode}
        finally:
            sender.close()


def validate_finding(
    harness: Harness,
    token: ScopeToken,
    request: ValidationRequest,
    approvals: ApprovalStore,
    sender_factory: Callable[[], Any],
) -> dict[str, Any]:
    action = Action("poc_catalog.run_parametrized", Phase.VALIDATE, requires_human_approval=True)
    if request.engagement_id != token.engagement_id:
        raise ValueError("aprobación ligada a otro engagement")
    catalog = load_catalog()
    entry = catalog.get(request.poc_id)
    if not entry or entry["cwe"] != request.cwe:
        harness.audit.record(
            "validation:catalog-miss", action, request.asset, token, Result.BLOCKED
        )
        return {
            "status": "not_validated",
            "attempts": 0,
            "mode": "none",
            "reason": "sin catálogo compatible",
        }
    from urllib.parse import urlsplit

    if urlsplit(request.params.get("base_url", "")).hostname != request.asset:
        harness.audit.record(
            "validation:target-mismatch", action, request.asset, token, Result.BLOCKED
        )
        return {
            "status": "not_validated",
            "attempts": 0,
            "mode": "none",
            "reason": "activo y parámetros no coinciden",
        }
    # El Guard genérico aprueba por acción/activo; se borra cualquier permiso anterior
    # y se exige en cada invocación la decisión para este contenido exacto.
    key = f"{action.name}@{request.asset}"
    harness.guard._approvals.discard(key)
    if approvals.approved(request.subject):
        harness.guard.approve(action.name, request.asset)
    harness.tools[action.name] = ValidationAdapter(request, sender_factory, catalog)
    approvals.pending(request.subject, f"Validar {request.id} ({request.execution_mode})")
    attempts = 0
    out: dict[str, Any] = {"status": "not_validated"}
    refs = []
    try:
        while decide_validation(attempts, out["status"] == "validated", 2).decision == "continue":
            if not approvals.approved(request.subject):
                harness.guard._approvals.discard(key)
            out = harness.invoke(
                f"validation:{request.id}:{request.poc_id}:{entry['version']}:{request.subject}",
                action,
                request.asset,
                token,
            )
            refs.append(harness.audit.entries[-1]["hash"])
            if out.get("status") == "PENDING_HITL":
                break
            attempts += 1
    except (OSError, ValueError, NotInCatalog, ParameterError) as exc:
        harness.audit.record(
            f"validation:{request.id}:failed:{type(exc).__name__}",
            action,
            request.asset,
            token,
            Result.BLOCKED,
        )
        refs.append(harness.audit.entries[-1]["hash"])
        out = {"status": "not_validated", "reason": type(exc).__name__}
    finally:
        harness.guard._approvals.discard(key)
    return {**out, "attempts": attempts, "evidence_refs": refs, "mode": out.get("mode", "none")}
