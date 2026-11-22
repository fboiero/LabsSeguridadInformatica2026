"""Orquestador determinista del Loop A (Relevamiento / Asset Discovery).

Cierra la deuda H1 del Turno 2 integrando en el flujo de ejecución:
- `Harness.invoke` y `Guard._in_scope` (invariantes I1, I2, I3)
- `ordered_recon` / `passive_before_active` (pasivo antes que activo)
- `dedupe_assets` (sin incorporar ni re-sondear activos repetidos)
- `decide_recon` (parada por grafo estabilizado o tope de iteraciones)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from harness.adapters.common import (
    AdapterOutputError,
    InvalidTarget,
    RateLimitExceeded,
    ToolExecutionError,
)
from harness.contracts import Action, Guard, Harness, Phase, ScopeToken, ScopeViolation
from harness.loops import decide_recon
from harness.policy_loader import load_policy
from harness.recon_order import ordered_recon, passive_before_active
from harness.schemas import Asset, dedupe_assets


@dataclass(frozen=True)
class GraphSnapshot:
    iteration: int
    total_assets: int
    new_assets: int
    digest: str


@dataclass
class AssetGraph:
    assets: list[Asset] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    def add_assets(self, candidates: list[Asset]) -> int:
        before = {(a.type, a.address) for a in self.assets}
        self.assets = dedupe_assets([*self.assets, *candidates])
        after = {(a.type, a.address) for a in self.assets}
        return len(after - before)

    def add_out_of_scope(self, target: str) -> None:
        normalized = target.strip().lower().rstrip(".")
        if normalized and normalized not in self.out_of_scope:
            self.out_of_scope.append(normalized)

    def digest(self) -> str:
        payload = {
            "assets": sorted(
                (
                    {
                        "id": a.id,
                        "type": a.type,
                        "address": a.address,
                        "source_tool": a.source_tool,
                        "technologies": list(a.technologies),
                    }
                    for a in self.assets
                ),
                key=lambda item: (item["type"], item["address"]),
            ),
            "out_of_scope": sorted(self.out_of_scope),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "assets": [asdict(a) for a in self.assets],
            "out_of_scope": sorted(self.out_of_scope),
            "digest": self.digest(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetGraph:
        assets = [
            Asset(
                id=item["id"],
                type=item["type"],
                address=item["address"],
                source_tool=item["source_tool"],
                technologies=tuple(item.get("technologies", ())),
            )
            for item in data.get("assets", [])
        ]
        return cls(
            assets=dedupe_assets(assets),
            out_of_scope=list(data.get("out_of_scope", [])),
        )


def run_loop_a(
    harness: Harness,
    token: ScopeToken,
    seed_domains: list[str],
    *,
    max_iterations: int | None = None,
    capabilities: list[str] | None = None,
) -> dict[str, Any]:
    """Ejecuta el Loop A completo pasando cada acción por `Harness.invoke`."""
    policy_limit = int(load_policy()["limits"]["max_loop_iterations"]["recon"])
    limit = policy_limit if max_iterations is None else min(max_iterations, policy_limit)

    selected = ordered_recon(capabilities or ["httpx.probe", "subfinder.enum"])
    if not passive_before_active(selected):
        raise ValueError("orden inválido de capabilities en Loop A")

    graph = AssetGraph()
    snapshots: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    passive_queried: set[str] = set()
    active_probed: set[str] = set()
    stop_reason = "tope de iteraciones alcanzado"

    for iteration in range(1, limit + 1):
        discovered_hosts: list[str] = []
        passive_targets = [d for d in seed_domains if d not in passive_queried]

        if "subfinder.enum" in selected:
            for domain in passive_targets:
                passive_queried.add(domain)
                try:
                    out = harness.invoke(
                        "asset_discovery",
                        Action("subfinder.enum", Phase.RECON),
                        domain,
                        token,
                        record_evidence=True,
                    )
                    discovered_hosts.extend(out.get("hosts", []))
                except ScopeViolation:
                    graph.add_out_of_scope(domain)
                except (AdapterOutputError, InvalidTarget, RateLimitExceeded, ToolExecutionError) as exc:
                    errors.append({"iteration": str(iteration), "tool": "subfinder.enum", "error": type(exc).__name__})

        new_assets_batch: list[Asset] = []
        candidates = sorted(set(discovered_hosts or ([] if iteration > 1 else seed_domains)))
        if "httpx.probe" in selected:
            for host in candidates:
                if host in active_probed:
                    continue
                if not Guard._in_scope(host, token):
                    # Se invoca igualmente para registrar BLOCKED en bitácora sin llegar al adaptador.
                    try:
                        harness.invoke(
                            "asset_discovery",
                            Action("httpx.probe", Phase.RECON),
                            host,
                            token,
                            record_evidence=True,
                        )
                    except ScopeViolation:
                        graph.add_out_of_scope(host)
                    continue

                active_probed.add(host)
                try:
                    probe = harness.invoke(
                        "asset_discovery",
                        Action("httpx.probe", Phase.RECON),
                        host,
                        token,
                        record_evidence=True,
                    )
                    new_assets_batch.append(
                        Asset(
                            id=f"web-{host}",
                            type="web_service",
                            address=host,
                            source_tool="httpx.probe",
                            technologies=tuple(probe.get("tech", ())),
                        )
                    )
                except ScopeViolation:
                    graph.add_out_of_scope(host)
                except (AdapterOutputError, InvalidTarget, RateLimitExceeded, ToolExecutionError) as exc:
                    errors.append({"iteration": str(iteration), "tool": "httpx.probe", "error": type(exc).__name__})

        new_count = graph.add_assets(new_assets_batch)
        snap = GraphSnapshot(
            iteration=iteration,
            total_assets=len(graph.assets),
            new_assets=new_count,
            digest=graph.digest(),
        )
        snapshots.append(asdict(snap))

        decision = decide_recon(iteration, new_count, limit)
        stop_reason = decision.reason
        if decision.decision == "stop":
            break

    return {
        "engagement_id": token.engagement_id,
        "phase": token.phase.value,
        "capabilities_order": selected,
        "stop_reason": stop_reason,
        "iterations": len(snapshots),
        "assets": [asdict(a) for a in graph.assets],
        "out_of_scope": sorted(graph.out_of_scope),
        "snapshots": snapshots,
        "errors": errors,
        "audit_verified": harness.audit.verify_chain(),
    }
