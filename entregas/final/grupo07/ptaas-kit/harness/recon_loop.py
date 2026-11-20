"""Orquestación del loop A: subfinder pasivo antes de HTTPX activo y acotado."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.asset_graph import AssetGraph
from harness.contracts import Action, Harness, Phase, ScopeToken, ScopeViolation
from harness.loops import LoopDecision, decide_recon
from harness.policy_loader import load_policy
from harness.schemas import Asset


@dataclass(frozen=True)
class ReconResult:
    reason: str
    iterations: int
    graph: AssetGraph


class ReconLoop:
    def __init__(self, harness: Harness, graph: AssetGraph | None = None,
                 max_iterations: int | None = None):
        self.harness = harness
        self.graph = graph or AssetGraph()
        policy = load_policy()
        self.max_iterations = max_iterations or policy["limits"]["max_loop_iterations"]["recon"]

    def run(self, seed: str, token: ScopeToken,
            persist_to: Path | None = None) -> ReconResult:
        if token.phase != Phase.RECON:
            raise ValueError("loop A requiere un token RECON")
        seed_host = seed.strip().lower().rstrip(".")
        self.graph.add(Asset("", "domain", seed_host, "seed"), in_scope=True)
        frontier = [seed_host]
        probed: set[str] = set()
        last_decision = LoopDecision("stop", "grafo estabilizado")
        completed = 0

        def probe(host: str) -> dict[str, Any]:
            result = self.harness.invoke(
                "recon", Action("httpx.probe", Phase.RECON), host, token
            )
            probed.add(host)
            for item in result.get("assets", []):
                self.graph.add(
                    Asset("", "host", item["host"], "httpx.probe",
                          tuple(item.get("technologies", []))),
                    in_scope=True,
                    discovered_from=host,
                )
            return result

        for iteration in range(1, self.max_iterations + 1):
            next_frontier: set[str] = set()
            new_assets = 0
            for parent in sorted(frontier):
                enumeration = self.harness.invoke(
                    "recon", Action("subfinder.enum", Phase.RECON), parent, token
                )
                if parent not in probed:
                    probe(parent)
                for host in sorted(set(enumeration.get("hosts", []))):
                    node, created = self.graph.add(
                        Asset("", "host", host, "subfinder.enum"),
                        in_scope=self.harness.guard.is_allowed(
                            Action("httpx.probe", Phase.RECON), host, token
                        ),
                        discovered_from=parent,
                    )
                    if not node.in_scope:
                        try:
                            self.harness.invoke(
                                "recon", Action("httpx.probe", Phase.RECON), host, token
                            )
                        except ScopeViolation:
                            pass
                        continue
                    if not created:
                        continue
                    new_assets += 1
                    next_frontier.add(host)
                    if host not in probed:
                        probe(host)

            completed = iteration
            last_decision = decide_recon(iteration, new_assets, self.max_iterations)
            if last_decision.decision == "stop":
                break
            frontier = sorted(next_frontier)

        if persist_to is not None:
            self.graph.save(persist_to)
        return ReconResult(last_decision.reason, completed, self.graph)
