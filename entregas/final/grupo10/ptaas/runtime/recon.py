"""Reconocimiento acotado al laboratorio y ejecutado únicamente por Harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from harness.audit import AuditLog
from harness.contracts import Guard, Harness, KillSwitch
from harness.types import Action, Phase, ScopeToken, ToolAdapter


@dataclass(frozen=True)
class Asset:
    address: str
    port: int
    status: int
    source: str


@dataclass
class AssetGraph:
    assets: dict[str, Asset] = field(default_factory=dict)
    out_of_scope: list[str] = field(default_factory=list)

    def add(self, asset: Asset) -> bool:
        key = f"{asset.address}:{asset.port}"
        old = self.assets.get(key)
        self.assets[key] = asset
        return old != asset

    def reject(self, address: str) -> None:
        if address not in self.out_of_scope:
            self.out_of_scope.append(address)

    def digest(self) -> str:
        data = {key: vars(value) for key, value in sorted(self.assets.items())}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


class Probe(Protocol):
    def __call__(self, target: str) -> Asset: ...


class HttpxAdapter:
    name = "httpx.probe"
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, probe: Probe | None = None) -> None:
        self._probe = probe or self._real_probe

    @staticmethod
    def _real_probe(target: str) -> Asset:
        if target != "juice-shop.lab.test":
            raise ValueError("recon_target_out_of_scope")
        request = urllib.request.Request("http://juice-shop.lab.test:3000/", method="GET")
        for attempt in range(15):
            try:
                with urllib.request.urlopen(request, timeout=2) as response:
                    return Asset(target, 3000, response.status, "httpx.probe")
            except urllib.error.HTTPError as error:
                return Asset(target, 3000, error.code, "httpx.probe")
            except urllib.error.URLError:
                if attempt == 14:
                    raise
                time.sleep(1)
        raise RuntimeError("recon_retry_exhausted")

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        asset = self._probe(target)
        return {"asset": vars(asset), "graph_key": f"{asset.address}:{asset.port}"}


class SubfinderAdapter:
    """Constructor y parser seguro; no acepta comandos del modelo."""

    @staticmethod
    def argv(domain: str) -> tuple[str, ...]:
        if domain != "juice-shop.lab.test":
            raise ValueError("recon_domain_not_allowed")
        return ("subfinder", "-d", domain, "-silent")

    @staticmethod
    def parse(lines: str, allowed: set[str]) -> list[str]:
        values = sorted({line.strip().lower().rstrip(".") for line in lines.splitlines() if line.strip()})
        return [value for value in values if value in allowed]


def run_loop(harness: Harness, token: ScopeToken, *, max_rounds: int = 3) -> dict[str, Any]:
    if token.phase is not Phase.RECON or not 1 <= max_rounds <= 3:
        raise ValueError("invalid_recon_loop")
    graph = AssetGraph()
    previous = ""
    trace: list[dict[str, Any]] = []
    reason = "budget_exhausted"
    for round_no in range(1, max_rounds + 1):
        action = Action("httpx.probe", Phase.RECON, parameters={"target": "juice-shop.lab.test"})
        output = harness.invoke("asset_discovery", action, "juice-shop.lab.test", token)
        asset_data = output["asset"]
        changed = graph.add(Asset(**asset_data))
        trace.append({"round": round_no, "changed": changed, "graph_digest": graph.digest()})
        current = graph.digest()
        if current == previous:
            reason = "graph_stabilized"
            break
        previous = current
    return {"state": "RECON_COMPLETE", "stop_reason": reason, "rounds": len(trace),
            "assets": [vars(asset) for asset in graph.assets.values()],
            "out_of_scope": graph.out_of_scope, "trace": trace}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rounds", type=int, default=3)
    args = parser.parse_args()
    now = time.time()
    token = ScopeToken("juice-shop-recon", (), ("juice-shop.lab.test",), now - 1, now + 120, Phase.RECON)
    action = "httpx.probe"
    adapter = HttpxAdapter()
    harness = Harness(Guard({Phase.RECON: {action}}), AuditLog(),
                      {action: cast(ToolAdapter, adapter)}, KillSwitch())
    try:
        result = run_loop(harness, token, max_rounds=args.max_rounds)
        result["audit"] = harness.audit.verify()
    except (OSError, ValueError) as error:
        print(json.dumps({"state": "FAILED", "reason": type(error).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
