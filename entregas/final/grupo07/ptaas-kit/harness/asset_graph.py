"""Grafo de activos versionado con persistencia JSON atómica."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from harness.schemas import Asset

SCHEMA_VERSION = 1


class GraphVersionError(ValueError):
    """El archivo no usa una versión de grafo soportada."""


@dataclass(frozen=True)
class AssetNode:
    asset: Asset
    sources: tuple[str, ...]
    in_scope: bool
    discovered_from: tuple[str, ...] = ()


class AssetGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, AssetNode] = {}

    @property
    def nodes(self) -> tuple[AssetNode, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    @staticmethod
    def stable_id(address: str) -> str:
        normalized = address.strip().lower().rstrip(".")
        return "asset-" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]

    def add(self, asset: Asset, *, in_scope: bool,
            discovered_from: str | None = None) -> tuple[AssetNode, bool]:
        address = asset.address.strip().lower().rstrip(".")
        stable = replace(asset, id=self.stable_id(address), address=address)
        source = asset.source_tool
        existing = self._nodes.get(stable.id)
        if existing is None:
            node = AssetNode(stable, (source,), in_scope,
                             (discovered_from,) if discovered_from else ())
            self._nodes[stable.id] = node
            return node, True
        merged = replace(
            existing.asset,
            technologies=tuple(sorted(set(existing.asset.technologies) |
                                      set(stable.technologies))),
        )
        parents = set(existing.discovered_from)
        if discovered_from:
            parents.add(discovered_from)
        node = AssetNode(
            merged,
            tuple(sorted(set(existing.sources) | {source})),
            existing.in_scope or in_scope,
            tuple(sorted(parents)),
        )
        self._nodes[stable.id] = node
        return node, False

    def get_by_address(self, address: str) -> AssetNode | None:
        normalized = address.strip().lower().rstrip(".")
        node_id = next((key for key, node in self._nodes.items()
                        if node.asset.address == normalized), None)
        return self._nodes.get(node_id) if node_id else None

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": SCHEMA_VERSION,
            "nodes": [
                {
                    "asset": {
                        "id": node.asset.id,
                        "type": node.asset.type,
                        "address": node.asset.address,
                        "source_tool": node.asset.source_tool,
                        "technologies": list(node.asset.technologies),
                    },
                    "sources": list(node.sources),
                    "in_scope": node.in_scope,
                    "discovered_from": list(node.discovered_from),
                }
                for node in self.nodes
            ],
        }
        fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                                         dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    @classmethod
    def load(cls, path: Path) -> AssetGraph:
        payload: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != SCHEMA_VERSION:
            raise GraphVersionError(f"schema_version no soportada: {payload.get('schema_version')}")
        graph = cls()
        for item in payload.get("nodes", []):
            data = item["asset"]
            asset = Asset(
                data["id"], data["type"], data["address"], data["source_tool"],
                tuple(data.get("technologies", [])),
            )
            node = AssetNode(asset, tuple(sorted(item["sources"])), bool(item["in_scope"]),
                             tuple(sorted(item.get("discovered_from", []))))
            if asset.id in graph._nodes:
                raise ValueError(f"nodo duplicado: {asset.id}")
            graph._nodes[asset.id] = node
        return graph
