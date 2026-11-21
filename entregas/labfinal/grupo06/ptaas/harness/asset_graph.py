"""Inventario RECON versionado; no ejecuta herramientas ni decide autorizaciones."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.adapters.common import validate_target


def normalize_asset(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get('type') != 'host':
        raise ValueError('tipo de activo inválido')
    address = value.get('address')
    source = value.get('source_tool')
    tech = value.get('technologies', [])
    if not isinstance(address, str) or not isinstance(source, str) or not source.strip():
        raise ValueError('activo requiere address y source_tool')
    address = validate_target(address)
    if not isinstance(tech, (list, tuple)) or any(not isinstance(t, str) or not t.strip() for t in tech):
        raise ValueError('technologies inválidas')
    key = hashlib.sha256(('host:' + address).encode()).hexdigest()[:24]
    return {'id': key, 'type': 'host', 'address': address, 'source_tool': source,
            'technologies': sorted(set(tech))}


@dataclass
class AssetGraph:
    engagement_id: str
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    excluded: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    frontier: list[str] = field(default_factory=list)
    revision: int = 0
    iteration: int = 0
    status: str = 'READY'
    stop_reason: str = ''
    schema_failures: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.engagement_id, str) or not self.engagement_id.strip():
            raise ValueError('engagement_id requerido')

    def add(self, value: dict[str, Any]) -> bool:
        item = normalize_asset(value)
        key = item['id']
        previous = self.assets.get(key)
        if previous:
            item['technologies'] = sorted(set(previous['technologies']) | set(item['technologies']))
            if previous['source_tool'] != 'scope.seed':
                item['source_tool'] = previous['source_tool']
        if item != previous:
            self.assets[key] = item
            self.revision += 1
        return previous is None

    def save(self, path: Path) -> None:
        path = Path(path)
        payload = {'schema_version': 1, **self.__dict__}
        # Validar antes del reemplazo, incluso si un consumidor mutó el objeto.
        self._from_dict(payload, self.engagement_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                json.dump(payload, stream, ensure_ascii=False, sort_keys=True, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any], engagement_id: str) -> AssetGraph:
        if not isinstance(raw, dict) or raw.get('schema_version') != 1 or raw.get('engagement_id') != engagement_id:
            raise ValueError('versión o engagement incompatible')
        expected = set(cls.__dataclass_fields__) | {'schema_version'}
        if set(raw) != expected:
            raise ValueError('campos del grafo inválidos')
        for key in ('revision', 'iteration', 'schema_failures'):
            if type(raw[key]) is not int or raw[key] < 0:
                raise ValueError('contador inválido')
        if raw['status'] not in {'READY', 'RUNNING', 'STOPPED', 'PENDING_HITL', 'BLOCKED', 'ABORTED', 'ERROR'}:
            raise ValueError('status inválido')
        if not isinstance(raw['stop_reason'], str) or not isinstance(raw['assets'], dict):
            raise ValueError('grafo inválido')
        for key in ('excluded', 'evidence_refs', 'frontier'):
            if not isinstance(raw[key], list) or any(not isinstance(x, str) for x in raw[key]):
                raise ValueError('referencias inválidas')
        for host in raw['frontier']:
            if validate_target(host) != host:
                raise ValueError('frontera no canónica')
        for key, item in raw['assets'].items():
            if normalize_asset(item) != item or key != item['id']:
                raise ValueError('activo persistido inválido')
        return cls(**{k: v for k, v in raw.items() if k != 'schema_version'})

    @classmethod
    def load(cls, path: Path, engagement_id: str) -> AssetGraph:
        return cls._from_dict(json.loads(Path(path).read_text(encoding='utf-8')), engagement_id)
