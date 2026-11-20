"""Corrida de recon P3 en el laboratorio y verificación de su evidencia exportada.

No implementa el almacenamiento SQLite de P1: exporta AuditLog y usa su verificador.
No firma ni crea aprobaciones: consume un archivo con la autorización del operador.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.audit import Entry, VerifyResult, verificar_cadena
from harness.contracts import AuditLog, Guard, Harness, KillSwitch, Phase

TARGETS = ('dvwa.lab.test', 'juiceshop.lab.test')

def export_audit(audit: AuditLog, path: Path) -> None:
    entries = list(audit.entries)
    payload = {'count': len(entries), 'head': entries[-1]['hash'] if entries else 'GENESIS',
               'entries': entries}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')

def verify_audit(path: Path) -> VerifyResult:
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
        rows = payload['entries']
        if payload['count'] != len(rows) or payload['head'] != (rows[-1]['hash'] if rows else 'GENESIS'):
            return VerifyResult(False, 'conteo o anclaje final diferente')
        entries = [Entry(i + 1, row['prev'], row['hash'],
                         {key: value for key, value in row.items() if key not in {'hash', 'prev'}})
                   for i, row in enumerate(rows)]
        return verificar_cadena(entries)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return VerifyResult(False, type(exc).__name__)

def validate_approval(approval: dict[str, Any]) -> None:
    if not isinstance(approval, dict):
        raise ValueError('autorización inválida')
    for key in ('actor', 'reference', 'quote'):
        if not isinstance(approval.get(key), str) or not approval[key].strip():
            raise ValueError('se requiere referencia de autorización humana')
    if type(approval.get('expires_at')) not in (int, float) or not time.time() < approval['expires_at'] <= time.time() + 3600:
        raise ValueError('ventana de autorización inválida o vencida')
    targets = approval.get('approved_targets')
    if not isinstance(targets, list) or not targets or set(targets) - set(TARGETS):
        raise ValueError('targets fuera del laboratorio')

def run(approval_path: Path, output: Path) -> int:
    from harness.adapters.httpx_adapter import HttpxProbe
    from harness.adapters.subfinder_adapter import OfflineSubfinderRunner, SubfinderEnum
    from harness.asset_graph import AssetGraph
    from harness.loops import run_recon
    from harness.policy_loader import phase_allowlist
    from harness.roe import parse
    from harness.tokens import issue

    approval = json.loads(approval_path.read_text(encoding='utf-8'))
    validate_approval(approval)
    if os.environ.get('PTAAS_LAB_ISOLATED') != '1':
        raise ValueError('ejecutar únicamente en runner de la red interna verificada')
    output.mkdir(parents=True, exist_ok=False)
    targets = approval['approved_targets']
    now = time.time()
    iso = lambda timestamp: datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    roe = parse({'engagement_id': 'p3-real-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'),
                 'approver': approval['actor'], 'approval_ref': approval['reference'],
                 'signed_at': iso(now), 'window': {'start': iso(now - 1), 'end': iso(approval['expires_at'])},
                 'scope': {'cidrs': ['10.99.0.0/24'], 'domains': targets},
                 'exclusions': {}, 'emergency_contacts': [approval['actor'] + ' — canal de coordinación'],
                 'authorized_phases': ['recon']})
    audit = AuditLog()
    token = issue(roe, Phase.RECON, audit=audit)
    resolve = lambda host: {entry[4][0] for entry in socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)}
    # Materializa la autorización humana recibida, no una decisión autónoma del agente.
    guard = Guard(phase_allowlist(), approvals={'httpx.probe@' + host for host in targets},
                  engagement_id=roe.engagement_id, resolver=resolve)
    captures = []

    def capture(tool: str, argv: list[str], raw: str) -> None:
        filename = f'{len(captures) + 1:02d}-{tool}.jsonl'
        (output / filename).write_text(raw, encoding='utf-8')
        captures.append({'file': filename, 'tool': tool, 'argv': argv,
                         'sha256': hashlib.sha256(raw.encode()).hexdigest(), 'bytes': len(raw.encode())})

    passive_runner = OfflineSubfinderRunner(capture=lambda argv, raw: capture('subfinder', argv, raw))
    harness = Harness(guard, audit, {
        'subfinder.enum': SubfinderEnum(runner=passive_runner),
        'httpx.probe': HttpxProbe(capture=lambda argv, raw: capture('httpx', argv, raw)),
    }, KillSwitch())
    graph = AssetGraph(roe.engagement_id)
    try:
        run_recon(harness, token, targets, graph, checkpoint=output / 'graph.json')
    finally:
        export_audit(audit, output / 'audit.json')
        manifest = {'engagement_id': roe.engagement_id, 'targets': targets, 'approval': approval,
                    'authorization_recorded_at': iso(now), 'status': graph.status,
                    'stop_reason': graph.stop_reason, 'iteration': graph.iteration,
                    'assets': len(graph.assets), 'captures': captures, 'subfinder_error': passive_runner.last_error,
                    'passive_mode': 'native subfinder: external providers disabled, UNAVAILABLE is recorded; seeds only, no passive discoveries claimed'}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    verified = verify_audit(output / 'audit.json')
    print(json.dumps({'status': graph.status, 'reason': graph.stop_reason, 'iterations': graph.iteration,
                      'assets': len(graph.assets), 'audit_verified': verified.ok}, ensure_ascii=False))
    return 0 if graph.status == 'STOPPED' and verified.ok and len(graph.assets) >= len(targets) else 1

def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    execute = sub.add_parser('run')
    execute.add_argument('--approval', type=Path, required=True)
    execute.add_argument('--output', type=Path, required=True)
    audit = sub.add_parser('audit')
    audit.add_argument('operation', choices=['verify'])
    audit.add_argument('path', type=Path)
    args = parser.parse_args()
    if args.command == 'run':
        return run(args.approval, args.output)
    result = verify_audit(args.path)
    print(json.dumps({'ok': result.ok, 'reason': result.motivo}, ensure_ascii=False))
    return 0 if result.ok else 1

if __name__ == '__main__':
    raise SystemExit(main())
