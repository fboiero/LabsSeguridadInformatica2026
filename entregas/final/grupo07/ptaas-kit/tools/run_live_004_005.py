"""Adaptadores reales en Docker interno; ejecutar desde la raíz del kit."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.adapters.common import load_profiles
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.nuclei_adapter import NucleiSafeTemplates
from harness.adapters.zap_adapter import ZapBaselineScan
from harness.contracts import Action, AuditLog, Harness, KillSwitch, Phase
from harness.policy_loader import phase_allowlist
from harness.roe import parse_roe
from harness.run import verify_entries
from harness.tokens import EngagementGuard, TokenIssuer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--tools', nargs='+', default=['httpx', 'nuclei', 'zap'],
                        choices=['httpx', 'nuclei', 'zap'])
    selected = parser.parse_args().tools
    root = Path.cwd()
    output = root / 'evidencia' / 'lorenzo' / datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
    output.mkdir(parents=True)
    calls = []
    images = {'httpx': 'projectdiscovery/httpx:latest',
              'nuclei': 'projectdiscovery/nuclei:latest',
              'zap-baseline.py': 'ghcr.io/zaproxy/zaproxy:stable'}
    internal = subprocess.check_output(
        ['docker', 'network', 'inspect', 'lab_lab', '--format', '{{.Internal}}'], text=True
    ).strip()
    if internal != 'true':
        raise RuntimeError('El lab debe ser internal:true')

    def runner(argv: list[str], timeout: int) -> str:
        tool = argv[0]
        args = argv[1:]
        if tool == 'nuclei':
            args = [arg for arg in args if arg != '-silent']
            for index, arg in enumerate(args[:-1]):
                if arg == '-t':
                    args[index + 1] = args[index + 1].replace('\\', '/')
        mounts = ['-v', str(root) + ':/work']
        if tool == 'zap-baseline.py':
            args = list(args)
            args[args.index('-J') + 1] = Path(args[args.index('-J') + 1]).name
            mounts.extend(['-v', str(output) + ':/zap/wrk'])
        command = ['docker', 'run', '--rm', '--network', 'lab_lab',
                   '--user', '0:0', *mounts, '-w', '/work',
                   '--entrypoint', tool, images[tool], *args]
        proc = subprocess.run(command, check=False, capture_output=True, text=True,
                              timeout=timeout + 30)
        calls.append({'argv': command, 'returncode': proc.returncode,
                      'stdout': proc.stdout, 'stderr': proc.stderr})
        (output / 'calls.json').write_text(json.dumps(calls, indent=2), encoding='utf-8')
        if proc.returncode not in ({0, 1, 2} if tool == 'zap-baseline.py' else {0}):
            raise RuntimeError(proc.stderr)
        return proc.stdout

    audit = AuditLog()
    roe = parse_roe(Path('roe/roe-lab.example.yaml'))
    ks = KillSwitch()
    issuer = TokenIssuer(roe, audit, killswitch=ks)
    profiles = load_profiles()
    zap_profile = dict(profiles['zap'], report_dir=str(output))
    tools = {'httpx.probe': HttpxProbe(runner),
             'zap.baseline_scan': ZapBaselineScan(runner, zap_profile),
             'nuclei.safe_templates': NucleiSafeTemplates(runner)}
    harness = Harness(EngagementGuard(roe.engagement_id, phase_allowlist()), audit, tools, ks)
    results = {}
    try:
        for name, phase in [('httpx.probe', Phase.RECON),
                            ('nuclei.safe_templates', Phase.ANALYZE),
                            ('zap.baseline_scan', Phase.ANALYZE)]:
            if name.split('.')[0] not in selected:
                continue
            print(name, flush=True)
            results[name] = harness.invoke('live-lorenzo', Action(name, phase),
                                           'dvwa.lab.test', issuer.issue(phase))
            (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    finally:
        (output / 'audit.json').write_text(json.dumps(audit.entries, indent=2), encoding='utf-8')
    if not verify_entries(audit.entries):
        raise RuntimeError('Cadena inválida')
    print(f'Evidencia: {output}; cadena JSON verificada (002 SQLite pendiente)')


if __name__ == '__main__':
    main()
