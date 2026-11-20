"""Ejecutor de herramientas del harness en la red interna del laboratorio."""
from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any


class DockerToolRunner:
    def __init__(self, output: Path, network: str = 'lab_lab') -> None:
        self.root = Path.cwd().resolve()
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.network = network
        config = json.loads(subprocess.check_output(
            ['docker', 'network', 'inspect', network], text=True))[0]
        subnets = {item['Subnet'] for item in config['IPAM']['Config']}
        if not config['Internal'] or subnets != {'10.99.0.0/28'}:
            raise ValueError('se exige red interna 10.99.0.0/28 del laboratorio')
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], timeout: int) -> str:
        images = {'httpx': 'projectdiscovery/httpx:latest',
                  'subfinder': 'projectdiscovery/subfinder:latest',
                  'nuclei': 'projectdiscovery/nuclei:latest',
                  'zap-baseline.py': 'ghcr.io/zaproxy/zaproxy:stable'}
        tool, args = argv[0], list(argv[1:])
        image = images[tool]
        mounts = ['-v', str(self.root) + ':/work:ro']
        if tool == 'nuclei':
            for index, arg in enumerate(args[:-1]):
                if arg == '-t':
                    args[index + 1] = args[index + 1].replace('\\', '/')
        if tool == 'zap-baseline.py':
            report = Path(args[args.index('-J') + 1])
            args[args.index('-J') + 1] = report.name
            mounts += ['-v', str(report.parent.resolve()) + ':/zap/wrk']
        name = 'ptaas-tool-' + uuid.uuid4().hex[:12]
        command = ['docker', 'run', '--rm', '--pull=never', '--name', name,
                   '--network', self.network, '--user', '0:0', *mounts, '-w', '/work',
                   '--entrypoint', tool, image, *args]
        # subfinder -timeout limita cada fuente; -max-time limita el proceso entero.
        total_timeout = timeout + 30
        if tool == 'subfinder':
            total_timeout += int(args[args.index('-max-time') + 1]) * 60
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=total_timeout, check=False)
            self.calls.append({'argv': command, 'returncode': proc.returncode,
                               'stdout': proc.stdout, 'stderr': proc.stderr})
            (self.output / 'tool-calls.json').write_text(
                json.dumps(self.calls, indent=2), encoding='utf-8')
            allowed = {0, 1, 2} if tool == 'zap-baseline.py' else {0}
            if proc.returncode not in allowed:
                raise RuntimeError(f'{tool}: {proc.stderr}')
            return proc.stdout
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True,
                           timeout=20, check=False)
