"""subfinder.enum: JSONL validado, sin proveedores externos habilitados en el lab."""
from __future__ import annotations

import json
import subprocess
from typing import Any

from harness.adapters.common import Runner
from harness.adapters.recon_common import LIMITER, RateLimiter, checked_target, profile_for
from harness.asset_graph import normalize_asset
from harness.contracts import Action, Phase, ScopeToken


def build_argv(target: str, profile: dict[str, Any]) -> list[str]:
    from harness.adapters.common import validate_target
    p = profile_for('subfinder', profile)
    return ['subfinder', '-d', validate_target(target), '-oJ', '-silent', '-duc',
            '-rl', str(p['rate_limit_rps']), '-timeout', str(p['timeout_s'])]


class NoPassiveSources(Exception):
    """El binario confirmó que no hay proveedores habilitados."""


class SubfinderEnum:
    name = 'subfinder.enum'
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner | None = None, profile: dict[str, Any] | None = None,
                 limiter: RateLimiter = LIMITER):
        self.runner = runner
        self.profile = profile_for('subfinder', profile)
        self.limiter = limiter

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        def error(code: str) -> dict[str, Any]:
            return {'status': 'ERROR', 'error': code, 'assets': [], 'capability': self.name}
        try:
            target = checked_target(target, token)
            if action.name != self.name or action.phase != Phase.RECON:
                return error('authorization')
            # subfinder usa proveedores pasivos externos. Ninguno se habilita por defecto.
            # runner inyectado permite capturas/simulaciones locales explícitas, nunca fallback a Internet.
            if self.runner is None:
                return error('local_source_required')
            argv = build_argv(target, self.profile)
            self.limiter.wait(target, self.profile['rate_limit_rps'])
            if not token.is_live():
                return error('authorization')
            raw = self.runner(argv, self.profile['timeout_s'])
            assets = []
            for line in raw.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                assets.append(normalize_asset({'type': 'host', 'address': item['host'],
                                               'source_tool': self.name, 'technologies': []}))
            return {'status': 'OK', 'assets': assets, 'capability': self.name, 'target': target}
        except NoPassiveSources:
            return {'status': 'UNAVAILABLE', 'reason': 'no_local_sources', 'assets': [], 'capability': self.name}
        except subprocess.TimeoutExpired:
            return error('timeout')
        except FileNotFoundError:
            return error('missing')
        except subprocess.CalledProcessError:
            return error('exit')
        except (ValueError, KeyError, TypeError, AttributeError):
            return error('schema')
        except OSError:
            return error('io')


class OfflineSubfinderRunner:
    """Ejecuta el binario real con TODOS los proveedores deshabilitados.

    .test no tiene fuentes públicas autorizadas. La enumeración nativa vacía
    se conserva como evidencia; no se fingen descubrimientos pasivos.
    Usar dentro del runner Docker aislado, desde SubfinderEnum/Harness.
    """

    def __init__(self, executor=None, capture=None):
        self.executor = executor or subprocess.run
        self.last_error = ''
        self.capture = capture

    def __call__(self, argv: list[str], timeout: int) -> str:
        import os
        import re
        import tempfile
        from pathlib import Path

        env = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
        with tempfile.TemporaryDirectory(prefix='ptaas-subfinder-') as directory:
            config = Path(directory) / 'config.yaml'
            providers = Path(directory) / 'providers.yaml'
            config.write_text('{}\n', encoding='utf-8')
            providers.write_text('{}\n', encoding='utf-8')
            extra = ['-config', str(config), '-pc', str(providers)]
            options = dict(shell=False, check=True, capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL, env=env, cwd=directory)
            catalog = self.executor(['subfinder', '-ls', '-silent', '-duc', *extra], **options)
            sources = []
            for line in catalog.stdout.splitlines():
                if not re.fullmatch(r'[a-z0-9]+(?: [*~])?', line.strip()):
                    raise ValueError('catálogo de fuentes no interpretable')
                sources.append(line.split()[0])
            if not sources:
                raise ValueError('catálogo vacío: no se puede excluir todas las fuentes')
            command = [*argv, '-es', ','.join(sorted(set(sources))), *extra]
            try:
                result = self.executor(command, **options)
            except subprocess.CalledProcessError as exc:
                self.last_error = exc.stderr or ''
                clean = re.sub(r'\x1b\[[0-9;]*m', '', self.last_error).strip()
                if exc.returncode == 1 and clean == '[FTL] No sources selected for this search':
                    if self.capture:
                        self.capture(command, exc.stdout or '')
                    raise NoPassiveSources() from exc
                raise
            if self.capture:
                self.capture(command, result.stdout)
            return result.stdout
