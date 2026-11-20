"""HTTP del laboratorio: un GET, IP fijada, sin seguir redirecciones."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from harness.adapters.common import RedirectPolicy, Runner, validate_target
from harness.adapters.recon_common import LIMITER, RateLimiter, checked_target, pinned_ip, profile_for
from harness.asset_graph import normalize_asset
from harness.contracts import Action, Phase, ScopeToken

def build_argv(target: str, profile: dict[str, Any]) -> list[str]:
    p = profile_for('httpx', profile)
    target = validate_target(target)
    return ['httpx', '-u', 'http://' + target, '-json', '-silent', '-duc', '-no-stdin',
            '-nfs', '-t', '1', '-retries', '0', '-rl', str(p['rate_limit_rps']),
            '-timeout', str(p['timeout_s']), '-location', '-tech-detect', '-rstr', '65536']

def _execute(argv: list[str], timeout: int) -> str:
    # Config vacía y entorno sin proxy: la configuración externa no puede ampliar argv.
    env = {k: v for k, v in os.environ.items() if 'proxy' not in k.lower()}
    with tempfile.TemporaryDirectory(prefix='ptaas-httpx-') as directory:
        config = Path(directory) / 'httpx.yaml'
        config.write_text('{}\n', encoding='utf-8')
        proc = subprocess.run([*argv, '-config', str(config)], shell=False, check=True,
                              capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, env=env, cwd=directory)
        return proc.stdout

class HttpxProbe:
    name = 'httpx.probe'
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, runner: Runner | None = None, profile: dict[str, Any] | None = None,
                 limiter: RateLimiter = LIMITER, capture=None):
        self.runner = runner
        self.capture = capture
        self.profile = profile_for('httpx', profile)
        self.limiter = limiter

    def run(self, action: Action, target: str, token: ScopeToken) -> dict[str, Any]:
        def error(code: str) -> dict[str, Any]:
            return {'status': 'ERROR', 'error': code, 'assets': [], 'capability': self.name}
        try:
            target = checked_target(target, token)
            if action.name != self.name or action.phase != Phase.RECON:
                return error('authorization')
            pinned = pinned_ip(target, token) if self.runner is None else target
            argv = build_argv(pinned, self.profile)
            if target == 'juiceshop.lab.test':
                argv[argv.index('-u') + 1] += ':3000'
            if pinned != target:
                argv.extend(['-H', 'Host: ' + target])
            self.limiter.wait(target, self.profile['rate_limit_rps'])
            if not token.is_live():
                return error('authorization')
            raw = (self.runner or _execute)(argv, self.profile['timeout_s'])
            if self.capture:
                self.capture(argv, raw)
            if not raw.strip():
                return error('empty_output')
            assets, blocked, redirects = [], [], []
            for line in raw.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                url = urlsplit(item['url'])
                if url.scheme not in ('http', 'https') or url.username or url.password or url.hostname not in {target, pinned}:
                    raise ValueError('URL de respuesta inválida')
                if item.get('failed'):
                    return error('probe_failed')
                assets.append(normalize_asset({'type': 'host', 'address': target,
                                               'source_tool': self.name, 'technologies': item.get('tech', [])}))
                location = item.get('location')
                if location:
                    if not isinstance(location, str):
                        raise ValueError('Location inválida')
                    try:
                        destination = RedirectPolicy(token.allowed_domains).check(
                            'http://' + target + (':3000' if target == 'juiceshop.lab.test' else ''), location)
                        checked_target(urlsplit(destination).hostname or '', token)
                    except ValueError:
                        blocked.append(location)
                    else:
                        redirects.append(destination)
            return {'status': 'OK', 'assets': assets, 'blocked_redirects': blocked,
                    'redirects': redirects, 'target': target, 'capability': self.name}
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
