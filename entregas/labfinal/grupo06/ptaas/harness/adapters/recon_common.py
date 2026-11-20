"""Validación y presupuesto compartido de adaptadores RECON de P3."""
from __future__ import annotations

import ipaddress
import math
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

from harness.adapters.common import load_profiles, validate_target
from harness.contracts import Guard, ScopeToken
from harness.policy_loader import load_policy


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.clock, self.sleep = clock, sleep
        self._next: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, target: str, rate: float) -> None:
        target = validate_target(target)
        with self._lock:
            now = self.clock()
            due = self._next.get(target, now)
            if target in self._last:
                due = max(due, self._last[target] + 1 / rate)
            while now < due:
                self.sleep(due - now)
                now = self.clock()
            self._next[target] = now + 1 / rate
            self._last[target] = now


LIMITER = RateLimiter()


def profile_for(name: str, profile: dict[str, Any] | None) -> dict[str, Any]:
    p = dict(load_profiles().get(name, {}) if profile is None else profile)
    if set(p) - {'rate_limit_rps', 'timeout_s'}:
        raise ValueError('perfil RECON no permite flags ni proveedores arbitrarios')
    for key in ('rate_limit_rps', 'timeout_s'):
        value = p.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError('perfil requiere rate y timeout positivos finitos')
    limit = load_policy()['limits']['rate_limit_rps_per_target']
    p['rate_limit_rps'] = min(p['rate_limit_rps'], limit)
    # Las CLI aceptan tasas enteras. Tasas menores a 1 se rechazan, no se redondean hacia arriba.
    if p['rate_limit_rps'] < 1:
        raise ValueError('rate CLI debe ser al menos 1')
    p['rate_limit_rps'] = int(p['rate_limit_rps'])
    return p


def checked_target(target: str, token: ScopeToken) -> str:
    target = validate_target(target)
    if not token.is_live() or token.phase.value != 'recon' or not Guard._in_scope(target, token):
        raise ValueError('target fuera del token')
    labs = load_profiles()['targets']
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        if not any(target == d or target.endswith('.' + d) for d in labs['lab_only_domains']):
            raise ValueError('target fuera del laboratorio')
    else:
        if not any(ip in ipaddress.ip_network(c) for c in labs['lab_only_cidrs']):
            raise ValueError('IP fuera del laboratorio')
    return target


def pinned_ip(target: str, token: ScopeToken) -> str:
    """Resolver solo nombres ya autorizados; la CLI recibe una IP, evitando segunda resolución."""
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(target, 80, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ValueError('DNS sin direcciones')
    labs = load_profiles()['targets']['lab_only_cidrs']
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not any(ip in ipaddress.ip_network(c) for c in token.allowed_cidrs):
            raise ValueError('DNS fuera del token')
        if not any(ip in ipaddress.ip_network(c) for c in labs):
            raise ValueError('DNS fuera del laboratorio')
    return addresses[0]
