"""Orden de técnicas de relevamiento: pasivo antes que activo (asset-discovery).

Las técnicas pasivas (consultas a fuentes de terceros, DNS pasivo) no tocan el
activo; las activas lo contactan. La spec `asset-discovery` exige agotar lo pasivo
antes de lanzar lo activo sobre un activo.
"""
from __future__ import annotations

# Capabilities que NO contactan el activo (relevamiento pasivo).
PASSIVE_CAPABILITIES: frozenset[str] = frozenset({"subfinder.enum"})
# Capabilities activas de recon (contactan el activo).
ACTIVE_CAPABILITIES: frozenset[str] = frozenset({"httpx.probe", "nmap.service_scan"})


def is_passive(capability: str) -> bool:
    """True si la capability no toca el activo. Lo desconocido se trata como activo."""
    return capability in PASSIVE_CAPABILITIES


def ordered_recon(capabilities: list[str]) -> list[str]:
    """Devuelve las pasivas primero y las activas después, de forma estable."""
    passive = [c for c in capabilities if is_passive(c)]
    active = [c for c in capabilities if not is_passive(c)]
    return passive + active


def passive_before_active(sequence: list[str]) -> bool:
    """True si ninguna técnica activa precede a una pasiva en la secuencia."""
    seen_active = False
    for capability in sequence:
        if is_passive(capability):
            if seen_active:
                return False
        else:
            seen_active = True
    return True
