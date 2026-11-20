"""Utilidades comunes de adaptadores: validación de target y ejecución sin shell."""
from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

import yaml

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_PROFILES = Path(__file__).resolve().parent.parent / "profiles.yaml"


class InvalidTarget(ValueError): ...
class ForbiddenArgument(ValueError): ...


def load_profiles(path: Path = _PROFILES) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_target(target: str, allow_cidr: bool = False) -> str:
    """Acepta IP, CIDR (si allow_cidr) o hostname FQDN. Rechaza todo lo demás
    (espacios, flags que empiecen con '-', metacaracteres de shell, esquemas)."""
    t = target.strip().lower().rstrip(".")
    if not t or t.startswith("-"):
        raise InvalidTarget(f"target inválido: {target!r}")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if allow_cidr:
        try:
            ipaddress.ip_network(t, strict=False)
            return t
        except ValueError:
            pass
    if _HOST_RE.match(t):
        return t
    raise InvalidTarget(f"target inválido: {target!r}")


def validate_url(url: str) -> str:
    """Solo http(s)://host[:puerto][/ruta] sin credenciales embebidas."""
    m = re.match(r"^(https?)://([^/:@\s]+)(:\d{1,5})?(/[^\s]*)?$", url.strip())
    if not m:
        raise InvalidTarget(f"URL inválida: {url!r}")
    validate_target(m.group(2))
    return url.strip()


def reject_forbidden(argv: list[str], forbidden: list[str]) -> None:
    for a in argv:
        for f in forbidden:
            if a == f or a.startswith(f + "="):
                raise ForbiddenArgument(f"argumento prohibido: {a}")


_PARAM_KEY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
_PARAM_VALUE_PROHIBIDA = re.compile(r"[\s;&|`$<>(){}\[\]\\*?!]")


def validate_parameters(parameters: Mapping[str, Any]) -> dict[str, str]:
    """Normaliza parámetros inertes y rechaza flags, espacios o metacaracteres.

    Se aplica antes de construir argv: ningún valor del agente llega al shell ni
    se interpreta como opción de la herramienta (A9).
    """
    if not isinstance(parameters, Mapping):
        raise InvalidTarget("parameters debe ser un mapping")
    limpio: dict[str, str] = {}
    for clave, valor in parameters.items():
        if not isinstance(clave, str) or not _PARAM_KEY_RE.match(clave):
            raise InvalidTarget(f"parámetro inválido: {clave!r}")
        if isinstance(valor, bool):
            texto = "true" if valor else "false"
        elif isinstance(valor, (int, float)):
            texto = str(valor)
        elif isinstance(valor, str):
            texto = valor.strip()
        else:
            raise InvalidTarget(f"valor no escalar en el parámetro {clave!r}")
        if not texto or texto.startswith("-") or _PARAM_VALUE_PROHIBIDA.search(texto):
            raise InvalidTarget(f"valor inválido en el parámetro {clave!r}: {texto!r}")
        limpio[clave] = texto
    return limpio


def _host_permitido(host: str, allowed_domains: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed_domains)


class RedirectPolicy:
    """Decide si una redirección HTTP se puede seguir sin salir del alcance (A5).

    El adaptador HTTP debe llamar a ``check`` antes de cada salto. Una
    redirección a otro host, con credenciales embebidas o con otro esquema se
    rechaza; no se sigue a ciegas.
    """

    def __init__(self, allowed_domains: tuple[str, ...] | list[str]):
        self.allowed_domains = tuple(d.lower().rstrip(".") for d in allowed_domains)

    def _parse(self, url: str) -> SplitResult:
        try:
            partes = urlsplit(url.strip())
        except ValueError as exc:
            raise InvalidTarget(f"URL inválida: {url!r}") from exc
        if partes.scheme not in ("http", "https"):
            raise InvalidTarget(f"esquema no permitido en redirección: {partes.scheme!r}")
        if not partes.hostname:
            raise InvalidTarget(f"redirección sin host: {url!r}")
        if partes.username is not None or partes.password is not None:
            raise InvalidTarget("redirección con credenciales embebidas")
        if not _host_permitido(partes.hostname, self.allowed_domains):
            raise InvalidTarget(f"redirección fuera de alcance: {partes.hostname}")
        return partes

    def check(self, base_url: str, location: str) -> str:
        self._parse(base_url)
        destino = urljoin(base_url.strip(), location.strip())
        return self._parse(destino).geturl()


Runner = Callable[[list[str], int], str]


def default_runner(argv: list[str], timeout_s: int) -> str:
    """Ejecuta SIN shell, con timeout. Se inyecta un fake en los tests."""
    proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                          timeout=timeout_s, check=False)
    return proc.stdout
