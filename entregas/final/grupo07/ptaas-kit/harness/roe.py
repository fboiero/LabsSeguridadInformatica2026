"""Rules of Engagement (RoE): modelo y parser con validaciones fuertes (change 003).

Un RoE es el documento firmado que autoriza el engagement. Este módulo lo
convierte de YAML a un objeto inmutable y RECHAZA, con un error explicativo,
cualquier RoE incompleto o peligroso antes de que exista un solo token.

Formato (ver `roe/roe-lab.example.yaml`):

    engagement_id: eng-lab-001
    scope:
      cidrs: [10.99.0.0/28]
      domains: [dvwa.lab.test, juiceshop.lab.test]
    exclusions:
      cidrs: [10.99.0.5/32]
      domains: []
    window:
      start: "2026-11-20T09:00:00-03:00"   # ISO-8601 con zona horaria obligatoria
      end:   "2026-11-20T18:00:00-03:00"
    phases: [recon, correlate, analyze, validate, report]
    emergency_contacts:
      - {name: "Docente", channel: "mail@ejemplo.test"}
    approver: {name: "Reviewer", role: reviewer, approved_at: "2026-11-20T08:30:00-03:00"}

Decisiones (detalle en openspec/changes/003-roe-and-tokens/design.md):
  * Toda fecha se pasa a UTC (epoch); una fecha sin zona horaria se rechaza (A7).
  * El alcance debe caer dentro de `targets` de `profiles.yaml`: un /8 o
    0.0.0.0/0 se rechaza (A8).
  * Las exclusiones prevalecen: si anulan todo el alcance, el RoE se rechaza.
  * La aprobación se representa con aprobador + rol + fecha, y el RoE se
    identifica por la huella SHA-256 de su contenido canónico.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from harness.contracts import Phase

_DIR = Path(__file__).resolve().parent
REQUIRED_FIELDS = ("engagement_id", "scope", "window", "phases",
                   "emergency_contacts", "approver")
APPROVER_ROLE = "reviewer"          # coincide con gates_hitl de policy.yaml


class RoEError(ValueError):
    """RoE inválido. El mensaje explica qué campo falla y por qué."""


@dataclass(frozen=True)
class RoE:
    engagement_id: str
    scope_cidrs: tuple[str, ...]
    scope_domains: tuple[str, ...]
    excluded_cidrs: tuple[str, ...]
    excluded_domains: tuple[str, ...]
    window_start: float              # epoch UTC
    window_end: float                # epoch UTC
    phases: tuple[Phase, ...]
    emergency_contacts: tuple[dict, ...]
    approver: dict
    fingerprint: str                 # SHA-256 del contenido canónico

    def authorizes(self, phase: Phase) -> bool:
        return phase in self.phases


# --------------------------------------------------------------------------- utilidades

def load_lab_targets(path: Path = _DIR / "profiles.yaml") -> dict:
    """Alcance máximo permitido en el laboratorio (`targets` de profiles.yaml)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    t = data["targets"]
    return {"cidrs": tuple(t["lab_only_cidrs"]), "domains": tuple(t["lab_only_domains"])}


def _norm_domain(d: str) -> str:
    return str(d).strip().lower().rstrip(".")


def _to_utc_epoch(value, field: str) -> float:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).strip())
        except ValueError as exc:
            raise RoEError(f"{field}: '{value}' no es una fecha ISO-8601 válida") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise RoEError(f"{field}: '{value}' no tiene zona horaria; "
                       "usá un offset explícito (p. ej. -03:00 o Z)")
    return dt.astimezone(timezone.utc).timestamp()


def _parse_networks(values, field: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for v in values or []:
        try:
            nets.append(ipaddress.ip_network(str(v).strip(), strict=True))
        except ValueError as exc:
            raise RoEError(f"{field}: '{v}' no es un CIDR válido ({exc})") from exc
    return nets


def _fingerprint(data: dict) -> str:
    canon = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- parser

def parse_roe(source: str | Path | dict, lab_targets: dict | None = None) -> RoE:
    """Valida y devuelve un RoE. Lanza RoEError con un mensaje explicativo."""
    if isinstance(source, dict):
        data = source
    else:
        text = Path(source).read_text(encoding="utf-8") if isinstance(source, Path) else source
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RoEError(f"el RoE no es YAML válido: {exc}") from exc
    if not isinstance(data, dict):
        raise RoEError("el RoE debe ser un mapa YAML con los campos obligatorios")

    faltan = [f for f in REQUIRED_FIELDS if not data.get(f)]
    if faltan:
        raise RoEError(f"faltan campos obligatorios: {', '.join(faltan)}")

    lab = lab_targets or load_lab_targets()
    lab_nets = _parse_networks(lab["cidrs"], "profiles.targets.lab_only_cidrs")
    lab_domains = {_norm_domain(d) for d in lab["domains"]}

    # --- alcance
    scope = data["scope"] if isinstance(data["scope"], dict) else {}
    scope_nets = _parse_networks(scope.get("cidrs"), "scope.cidrs")
    scope_domains = [_norm_domain(d) for d in scope.get("domains") or []]
    if not scope_nets and not scope_domains:
        raise RoEError("scope: el alcance está vacío; declarar al menos un CIDR o dominio")
    for net in scope_nets:
        if not any(net.version == lab.version and net.subnet_of(lab) for lab in lab_nets):
            raise RoEError(f"scope.cidrs: {net} excede el alcance permitido en el laboratorio "
                           f"({', '.join(map(str, lab_nets))}); un CIDR amplio no se acepta")
    for d in scope_domains:
        if d not in lab_domains:
            raise RoEError(f"scope.domains: '{d}' no es un host del laboratorio "
                           f"({', '.join(sorted(lab_domains))})")

    # --- exclusiones (prevalecen sobre el alcance)
    excl = data.get("exclusions") or {}
    excl_nets = _parse_networks(excl.get("cidrs"), "exclusions.cidrs")
    excl_domains = [_norm_domain(d) for d in excl.get("domains") or []]
    for d in excl_domains:
        for s in scope_domains:
            if d != s and d.endswith("." + s):
                raise RoEError(f"exclusions.domains: '{d}' es subdominio de '{s}'; un token no "
                               "puede expresar esa excepción. Listá en scope los hosts exactos")
    remaining_nets = [n for n in scope_nets if not any(n.subnet_of(e) for e in excl_nets
                                                         if e.version == n.version)]
    remaining_domains = [d for d in scope_domains if d not in excl_domains]
    if not remaining_nets and not remaining_domains:
        raise RoEError("exclusions: las exclusiones anulan todo el alcance; no queda nada autorizado")

    # --- ventana (UTC)
    window = data["window"] if isinstance(data["window"], dict) else {}
    if "start" not in window or "end" not in window:
        raise RoEError("window: se requieren 'start' y 'end'")
    start = _to_utc_epoch(window["start"], "window.start")
    end = _to_utc_epoch(window["end"], "window.end")
    if end <= start:
        raise RoEError("window: la ventana está invertida o vacía (end debe ser posterior a start)")

    # --- fases
    try:
        phases = tuple(Phase(str(p).strip().lower()) for p in data["phases"])
    except ValueError as exc:
        validas = ", ".join(p.value for p in Phase)
        raise RoEError(f"phases: fase desconocida ({exc}); válidas: {validas}") from exc

    # --- contactos y aprobación
    contacts = data["emergency_contacts"]
    if not isinstance(contacts, list) or not all(isinstance(c, dict) and c.get("name")
                                                 and c.get("channel") for c in contacts):
        raise RoEError("emergency_contacts: cada contacto necesita 'name' y 'channel'")
    approver = data["approver"]
    if not isinstance(approver, dict) or not approver.get("name"):
        raise RoEError("approver: falta el nombre de quien aprueba el RoE")
    if approver.get("role") != APPROVER_ROLE:
        raise RoEError(f"approver.role: debe ser '{APPROVER_ROLE}' (gate HITL de policy.yaml)")
    if "approved_at" not in approver:
        raise RoEError("approver.approved_at: falta la fecha de aprobación")
    approved_at = _to_utc_epoch(approver["approved_at"], "approver.approved_at")
    if approved_at > end:
        raise RoEError("approver.approved_at: la aprobación es posterior al fin de la ventana")

    return RoE(
        engagement_id=str(data["engagement_id"]).strip(),
        scope_cidrs=tuple(str(n) for n in scope_nets),
        scope_domains=tuple(scope_domains),
        excluded_cidrs=tuple(str(n) for n in excl_nets),
        excluded_domains=tuple(excl_domains),
        window_start=start,
        window_end=end,
        phases=phases,
        emergency_contacts=tuple(contacts),
        approver=dict(approver),
        fingerprint=_fingerprint(data),
    )
