"""Análisis real del recorrido (change 008, P5): loop B de P4 con ZAP baseline.

- Ejecuta `run_detection_p4` (P4) sin cambios, por `Harness.invoke`, una vez por
  activo relevado. El "candidato" del loop B es el activo que confirmó el recon.
- Convierte alertas de ZAP en hallazgos: título, CWE y remediación salen de ZAP;
  el vector CVSS v4.0 y la verificación del catálogo, de una tabla de mapeo
  aprobada por una persona (`harness/zap_mapping.yaml`).
- Rechaza reportes con instancias fuera del objetivo.

Decisiones: openspec/changes/008-analisis-real-en-recorrido/design.md
"""
from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from harness.contracts import ScopeToken
from harness.detection_runner_p4 import run_detection_p4
from harness.poc.catalog import _PATH_RE, AGENT_APPROVERS, load_catalog
from harness.reporting import MissingField
from harness.reporting_p3 import validate_cvss4

MAPPING_PATH = Path(__file__).resolve().parent / "zap_mapping.yaml"
NO_POC = "NINGUNA"      # sin verificación en el catálogo → "no validado"
_MAX_REMEDIATION = 500


class ZapMappingError(ValueError):
    """La tabla de mapeo no es válida o no está aprobada por una persona."""


class ZapScopeError(ValueError):
    """El reporte de ZAP incluye instancias fuera del objetivo analizado."""


class AnalysisBlocked(Exception):
    """El loop B no terminó (pendiente de aprobación, bloqueado o abortado)."""

    def __init__(self, status: str, reason: str):
        super().__init__(f"{status}: {reason}")
        self.status, self.reason = status, reason


@dataclass(frozen=True)
class MappingEntry:
    poc_id: str | None
    cvss_v4_vector: str
    rationale: str


@dataclass(frozen=True)
class ZapMapping:
    approved_by: str
    approved_at: str
    entries: Mapping[str, MappingEntry]


def load_mapping(path: Path = MAPPING_PATH, *, require_approval: bool = True) -> ZapMapping:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    approved_by = str(data.get("approved_by") or "").strip()
    approved_at = str(data.get("approved_at") or "").strip()
    if require_approval:
        if not approved_by or not approved_at:
            raise ZapMappingError("la tabla de mapeo requiere approved_by y approved_at "
                                  "de la persona que la revisó")
        if approved_by.lower() in AGENT_APPROVERS:
            raise ZapMappingError("la aprobación de la tabla de mapeo debe ser humana, "
                                  "no de un agente")
    plugins = data.get("plugins")
    if not isinstance(plugins, Mapping) or not plugins:
        raise ZapMappingError("la tabla de mapeo no tiene plugins")
    catalog = load_catalog()
    entries: dict[str, MappingEntry] = {}
    for pid, raw in plugins.items():
        pid = str(pid)
        if not isinstance(raw, Mapping):
            raise ZapMappingError(f"plugin {pid}: entrada inválida")
        vector = str(raw.get("cvss_v4_vector") or "")
        try:
            validate_cvss4(vector)
        except MissingField as exc:
            raise ZapMappingError(f"plugin {pid}: vector CVSS v4.0 inválido ({exc})") from exc
        poc = raw.get("poc_id")
        if poc is not None and str(poc) not in catalog:
            raise ZapMappingError(f"plugin {pid}: {poc} no está en el catálogo")
        rationale = str(raw.get("rationale") or "").strip()
        if not rationale:
            raise ZapMappingError(f"plugin {pid}: falta la justificación del vector")
        entries[pid] = MappingEntry(str(poc) if poc is not None else None, vector, rationale)
    return ZapMapping(approved_by, approved_at, entries)


def check_report_scope(target: str, alerts: Sequence[Mapping[str, Any]]) -> None:
    for alert in alerts:
        for inst in alert.get("instances") or []:
            host = urlsplit(str(inst.get("uri", ""))).hostname
            if host and host.lower() != target.lower():
                raise ZapScopeError(f"el reporte de ZAP para {target} incluye {host}")


def _clean(text: Any) -> str:
    plain = re.sub(r"<[^>]+>", " ", html.unescape(str(text or "")))
    return " ".join(plain.split())


def _path(target: str, instances: Any) -> str:
    for inst in instances or []:
        parts = urlsplit(str(inst.get("uri", "")))
        if (parts.hostname or "").lower() == target.lower():
            path = parts.path or "/"
            if _PATH_RE.match(path) and ".." not in path.split("/"):
                return path
    return "/"


def findings_from_alerts(target: str, alerts: Sequence[Mapping[str, Any]],
                         mapping: ZapMapping) -> tuple[list[dict[str, Any]],
                                                       list[dict[str, Any]]]:
    """Devuelve (candidatos, descartadas). Nunca completa un dato que ZAP no trae."""
    check_report_scope(target, alerts)
    candidates: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []
    prefix = target.split(".")[0].upper()
    for alert in alerts:
        pid = str(alert.get("pluginid", ""))
        try:
            risk = int(alert.get("riskcode", 0))
        except (TypeError, ValueError):
            risk = 0
        if risk < 1:
            continue                      # informativa: no es un hallazgo
        name = _clean(alert.get("name"))[:200]
        entry = mapping.entries.get(pid)
        if entry is None:
            discarded.append({"pluginid": pid, "name": name, "risk": risk,
                              "reason": "sin mapeo aprobado: no hay vector CVSS evaluado"})
            continue
        try:
            cwe_id = int(alert.get("cweid", -1))
        except (TypeError, ValueError):
            cwe_id = -1
        remediation = _clean(alert.get("solution"))[:_MAX_REMEDIATION]
        if cwe_id < 1 or not remediation:
            discarded.append({"pluginid": pid, "name": name, "risk": risk,
                              "reason": "la alerta de ZAP no trae CWE o remediación"})
            continue
        candidates.append({
            "id": f"{prefix}-ZAP-{pid}", "title": name, "asset": target,
            "cwe": f"CWE-{cwe_id}", "cvss_v4_vector": entry.cvss_v4_vector,
            "remediation": remediation, "poc_id": entry.poc_id,
            "path": _path(target, alert.get("instances")),
            "pluginid": pid, "risk": risk, "source": "zap",
        })
    return candidates, discarded


class ZapAnalysis:
    """Análisis real: loop B de P4 con ZAP baseline, por Harness.invoke."""

    provenance = "real"
    requires_harness = True

    def __init__(self, mapping_path: Path = MAPPING_PATH, *, require_approval: bool = True):
        self.mapping_path = Path(mapping_path)
        self.require_approval = require_approval

    def mapping(self) -> ZapMapping:
        return load_mapping(self.mapping_path, require_approval=self.require_approval)

    def cvss_source(self) -> str:
        m = self.mapping()
        return (f"asignado por el analista: tabla {self.mapping_path.name} aprobada por "
                f"{m.approved_by} el {m.approved_at}; no proviene de NVD (sin CVE)")

    def run(self, harness: Any, token: ScopeToken, assets: set[str], *,
            evidence: Any) -> list[dict[str, Any]]:
        mapping = self.mapping()          # falla antes de ejecutar ZAP si no está aprobada
        candidates: list[dict[str, Any]] = []
        for host in sorted(assets):
            run = run_detection_p4(harness, token, host, candidate_count=1,
                                   capabilities=frozenset({"zap.baseline_scan"}))
            evidence.append({"event": "stage.analysis.zap", "engagement": token.engagement_id,
                             "asset": host, "status": run.status, "reason": run.reason,
                             "rounds": run.rounds, "alerts": len(run.evidence)})
            if run.status not in ("STOP_COMPLETE", "STOP_INCONCLUSIVE"):
                raise AnalysisBlocked(run.status, run.reason)
            alerts = [e["observation"] for e in run.evidence]
            found, discarded = findings_from_alerts(host, alerts, mapping)
            for item in discarded:
                evidence.append({"event": "analysis.discarded",
                                 "engagement": token.engagement_id, "asset": host, **item})
            candidates.extend(found)
        return candidates
