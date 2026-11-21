"""Correlación de inventario RECON con snapshots locales, SIN sondear activos.

Contrato conservador: coincidencia literal de 'producto/version' en tecnologías.
Una coincidencia es candidata, nunca prueba explotabilidad ni confirma un hallazgo.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from harness.asset_graph import AssetGraph
from harness.cwe_mapping import TaxonomyMapping, normalize_taxonomy
from harness.epss_snapshot import EPSSSnapshot
from harness.nvd_snapshot import NVDSnapshot
from harness.schemas import CandidateFinding, dedupe

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")


def correlate_assets(
    graph: AssetGraph,
    nvd: NVDSnapshot,
    epss: EPSSSnapshot | None = None,
    *,
    mappings: Mapping[str, TaxonomyMapping] | None = None,
) -> list[CandidateFinding]:
    """Crea candidatos únicamente ante coincidencia exacta y snapshots vigentes.

    Se exige un `AssetGraph` existente con identidad y procedencia para cada activo.
    Sin snapshot NVD vigente, o sin producto+versión, no hay candidato por CVE.
    EPSS obsoleto no aporta puntuaciones: se conserva None.
    """
    if nvd.status != "current":
        return []
    catalog = mappings if mappings is not None else {}
    candidates: list[CandidateFinding] = []
    for asset_id, asset in sorted(graph.assets.items()):
        if not isinstance(asset, dict) or asset.get("id") != asset_id:
            continue
        source = asset.get("source_tool")
        technologies = asset.get("technologies")
        if not isinstance(source, str) or not source.strip() or not isinstance(technologies, list):
            continue
        detected = {item.casefold() for item in technologies if isinstance(item, str)}
        for cve_id, record in sorted(nvd.records.items()):
            if not _CVE.fullmatch(cve_id):
                continue
            product, version = record.get("product"), record.get("version")
            if not isinstance(product, str) or not isinstance(version, str):
                continue
            # Solo versiones exactas explícitas, no inferencias por nombre de producto.
            if not product.strip() or not version.strip():
                continue
            if f"{product}/{version}".casefold() not in detected:
                continue
            raw_cwe: Any = record.get("cwe", "unknown")
            cwe, attack = normalize_taxonomy(raw_cwe if isinstance(raw_cwe, str) else None, catalog)
            epss_score = (
                epss.lookup(cve_id) if epss is not None and epss.status == "current" else None
            )
            # Referencias recuperables desde los objetos de entrada (sin URLs inventadas).
            evidence = [f"asset:{graph.engagement_id}:{asset_id}", f"nvd:{nvd.sha256}:{cve_id}"]
            if epss_score is not None and epss is not None:
                evidence.append(f"epss:{epss.sha256}:{cve_id}")
            candidates.append(
                CandidateFinding(
                    id=f"{asset_id}:{cve_id}",
                    asset_id=asset_id,
                    cve=cve_id,
                    cwe=cwe,
                    epss=epss_score,
                    attack_technique=attack,
                    evidence_refs=evidence,
                    confidence="medium",  # coincidencia exacta; no prueba de explotabilidad
                )
            )
    return dedupe(candidates)
