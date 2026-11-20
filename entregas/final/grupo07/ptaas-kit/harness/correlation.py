"""Correlación determinista de activos con snapshots locales y evidencia trazable."""
from __future__ import annotations

import hashlib

from harness.adapters.feed_adapter import LookupAction
from harness.contracts import Harness, Phase, ScopeToken
from harness.schemas import Asset, CandidateFinding, dedupe


class Correlator:
    def __init__(self, harness: Harness):
        self.harness = harness

    def correlate(self, assets: list[Asset], token: ScopeToken) -> list[CandidateFinding]:
        if token.phase != Phase.CORRELATE:
            raise ValueError("correlación requiere un token CORRELATE")
        candidates: list[CandidateFinding] = []
        for asset in assets:
            for technology in asset.technologies:
                match = self.harness.invoke(
                    "correlation",
                    LookupAction("cve.lookup", Phase.CORRELATE, query=technology),
                    asset.address,
                    token,
                )["record"]
                if match is None:
                    continue
                cwe_result = self.harness.invoke(
                    "correlation",
                    LookupAction("cwe.map", Phase.CORRELATE, query=match.get("cwe") or ""),
                    asset.address,
                    token,
                )
                epss_result = self.harness.invoke(
                    "correlation",
                    LookupAction("epss.lookup", Phase.CORRELATE, query=match["cve"]),
                    asset.address,
                    token,
                )
                refs = [f"asset:{asset.id}", f"technology:{technology}",
                        f"nvd:{match['cve']}@{match['url']}"]
                if epss_result["record"] is not None:
                    refs.append(f"epss:{match['cve']}@{epss_result['snapshot']['as_of']}")
                key = f"{asset.id}:{match['cve']}"
                finding_id = "finding-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
                candidates.append(CandidateFinding(
                    id=finding_id,
                    asset_id=asset.id,
                    cwe=cwe_result["cwe"],
                    cve=match["cve"],
                    epss=epss_result["score"],
                    attack_technique=cwe_result["attack_technique"],
                    evidence_refs=refs,
                    confidence="high",
                    cvss_v4_score=match.get("cvss_v4_score"),
                ))
        return dedupe(candidates)
