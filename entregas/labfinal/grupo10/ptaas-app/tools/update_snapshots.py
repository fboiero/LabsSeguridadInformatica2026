"""Descarga snapshots acotados y reproducibles de NVD y EPSS."""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CVES = ("CVE-2021-44228", "CVE-2023-4863")
ROOT = Path(__file__).resolve().parent.parent


def fetch(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "PTaaS-Grupo10/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.loads(response.read())
        if not isinstance(data, dict):
            raise TypeError("snapshot_response_not_object")
        return data


def write_snapshot(path: Path, source: str, data: dict[str, Any]) -> None:
    raw = json.dumps(data, sort_keys=True, indent=2).encode()
    payload = {"metadata": {"source": source, "fetched_at": datetime.now(UTC).isoformat(),
                             "sha256": hashlib.sha256(raw).hexdigest()}, "data": data}
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    try:
        nvd: dict[str, dict[str, Any]] = {}
        for cve in CVES:
            query = urllib.parse.urlencode({"cveId": cve})
            response = fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}")
            vulnerabilities = response.get("vulnerabilities", [])
            if vulnerabilities:
                nvd[cve] = vulnerabilities[0].get("cve", {})
        epss_response = fetch("https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": ",".join(CVES)}))
        epss = {row["cve"]: float(row["epss"]) for row in epss_response.get("data", []) if "cve" in row and "epss" in row}
        if not nvd or not epss:
            raise RuntimeError("snapshot_source_returned_no_records")
        write_snapshot(ROOT / "data/nvd-snapshot.json", "NVD CVE API 2.0", nvd)
        write_snapshot(ROOT / "data/epss-snapshot.json", "FIRST EPSS API v1", epss)
        print(json.dumps({"nvd_records": len(nvd), "epss_records": len(epss)}))
        return 0
    except (OSError, TypeError, ValueError, KeyError, RuntimeError) as error:
        print(f"snapshot_update_failed: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
