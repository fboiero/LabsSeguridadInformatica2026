"""Publicador opcional a DefectDojo; fail-closed y nunca con credenciales fijas."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .reporting import ReportError, verify_approval


class DefectDojoError(RuntimeError):
    pass


def publish(report: dict[str, Any], base_url: str | None = None, token: str | None = None,
            *, approved_sha256: str | None = None, opener: Any = urllib.request.urlopen) -> dict[str, Any]:
    endpoint = base_url or os.environ.get("DEFECTDOJO_URL")
    api_token = token or os.environ.get("DEFECTDOJO_API_TOKEN")
    if not endpoint or not api_token:
        raise DefectDojoError("defectdojo_instance_or_token_missing")
    try:
        verify_approval(report, approved_sha256)
    except ReportError as error:
        raise DefectDojoError(f"approval_blocked: {error}") from None
    payload = {"engagement": report["engagement"], "findings": report["findings"],
               "source_report_sha256": report["report_sha256"]}
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/v2/import-scan/",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": f"Token {api_token}", "Content-Type": "application/json"})
    try:
        with opener(request, timeout=20) as response:
            if response.status not in {200, 201, 202}:
                raise DefectDojoError(f"defectdojo_http_{response.status}")
            return {"state": "PUBLISHED", "status": response.status,
                    "body": response.read(4096).decode("utf-8", "replace")}
    except urllib.error.URLError as error:
        raise DefectDojoError("defectdojo_unreachable") from error
