"""Publicador opcional a DefectDojo; fail-closed y nunca con credenciales fijas."""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from .reporting import ReportError, verify_approval


class DefectDojoError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def publish(report: dict[str, Any], base_url: str | None = None, token: str | None = None,
            *, approved_sha256: str | None = None, engagement_id: int | None = None,
            opener: Any = None) -> dict[str, Any]:
    endpoint = base_url or os.environ.get("DEFECTDOJO_URL")
    api_token = token or os.environ.get("DEFECTDOJO_API_TOKEN")
    if not endpoint or not api_token:
        raise DefectDojoError("defectdojo_instance_or_token_missing")
    try:
        verify_approval(report, approved_sha256)
    except ReportError as error:
        raise DefectDojoError(f"approval_blocked: {error}") from None
    target = str(engagement_id if engagement_id is not None else os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", ""))
    if not re.fullmatch(r"[1-9][0-9]*", target):
        raise DefectDojoError("defectdojo_engagement_required")
    try:
        url = urlsplit(endpoint)
        local_http = url.scheme == "http" and url.hostname in {"127.0.0.1", "::1"}
        if (not url.hostname or url.username is not None or url.query or url.fragment
                or (url.scheme != "https" and not local_http)):
            raise ValueError
    except ValueError:
        raise DefectDojoError("defectdojo_invalid_url") from None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", api_token):
        raise DefectDojoError("defectdojo_invalid_token")
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect()).open
    payload = {"engagement": report["engagement"], "findings": [
        {**item, "description": item["remediation"], "severity": "Info",
         "active": False, "verified": False} for item in report["findings"]],
        "source_report_sha256": report["report_sha256"]}
    boundary = uuid4().hex
    chunks = []
    fields = {"engagement": target, "scan_type": "Generic Findings Import", "minimum_severity": "Info",
              "active": "false", "verified": "false", "close_old_findings": "false", "push_to_jira": "false"}
    for key, value in fields.items():
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n')
    chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="report.json"\r\n'
                  f'Content-Type: application/json\r\n\r\n{json.dumps(payload)}\r\n--{boundary}--\r\n')
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/v2/import-scan/",
        data="".join(chunks).encode(), method="POST",
        headers={"Authorization": f"Token {api_token}", "Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with opener(request, timeout=20) as response:
            if response.status not in {200, 201, 202}:
                raise DefectDojoError(f"defectdojo_http_{response.status}")
            return {"state": "PUBLISHED", "status": response.status,
                    "body": response.read(4096).decode("utf-8", "replace")}
    except urllib.error.HTTPError as error:
        raise DefectDojoError(f"defectdojo_http_{error.code}") from None
    except (urllib.error.URLError, TimeoutError):
        raise DefectDojoError("defectdojo_unreachable") from None
