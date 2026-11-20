"""Revisión local de evidencia Bandit preexistente. No corre Bandit ni publica."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from .bandit_input import BanditInputError, load_report


class ReportError(ValueError):
    """No puede entregarse el borrador solicitado."""


def _encode(payload: object) -> bytes:
    return (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def create_draft(source: Path) -> bytes:
    evidence = load_report(source)
    return _encode({
        "schema_version": 1,
        "state": "PENDING_HITL",
        "source": "bandit_static_report",
        "source_sha256": evidence.source_sha256,
        "total_alerts": evidence.total_alerts,
        "included_alerts": len(evidence.alerts),
        "alerts": evidence.alerts,
        "confirmed_findings": [],
        "limitations": ["Solo evidencia estatica, sin confirmacion de vulnerabilidad o explotabilidad.",
                        "Metadatos de hasta 20 alertas; contrastar con el artefacto local original."],
    })


def export_review(source: Path, draft_path: Path, approved_sha256: str, output: Path) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", approved_sha256):
        raise ReportError("approval_digest_required")
    expected = create_draft(source)
    with draft_path.open("rb") as stream:
        draft = stream.read(len(expected) + 1)
    if draft != expected or hashlib.sha256(draft).hexdigest() != approved_sha256:
        raise ReportError("approval_or_evidence_mismatch")
    with output.open("xb") as stream:
        stream.write(_encode({"state": "EXPORTED_LOCAL", "publication": "not_published",
                              "reviewed_draft_sha256": approved_sha256, "reviewed_draft": json.loads(draft)}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    draft = commands.add_parser("draft")
    draft.add_argument("source", type=Path)
    export = commands.add_parser("export")
    export.add_argument("source", type=Path)
    export.add_argument("draft", type=Path)
    export.add_argument("output", type=Path)
    export.add_argument("--approved-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.command == "draft":
            sys.stdout.buffer.write(create_draft(args.source))
        else:
            export_review(args.source, args.draft, args.approved_sha256, args.output)
    except (BanditInputError, ReportError, OSError) as error:
        print(f"report_blocked: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
