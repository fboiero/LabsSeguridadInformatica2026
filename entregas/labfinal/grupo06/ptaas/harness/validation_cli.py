"""CLI de aprobación del loop C (change 006 · 2.5). La usa una PERSONA, nunca un agente.

    python -m harness.validation_cli --store <approvals.json> list
    python -m harness.validation_cli --store <approvals.json> approve <hallazgo> --reviewer "<nombre>" --reason "<motivo>"
    python -m harness.validation_cli --store <approvals.json> reject  <hallazgo> --reviewer "<nombre>" --reason "<motivo>"
    python -m harness.validation_cli --store <approvals.json> approve-delivery <engagement> --report-hash <hash> --reviewer "<nombre>" --reason "<motivo>"

`approve` aprueba exactamente la verificación y los parámetros que muestra `list`.
Si el agente cambia algo después, la aprobación deja de valer.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from harness.audit import InMemoryAuditStore
from harness.validation import KNOWN_GATES, ApprovalStore


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m harness.validation_cli",
                                description="Aprobación humana de hallazgos del loop C")
    p.add_argument("--store", required=True, type=Path, help="archivo de aprobaciones (JSON)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="listar hallazgos pendientes")
    for name in ("approve", "reject"):
        cmd = sub.add_parser(name)
        cmd.add_argument("finding_id")
        cmd.add_argument("--reviewer", required=True, help="nombre de la persona que decide")
        cmd.add_argument("--reason", required=True, help="motivo de la decisión")
    gate = sub.add_parser("approve-gate", help="aprobar un gate del engagement (007 · 3.5)")
    gate.add_argument("engagement_id")
    gate.add_argument("gate", choices=sorted(KNOWN_GATES))
    gate.add_argument("--reviewer", required=True, help="nombre de la persona que decide")
    gate.add_argument("--reason", required=True, help="motivo de la decisión")
    dlv = sub.add_parser("approve-delivery", help="aprobar la entrega de un informe (007 · 2.6)")
    dlv.add_argument("engagement_id")
    dlv.add_argument("--report-hash", required=True, help="hash exacto del informe a entregar")
    dlv.add_argument("--reviewer", required=True, help="nombre de la persona que decide")
    dlv.add_argument("--reason", required=True, help="motivo de la decisión")
    return p


def main(argv: list[str] | None = None, *, audit: Any = None) -> int:
    args = _parser().parse_args(argv)
    # La bitácora persistente es del change 002 (P1); mientras tanto, la decisión
    # queda en el archivo de aprobaciones y en el almacén de bitácora recibido.
    store = ApprovalStore(args.store, audit=audit if audit is not None else InMemoryAuditStore())

    if args.command == "list":
        pendientes = store.pending()
        if not pendientes:
            print("No hay hallazgos pendientes.")
        for finding_id, rec in pendientes:
            print(f"{finding_id}\t{rec['poc_id']}\t{json.dumps(rec['params'], sort_keys=True)}")
        return 0

    if args.command == "approve-gate":
        try:
            store.approve_gate(args.engagement_id, args.gate,
                               reviewer=args.reviewer, reason=args.reason)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"{args.engagement_id}: gate {args.gate} aprobado por {args.reviewer}")
        return 0

    if args.command == "approve-delivery":
        try:
            store.approve_delivery(args.engagement_id, args.report_hash,
                                   reviewer=args.reviewer, reason=args.reason)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"{args.engagement_id}: entrega aprobada para {args.report_hash} por {args.reviewer}")
        return 0

    try:
        if args.command == "approve":
            store.approve_pending(args.finding_id, reviewer=args.reviewer, reason=args.reason)
        else:
            store.reject(args.finding_id, reviewer=args.reviewer, reason=args.reason)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{args.finding_id}: {store.status(args.finding_id)} por {args.reviewer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
