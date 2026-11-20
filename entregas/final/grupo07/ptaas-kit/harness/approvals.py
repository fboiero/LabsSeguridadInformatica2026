"""Decisiones humanas explícitas y vinculadas al contenido; CLI local de laboratorio."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def subject_key(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


@dataclass
class ApprovalStore:
    records: list[dict[str, Any]] = field(default_factory=list)

    def decide(
        self, subject: str, decision: str, reviewer: str, reason: str, ttl: float = 900
    ) -> None:
        if decision not in {"approve", "reject"} or not reviewer.strip() or not reason.strip():
            raise ValueError("decisión, Reviewer y motivo obligatorios")
        self.records.append(
            {
                "subject": subject,
                "decision": decision,
                "reviewer": reviewer,
                "reason": reason,
                "ts": time.time(),
                "expires": time.time() + ttl,
            }
        )

    def pending(self, subject: str, label: str) -> None:
        if not any(r["subject"] == subject for r in self.records):
            self.records.append(
                {
                    "subject": subject,
                    "decision": "pending",
                    "reviewer": "",
                    "reason": label,
                    "ts": time.time(),
                    "expires": 0,
                }
            )

    def approved(self, subject: str) -> bool:
        for item in reversed(self.records):
            if item["subject"] == subject:
                return bool(item["decision"] == "approve" and time.time() < item["expires"])
        return False

    @classmethod
    def load(cls, path: Path) -> ApprovalStore:
        return cls(json.loads(path.read_text(encoding="utf-8"))) if path.exists() else cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.records, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Registro local de decisiones; no autentica identidad del Reviewer"
    )
    ap.add_argument("--store", type=Path, required=True)
    ap.add_argument("command", choices=["list", "approve", "reject"])
    ap.add_argument("--subject")
    ap.add_argument("--reviewer")
    ap.add_argument("--reason")
    args = ap.parse_args()
    store = ApprovalStore.load(args.store)
    if args.command == "list":
        print(json.dumps(store.records, ensure_ascii=False, indent=2))
        return
    if not args.subject or not args.reviewer or not args.reason:
        ap.error("--subject, --reviewer y --reason son obligatorios")
    store.decide(args.subject, args.command, args.reviewer, args.reason)
    store.save(args.store)


if __name__ == "__main__":
    main()
