"""Allow-list de Nuclei verificable (cierre de 005 · 3.2/3.3, P5).

Antes de ejecutar Nuclei, cada template de `templates/allowlist/` DEBE figurar en
`MANIFEST.md` con su SHA-256 y la segunda aprobación de una persona distinta de quien
lo propuso (plan 6.4 y regla I8). Así el manifiesto deja de ser solo documentación.

El hash se calcula con finales de línea normalizados a LF, para que la conversión a
CRLF de Git en Windows no invalide una aprobación.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from harness.poc.catalog import AGENT_APPROVERS

ALLOWLIST_DIR = Path(__file__).resolve().parent.parent / "templates" / "allowlist"
_PENDING = {"", "pendiente", "pending", "-", "—"}


class AllowlistError(ValueError):
    """La allow-list no está aprobada o no coincide con su manifiesto."""


def normalized_sha256(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _manifest_rows(manifest: Path) -> list[dict[str, str]]:
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 5 and cells[0].endswith(".yaml"):
            rows.append({"archivo": cells[0].strip("`"), "sha256": cells[1].strip("`").lower(),
                         "propuso": cells[2], "aprobo": cells[3], "fecha": cells[4]})
    return rows


def _name(person: str) -> str:
    return re.sub(r"\s*\(.*?\)\s*", "", person).strip().lower()


def verify_allowlist(directory: Path = ALLOWLIST_DIR) -> list[dict[str, Any]]:
    directory = Path(directory)
    templates = sorted(p.name for p in directory.glob("*.yaml"))
    if not templates:
        raise AllowlistError(f"la allow-list {directory} no tiene templates")
    manifest = directory / "MANIFEST.md"
    if not manifest.is_file():
        raise AllowlistError("falta MANIFEST.md en la allow-list")
    rows = {r["archivo"]: r for r in _manifest_rows(manifest)}
    for name in templates:
        row = rows.get(name)
        if row is None:
            raise AllowlistError(f"{name} está en la allow-list pero no en MANIFEST.md")
        if normalized_sha256(directory / name) != row["sha256"]:
            raise AllowlistError(f"{name}: el hash no coincide con el aprobado en MANIFEST.md")
        approver = row["aprobo"].strip()
        if approver.lower() in _PENDING or _name(approver) in AGENT_APPROVERS:
            raise AllowlistError(f"{name}: falta la segunda aprobación de una persona")
        if _name(approver) == _name(row["propuso"]):
            raise AllowlistError(f"{name}: la segunda aprobación debe ser de otra persona")
    missing = sorted(set(rows) - set(templates))
    if missing:
        raise AllowlistError(f"MANIFEST.md lista templates que no están: {missing}")
    return [rows[n] for n in templates]
