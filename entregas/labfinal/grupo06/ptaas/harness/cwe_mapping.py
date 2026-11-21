"""Normalización CWE/ATT&CK basada SOLO en correspondencias con procedencia.

Este módulo no incorpora ni infiere un catálogo de vulnerabilidades. El llamador
proporciona entradas revisadas; ninguna técnica ATT&CK se inventa por el CWE.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

_CWE = re.compile(r"CWE-[1-9][0-9]*\Z")
_ATTACK = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")


@dataclass(frozen=True)
class TaxonomyMapping:
    cwe: str
    attack_technique: str | None
    source: str

    def __post_init__(self) -> None:
        if not _CWE.fullmatch(self.cwe):
            raise ValueError("CWE inválido")
        if self.attack_technique is not None and not _ATTACK.fullmatch(self.attack_technique):
            raise ValueError("técnica ATT&CK inválida")
        if not self.source.strip():
            raise ValueError("un mapeo requiere fuente verificable")


def normalize_taxonomy(
    cwe: str | None,
    catalog: Mapping[str, TaxonomyMapping],
) -> tuple[str, str | None]:
    """Retorna CWE de fuente y ATT&CK solo con mapeo explícito y documentado.

    No comprobar autenticidad de la fuente aquí: corresponde a la revisión humana.
    """
    if cwe is None or cwe == "unknown" or not _CWE.fullmatch(cwe):
        return "unknown", None
    entry = catalog.get(cwe)
    if entry is None:
        # El CWE ya fue leído del registro NVD; ATT&CK no se presume.
        return cwe, None
    if entry.cwe != cwe:
        raise ValueError("clave de mapeo y CWE contradictorios")
    return cwe, entry.attack_technique
