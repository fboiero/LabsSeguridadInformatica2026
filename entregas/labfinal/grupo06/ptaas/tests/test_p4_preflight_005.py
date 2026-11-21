"""Pruebas de validación estática de templates P4; sin networking."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.p4_preflight_005 import EXPECTED, PreflightError, review_one, run_preflight

ROOT = Path(__file__).resolve().parents[1]


def test_las_cinco_propuestas_pasan_preflight_sin_aprobarse() -> None:
    r = run_preflight(ROOT)
    assert r["cantidad"] == 5
    # Actualizado por P5 (2026-11-19): el estado sale de la allow-list verificada.
    hay_copias = bool(list((ROOT / "templates/allowlist").glob("p4-*.yaml")))
    assert r["aprobacion_humana"] == ("APROBADA" if hay_copias else "PENDIENTE")
    assert r["escaneo_real"] == "NO_REALIZADO"
    assert all(len(t["sha256"]) == 64 for t in r["templates"])


@pytest.mark.parametrize("filename", sorted(EXPECTED))
def test_huella_corresponde_al_archivo_original(filename: str) -> None:
    import hashlib
    p = ROOT / "templates" / "proposed_p4" / filename
    assert review_one(p)["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()


def test_rechaza_redirects_y_opciones_agregadas(tmp_path: Path) -> None:
    p = ROOT / "templates/proposed_p4/p4-security-header-csp.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    data["http"][0]["redirects"] = True
    q = tmp_path / p.name
    q.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PreflightError, match="redirecciones"):
        review_one(q)
    data["http"][0]["redirects"] = False
    data["http"][0]["payloads"] = {"p": ["bad"]}
    q.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PreflightError, match="opción http"):
        review_one(q)


def test_rechaza_matchers_diferentes(tmp_path: Path) -> None:
    p = ROOT / "templates/proposed_p4/p4-server-header-present.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    data["http"][0]["matchers"][1]["dsl"] = ["true"]
    q = tmp_path / p.name
    q.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(PreflightError, match="matchers"):
        review_one(q)


def test_rechaza_template_extrano(tmp_path: Path) -> None:
    q = tmp_path / "cualquier-template.yaml"
    q.write_text("id: ok\n", encoding="utf-8")
    with pytest.raises(PreflightError, match="fuera de lista"):
        review_one(q)
