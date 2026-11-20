"""P4: pruebas offline de borradores de templates y cobertura de evals.

No ejecuta Nuclei ni hace solicitudes HTTP.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DRAFT = ROOT / "templates" / "proposed_p4"


def test_cinco_templates_propuestos_no_en_allowlist() -> None:
    # Intención original (P4): ningún template propuesto entra a la allow-list sin
    # aprobación. Actualizado por P5 el 2026-11-19, cuando la segunda aprobación quedó
    # registrada: ahora se exige que cada template de P4 en la allow-list pase la
    # verificación del MANIFEST (hash + aprobación de otra persona) y sea idéntico a
    # su propuesta. Sin aprobación, verify_allowlist falla y este test también.
    from harness.nuclei_allowlist import normalized_sha256, verify_allowlist

    drafts = sorted(DRAFT.glob("*.yaml"))
    assert len(drafts) == 5
    allow = ROOT / "templates" / "allowlist"
    copied = sorted(allow.glob("p4-*.yaml"))
    if copied:
        approved = {r["archivo"] for r in verify_allowlist(allow)}
        for path in copied:
            assert path.name in approved
            assert normalized_sha256(path) == normalized_sha256(DRAFT / path.name)


@pytest.mark.parametrize("name", [
    "p4-security-header-x-content-type-options",
    "p4-security-header-x-frame-options",
    "p4-security-header-csp",
    "p4-server-header-present",
    "p4-login-form-visible",
])
def test_template_lectura_acotada_sin_redirecciones(name: str) -> None:
    data = yaml.safe_load((DRAFT / f"{name}.yaml").read_text(encoding="utf-8"))
    assert data["id"] == name
    assert data["info"]["severity"] == "info"
    assert data["info"]["tags"] in {"tech", "exposure", "misconfig", "headers", "panel"}
    assert set(data) == {"id", "info", "http"}
    assert len(data["http"]) == 1
    req = data["http"][0]
    assert req["method"] == "GET"
    assert req["redirects"] is False
    assert req["max-redirects"] == 0
    assert len(req["path"]) == 1
    assert req["path"][0] in {"{{BaseURL}}/", "{{BaseURL}}/login.php"}
    assert req["matchers-condition"] == "and"
    assert len(req["matchers"]) == 2
    assert req["matchers"][0] == {"type": "status", "status": [200]}
    assert req["matchers"][1]["type"] == "dsl"
    assert len(req["matchers"][1]["dsl"]) == 1
    assert "interactsh" not in str(data).lower()


def test_evals_adicionales_completan_diez_por_agente() -> None:
    folder = ROOT / "evals" / "cases"
    cases = [c for f in folder.glob("*.json") for c in json.loads(f.read_text(encoding="utf-8"))]
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    for agent in ("correlation", "vuln_analysis"):
        subset = [c for c in cases if c["agent"] == agent]
        assert len(subset) >= 10
        assert all("golden_output" in c and "input" in c for c in subset)


def test_rubrica_detecta_desviaciones_no_solo_golden() -> None:
    from evals.rubric import score

    case = json.loads((ROOT / "evals" / "cases" / "vuln_analysis_p4.json").read_text(encoding="utf-8"))[0]
    assert score(case, case["golden_output"]) == []
    assert score(case, {"status": "confirmed", "rationale": "confirmado sin evidencia"})

@pytest.mark.parametrize("directory", [
    "templates/proposed_p4",
    "templates/allowlist/../proposed_p4",
])
def test_nuclei_rechaza_directorio_fuera_allowlist(directory: str) -> None:
    from harness.adapters.common import load_profiles
    from harness.adapters.nuclei_adapter import build_argv

    profile = dict(load_profiles()["nuclei"])
    profile["templates_dir"] = directory

    with pytest.raises(ValueError, match="allow-list"):
        build_argv("http://dvwa.lab.test/", profile)


def test_nuclei_bloquea_templates_extra_sin_ejecutar() -> None:
    from harness.adapters.common import load_profiles
    from harness.adapters.nuclei_adapter import NucleiSafeTemplates
    from harness.contracts import Phase
    from tests.conftest import act, make_token

    profile = dict(load_profiles()["nuclei"])
    profile["fixed_args"] = [
        *profile["fixed_args"],
        "-t",
        "templates/proposed_p4",
    ]

    llamadas: list[list[str]] = []

    def fake_runner(argv: list[str], timeout: int) -> str:
        llamadas.append(argv)
        return ""

    adapter = NucleiSafeTemplates(
        runner=fake_runner,
        profile=profile,
    )

    with pytest.raises(ValueError, match="allow-list"):
        adapter.run(
            act("nuclei.safe_templates", Phase.ANALYZE),
            "http://dvwa.lab.test/",
            make_token(Phase.ANALYZE),
        )

    assert llamadas == []
