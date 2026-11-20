import hashlib
import json
from pathlib import Path

import pytest

from harness.adapters.common import InvalidTarget
from harness.adapters.httpx_adapter import HttpxProbe
from harness.adapters.httpx_adapter import build_argv as httpx_argv
from harness.adapters.nuclei_adapter import build_argv as nuclei_argv
from harness.adapters.subfinder_adapter import SubfinderEnum
from harness.adapters.subfinder_adapter import build_argv as subfinder_argv
from harness.adapters.zap_adapter import ZapBaselineScan
from harness.adapters.zap_adapter import build_argv as zap_argv
from harness.contracts import Action, Phase
from tests.conftest import make_token

FIXTURES = Path(__file__).parent / "fixtures"


def test_subfinder_argv_usa_solo_enumeracion_pasiva_y_rate_limit():
    argv = subfinder_argv("lab.example.test")
    assert argv[0] == "subfinder"
    assert "-d" in argv and "-json" in argv and "-silent" in argv
    assert "-rl" in argv and "-duc" in argv
    assert argv[argv.index("-rl") + 1] == "5"
    assert not {"-all", "-active", "-proxy"}.intersection(argv)


def test_subfinder_parsea_jsonl_y_rechaza_linea_invalida():
    fixture = (FIXTURES / "004" / "subfinder.jsonl").read_text(encoding="utf-8")
    out = SubfinderEnum(lambda _argv, _timeout: fixture).run(
        Action("subfinder.enum", Phase.RECON), "lab.example.test", make_token())
    assert out["hosts"] == ["dvwa.lab.test", "juiceshop.lab.test"]
    with pytest.raises(ValueError):
        SubfinderEnum(lambda _argv, _timeout: '{"url":"not-a-host"}\n').run(
            Action("subfinder.enum", Phase.RECON), "lab.example.test", make_token())


def test_httpx_argv_y_salida_quedan_limitados():
    argv = httpx_argv("dvwa.lab.test")
    assert "-j" in argv and "-rl" in argv and "-timeout" in argv and "-retries" in argv
    assert "0" == argv[argv.index("-retries") + 1]
    assert argv[argv.index("-rl") + 1] == "5"
    assert not any("cloud" in arg.lower() or arg in {"-path", "-raw"} for arg in argv)
    raw = (FIXTURES / "004" / "httpx.jsonl").read_text(encoding="utf-8")
    out = HttpxProbe(lambda _argv, _timeout: raw).run(
        Action("httpx.probe", Phase.RECON), "dvwa.lab.test", make_token())
    assert out["assets"][0]["host"] == "dvwa.lab.test"
    assert out["assets"][0]["technologies"] == ["Apache", "PHP"]


def test_zap_baseline_argv_es_pasivo_y_reporte_json(tmp_path):
    profile = {"binary": "zap-baseline.py", "fixed_args": ["-m", "1"],
               "timeout_s": 120, "report_dir": str(tmp_path)}
    argv = zap_argv("dvwa.lab.example.test", profile)
    assert argv[:3] == ["zap-baseline.py", "-t", "http://dvwa.lab.example.test"]
    assert "-J" in argv and "-m" in argv
    assert "-I" not in argv


def test_zap_parsea_fixture_sin_lanzar_herramienta():
    raw_report = (FIXTURES / "005" / "zap-baseline.json").read_text(encoding="utf-8")
    def runner(argv, _timeout):
        report_path = argv[argv.index("-J") + 1]
        with open(report_path, "w", encoding="utf-8") as stream:
            stream.write(raw_report)
        return ""
    out = ZapBaselineScan(runner).run(Action("zap.baseline_scan", Phase.ANALYZE),
                                      "dvwa.lab.test", make_token(Phase.ANALYZE))
    assert out["alerts"][0]["alert"] == "X-Content-Type-Options Header Missing"


def test_nuclei_argv_solo_incluye_manifest_y_rechaza_hash_alterado(tmp_path):
    argv = nuclei_argv("dvwa.lab.test")
    assert argv.count("-t") >= 5
    assert "-ni" in argv and "-duc" in argv and "-disable-redirects" in argv
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    template = template_dir / "safe.yaml"
    template.write_text("id: safe\ninfo:\n  name: Safe\n  author: test\n  severity: info\n\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n    matchers:\n      - type: status\n        status:\n          - 200\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "templates": [{"path": "safe.yaml",
                                  "sha256": "0" * 64, "methods": ["GET"]}]}),
                        encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        nuclei_argv("dvwa.lab.test", {"templates_dir": str(template_dir),
                                      "manifest_path": str(manifest), "binary": "nuclei",
                                      "include_tags": ["headers"], "exclude_tags": ["oast"],
                                      "rate_limit_rps": 1,
                                      "fixed_args": ["-jsonl", "-silent", "-ni", "-duc"]})

    manifest.write_text(json.dumps({"version": 1, "templates": [{"path": "../outside.yaml",
                                  "sha256": "0" * 64, "methods": ["GET"]}]}),
                        encoding="utf-8")
    with pytest.raises(ValueError, match="fuera de la allow-list"):
        nuclei_argv("dvwa.lab.test", {"templates_dir": str(template_dir),
                                      "manifest_path": str(manifest), "binary": "nuclei",
                                      "include_tags": ["headers"], "exclude_tags": ["oast"],
                                      "rate_limit_rps": 1,
                                      "fixed_args": ["-jsonl", "-silent", "-ni", "-duc"]})


def test_adaptador_httpx_rechaza_target_con_flag():
    with pytest.raises(InvalidTarget):
        httpx_argv("dvwa.lab.test -A")


def test_nuclei_no_ejecuta_templates_sin_manifest_y_rechaza_post(tmp_path):
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    safe = template_dir / "safe.yaml"
    safe_text = ("id: safe\ninfo:\n  name: Safe\n  author: test\n  severity: info\n"
                 "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"
                 "    matchers:\n      - type: status\n        status:\n          - 200\n")
    safe.write_text(safe_text, encoding="utf-8")
    (template_dir / "unlisted.yaml").write_text(safe_text.replace("id: safe", "id: unlisted"),
                                                 encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "templates": [{
        "path": "safe.yaml", "sha256": hashlib.sha256(safe_text.encode()).hexdigest(),
        "methods": ["GET"],
    }]}), encoding="utf-8")
    profile = {"templates_dir": str(template_dir), "manifest_path": str(manifest),
               "binary": "nuclei", "include_tags": ["headers"], "exclude_tags": ["oast"],
               "rate_limit_rps": 1, "fixed_args": ["-jsonl", "-silent", "-ni", "-duc"]}

    argv = nuclei_argv("dvwa.lab.test", profile)
    assert argv.count("-t") == 1 and "unlisted.yaml" not in argv

    post_text = safe_text.replace("method: GET", "method: POST")
    safe.write_text(post_text, encoding="utf-8")
    manifest.write_text(json.dumps({"version": 1, "templates": [{
        "path": "safe.yaml", "sha256": hashlib.sha256(post_text.encode()).hexdigest(),
        "methods": ["GET"],
    }]}), encoding="utf-8")
    with pytest.raises(ValueError, match="perfil GET"):
        nuclei_argv("dvwa.lab.test", profile)
