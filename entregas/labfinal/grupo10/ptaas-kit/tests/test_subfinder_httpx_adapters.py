"""Tests de adaptadores de recon `subfinder.enum` y `httpx.probe` (Change 004)."""
from __future__ import annotations

import json
import subprocess

import pytest

from harness.adapters.common import InvalidTarget, RateLimiter
from harness.adapters.httpx_adapter import (
    HttpxProbe,
    RateLimitExceeded,
    ToolExecutionError,
)
from harness.adapters.httpx_adapter import (
    build_argv as httpx_argv,
)
from harness.adapters.subfinder_adapter import (
    AdapterOutputError,
    SubfinderEnum,
)
from harness.adapters.subfinder_adapter import (
    build_argv as subfinder_argv,
)
from harness.contracts import Phase
from tests.conftest import act, make_token


def test_subfinder_argv_fijo_y_validacion_target():
    argv = subfinder_argv("dvwa.lab.test")
    assert argv == ["subfinder", "-d", "dvwa.lab.test", "-silent", "-oJ"]
    with pytest.raises(InvalidTarget):
        subfinder_argv("dvwa.lab.test; id")


def test_subfinder_parsea_jsonl_y_filtra_hosts_validos():
    raw = (
        '{"host":"dvwa.lab.test","input":"dvwa.lab.test","source":"crtsh"}\n'
        '{"host":"APP.DVWA.LAB.TEST.","input":"dvwa.lab.test","source":"dns"}\n'
    )
    adapter = SubfinderEnum(runner=lambda argv, timeout: raw)
    out = adapter.run(act("subfinder.enum", Phase.RECON), "dvwa.lab.test", make_token(domains=("dvwa.lab.test",)))
    assert out["tool"] == "subfinder"
    assert out["hosts"] == ["app.dvwa.lab.test", "dvwa.lab.test"]


def test_subfinder_rechaza_salida_json_malformada():
    adapter = SubfinderEnum(runner=lambda argv, timeout: "{esto-no-es-json")
    with pytest.raises(AdapterOutputError):
        adapter.run(act("subfinder.enum", Phase.RECON), "dvwa.lab.test", make_token(domains=("dvwa.lab.test",)))


def test_httpx_argv_fijo_y_rechazo_credenciales():
    argv = httpx_argv("http://juiceshop.lab.test:3000")
    assert argv == ["httpx", "-u", "http://juiceshop.lab.test:3000", "-silent", "-json"]
    with pytest.raises(InvalidTarget):
        httpx_argv("http://user:pass@juiceshop.lab.test:3000")


def test_httpx_parsea_salida_jsonl_y_aplica_rate_limit():
    calls = []
    tick = [0.0]

    def runner(argv, timeout):
        calls.append(argv)
        return json.dumps({
            "url": "http://dvwa.lab.test",
            "host": "dvwa.lab.test",
            "status_code": 200,
            "tech": ["Apache", "PHP"],
        })

    adapter = HttpxProbe(
        runner=runner,
        rate_limiter=RateLimiter(rps=2),
        clock=lambda: tick[0],
    )
    tok = make_token(domains=("dvwa.lab.test",))
    action = act("httpx.probe", Phase.RECON)
    out1 = adapter.run(action, "dvwa.lab.test", tok)
    out2 = adapter.run(action, "dvwa.lab.test", tok)
    assert out1["status_code"] == 200 and out2["tech"] == ["Apache", "PHP"]
    with pytest.raises(RateLimitExceeded):
        adapter.run(action, "dvwa.lab.test", tok)
    assert len(calls) == 2


def test_adaptador_maneja_timeout_y_binario_ausente():
    def missing_runner(argv, timeout):
        raise FileNotFoundError("httpx not found")

    def timeout_runner(argv, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    tok = make_token(domains=("dvwa.lab.test",))
    action = act("httpx.probe", Phase.RECON)
    with pytest.raises(ToolExecutionError):
        HttpxProbe(runner=missing_runner).run(action, "dvwa.lab.test", tok)
    with pytest.raises(ToolExecutionError):
        HttpxProbe(runner=timeout_runner).run(action, "dvwa.lab.test", tok)
