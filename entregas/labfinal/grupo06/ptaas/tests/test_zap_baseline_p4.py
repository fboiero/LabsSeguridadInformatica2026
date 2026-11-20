"""Change 005 · 3.1: contrato de ZAP baseline con runner falso.

No realiza conexiones de red ni ejecuta ZAP.
"""

from __future__ import annotations

import pytest

from harness.adapters.common import InvalidTarget
from harness.adapters.zap_adapter import ZapBaseline, build_argv
from harness.contracts import Action, Phase
from tests.conftest import make_token


def test_zap_argv_fijo_para_dvwa() -> None:
    argv = build_argv("dvwa.lab.test")
    assert isinstance(argv, list)
    assert all(isinstance(part, str) for part in argv)
    assert "http://dvwa.lab.test/" in argv
    assert not any(";" in part or "$(" in part for part in argv)


@pytest.mark.parametrize("host", [
    "example.com",
    "sub.dvwa.lab.test",
    "dvwa.lab.test;echo injected",
    "http://dvwa.lab.test/",
])
def test_zap_rechaza_target_no_permitido(host: str) -> None:
    with pytest.raises(InvalidTarget):
        build_argv(host)


def test_zap_usa_runner_inyectado_sin_shell() -> None:
    calls: list[tuple[list[str], int]] = []

    def fake_runner(argv: list[str], timeout: int) -> str:
        calls.append((argv, timeout))
        return '{"alerts": []}'

    adapter = ZapBaseline(runner=fake_runner)
    token = make_token(Phase.ANALYZE, domains=("dvwa.lab.test", "juiceshop.lab.test"))
    result = adapter.run(Action("zap.baseline_scan", Phase.ANALYZE), "dvwa.lab.test", token)
    assert len(calls) == 1
    assert isinstance(calls[0][0], list)
    assert calls[0][1] > 0
    assert result["tool"] == "zap"


def test_zap_rechaza_fase_incorrecta_antes_de_runner() -> None:
    calls: list[list[str]] = []

    def fake_runner(argv: list[str], timeout: int) -> str:
        calls.append(argv)
        return '{"alerts": []}'

    adapter = ZapBaseline(runner=fake_runner)
    token = make_token(Phase.RECON, domains=("dvwa.lab.test",))
    with pytest.raises((ValueError, PermissionError)):
        adapter.run(Action("zap.baseline_scan", Phase.RECON), "dvwa.lab.test", token)
    assert calls == []
