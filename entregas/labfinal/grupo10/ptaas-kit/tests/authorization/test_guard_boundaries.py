"""Bloque A: todas las decisiones se observan en el límite del harness."""
import pytest

from harness.contracts import Phase, ScopeViolation
from tests.conftest import act, make_token


def assert_blocked(env, token, target):
    harness, _, audit, _, adapters = env
    with pytest.raises(ScopeViolation):
        harness.invoke('recon', act('httpx.probe', Phase.RECON), target, token)
    assert audit.entries[-1]['result'] == 'BLOCKED'
    assert audit.entries[-1]['target'] == target
    assert adapters['httpx.probe'].calls == []


def test_a1_dns_case_and_root_dot(env, token):
    harness, _, audit, _, adapters = env
    target = 'APP.LAB.EXAMPLE.TEST.'
    harness.invoke('recon', act('httpx.probe', Phase.RECON), target, token)
    assert audit.entries[-1]['result'] == 'OK'
    assert adapters['httpx.probe'].calls == [target]


def test_a2_domain_is_not_an_arbitrary_suffix(env, token):
    assert_blocked(env, token, 'app.other-lab.example.test')


def test_a3_ipv6_outside_authorized_prefix(env):
    assert_blocked(env, make_token(cidrs=('2001:db8:1::/64',)), '2001:db8:2::1')


def test_a6_previous_phase_token(env):
    assert_blocked(env, make_token(phase=Phase.ANALYZE), '10.0.0.5')


def test_a9_internal_whitespace_in_target(env, token):
    assert_blocked(env, token, 'two labels.lab.example.test')
