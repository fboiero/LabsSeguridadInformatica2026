"""Scenarios 004: fakes explícitos, sin red ni aprobaciones de runtime."""
import importlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from harness.contracts import Action, AuditLog, Guard, Harness, KillSwitch, Phase, ScopeToken
from harness.policy_loader import phase_allowlist


def api(module):
    return importlib.import_module('harness.' + module)


def token():
    return ScopeToken('p3-test', ('10.99.0.0/24',), ('dvwa.lab.test', 'juiceshop.lab.test'),
                      time.time() - 10, time.time() + 60, Phase.RECON)


def asset(host='dvwa.lab.test', source='subfinder.enum', tech=()):
    return {'type': 'host', 'address': host, 'source_tool': source, 'technologies': list(tech)}


class FakeAdapter:
    allowed_phases = (Phase.RECON,)
    destructive = False

    def __init__(self, name, calls, response=None):
        self.name, self.calls, self.response = name, calls, response

    def run(self, action, target, scope):
        self.calls.append((self.name, target))
        if callable(self.response):
            return self.response(target)
        return self.response or {'status': 'OK', 'assets': [asset(target, self.name)]}


def setup_loop(passive=None, approved=True):
    calls = []
    # Precondición simulada del Scenario; no representa aprobación humana real.
    approvals = {'httpx.probe@dvwa.lab.test', 'httpx.probe@juiceshop.lab.test'} if approved else set()
    guard = Guard(phase_allowlist(), approvals=approvals, engagement_id='p3-test',
                  resolver=lambda host: ['10.99.0.2'])
    harness = Harness(guard, AuditLog(), {
        'subfinder.enum': FakeAdapter('subfinder.enum', calls, passive),
        'httpx.probe': FakeAdapter('httpx.probe', calls),
    }, KillSwitch())
    graph = api('asset_graph').AssetGraph('p3-test')
    return harness, graph, calls


def test_order_and_fixed_point(tmp_path):
    h, g, calls = setup_loop()
    result = api('loops').run_recon(h, token(), ['dvwa.lab.test', 'juiceshop.lab.test'], g,
                                  checkpoint=tmp_path / 'graph.json')
    assert [name for name, _ in calls[:4]] == ['subfinder.enum'] * 2 + ['httpx.probe'] * 2
    assert result.stop_reason == 'grafo estabilizado'
    assert result.iteration == 2
    assert len(result.assets) == 2
    assert all(e['engagement'] == 'p3-test' for e in h.audit.entries)


def test_excluded_never_reaches_adapter_or_dns():
    h, g, calls = setup_loop({'status': 'OK', 'assets': [asset(), asset('external.invalid')]})
    resolved = []
    h.guard.resolver = lambda host: resolved.append(host) or ['10.99.0.2']
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert 'external.invalid' not in resolved
    assert all(host != 'external.invalid' for _, host in calls)
    assert any(e['target'] == 'external.invalid' and e['result'] == 'BLOCKED' for e in h.audit.entries)
    assert 'external.invalid' in g.excluded


def test_gate_does_not_self_approve():
    h, g, calls = setup_loop(approved=False)
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.status == 'PENDING_HITL'
    assert all(name == 'subfinder.enum' for name, _ in calls)
    assert not h.guard._approvals


@pytest.mark.parametrize('stop', ['expired', 'kill'])
def test_stop_between_actions(stop):
    h, g, calls = setup_loop()
    t = token()
    def passive(host):
        if stop == 'kill':
            h.killswitch.engaged = True
        else:
            object.__setattr__(t, 'window_end', 0)
        return {'status': 'OK', 'assets': [asset(host)]}
    h.tools['subfinder.enum'].response = passive
    api('loops').run_recon(h, t, ['dvwa.lab.test'], g)
    assert len(calls) == 1
    assert g.status == ('ABORTED' if stop == 'kill' else 'BLOCKED')


def test_cap_survives_reload(tmp_path):
    h, g, calls = setup_loop()
    g.iteration = 5
    p = tmp_path / 'g.json'
    g.save(p)
    loaded = api('asset_graph').AssetGraph.load(p, 'p3-test')
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], loaded)
    assert calls == []
    assert loaded.stop_reason == 'tope de iteraciones alcanzado'


def test_five_iterations_with_new_assets():
    n = 0
    def passive(host):
        nonlocal n
        n += 1
        return {'status': 'OK', 'assets': [asset(f'host{n}.dvwa.lab.test')]}
    h, g, calls = setup_loop(passive)
    h.guard._approvals.update(f'httpx.probe@host{i}.dvwa.lab.test' for i in range(1, 6))
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.iteration == 5
    assert g.stop_reason == 'tope de iteraciones alcanzado'
    assert sum(name == 'subfinder.enum' for name, _ in calls) == 5


def test_invalid_passive_twice_escalates():
    h, g, calls = setup_loop({'status': 'ERROR', 'error': 'schema', 'assets': []})
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.status == 'PENDING_HITL'
    assert len(calls) == 2
    assert all(name == 'subfinder.enum' for name, _ in calls)
    assert g.stop_reason != 'grafo estabilizado'


def test_graph_merge_and_atomic_rejection(tmp_path):
    cls = api('asset_graph').AssetGraph
    g = cls('p3-test')
    assert g.add(asset('DVWA.LAB.TEST.', tech=['PHP']))
    assert not g.add(asset(tech=['Apache']))
    assert len(g.assets) == 1
    assert next(iter(g.assets.values()))['technologies'] == ['Apache', 'PHP']
    p = tmp_path / 'g.json'
    g.save(p)
    original = p.read_bytes()
    with pytest.raises(ValueError):
        g.add({'address': 'dvwa.lab.test', 'type': 'host'})
    assert p.read_bytes() == original
    assert cls.load(p, 'p3-test').assets == g.assets
    with pytest.raises(ValueError):
        cls.load(p, 'other')
    raw = json.loads(original)
    raw['schema_version'] = 99
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        cls.load(p, 'p3-test')


@pytest.mark.parametrize('module,name', [('subfinder_adapter', 'SubfinderEnum'), ('httpx_adapter', 'HttpxProbe')])
def test_adapter_argv_and_schema(module, name):
    mod = api('adapters.' + module)
    seen = []
    fixture = Path(__file__).parent / 'fixtures' / 'p3' / (module + '.jsonl')
    adapter = getattr(mod, name)(runner=lambda argv, timeout: seen.append((argv, timeout)) or fixture.read_text(),
                                 profile={'rate_limit_rps': 2, 'timeout_s': 10})
    result = adapter.run(Action(adapter.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'OK'
    assert result['assets'][0]['source_tool'] == adapter.name
    argv, timeout = seen[0]
    assert argv[0] in {'subfinder', 'httpx'}
    assert '-rl' in argv and argv[argv.index('-rl') + 1] == '2'
    assert timeout == 10
    assert not {'-fr', '-fhr', '-proxy', '-all', '-up'}.intersection(argv)


@pytest.mark.parametrize('target', ['; rm -rf /', '10.99.0.2 -A', 'evil.invalid', '-proxy', 'http://user:pass@dvwa.lab.test'])
def test_reject_target_before_runner(target):
    cls = api('adapters.httpx_adapter').HttpxProbe
    calls = []
    obj = cls(runner=lambda *args: calls.append(args), profile={'rate_limit_rps': 1, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), target, token())
    assert result['status'] == 'ERROR'
    assert not calls


@pytest.mark.parametrize('raw', ['{broken', '{"url":"http://dvwa.lab.test","tech":"PHP"}',
                                  '{"url":"http://dvwa.lab.test"}\n{broken'])
def test_partial_json_discarded(raw):
    cls = api('adapters.httpx_adapter').HttpxProbe
    obj = cls(runner=lambda *args: raw, profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'ERROR' and result['error'] == 'schema'
    assert result['assets'] == []


@pytest.mark.parametrize('failure', ['missing', 'timeout', 'exit'])
def test_execution_error_is_not_empty_success(failure):
    import subprocess
    def runner(*args):
        if failure == 'missing':
            raise FileNotFoundError()
        if failure == 'timeout':
            raise subprocess.TimeoutExpired('httpx', 10)
        raise subprocess.CalledProcessError(1, 'httpx')
    obj = api('adapters.httpx_adapter').HttpxProbe(runner=runner, profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'ERROR' and result['error'] == failure


@pytest.mark.parametrize('rate', [0, -1, float('nan'), float('inf'), True])
def test_invalid_profile(rate):
    with pytest.raises(ValueError):
        api('adapters.httpx_adapter').HttpxProbe(profile={'rate_limit_rps': rate, 'timeout_s': 10})


def test_shared_rate_limit():
    now = [0.0]
    limiter = api('adapters.recon_common').RateLimiter(clock=lambda: now[0], sleep=lambda dt: now.__setitem__(0, now[0] + dt))
    emitted = []
    for _ in range(7):
        limiter.wait('DVWA.LAB.TEST.', 5)
        emitted.append(now[0])
    assert all(b - a >= 0.199999 for a, b in zip(emitted, emitted[1:]))
    assert emitted[-1] >= 1.19


def test_redirect_external_never_followed():
    calls = []
    obj = api('adapters.httpx_adapter').HttpxProbe(
        runner=lambda *args: calls.append(args) or json.dumps({'url': 'http://dvwa.lab.test', 'location': 'https://external.invalid/'}),
        profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert len(calls) == 1
    assert result['blocked_redirects'] == ['https://external.invalid/']


def test_real_passive_is_closed_without_local_source():
    obj = api('adapters.subfinder_adapter').SubfinderEnum(profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'ERROR'
    assert result['error'] == 'local_source_required'


def test_wrong_phase_never_runs():
    h, g, calls = setup_loop()
    from harness.contracts import ScopeViolation
    with pytest.raises(ScopeViolation):
        h.invoke('recon', Action('httpx.probe', Phase.RECON), 'dvwa.lab.test', replace(token(), phase=Phase.ANALYZE))
    assert not calls


def test_shared_budget_across_adapter_instances():
    now, emitted = [0.0], []
    limiter = api('adapters.recon_common').RateLimiter(clock=lambda: now[0], sleep=lambda dt: now.__setitem__(0, now[0] + dt))
    def runner(*args):
        emitted.append(now[0])
        return '{"url":"http://dvwa.lab.test"}'
    cls = api('adapters.httpx_adapter').HttpxProbe
    for _ in range(7):
        obj = cls(runner=runner, profile={'rate_limit_rps': 50, 'timeout_s': 10}, limiter=limiter)
        assert obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())['status'] == 'OK'
    assert emitted[-1] >= 1.19  # policy=5 limita incluso un perfil más rápido


def test_real_http_pins_dns_and_drops_external_address(monkeypatch):
    common = api('adapters.recon_common')
    http = api('adapters.httpx_adapter')
    monkeypatch.setattr(common.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', ('10.99.0.2', 80))])
    calls = []
    monkeypatch.setattr(http, '_execute', lambda argv, timeout: calls.append(argv) or '{"url":"http://10.99.0.2"}')
    obj = http.HttpxProbe(profile={'rate_limit_rps': 5, 'timeout_s': 10})
    assert obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())['status'] == 'OK'
    assert 'http://10.99.0.2' in calls[0] and 'Host: dvwa.lab.test' in calls[0]
    monkeypatch.setattr(common.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', ('192.0.2.1', 80))])
    assert obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())['status'] == 'ERROR'
    assert len(calls) == 1


def test_http_empty_output_is_not_convergence():
    obj = api('adapters.httpx_adapter').HttpxProbe(runner=lambda *a: '', profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'ERROR' and result['error'] == 'empty_output'


def test_stopped_checkpoint_is_terminal():
    h, g, calls = setup_loop()
    g.status, g.stop_reason, g.iteration = 'STOPPED', 'grafo estabilizado', 2
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert not calls and g.iteration == 2


def test_local_redirect_is_inspected_without_following():
    calls = []
    obj = api('adapters.httpx_adapter').HttpxProbe(
        runner=lambda *a: calls.append(a) or '{"url":"http://dvwa.lab.test","location":"/login.php"}',
        profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['redirects'] == ['http://dvwa.lab.test/login.php']
    assert len(calls) == 1


def test_external_redirect_recorded_by_loop():
    h, g, calls = setup_loop()
    h.tools['httpx.probe'].response = {'status': 'OK', 'assets': [asset()],
                                      'blocked_redirects': ['https://external.invalid/private?secret=omitted']}
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    entries = [e for e in h.audit.entries if e['action'] == 'recon.redirect_blocked']
    assert entries and all(e['target'] == 'external.invalid' for e in entries)


@pytest.mark.parametrize('profile', [{'rate_limit_rps': 5, 'timeout_s': 0},
                                   {'rate_limit_rps': 5, 'timeout_s': 10, 'fixed_args': ['-fr']}])
def test_invalid_timeout_or_unapproved_flags(profile):
    with pytest.raises(ValueError):
        api('adapters.httpx_adapter').HttpxProbe(profile=profile)


def test_subfinder_partial_json_rejected():
    obj = api('adapters.subfinder_adapter').SubfinderEnum(
        runner=lambda *a: '{"host":"dvwa.lab.test"}\n{broken', profile={'rate_limit_rps': 5, 'timeout_s': 10})
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'ERROR' and result['assets'] == []


def test_loop_tool_error_is_recorded():
    h, g, calls = setup_loop({'status': 'ERROR', 'error': 'timeout', 'assets': []})
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.status == 'ERROR' and len(calls) == 1
    assert any(e['action'] == 'recon.error.timeout' and e['result'] == 'BLOCKED' for e in h.audit.entries)


def test_schema_hitl_is_preserved_on_resume():
    h, g, calls = setup_loop()
    g.status, g.stop_reason, g.schema_failures = 'PENDING_HITL', 'dos salidas inválidas', 2
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert not calls and g.status == 'PENDING_HITL'


def test_rate_lowered_between_calls():
    now = [0.0]
    limiter = api('adapters.recon_common').RateLimiter(clock=lambda: now[0], sleep=lambda dt: now.__setitem__(0, now[0] + dt))
    limiter.wait('dvwa.lab.test', 5)
    limiter.wait('dvwa.lab.test', 1)
    assert now[0] >= 1


def test_malformed_redirect_cannot_crash_loop(tmp_path):
    h, g, calls = setup_loop()
    h.tools['httpx.probe'].response = {'status': 'OK', 'assets': [asset()], 'blocked_redirects': ['http://[']}
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g, checkpoint=tmp_path / 'g.json')
    assert g.status == 'STOPPED'
    assert any(e['action'] == 'recon.redirect_blocked' and e['target'] == 'invalid' for e in h.audit.entries)


def test_empty_passive_still_probes_authorized_seed():
    h, g, calls = setup_loop({'status': 'OK', 'assets': []})
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert ('httpx.probe', 'dvwa.lab.test') in calls
    assert len(g.assets) == 1


def test_frontier_survives_checkpoint(tmp_path):
    h, g, calls = setup_loop()
    g.frontier = ['juiceshop.lab.test']
    g.iteration = 1
    p = tmp_path / 'g.json'
    g.save(p)
    loaded = api('asset_graph').AssetGraph.load(p, 'p3-test')
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], loaded)
    assert calls[0] == ('subfinder.enum', 'juiceshop.lab.test')


def test_native_subfinder_excludes_all_sources(tmp_path):
    from types import SimpleNamespace
    calls = []
    def executor(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout='crtsh\nhackertarget ~\n' if '-ls' in argv else '', stderr='', returncode=0)
    mod = api('adapters.subfinder_adapter')
    runner = mod.OfflineSubfinderRunner(executor=executor)
    output = runner(mod.build_argv('dvwa.lab.test', {'rate_limit_rps': 5, 'timeout_s': 10}), 10)
    assert output == ''
    assert len(calls) == 2
    argv, options = calls[-1]
    assert set(argv[argv.index('-es') + 1].split(',')) == {'crtsh', 'hackertarget'}
    assert options['shell'] is False and options['check'] is True
    assert '-config' in argv and '-pc' in argv


@pytest.mark.parametrize('catalog', ['', 'unrecognized output!', 'crtsh\n[bad]'])
def test_native_subfinder_unknown_catalog_closed(catalog):
    from types import SimpleNamespace
    calls = []
    def executor(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=catalog, stderr='', returncode=0)
    mod = api('adapters.subfinder_adapter')
    with pytest.raises(ValueError):
        mod.OfflineSubfinderRunner(executor=executor)(mod.build_argv('dvwa.lab.test', {'rate_limit_rps': 5, 'timeout_s': 10}), 10)
    assert len(calls) == 1


def test_real_audit_export_uses_p1_verifier(tmp_path):
    mod = api('recon_lab')
    audit = AuditLog()
    t = token()
    from harness.contracts import Result
    for _ in range(3):
        audit.record('recon', Action('httpx.probe', Phase.RECON), 'dvwa.lab.test', t, Result.OK)
    path = tmp_path / 'audit.json'
    mod.export_audit(audit, path)
    assert mod.verify_audit(path).ok
    original = json.loads(path.read_text())
    changed = json.loads(path.read_text())
    changed['entries'][1]['target'] = 'juiceshop.lab.test'
    path.write_text(json.dumps(changed))
    assert not mod.verify_audit(path).ok
    original['entries'].pop(1)
    path.write_text(json.dumps(original))
    assert not mod.verify_audit(path).ok


def test_lab_approval_missing_or_expired_rejected():
    mod = api('recon_lab')
    with pytest.raises(ValueError):
        mod.validate_approval({})
    with pytest.raises(ValueError):
        mod.validate_approval({'actor': 'test-only', 'reference': 'test-only', 'expires_at': 0,
                               'approved_targets': ['dvwa.lab.test'], 'quote': 'test-only'})


def test_capture_does_not_bypass_pinning(monkeypatch):
    common = api('adapters.recon_common')
    mod = api('adapters.httpx_adapter')
    monkeypatch.setattr(common.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', ('10.99.0.2', 80))])
    calls, captures = [], []
    monkeypatch.setattr(mod, '_execute', lambda argv, timeout: calls.append(argv) or '{"url":"http://10.99.0.2"}')
    obj = mod.HttpxProbe(capture=lambda *args: captures.append(args))
    assert obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())['status'] == 'OK'
    assert captures and 'http://10.99.0.2' in calls[0]


def test_juiceshop_uses_its_fixed_lab_port(monkeypatch):
    common = api('adapters.recon_common')
    mod = api('adapters.httpx_adapter')
    monkeypatch.setattr(common.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', ('10.99.0.3', 3000))])
    calls = []
    monkeypatch.setattr(mod, '_execute', lambda argv, timeout: calls.append(argv) or '{"url":"http://10.99.0.3:3000"}')
    obj = mod.HttpxProbe()
    assert obj.run(Action(obj.name, Phase.RECON), 'juiceshop.lab.test', token())['status'] == 'OK'
    assert 'http://10.99.0.3:3000' in calls[0]


def test_juiceshop_relative_redirect_preserves_port():
    mod = api('adapters.httpx_adapter')
    obj = mod.HttpxProbe(runner=lambda *a: '{"url":"http://juiceshop.lab.test:3000","location":"/login"}')
    result = obj.run(Action(obj.name, Phase.RECON), 'juiceshop.lab.test', token())
    assert result['redirects'] == ['http://juiceshop.lab.test:3000/login']


def test_passive_unavailable_is_audited_and_seeds_probed():
    h, g, calls = setup_loop({'status': 'UNAVAILABLE', 'reason': 'no_local_sources', 'assets': []})
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.status == 'STOPPED'
    assert ('httpx.probe', 'dvwa.lab.test') in calls
    assert any(e['action'] == 'recon.passive_unavailable' for e in h.audit.entries)


def test_no_sources_is_unavailable_not_success():
    import subprocess
    from types import SimpleNamespace
    def executor(argv, **kwargs):
        if '-ls' in argv:
            return SimpleNamespace(stdout='crtsh\n', stderr='', returncode=0)
        raise subprocess.CalledProcessError(1, argv, output='', stderr='[\x1b[1;31mFTL\x1b[0m] No sources selected for this search\n')
    mod = api('adapters.subfinder_adapter')
    obj = mod.SubfinderEnum(runner=mod.OfflineSubfinderRunner(executor=executor))
    result = obj.run(Action(obj.name, Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'UNAVAILABLE' and result['reason'] == 'no_local_sources'


def test_unexpected_passive_exit_still_aborts():
    h, g, calls = setup_loop({'status': 'ERROR', 'error': 'exit', 'assets': []})
    api('loops').run_recon(h, token(), ['dvwa.lab.test'], g)
    assert g.status == 'ERROR'
    assert all(name != 'httpx.probe' for name, _ in calls)


def test_active_evidence_replaces_seed_provenance():
    graph = api('asset_graph').AssetGraph('p3-test')
    graph.add(asset(source='scope.seed'))
    graph.add(asset(source='httpx.probe', tech=['PHP']))
    observed = next(iter(graph.assets.values()))
    assert observed['source_tool'] == 'httpx.probe'


@pytest.mark.parametrize('name', ['httpx-dvwa.jsonl', 'httpx-juiceshop.jsonl'])
def test_recorded_real_httpx_output(name):
    from urllib.parse import urlsplit
    raw = (Path(__file__).parent / 'fixtures/p3/real' / name).read_text()
    host = urlsplit(json.loads(raw)['url']).hostname
    cls = api('adapters.httpx_adapter').HttpxProbe
    obj = cls(runner=lambda *args: raw)
    result = obj.run(Action(obj.name, Phase.RECON), host, token())
    assert result['status'] == 'OK'
    assert result['assets'][0]['address'] == host
    assert result['assets'][0]['source_tool'] == 'httpx.probe'


@pytest.fixture
def simulated_subfinder(monkeypatch):
    """Parser y Guard reales; ejecución y resolución exclusivamente simuladas."""
    import socket
    import subprocess

    def forbidden_io(*args, **kwargs):
        pytest.fail('Los casos simulados no permiten red ni procesos externos')

    monkeypatch.setattr(socket, 'getaddrinfo', forbidden_io)
    monkeypatch.setattr(subprocess, 'run', forbidden_io)
    h, graph, probes = setup_loop()
    h.guard._approvals.update({'httpx.probe@api.dvwa.lab.test', 'httpx.probe@admin.dvwa.lab.test'})
    resolved, enumerated = [], []
    h.guard.resolver = lambda host: resolved.append(host) or ['10.99.0.2']
    now = [0.0]
    limiter = api('adapters.recon_common').RateLimiter(
        clock=lambda: now[0], sleep=lambda dt: now.__setitem__(0, now[0] + dt))

    def load_fixture(name):
        raw = (Path(__file__).parent / 'fixtures/p3/simulated' / name).read_text(encoding='utf-8')
        def runner(argv, timeout):
            enumerated.append(argv[argv.index('-d') + 1])
            return raw
        h.tools['subfinder.enum'] = api('adapters.subfinder_adapter').SubfinderEnum(
            runner=runner, limiter=limiter)
        return h, graph, probes, resolved, enumerated

    return load_fixture


@pytest.mark.parametrize('fixture,excluded,expected,blocked', [
    ('subfinder-authorized.jsonl', (), {'dvwa.lab.test', 'api.dvwa.lab.test', 'admin.dvwa.lab.test'}, set()),
    ('subfinder-mixed.jsonl', ('admin.dvwa.lab.test',), {'dvwa.lab.test', 'api.dvwa.lab.test'},
     {'admin.dvwa.lab.test', 'external.invalid', 'dvwa.lab.test.external.invalid'}),
    ('subfinder-empty.jsonl', (), {'dvwa.lab.test'}, set()),
])
def test_subfinder_simulated_fixture_through_loop(simulated_subfinder, fixture, excluded, expected, blocked):
    h, graph, probes, resolved, enumerated = simulated_subfinder(fixture)
    scope = replace(token(), allowed_domains=('dvwa.lab.test',), excluded_domains=excluded)
    api('loops').run_recon(h, scope, ['dvwa.lab.test'], graph)
    assert graph.status == 'STOPPED' and graph.stop_reason == 'grafo estabilizado'
    assert graph.iteration == 2
    assert {a['address'] for a in graph.assets.values()} == expected
    assert len(graph.assets) == len(expected)  # Normalización y deduplicación de JSONL.
    assert {host for name, host in probes if name == 'httpx.probe'} == expected
    assert set(graph.excluded) == blocked
    assert blocked.isdisjoint(resolved)
    assert blocked.isdisjoint(host for _, host in probes)
    assert enumerated == ['dvwa.lab.test', 'dvwa.lab.test']
    assert {e['target'] for e in h.audit.entries if e['action'] == 'recon.out_of_scope'
            and e['result'] == 'BLOCKED'} == blocked
    assert not any(e['action'] == 'recon.passive_unavailable' for e in h.audit.entries)


@pytest.mark.parametrize('target', ['external.invalid', 'juiceshop.lab.test'])
def test_subfinder_simulated_out_of_scope_input_never_runs(simulated_subfinder, target):
    from harness.contracts import ScopeViolation
    h, graph, probes, resolved, enumerated = simulated_subfinder('subfinder-authorized.jsonl')
    scope = replace(token(), allowed_domains=('dvwa.lab.test',))
    with pytest.raises(ScopeViolation):
        h.invoke('recon', Action('subfinder.enum', Phase.RECON), target, scope)
    assert not enumerated and not resolved and not probes
    assert h.audit.entries[-1]['target'] == target
    assert h.audit.entries[-1]['result'] == 'BLOCKED'


def test_subfinder_simulated_empty_is_success_without_discoveries(simulated_subfinder):
    h, graph, probes, resolved, enumerated = simulated_subfinder('subfinder-empty.jsonl')
    result = h.invoke('recon', Action('subfinder.enum', Phase.RECON), 'dvwa.lab.test', token())
    assert result['status'] == 'OK' and result['assets'] == []
    assert 'reason' not in result and 'error' not in result
    assert enumerated == ['dvwa.lab.test']
    assert not probes  # La llamada pasiva aislada no ejecuta HTTP.
