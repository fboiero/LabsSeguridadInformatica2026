from harness.approvals import ApprovalStore
from harness.run import execute
from harness.team_pipeline import fixture_runner
from tests.test_run_integration import roe  # noqa: F401


def test_docker_mode_keeps_gates_and_provenance(roe, tmp_path, monkeypatch):  # noqa: F811
    calls = []

    class DockerDouble:
        def __init__(self, output, network):
            assert network == 'lab_lab'

        def __call__(self, argv, timeout):
            calls.append(argv[0])
            return fixture_runner(argv, timeout)

    monkeypatch.setattr('harness.docker_runner.DockerToolRunner', DockerDouble)
    result = execute(roe, tmp_path / 'out', ApprovalStore(), tools_mode='docker')
    assert {'subfinder', 'httpx', 'nuclei', 'zap-baseline.py'} <= set(calls)
    assert result['bundle']['pipeline']['analysis'].startswith('Docker real')
    assert result['delivery']['status'] == 'PENDING_HITL'
    assert not (tmp_path / 'out/published').exists()


def test_docker_failure_never_falls_back(roe, tmp_path, monkeypatch):  # noqa: F811
    import pytest

    class Unavailable:
        def __init__(self, *args):
            raise RuntimeError('Docker no disponible')

    monkeypatch.setattr('harness.docker_runner.DockerToolRunner', Unavailable)
    with pytest.raises(RuntimeError, match='Docker no disponible'):
        execute(roe, tmp_path / 'failure', ApprovalStore(), tools_mode='docker')
    assert not (tmp_path / 'failure/pipeline-evidence.json').exists()


def test_public_network_rejected_before_tool(monkeypatch, tmp_path):
    import pytest

    from harness.docker_runner import DockerToolRunner

    monkeypatch.setattr('subprocess.check_output', lambda *a, **k:
                        '[{"Internal": false, "IPAM": {"Config": [{"Subnet": "10.99.0.0/28"}]}}]')
    with pytest.raises(ValueError, match='red interna'):
        DockerToolRunner(tmp_path)


def test_tool_timeout_removes_worker(monkeypatch, tmp_path):
    import subprocess

    import pytest

    from harness.docker_runner import DockerToolRunner

    monkeypatch.setattr('subprocess.check_output', lambda *a, **k:
                        '[{"Internal": true, "IPAM": {"Config": [{"Subnet": "10.99.0.0/28"}]}}]')
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        if argv[1] == 'run':
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr('subprocess.run', run)
    with pytest.raises(subprocess.TimeoutExpired):
        DockerToolRunner(tmp_path)(['httpx', '-u', 'dvwa.lab.test'], 1)
    assert commands[-1][:3] == ['docker', 'rm', '-f']
    assert commands[-1][-1] == commands[0][commands[0].index('--name') + 1]
