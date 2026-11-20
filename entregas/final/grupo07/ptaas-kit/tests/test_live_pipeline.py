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
