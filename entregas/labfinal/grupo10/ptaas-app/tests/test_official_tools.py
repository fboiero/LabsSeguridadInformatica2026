import pytest

from runtime.official_tools import TARGET, OfficialDockerAdapter


def test_official_argv_is_fixed_and_lab_only():
    adapter = OfficialDockerAdapter("httpx.probe.official", "net", "image")
    argv = adapter._argv(TARGET)
    assert argv[-6:] == ["-u", "http://juice-shop.lab.test:3000", "-json", "-silent", "-status-code", "-title"]
    with pytest.raises(ValueError): adapter._argv("example.test")


def test_zap_and_nuclei_do_not_accept_model_arguments():
    for name in ("zap.baseline_scan", "nuclei.safe_templates"):
        argv = OfficialDockerAdapter(name, "net", "image")._argv(TARGET)
        assert "example.test" not in " ".join(argv)
