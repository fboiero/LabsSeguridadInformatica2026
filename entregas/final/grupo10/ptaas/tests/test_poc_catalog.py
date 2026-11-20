import pytest

from harness.poc.catalog import (
    ApprovalRequired,
    NotInCatalog,
    ParameterError,
    ResponseRecord,
    load_catalog,
    run_parametrized,
    validate_target_path,
)


@pytest.fixture(scope="module")
def catalog(): return load_catalog()


def test_catalog_has_inert_checks(catalog):
    assert len(catalog) == 16 and all(row["kind"] == "inert_check" and row["lab_only"] for row in catalog.values())


def test_gate_and_parameters(catalog):
    with pytest.raises(NotInCatalog): run_parametrized(catalog, "POC-EXPLOIT-999", {}, True, lambda *_: None)
    sent = []
    with pytest.raises(ApprovalRequired): run_parametrized(catalog, "POC-CSP-001", {"base_url": "http://juice-shop.lab.test", "path": "/"}, False, lambda *_: sent.append(1))
    assert sent == []
    with pytest.raises(ParameterError): run_parametrized(catalog, "POC-CSP-001", {"base_url": "x", "path": "/", "payload": "x"}, True, lambda *_: None)


def test_evaluators(catalog):
    params = {"base_url": "http://juice-shop.lab.test", "path": "/"}
    assert run_parametrized(catalog, "POC-CSP-001", params, True, lambda *_: ResponseRecord(200, {}, "")).status == "validated"
    assert run_parametrized(catalog, "POC-HDR-001", params, True, lambda *_: ResponseRecord(200, {"X-Frame-Options": "DENY"}, "")).status == "not_validated"
    assert run_parametrized(catalog, "POC-ERRDISC-001", params, True, lambda *_: ResponseRecord(500, {}, "Fatal error on line 1")).status == "validated"


def test_canary_is_inert(catalog):
    params = {"base_url": "http://juice-shop.lab.test", "path": "/", "param_name": "q"}
    def sender(_, values): return ResponseRecord(200, {}, values["canary"], canary=values["canary"])
    result = run_parametrized(catalog, "POC-REFLECT-001", params, True, sender)
    assert result.status == "validated" and "<script" not in result.parameters.get("param_name", "")


@pytest.mark.parametrize(("poc_id", "body"), [
    ("POC-FTP-001", '<title>Index of /ftp</title><a href="/ftp/acquisitions.md">'),
    ("POC-ADMINCFG-001", '{"config":{"server":{"port":3000}}}'),
    ("POC-METRICS-001", "# HELP process_cpu_seconds_total\n# TYPE process_cpu_seconds_total counter"),
    ("POC-APIDOCS-001", "<html><body>Swagger UI</body></html>"),
    ("POC-CAPTCHA-001", '{"captcha":"1+1","answer":"2"}'),
    ("POC-PRODUCTS-001", '[{"name":"Apple","price":1}]'),
    ("POC-REVIEWS-001", '{"data":[{"message":"ok","author":"a"}]}'),
    ("POC-ADMINAUTHZ-001", "[]"),
    ("POC-CHALLENGES-001", '{"challenges":[{"name":"Score Board","description":"x"}]}'),
    ("POC-MAINJS-001", 'window.routes="/administration"; /* customer feedback */'),
])
def test_new_evaluators(catalog, poc_id, body):
    params = {"base_url": "http://juice-shop.lab.test:3000", "path": "/x"}
    assert run_parametrized(catalog, poc_id, params, True, lambda *_: ResponseRecord(200, {}, body)).status == "validated"


def test_protected_admin_route_is_not_a_finding(catalog):
    params = {"base_url": "http://juice-shop.lab.test:3000", "path": "/api/Users"}
    assert run_parametrized(catalog, "POC-ADMINAUTHZ-001", params, True,
                            lambda *_: ResponseRecord(401, {}, "")).status == "not_validated"


def test_dynamic_path_is_passed_to_sender(catalog):
    seen = {}

    def sender(poc_id, params):
        seen.update(params)
        return ResponseRecord(200, {}, "# HELP demo")

    params = {"base_url": "http://juice-shop.lab.test:3000", "path": "/metrics/custom"}
    result = run_parametrized(catalog, "POC-METRICS-001", params, True, sender)
    assert result.status == "validated" and seen["path"] == "/metrics/custom"


@pytest.mark.parametrize("path", ["/", "/ftp", "/rest/products/search?q=", "/rest/products/reviews?productId=1"])
def test_valid_dynamic_paths(path):
    assert validate_target_path(path) == path


@pytest.mark.parametrize("path", [
    "//evil.test/x", "/../etc/passwd", "/a\\b", "ftp", "/a\r\nHost: x", "/%2e%2e/x", "/" + "a" * 600,
])
def test_invalid_dynamic_paths(path):
    with pytest.raises(ParameterError):
        validate_target_path(path)


def test_run_parametrized_rejects_unsafe_path(catalog):
    params = {"base_url": "http://juice-shop.lab.test:3000", "path": "//evil.test/metrics"}
    with pytest.raises(ParameterError):
        run_parametrized(catalog, "POC-METRICS-001", params, True, lambda *_: None)
