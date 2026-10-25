"""Per-check tests against the vuln app: every check must fire on its target
and the safe endpoint must not raise a false positive."""

from mythos.scan.common import InjectionPoint
from mythos.scan import quick, headers


def _point(base, path, param, method="GET", where="query"):
    return InjectionPoint(method=method, url=base + path, param=param, where=where)


def test_reflected_xss(client, vulnapp):
    f = quick.check_xss(client, _point(vulnapp, "/search", "q"))
    assert f and f[0].kind == "reflected-xss" and f[0].severity.value == "high"


def test_xss_no_false_positive_on_safe(client, vulnapp):
    f = quick.check_xss(client, _point(vulnapp, "/safe", "q"))
    assert f == []  # escaped output must not be flagged


def test_error_sqli(client, vulnapp):
    f = quick.check_sqli(client, _point(vulnapp, "/user", "id"))
    assert f and f[0].kind == "sqli" and f[0].severity.value == "critical"


def test_open_redirect(client, vulnapp):
    f = quick.check_open_redirect(client, _point(vulnapp, "/go", "next"))
    assert f and f[0].kind == "open-redirect"


def test_path_traversal(client, vulnapp):
    f = quick.check_path_traversal(client, _point(vulnapp, "/download", "file"))
    assert f and f[0].kind == "path-traversal"


def test_cors_misconfig(client, vulnapp):
    f = headers.check_cors(client, vulnapp + "/api/data")
    assert f and f[0].kind == "cors-misconfig"


def test_security_headers_flagged(client, vulnapp):
    f = headers.check_security_headers(client, vulnapp + "/")
    kinds = {x.kind for x in f}
    assert "missing-security-header" in kinds
