"""Advanced check tests against the vuln app hard routes."""

import pytest

from mythos.scan.common import InjectionPoint
from mythos.scan import advanced as adv
from mythos.oast import OastListener


def _point(base, path, param):
    return InjectionPoint(method="GET", url=base + path, param=param, where="query")


def test_ssti(client, vulnapp):
    f = adv.check_ssti(client, _point(vulnapp, "/render", "name"))
    assert f and f[0].kind == "ssti" and f[0].severity.value == "critical"


def test_crlf(client, vulnapp):
    f = adv.check_crlf(client, _point(vulnapp, "/log", "msg"))
    assert f and f[0].kind == "crlf-injection"


@pytest.mark.slow
def test_command_injection_timebased(client, vulnapp):
    f = adv.check_command_injection(client, _point(vulnapp, "/ping", "host"))
    assert f and f[0].kind == "command-injection"


@pytest.mark.slow
def test_blind_sqli_timebased(client, vulnapp):
    f = adv.check_blind_sqli(client, _point(vulnapp, "/blind", "id"))
    assert f and f[0].kind == "sqli"


def test_ssrf_oob(client, vulnapp):
    with OastListener(public_host="127.0.0.1") as oast:
        f = adv.check_ssrf(client, _point(vulnapp, "/fetch", "url"), oast)
    assert f and f[0].kind == "ssrf" and f[0].confidence == "certain"


def test_graphql_introspection(client, vulnapp):
    f = adv.check_graphql_introspection(client, vulnapp + "/graphql")
    assert f and f[0].kind == "graphql-introspection"


def test_jwt_weak_secret(client, vulnapp):
    resp = client.get(vulnapp + "/api/login?user=alice")
    token = resp.json()["token"]
    f = adv.check_jwt(token, url=vulnapp + "/api/login")
    assert f and any(x.kind == "jwt-weak-secret" for x in f)


def test_jwt_alg_none():
    import base64, json
    def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    tok = b64(json.dumps({"alg": "none"}).encode()) + "." + \
        b64(json.dumps({"sub": "admin"}).encode()) + "."
    f = adv.check_jwt(tok)
    assert f and f[0].kind == "jwt-alg-none"


def test_idor(client, vulnapp):
    from mythos.scan.idor import check_idor
    pt = InjectionPoint(method="GET", url=vulnapp + "/api/account", param="id",
                        base_params={"id": "1"}, where="query")
    f = check_idor(client, pt)
    assert f and f[0].kind == "idor"
