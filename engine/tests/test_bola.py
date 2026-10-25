"""Two-identity BOLA confirmation against the vuln app's /api/order endpoint."""

from mythos.http_client import HttpClient
from mythos.scope import Scope
from mythos.scan.bola import check_bola


def _client_as(token: str):
    scope = Scope.from_dict({"in_scope": ["127.0.0.1"],
                             "auth": {"bearer": token},
                             "rules": {"rate_limit_rps": 1000}})
    return HttpClient(scope=scope)


def test_bola_confirmed_cross_user(vulnapp):
    victim = _client_as("tokenA")       # owns order 1
    attacker = _client_as("tokenB")     # owns order 2
    f = check_bola(victim, attacker,
                   object_url=vulnapp + "/api/order/1",            # victim's object
                   attacker_own_url=vulnapp + "/api/order/2")      # attacker's own
    assert f and f[0].kind == "bola" and f[0].severity.value == "high"
    assert f[0].confidence == "certain"


def test_bola_not_flagged_when_denied(vulnapp, monkeypatch):
    # if the attacker is denied (simulated by pointing at a 404 object), no finding
    victim = _client_as("tokenA")
    attacker = _client_as("tokenB")
    f = check_bola(victim, attacker, object_url=vulnapp + "/api/order/999")
    assert f == []
