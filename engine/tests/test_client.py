import pytest

from mythos.http_client import HttpClient, ScopeViolation, BudgetExceeded
from mythos.scope import Scope


def test_client_blocks_out_of_scope(vulnapp):
    scope = Scope.from_dict({"in_scope": ["127.0.0.1"]})
    c = HttpClient(scope=scope)
    with pytest.raises(ScopeViolation):
        c.get("https://example.com")


def test_client_allows_in_scope(client, vulnapp):
    resp = client.get(vulnapp + "/")
    assert resp is not None and resp.status_code == 200


def test_budget_enforced(vulnapp):
    scope = Scope.from_dict({"in_scope": ["127.0.0.1"],
                             "rules": {"max_requests": 1, "rate_limit_rps": 1000}})
    c = HttpClient(scope=scope)
    c.get(vulnapp + "/")
    with pytest.raises(BudgetExceeded):
        c.get(vulnapp + "/")


def test_transactions_recorded(client, vulnapp):
    client.get(vulnapp + "/")
    assert client.transactions and client.transactions[-1].status == 200
