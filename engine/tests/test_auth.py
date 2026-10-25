"""Authenticated-scanning tests: scope auth is applied to requests."""

from mythos.http_client import HttpClient
from mythos.scope import Scope, Auth


def test_auth_from_dict():
    s = Scope.from_dict({"in_scope": ["x"], "auth": {
        "cookies": {"PHPSESSID": "abc", "security": "low"},
        "headers": {"X-API": "k"}, "bearer": "tok"}})
    assert s.auth.active()
    assert s.auth.cookies["security"] == "low"
    assert s.auth.bearer == "tok"


def test_client_applies_auth(vulnapp):
    scope = Scope.from_dict({"in_scope": ["127.0.0.1"], "auth": {
        "cookies": {"session": "s3cr3t"},
        "headers": {"X-Test": "1"}, "bearer": "mytoken"}})
    c = HttpClient(scope=scope)
    assert c._session.headers.get("Authorization") == "Bearer mytoken"
    assert c._session.headers.get("X-Test") == "1"
    assert c._session.cookies.get("session") == "s3cr3t"


def test_no_auth_by_default(vulnapp):
    scope = Scope.from_dict({"in_scope": ["127.0.0.1"]})
    c = HttpClient(scope=scope)
    assert not scope.auth.active()
    assert "Authorization" not in c._session.headers
