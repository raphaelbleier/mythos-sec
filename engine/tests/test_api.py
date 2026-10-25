"""OpenAPI import parsing (offline) and the API sensitive-data check."""

from mythos.recon.openapi import parse_spec
from mythos.scan.api import check_sensitive_api_response

SPEC = {
    "basePath": "",
    "paths": {
        "/users/v1": {"get": {"parameters": [{"name": "limit", "in": "query"}]}},
        "/users/v1/{username}": {"get": {"parameters": [{"name": "username", "in": "path"}]}},
        "/users/v1/login": {"post": {}},
        "/books/v1/{title}": {"get": {}},
    },
}


def test_parse_spec_builds_concrete_endpoints():
    eps = parse_spec(SPEC, "http://t")
    urls = {(e["url"].split("http://t")[-1], e["method"]) for e in eps}
    assert ("/users/v1", "GET") in urls
    assert ("/users/v1/1", "GET") in urls          # {username} -> 1
    assert ("/users/v1/login", "POST") in urls
    # query param captured
    users = [e for e in eps if e["url"].endswith("/users/v1") and e["method"] == "GET"][0]
    assert "limit" in users["query_params"]


def test_api_sensitive_response_flagged(client, vulnapp):
    f = check_sensitive_api_response(client, vulnapp + "/api/debug")
    assert f and f[0].kind == "sensitive-exposure"
    assert f[0].severity.value == "high"      # >=3 sensitive fields (password/token x2)
    # the actual secret values must be redacted in evidence
    assert "s3cr3t" not in f[0].evidence.response


def test_api_check_ignores_clean_json(client, vulnapp):
    f = check_sensitive_api_response(client, vulnapp + "/api/data")
    assert f == []


def test_body_params_parsed_from_openapi():
    spec = {"paths": {"/users/v1/login": {"post": {"requestBody": {"content": {
        "application/json": {"schema": {"properties": {"username": {}, "password": {}}}}}}}}}}
    eps = parse_spec(spec, "http://t")
    login = [e for e in eps if e["url"].endswith("/users/v1/login")][0]
    assert set(login["body_params"]) == {"username", "password"}


def test_json_body_sqli(client, vulnapp):
    from mythos.scan.common import InjectionPoint
    from mythos.scan.quick import check_sqli
    pt = InjectionPoint(method="POST", url=vulnapp + "/api/jsonlogin",
                        param="username", where="json")
    f = check_sqli(client, pt)
    assert f and f[0].kind == "sqli" and f[0].severity.value == "critical"


def test_path_param_sqli(client, vulnapp):
    from mythos.scan.common import InjectionPoint
    from mythos.scan.quick import check_sqli
    pt = InjectionPoint(method="GET", url=vulnapp + "/item/1", param="thing",
                        where="path", template=vulnapp + "/item/{thing}")
    f = check_sqli(client, pt)
    assert f and f[0].kind == "sqli"


def test_path_params_parsed_from_openapi():
    spec = {"paths": {"/vehicle/{id}/location": {"get": {"parameters": [
        {"name": "id", "in": "path"}]}}}}
    eps = parse_spec(spec, "http://t")
    ep = eps[0]
    assert "id" in ep["path_params"]
    assert ep["path_template"] == "http://t/vehicle/{id}/location"
