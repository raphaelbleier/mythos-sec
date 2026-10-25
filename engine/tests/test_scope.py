from mythos.scope import Scope


def test_in_scope_exact_and_glob():
    s = Scope.from_dict({"in_scope": ["example.com", "*.example.com"]})
    assert s.contains("https://example.com/path")
    assert s.contains("https://api.example.com")
    assert not s.contains("https://evil.com")


def test_out_of_scope_wins():
    s = Scope.from_dict({"in_scope": ["*.example.com"],
                         "out_of_scope": ["admin.example.com"]})
    assert s.contains("https://app.example.com")
    assert not s.contains("https://admin.example.com")


def test_cidr():
    s = Scope.from_dict({"in_scope": ["203.0.113.0/24"]})
    assert s.contains("http://203.0.113.5")
    assert not s.contains("http://203.0.114.5")


def test_reason_strings():
    s = Scope.from_dict({"in_scope": ["example.com"]})
    assert "in-scope" in s.reason("https://example.com")
    assert "no in-scope" in s.reason("https://other.com")
