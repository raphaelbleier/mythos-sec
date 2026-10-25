"""Pytest fixtures: launch the vuln app in a background thread."""

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

# make the vuln app importable
VULNAPP = Path(__file__).resolve().parents[2] / "lab" / "vulnapp"
sys.path.insert(0, str(VULNAPP))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def vulnapp():
    import app as vulnapp_module  # noqa: E402
    port = _free_port()
    srv = vulnapp_module.app
    t = threading.Thread(
        target=lambda: srv.run(host="127.0.0.1", port=port,
                               use_reloader=False, threaded=True),
        daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    # wait for readiness
    import urllib.request
    for _ in range(50):
        try:
            urllib.request.urlopen(base, timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    yield base


@pytest.fixture
def client(vulnapp):
    from mythos.http_client import HttpClient
    from mythos.scope import Scope
    scope = Scope.from_dict({
        "target": vulnapp,
        "in_scope": ["127.0.0.1"],
        "rules": {"rate_limit_rps": 1000, "allow_active": True, "allow_exploit": True},
    })
    return HttpClient(scope=scope)
