"""Out-of-band application security testing (OAST) listener.

A minimal local HTTP collaborator for detecting *blind* vulnerabilities: blind
SSRF, blind XSS, blind XXE, OOB command execution. A check embeds a unique
callback URL carrying a token; if the target interacts with it out of band, the
listener records the hit and the check confirms the bug.

For engagements against remote targets the listener must be reachable by the
target (bind to a routable address / use a tunnel). For the local lab it binds
to loopback and the target containers reach it via host.docker.internal.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Interaction:
    token: str
    path: str
    method: str
    headers: dict
    client: str


class _Handler(BaseHTTPRequestHandler):
    def _record(self):
        token = self.path.strip("/").split("/")[0].split("?")[0]
        self.server.sink.record(Interaction(  # type: ignore[attr-defined]
            token=token, path=self.path, method=self.command,
            headers={k: v for k, v in self.headers.items()},
            client=self.client_address[0]))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"mythos-oast")

    def do_GET(self):
        self._record()

    def do_POST(self):
        self._record()

    def log_message(self, *a):  # silence
        pass


class OastListener:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 public_host: str | None = None):
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.sink = self  # type: ignore[attr-defined]
        self.host = host
        self.port = self._server.server_address[1]
        # address the TARGET should call back to (e.g. host.docker.internal)
        self.public_host = public_host or host
        self._interactions: list[Interaction] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "OastListener":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def record(self, interaction: Interaction) -> None:
        with self._lock:
            self._interactions.append(interaction)

    def new_token(self) -> str:
        return "mx" + uuid.uuid4().hex[:12]

    def callback_url(self, token: str) -> str:
        return f"http://{self.public_host}:{self.port}/{token}"

    def saw(self, token: str) -> bool:
        with self._lock:
            return any(i.token == token for i in self._interactions)

    def interactions(self, token: str | None = None) -> list[Interaction]:
        with self._lock:
            if token is None:
                return list(self._interactions)
            return [i for i in self._interactions if i.token == token]
