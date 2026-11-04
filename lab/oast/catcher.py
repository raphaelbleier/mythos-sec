"""Tiny OAST catcher: logs every HTTP request (any path, port 8080) and DNS
query (UDP 5353) to stdout and /data/log.jsonl. GET /__log returns the log."""
import json, os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "/data/log.jsonl"
ANSWER_IP = os.environ.get("OAST_IP", "127.0.0.1")
os.makedirs("/data", exist_ok=True)


def log(**kw):
    line = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **kw})
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


class H(BaseHTTPRequestHandler):
    def handle_any(self):
        if self.path == "/__log":
            body = open(LOG).read().encode() if os.path.exists(LOG) else b""
        else:
            n = int(self.headers.get("Content-Length") or 0)
            log(proto="http", src=self.client_address[0], method=self.command, path=self.path,
                host=self.headers.get("Host"), ua=self.headers.get("User-Agent"),
                body=self.rfile.read(n).decode(errors="replace")[:2000])
            body = b"ok"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_OPTIONS = handle_any
    def log_message(self, *a): pass


def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 5353))
    while True:
        data, addr = s.recvfrom(512)
        i, labels = 12, []
        while i < len(data) and data[i]:
            labels.append(data[i + 1:i + 1 + data[i]].decode(errors="replace")); i += data[i] + 1
        q = data[12:i + 5]
        log(proto="dns", src=addr[0], name=".".join(labels))
        ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(ANSWER_IP)
        s.sendto(data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q + ans, addr)


threading.Thread(target=dns, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
