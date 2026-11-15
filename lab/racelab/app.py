"""Race-condition target — fixture for the race-conditions package.

Deliberate flaws, both of them the same bug in two shapes: a check and the
state change it guards are not atomic, and the window between them is a real
`await` rather than a hope.

  POST /coupon/new      mint a fresh single-use coupon owned by the caller
  POST /redeem {code}   LIMIT OVERRUN: reads coupon["used"], awaits, then
                        writes it. N concurrent redemptions all pass the check
                        and all credit the balance.
  POST /order/new       a pending order owned by the caller
  POST /order/confirm   step one of the two-step flow
  POST /order/use {id}  TOCTOU: checks confirmed-and-not-used, awaits, then
                        marks used and credits. Raced at the gap after confirm.
  GET  /balance         the AUTHORITATIVE state: balance and redemption count.
                        This is the read-back oracle; a redeem response is not.
  GET  /mine            the object ids this caller owns (the ownership check)
  GET  /__state         everything, for debugging a run
  POST /__reset         back to the initial state

Identities are bearer tokens: `MYTHOS_LAB_CANARY-alice` and
`MYTHOS_LAB_CANARY-bob`. Every fake credential in here is that one canary
string, so a run greps for exactly one token and nothing resembles a real key.
`victim-coupon` is a coupon owned by bob that alice does not own: it exists so
the ownership refusal in `scripts/race` has a real object to refuse.

RACE_WINDOW_MS (default 25) is the width of the window. Set it to 0 and the
limit overrun stops reproducing, which is the control for the measurement
itself.

Served by hypercorn: HTTP/1.1 and h2c on PORT, and HTTP/2 over TLS with ALPN
`h2` on TLS_PORT, so the single-packet attack can be exercised against a real
HPACK/HTTP-2 implementation. Everything is in memory and resets with the
container. Local lab only. Do not deploy it.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets

CANARY = "MYTHOS_LAB_CANARY"
WINDOW = float(os.environ.get("RACE_WINDOW_MS", "25")) / 1000.0
USERS = {f"{CANARY}-alice": "alice", f"{CANARY}-bob": "bob"}

COUPON_VALUE = 10
ORDER_VALUE = 25


def initial():
    return {
        # code -> {owner, used}
        "coupons": {"victim-coupon": {"owner": "bob", "used": False}},
        # id -> {owner, confirmed, used}
        "orders": {},
        "balance": {"alice": 0, "bob": 0},
        "redemptions": {"alice": 0, "bob": 0},
        "uses": {"alice": 0, "bob": 0},
    }


S = initial()


def who(headers):
    auth = headers.get(b"authorization", b"").decode("latin-1")
    return USERS.get(auth[7:] if auth[:7].lower() == "bearer " else auth)


async def handler(scope, receive, send):
    if scope["type"] != "http":
        return
    headers = {k.lower(): v for k, v in scope["headers"]}
    path = scope["path"]
    method = scope["method"]
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    try:
        data = json.loads(body) if body.strip() else {}
    except ValueError:
        data = {}
    status, payload = await route(method, path, who(headers), data)
    raw = json.dumps(payload).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(raw)).encode())]})
    await send({"type": "http.response.body", "body": raw})


async def route(method, path, user, data):
    if path == "/" and method == "GET":
        return 200, {"app": "mythos racelab", "canary": CANARY,
                     "endpoints": ["/coupon/new", "/redeem", "/order/new",
                                   "/order/confirm", "/order/use", "/balance",
                                   "/mine", "/__state", "/__reset"]}
    if path == "/__state" and method == "GET":
        return 200, S
    if path == "/__reset" and method == "POST":
        S.clear()
        S.update(initial())
        return 200, {"reset": True}
    if user is None:
        return 401, {"error": "bearer token required",
                     "hint": f"Authorization: Bearer {CANARY}-alice"}

    if path == "/balance" and method == "GET":
        # The authoritative state. A read-back oracle reads this, as the owner.
        return 200, {"owner": user, "balance": S["balance"][user],
                     "redemptions": S["redemptions"][user], "uses": S["uses"][user]}
    if path == "/mine" and method == "GET":
        return 200, {"owner": user,
                     "coupons": [c for c, v in S["coupons"].items() if v["owner"] == user],
                     "orders": [o for o, v in S["orders"].items() if v["owner"] == user]}
    if path == "/coupon/new" and method == "POST":
        code = "cpn-" + secrets.token_hex(6)
        S["coupons"][code] = {"owner": user, "used": False}
        return 201, {"code": code, "value": COUPON_VALUE, "owner": user}
    if path == "/order/new" and method == "POST":
        oid = "ord-" + secrets.token_hex(6)
        S["orders"][oid] = {"owner": user, "confirmed": False, "used": False}
        return 201, {"id": oid, "value": ORDER_VALUE, "owner": user}

    if path == "/redeem" and method == "POST":
        code = str(data.get("code", ""))
        c = S["coupons"].get(code)
        if c is None:
            return 404, {"error": "no such coupon"}
        if c["owner"] != user:
            return 403, {"error": "not your coupon"}
        # The bug. Read, yield, write: every request that got here before the
        # first write saw used=False and will credit the balance.
        used = c["used"]
        if WINDOW:
            await asyncio.sleep(WINDOW)
        if used:
            return 409, {"error": "coupon already redeemed", "code": code}
        c["used"] = True
        S["balance"][user] += COUPON_VALUE
        S["redemptions"][user] += 1
        return 200, {"ok": True, "credited": COUPON_VALUE, "code": code}

    if path == "/order/confirm" and method == "POST":
        o = S["orders"].get(str(data.get("id", "")))
        if o is None:
            return 404, {"error": "no such order"}
        if o["owner"] != user:
            return 403, {"error": "not your order"}
        o["confirmed"] = True
        return 200, {"ok": True, "confirmed": True}
    if path == "/order/use" and method == "POST":
        oid = str(data.get("id", ""))
        o = S["orders"].get(oid)
        if o is None:
            return 404, {"error": "no such order"}
        if o["owner"] != user:
            return 403, {"error": "not your order"}
        if not o["confirmed"]:
            return 409, {"error": "order not confirmed"}
        # The same bug at the gap of a two-step flow: check-then-write, with
        # the window sitting between confirm and use.
        used = o["used"]
        if WINDOW:
            await asyncio.sleep(WINDOW)
        if used:
            return 409, {"error": "order already used", "id": oid}
        o["used"] = True
        S["balance"][user] += ORDER_VALUE
        S["uses"][user] += 1
        return 200, {"ok": True, "credited": ORDER_VALUE, "id": oid}

    return 404, {"error": "no such endpoint", "path": path}


app = handler


def main():
    from hypercorn.config import Config
    from hypercorn.asyncio import serve

    port = os.environ.get("PORT", "5000")
    tls_port = os.environ.get("TLS_PORT", "5443")
    # Loopback unless something asks otherwise. This app is deliberately
    # exploitable, so a default of 0.0.0.0 would put a working limit overrun on
    # whatever network the machine is attached to. The image sets BIND=0.0.0.0
    # because a container's own namespace has no route to the host's loopback,
    # and the compose publish line restricts it to the host's loopback again.
    host = os.environ.get("BIND", "127.0.0.1")
    cfg = Config()
    cfg.bind = [f"{host}:{port}"]
    cfg.certfile = os.environ.get("CERTFILE", "/app/cert.pem")
    cfg.keyfile = os.environ.get("KEYFILE", "/app/key.pem")
    if os.path.exists(cfg.certfile):
        # One process, two binds: plaintext (HTTP/1.1 and h2c upgrade) and TLS
        # with ALPN h2, which is the only way the single-packet attack runs for
        # real rather than falling back.
        cfg.insecure_bind = [f"{host}:{port}"]
        cfg.bind = [f"{host}:{tls_port}"]
    cfg.accesslog = "-"
    # One worker: a race window is only a window if both requests are in the
    # same process.
    cfg.workers = 1
    asyncio.run(serve(handler, cfg))


if __name__ == "__main__":
    main()
