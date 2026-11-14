"""Auth / account-takeover target — fixture for the account-takeover package.

Deliberate flaws, one per flow:

  POST /login                 password login, issues a session
  POST /2fa/verify            the second factor (code 000000)
  GET  /api/me                enforces the second factor
  GET  /api/balance           does NOT enforce it (2FA bypass on one endpoint)
  POST /elevate               privilege change keeps the SAME session token
  POST /password/reset/request  reset link built from Host / X-Forwarded-Host
  POST /password/reset        token not bound to a user, and not consumed
  POST /email/change          confirmation goes to the NEW address only
  GET  /email/confirm?token=
  GET  /__mail                JSONL of every mail this app "sent"

  GET  /oauth/authorize       loose redirect_uri match, state never checked,
                              PKCE challenge stored but never verified
  POST /oauth/token           the code is reusable

Everything lives in memory and resets with the container. Local lab only.
Do not deploy it.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time

from flask import Flask, Response, make_response, redirect, request

app = Flask(__name__)
MAIL = "/tmp/mail.jsonl"
_lock = threading.Lock()

USERS = {
    "alice": {"password": "alice123", "email": "alice@mythos.lab",
              "role": "user", "secret": "MYTHOS_LAB_CANARY_alice_notes"},
    "bob": {"password": "bob123", "email": "bob@mythos.lab",
            "role": "user", "secret": "MYTHOS_LAB_CANARY_bob_notes"},
}
ADMIN_PASSWORD = "admin123"
SESSIONS: dict[str, dict] = {}       # token -> {user, mfa, role}
RESETS: dict[str, dict] = {}         # reset token -> {user, used}
EMAIL_CHANGES: dict[str, dict] = {}  # confirm token -> {user, new_email}
CODES: dict[str, dict] = {}          # oauth code -> {user, challenge}
OAUTH_CLIENT = {"client_id": "mythos-lab-client",
                "client_secret": "mythos-lab-secret",
                "redirect_uri": "http://127.0.0.1:5023/callback"}


def _mail(to: str, subject: str, body: str) -> None:
    with _lock, open(MAIL, "a") as fh:
        fh.write(json.dumps({"ts": time.time(), "to": to,
                             "subject": subject, "body": body}) + "\n")


def _session() -> dict | None:
    tok = request.cookies.get("session") or request.headers.get("X-Session", "")
    return SESSIONS.get(tok)


@app.route("/")
def index():
    return """<html><head><title>Mythos AuthLab</title></head><body>
    <h1>AuthLab</h1>
    <p>users: alice/alice123, bob/bob123; 2fa code 000000; admin password
    admin123</p>
    <p>POST /login, /2fa/verify, /elevate, /password/reset/request,
    /password/reset, /email/change; GET /email/confirm, /__mail,
    /oauth/authorize, POST /oauth/token</p>
    </body></html>"""


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    user = data.get("user", "")
    rec = USERS.get(user)
    if not rec or rec["password"] != data.get("password"):
        return Response(json.dumps({"error": "bad credentials"}), status=401,
                        mimetype="application/json")
    tok = secrets.token_hex(12)
    SESSIONS[tok] = {"user": user, "mfa": False, "role": rec["role"]}
    resp = make_response({"session": tok, "mfa_required": True})
    resp.set_cookie("session", tok)
    return resp


@app.route("/2fa/verify", methods=["POST"])
def verify_2fa():
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    data = request.get_json(silent=True) or request.form
    if data.get("code") != "000000":
        return Response(json.dumps({"error": "bad code"}), status=401,
                        mimetype="application/json")
    sess["mfa"] = True
    return {"ok": True, "mfa": True}


@app.route("/api/me")
def api_me():
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    if not sess["mfa"]:
        return Response(json.dumps({"error": "second factor required"}),
                        status=403, mimetype="application/json")
    return {"user": sess["user"], "role": sess["role"],
            "secret": USERS[sess["user"]]["secret"]}


@app.route("/api/balance")
def api_balance():
    # VULN: the second factor is enforced on /api/me and forgotten here, so a
    # stolen password alone reaches the account data.
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    return {"user": sess["user"], "balance": 4200,
            "secret": USERS[sess["user"]]["secret"]}


@app.route("/elevate", methods=["POST"])
def elevate():
    # VULN: the session is not rotated on a privilege change — the token the
    # caller had as a user is the token they hold as an admin, so a session
    # fixated before the change inherits the new role.
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    data = request.get_json(silent=True) or request.form
    if data.get("password") != ADMIN_PASSWORD:
        return Response(json.dumps({"error": "bad password"}), status=401,
                        mimetype="application/json")
    sess["role"] = "admin"
    tok = request.cookies.get("session") or request.headers.get("X-Session", "")
    return {"ok": True, "role": "admin", "session": tok}


@app.route("/password/reset/request", methods=["POST"])
def reset_request():
    # VULN: the reset link's host comes from the request, X-Forwarded-Host
    # first, so a poisoned header mails the victim a link to the attacker.
    data = request.get_json(silent=True) or request.form
    user = data.get("user", "")
    if user not in USERS:
        return {"ok": True}  # no user enumeration here, that is not the bug
    tok = secrets.token_hex(8)
    RESETS[tok] = {"user": user, "used": False}
    host = request.headers.get("X-Forwarded-Host") or request.host
    link = f"http://{host}/reset?token={tok}"
    _mail(USERS[user]["email"], "Password reset", link)
    return {"ok": True}


@app.route("/password/reset", methods=["POST"])
def reset():
    # VULN (two of them): the token is never bound to the user it was issued
    # for — the body's `user` wins — and it is not consumed, so it works
    # again and again.
    data = request.get_json(silent=True) or request.form
    rec = RESETS.get(data.get("token", ""))
    if not rec:
        return Response(json.dumps({"error": "bad token"}), status=400,
                        mimetype="application/json")
    user = data.get("user") or rec["user"]
    if user not in USERS:
        return Response(json.dumps({"error": "no such user"}), status=400,
                        mimetype="application/json")
    USERS[user]["password"] = data.get("new_password", "")
    return {"ok": True, "user": user, "issued_for": rec["user"]}


@app.route("/email/change", methods=["POST"])
def email_change():
    # VULN: the confirmation goes to the new address only. The account's
    # current owner is never asked, so a hijacked session moves the account.
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    data = request.get_json(silent=True) or request.form
    new_email = data.get("new_email", "")
    tok = secrets.token_hex(8)
    EMAIL_CHANGES[tok] = {"user": sess["user"], "new_email": new_email}
    _mail(new_email, "Confirm your new address",
          f"http://{request.host}/email/confirm?token={tok}")
    return {"ok": True, "confirmation_sent_to": new_email}


@app.route("/email/confirm")
def email_confirm():
    rec = EMAIL_CHANGES.pop(request.args.get("token", ""), None)
    if not rec:
        return Response("bad token", status=400)
    USERS[rec["user"]]["email"] = rec["new_email"]
    return {"ok": True, "user": rec["user"], "email": rec["new_email"]}


@app.route("/__mail")
def mailbox():
    try:
        with open(MAIL) as fh:
            return Response(fh.read(), mimetype="application/x-ndjson")
    except OSError:
        return Response("", mimetype="application/x-ndjson")


# ---- OAuth 2.0 authorization server -----------------------------------
@app.route("/oauth/authorize")
def authorize():
    # VULN: redirect_uri is matched by substring, state is accepted and never
    # remembered, and PKCE is optional. Consent is implicit for alice so the
    # flow can be driven without a browser.
    if request.args.get("client_id") != OAUTH_CLIENT["client_id"]:
        return Response("unknown client", status=400)
    redirect_uri = request.args.get("redirect_uri", "")
    if "127.0.0.1" not in redirect_uri and "localhost" not in redirect_uri:
        return Response("redirect_uri rejected", status=400)
    code = secrets.token_hex(8)
    CODES[code] = {"user": "alice",
                   "challenge": request.args.get("code_challenge", "")}
    sep = "&" if "?" in redirect_uri else "?"
    target = f"{redirect_uri}{sep}code={code}"
    state = request.args.get("state")
    if state:
        target += f"&state={state}"
    return redirect(target, code=302)


@app.route("/oauth/token", methods=["POST"])
def token():
    # VULN: the code is not consumed and the PKCE verifier is never checked
    # against the stored challenge.
    data = request.get_json(silent=True) or request.form
    rec = CODES.get(data.get("code", ""))
    if not rec:
        return Response(json.dumps({"error": "invalid_grant"}), status=400,
                        mimetype="application/json")
    return {"access_token": f"MYTHOS_LAB_CANARY_oauth_{rec['user']}",
            "token_type": "Bearer", "expires_in": 3600,
            "scope": "profile email",
            "pkce_challenge_seen": rec["challenge"],
            "pkce_verifier_checked": False}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True, use_reloader=False)
