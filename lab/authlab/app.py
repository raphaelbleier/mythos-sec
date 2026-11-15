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

  GET  /saml/metadata         SP metadata, with the certificate it claims to trust
  POST /saml/acs              signature NEVER verified, so an unsigned assertion
                              logs you in; NameID read as the first text node, so
                              a comment truncates it; no Audience / Recipient /
                              Destination / NotOnOrAfter check; replay allowed;
                              RelayState is followed as a redirect
  POST /saml/acs-sigpresent   demands that a <ds:Signature> element exists but
                              still never verifies it, and reads the LAST NameID
                              in document order — the signature-wrapping target
  GET  /saml/whoami           who the SAML session belongs to
  GET  /oidc/callback         state is never bound to the flow that started it
  POST /oidc/link             id_token signature, `aud` and `email_verified` all
                              ignored, and the account is keyed on `email`; an
                              access token is accepted in place of an id_token
  POST /oidc/unlink           drops the link and leaves the session alive

Everything lives in memory and resets with the container. Local lab only.
Do not deploy it.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
import xml.etree.ElementTree as ET
import zlib

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
SAML_SESSIONS: dict[str, dict] = {}     # token -> {subject, raw_nameid}
SEEN_ASSERTION_IDS: list[str] = []      # recorded and never enforced
OIDC_LINKS: dict[str, dict] = {}        # local user -> {iss, sub, email}
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




# ---- SAML service provider (deliberately broken) ----------------------
#
# Three flaws, on purpose, and they are the ones `scripts/federation` probes:
#
#   * no signature is ever verified. /saml/acs does not even require a
#     <ds:Signature> element, so a response this lab minted itself logs you in.
#   * the NameID is read as the element's first text node. The parser below is
#     built with insert_comments=True, which is what a library that keeps
#     comments in the tree does, so `victim@x<!---->.evil.test` reads as
#     `victim@x` while canonicalization (and therefore any signature) covered
#     the whole string. (Duo, 2018.)
#   * Audience, Recipient, Destination, InResponseTo, NotBefore/NotOnOrAfter
#     and assertion-ID replay are all unchecked. The IDs are recorded so a
#     replay is visible in the response, never refused.

SAML_NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
           "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
           "ds": "http://www.w3.org/2000/09/xmldsig#"}


def _saml_decode(value: str) -> bytes:
    raw = base64.b64decode(value, validate=False)
    if raw[:1] != b"<":                      # HTTP-Redirect binding: deflated
        try:
            raw = zlib.decompress(raw, -15)
        except zlib.error:
            pass
    return raw


def _saml_tree(raw: bytes):
    # insert_comments=True is the whole point: with comments in the tree,
    # `el.text` stops at the first comment.
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    parser.feed(raw)
    return parser.close()


def _nameids(root):
    return root.findall(".//saml:Subject/saml:NameID", SAML_NS)


@app.route("/saml/metadata")
def saml_metadata():
    base = f"http://{request.host}"
    return Response(f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{base}/saml/sp">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
      WantAssertionsSigned="true" AuthnRequestsSigned="false">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>
        <ds:X509Certificate>MYTHOS_LAB_CANARY_sp_cert_not_a_real_certificate</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService index="0"
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{base}/saml/acs"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>""", mimetype="application/samlmetadata+xml")


def _saml_login(root, subject_el, note):
    if subject_el is None:
        return Response(json.dumps({"error": "no NameID in the assertion"}),
                        status=400, mimetype="application/json")
    subject = subject_el.text or ""        # <- truncates at a comment
    whole = "".join(subject_el.itertext())
    for a in root.findall(".//saml:Assertion", SAML_NS):
        SEEN_ASSERTION_IDS.append(a.get("ID", ""))
    tok = "MYTHOS_LAB_CANARY_saml_" + secrets.token_hex(6)
    SAML_SESSIONS[tok] = {"subject": subject, "raw_nameid": whole}
    body = {"ok": True, "subject": subject, "nameid_full_text": whole,
            "session": tok, "signature_verified": False,
            "assertion_ids_seen": SEEN_ASSERTION_IDS[-4:], "acs": note}
    relay = (request.form.get("RelayState") or "").strip()
    if relay.startswith("http://") or relay.startswith("https://"):
        # VULN: RelayState is meant to be opaque SP state. Following it makes
        # the ACS an open redirect that carries a fresh session.
        resp = make_response(redirect(relay, code=302))
    else:
        resp = make_response(body)
    resp.set_cookie("saml_session", tok)
    return resp


@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    value = request.form.get("SAMLResponse", "")
    if not value:
        return Response("no SAMLResponse", status=400)
    try:
        root = _saml_tree(_saml_decode(value))
    except Exception as exc:                       # noqa: BLE001 - lab target
        return Response(json.dumps({"error": f"parse failed: {exc}"}),
                        status=400, mimetype="application/json")
    ids = _nameids(root)
    return _saml_login(root, ids[0] if ids else None, "first NameID, no signature check")


@app.route("/saml/acs-sigpresent", methods=["POST"])
def saml_acs_sigpresent():
    value = request.form.get("SAMLResponse", "")
    if not value:
        return Response("no SAMLResponse", status=400)
    try:
        root = _saml_tree(_saml_decode(value))
    except Exception as exc:                       # noqa: BLE001 - lab target
        return Response(json.dumps({"error": f"parse failed: {exc}"}),
                        status=400, mimetype="application/json")
    # VULN: presence of a signature is not verification of one. The element is
    # looked for and then ignored, and the NameID that is consumed is the last
    # one in the document, which is not the one the signature covers.
    if root.find(".//ds:Signature", SAML_NS) is None:
        return Response(json.dumps({"error": "unsigned assertion refused"}),
                        status=403, mimetype="application/json")
    ids = _nameids(root)
    return _saml_login(root, ids[-1] if ids else None,
                       "last NameID, signature element required but not verified")


@app.route("/saml/whoami")
def saml_whoami():
    tok = request.cookies.get("saml_session") or request.headers.get("X-Saml-Session", "")
    sess = SAML_SESSIONS.get(tok)
    if not sess:
        return Response("no saml session", status=401)
    return {"subject": sess["subject"], "nameid_full_text": sess["raw_nameid"],
            "secret": "MYTHOS_LAB_CANARY_saml_session_data"}


# ---- OIDC relying party (deliberately broken) -------------------------
@app.route("/oidc/callback")
def oidc_callback():
    # VULN: `state` is echoed back and never compared with anything this RP
    # stored, so a callback minted elsewhere completes a login here.
    code = request.args.get("code", "")
    rec = CODES.get(code)
    if not rec:
        return Response(json.dumps({"error": "invalid_grant"}), status=400,
                        mimetype="application/json")
    tok = "MYTHOS_LAB_CANARY_rp_" + secrets.token_hex(6)
    SESSIONS[tok] = {"user": rec["user"], "mfa": True, "role": "user"}
    resp = make_response({"ok": True, "user": rec["user"], "session": tok,
                          "state_seen": request.args.get("state", ""),
                          "state_checked": False})
    resp.set_cookie("session", tok)
    return resp


def _jwt_part(token: str, index: int) -> dict:
    try:
        part = token.split(".")[index]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:                              # noqa: BLE001 - lab target
        return {}


@app.route("/oidc/link", methods=["POST"])
def oidc_link():
    # VULN, four of them: the id_token signature is never checked, `aud` is
    # never compared with this RP's client_id, `email_verified` is ignored, and
    # the account is keyed on `email` rather than on (iss, sub). An access
    # token is also accepted where an id_token belongs.
    data = request.get_json(silent=True) or request.form
    token = data.get("id_token") or data.get("access_token") or ""
    if not token:
        return Response(json.dumps({"error": "no token"}), status=400,
                        mimetype="application/json")
    claims = _jwt_part(token, 1)
    email = (claims.get("email") or "").strip().lower()
    substituted = not data.get("id_token")
    local = next((u for u, r in USERS.items() if r["email"].lower() == email), None)
    if not local:
        return Response(json.dumps({"error": "no local account for that email",
                                    "email": email}), status=404,
                        mimetype="application/json")
    OIDC_LINKS[local] = {"iss": claims.get("iss", ""), "sub": claims.get("sub", ""),
                         "email": email}
    tok = "MYTHOS_LAB_CANARY_link_" + secrets.token_hex(6)
    SESSIONS[tok] = {"user": local, "mfa": True, "role": USERS[local]["role"]}
    resp = make_response({"ok": True, "linked_to": local, "session": tok,
                          "alg_seen": _jwt_part(token, 0).get("alg", "?"),
                          "signature_checked": False,
                          "aud_seen": claims.get("aud", ""),
                          "aud_checked": False,
                          "email_verified_seen": claims.get("email_verified", None),
                          "email_verified_checked": False,
                          "token_was_an_access_token": substituted,
                          "secret": USERS[local]["secret"]})
    resp.set_cookie("session", tok)
    return resp


@app.route("/oidc/unlink", methods=["POST"])
def oidc_unlink():
    # VULN: the federated identity is dropped and every session it created
    # stays valid, so revoking the link revokes nothing.
    sess = _session()
    if not sess:
        return Response("no session", status=401)
    OIDC_LINKS.pop(sess["user"], None)
    return {"ok": True, "unlinked": sess["user"], "sessions_revoked": 0}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True, use_reloader=False)
