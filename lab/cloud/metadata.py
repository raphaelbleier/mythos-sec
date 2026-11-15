"""Cloud instance-metadata emulator — fixture for the cloud-metadata package.

Imitates the three metadata surfaces with their real access requirements, so
the difference between them is testable:

  IMDSv1  GET /latest/meta-data/iam/security-credentials/<role>   no header
  IMDSv2  PUT /latest/api/token  -> token, then GET with
          X-aws-ec2-metadata-token; a GET without it is 401
  GCP     GET /computeMetadata/v1/...        needs Metadata-Flavor: Google
  Azure   GET /metadata/identity/oauth2/token  needs Metadata: true

IMDS_REQUIRE_TOKEN=1 turns this instance into an IMDSv2-only one, which is the
case that only falls to an SSRF controlling method and headers. The compose
file runs one instance of each.

Every credential is the canary MYTHOS_LAB_CANARY and nothing else: it is a
string to grep for, not a key. Local lab only. Do not deploy it.
"""

from __future__ import annotations

import os

from flask import Flask, Response, request

app = Flask(__name__)

CANARY = "MYTHOS_LAB_CANARY"
REQUIRE_TOKEN = os.environ.get("IMDS_REQUIRE_TOKEN", "0") == "1"
TOKEN = "MYTHOS_LAB_CANARY_imdsv2_token"
ROLE = "mythos-lab-role"

AWS_CREDS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": f"ASIA{CANARY}0000",
    "SecretAccessKey": f"{CANARY}/aws-secret-access-key",
    "Token": f"{CANARY}.aws-session-token",
    "Expiration": "2099-01-01T00:00:00Z",
}


def _text(body: str) -> Response:
    return Response(body, mimetype="text/plain")


@app.route("/")
def index():
    return _text("mythos lab metadata emulator\n"
                 f"imdsv2 token required: {REQUIRE_TOKEN}\n")


# ---- AWS ---------------------------------------------------------------
@app.route("/latest/api/token", methods=["PUT", "GET"])
def imds_token():
    # IMDSv2 only hands a token to PUT, which is what keeps a plain
    # <img src> or a URL-only SSRF out.
    if request.method != "PUT":
        return _text("method not allowed")
    return _text(TOKEN)


def _imds_guard() -> Response | None:
    if not REQUIRE_TOKEN:
        return None  # VULN (by design): IMDSv1 enabled, no header needed
    if request.headers.get("X-aws-ec2-metadata-token") == TOKEN:
        return None
    return Response("401 - Unauthorized", status=401, mimetype="text/plain")


@app.route("/latest/meta-data/")
def imds_root():
    return _imds_guard() or _text("iam/\ninstance-id\nhostname\n")


@app.route("/latest/meta-data/instance-id")
def imds_instance_id():
    return _imds_guard() or _text("i-0mythoslab0000000")


@app.route("/latest/meta-data/iam/security-credentials/")
def imds_role_list():
    return _imds_guard() or _text(ROLE)


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def imds_creds(role):
    denied = _imds_guard()
    if denied:
        return denied
    if role != ROLE:
        return Response("404 - Not Found", status=404, mimetype="text/plain")
    return AWS_CREDS


# ---- GCP ---------------------------------------------------------------
@app.route("/computeMetadata/v1/<path:rest>")
def gcp(rest):
    # The Metadata-Flavor header is GCP's whole defence against a
    # header-less SSRF; this emulator enforces it exactly.
    if request.headers.get("Metadata-Flavor") != "Google":
        return Response("Metadata-Flavor: Google header required", status=403,
                        mimetype="text/plain")
    if rest.endswith("service-accounts/default/token"):
        return {"access_token": f"ya29.{CANARY}.gcp-access-token",
                "expires_in": 3599, "token_type": "Bearer"}
    if rest.endswith("service-accounts/default/email"):
        return _text("mythos-lab@mythos-lab.iam.gserviceaccount.com")
    return _text("project/\ninstance/\n")


# ---- Azure -------------------------------------------------------------
@app.route("/metadata/identity/oauth2/token")
@app.route("/metadata/instance")
def azure():
    if request.headers.get("Metadata") != "true":
        return {"error": "invalid_request",
                "error_description": "Required metadata header not specified"}, 400
    if request.path.endswith("/token"):
        return {"access_token": f"{CANARY}.azure-access-token",
                "client_id": f"{CANARY}-0000-0000-0000-000000000000",
                "expires_in": "3599", "resource": request.args.get(
                    "resource", "https://management.azure.com/"),
                "token_type": "Bearer"}
    return {"compute": {"name": "mythos-lab", "location": "lab",
                        "subscriptionId": f"{CANARY}-sub"}}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "80")),
            threaded=True, use_reloader=False)
