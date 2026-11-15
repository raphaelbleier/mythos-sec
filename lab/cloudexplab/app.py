"""Deliberately misconfigured cloud / Kubernetes exposure — cloudexp fixture.

One stdlib HTTP server standing in for five third parties at once, so
`scripts/cloudexp` can be exercised end to end without touching a real cloud
account. Everything here is read-only and every fake credential contains the
literal string MYTHOS_LAB_CANARY, so a run greps for exactly one token and
nothing in this file resembles a real key.

Bound to 127.0.0.1 only. Local lab, never deployed.

    python3 lab/cloudexplab/app.py [--port 5025]

    page / bundle / map / css        http://127.0.0.1:5025/
    S3-style endpoint (path style)   http://127.0.0.1:5025/s3
    GCS-style JSON API               http://127.0.0.1:5025/gcs
    Azure Blob-style endpoint        http://127.0.0.1:5025/azure
    Lambda function URL, no auth     http://127.0.0.1:5025/lambda/
    API Gateway, two stages          http://127.0.0.1:5025/{prod,dev}/items
    kubelet read-only shapes         http://127.0.0.1:5025/{pods,metrics,healthz}

Buckets served by the S3 leg:
  mythos-lab-public   list allowed, one object readable, one 403, an ACL with
                      the AllUsers WRITE grant and a policy with s3:PutObject
                      for Principal "*" — public write, provable without a PUT
  mythos-lab-private  403 AccessDenied on everything
  mythos-lab-missing  404 NoSuchBucket
"""

from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import urllib.parse

CANARY = "MYTHOS_LAB_CANARY"
# A presigned URL that expired in the past: the expiry arithmetic is the thing
# under test, and a fixed date keeps the fixture deterministic.
PRESIGNED = (
    "https://mythos-lab-public.s3.eu-central-1.amazonaws.com/reports/q3.pdf"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
    f"&X-Amz-Credential=ASIA{CANARY}0000%2F20260101%2Feu-central-1%2Fs3%2Faws4_request"
    "&X-Amz-Date=20260101T000000Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host"
    f"&X-Amz-Security-Token={CANARY}.aws-session-token"
    f"&X-Amz-Signature={'a1b2c3d4' * 8}")

PAGE = f"""<!doctype html>
<html><head><title>Mythos CloudExpLab</title>
<link rel="stylesheet" href="/static/app.css">
<script>
// VULN (by design): the whole Firebase config in the page, as every Firebase
// quickstart does. Public by design; the finding is the security rules.
var firebaseConfig = {{
  apiKey: "AIza{CANARY}000000000000000000",   // AIza + 35 chars, the real shape
  authDomain: "mythos-lab.firebaseapp.com",
  databaseURL: "https://mythos-lab-default-rtdb.firebaseio.com",
  projectId: "mythos-lab",
  storageBucket: "mythos-lab.appspot.com",
  messagingSenderId: "109900001111",
  appId: "1:109900001111:web:{CANARY}"
}};
</script></head>
<body>
<h1>CloudExpLab</h1>
<img src="{PRESIGNED}" alt="q3 report">
<a href="https://mythos-lab-public.s3.amazonaws.com/public.txt">asset</a>
<a href="https://mythoslabstorage.blob.core.windows.net/uploads/readme.txt">upload</a>
<a href="https://storage.googleapis.com/mythos-lab-gcs/logo.svg">logo</a>
<a href="https://ab12cd34ef.lambda-url.eu-central-1.on.aws/">serverless</a>
<a href="https://ab12cd34ef.execute-api.eu-central-1.amazonaws.com/prod/items">api</a>
<a href="https://mythos-lab-fn.azurewebsites.net/api/report?code={CANARY}functionkey">report</a>
<a href="https://mythos-lab-run-109900001111.europe-west1.run.app/">run</a>
<script src="/static/app.js"></script>
</body></html>
"""

BUNDLE = f"""// build output, do not edit
export const SUPABASE_URL = "https://mythoslabref.supabase.co";
// VULN (by design): an anon key is meant to be published. The finding is a
// table with row-level security off, not this string.
export const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiJ9.{CANARY}_anon_role_payload.{CANARY}signature";
export const REPORT_URL =
  "https://mythos-lab-fn.azurewebsites.net/api/report?code={CANARY}functionkey00";
export const BUCKETS = ["mythos-lab-public", "mythos-lab-private",
                        "mythos-lab-assets.s3.amazonaws.com"];
export const AZURE_CONTAINER = "https://mythoslabstorage.blob.core.windows.net/uploads";
//# sourceMappingURL=app.js.map
"""

BUNDLE_MAP = json.dumps({
    "version": 3,
    "sources": ["src/config.ts", "src/upload.ts"],
    "sourcesContent": [
        'export const INTERNAL_BUCKET =\n'
        '  "https://mythos-lab-internal-backups.s3.eu-central-1.amazonaws.com";\n',
        'export const SIGNER = "https://mythos-lab-fn.azurewebsites.net/api/presign";\n'],
    "mappings": "",
})

CSS = """body{font:14px system-ui}
h1{background:url(https://mythos-lab-assets.s3.amazonaws.com/bg.png) no-repeat}
.logo{background-image:url("https://storage.googleapis.com/mythos-lab-gcs/logo.svg")}
"""

LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>mythos-lab-public</Name><Prefix></Prefix><KeyCount>2</KeyCount>
<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>
<Contents><Key>public.txt</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified>
<Size>12</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>private.txt</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified>
<Size>34</Size><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>"""

# VULN (by design): the AllUsers WRITE grant. This is how public write is shown
# without ever sending a PUT.
ACL_XML = """<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner><ID>mythoslabowner</ID></Owner><AccessControlList>
<Grant><Grantee xsi:type="Group"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
<Permission>READ</Permission></Grant>
<Grant><Grantee xsi:type="Group"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
<Permission>WRITE</Permission></Grant>
</AccessControlList></AccessControlPolicy>"""

BUCKET_POLICY = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
     "Action": ["s3:GetObject"],
     "Resource": "arn:aws:s3:::mythos-lab-public/*"},
    # VULN (by design): anonymous write, readable straight off the policy.
    {"Sid": "PublicUpload", "Effect": "Allow", "Principal": {"AWS": "*"},
     "Action": ["s3:PutObject", "s3:DeleteObject"],
     "Resource": "arn:aws:s3:::mythos-lab-public/*"}]})

POD_LIST = json.dumps({"kind": "PodList", "apiVersion": "v1", "metadata": {},
                       "items": [{"metadata": {"name": "mythos-lab-web-0",
                                               "namespace": "default"},
                                  "spec": {"nodeName": "mythos-lab-node",
                                           "containers": [{"name": "web",
                                                           "image": "mythos/lab:1"}]},
                                  "status": {"phase": "Running"}}]})

KUBELET_METRICS = """# HELP kubelet_running_pods Number of pods currently running
# TYPE kubelet_running_pods gauge
kubelet_running_pods 1
# HELP kubernetes_build_info A metric with a constant 1 value
# TYPE kubernetes_build_info gauge
kubernetes_build_info{gitVersion="v1.29.4",major="1",minor="29"} 1
"""


def s3_error(code, msg, status):
    return (status, "application/xml",
            f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{code}</Code>'
            f"<Message>{msg}</Message><RequestId>MYTHOSLAB0001</RequestId></Error>")


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MythosCloudExpLab/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet; the script under test is the output
        pass

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_GET(self, head=False):
        parts = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        status, ctype, body, extra = self.route(parts.path, parts.query, q)
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(raw)

    # ------------------------------------------------------------ routing
    def route(self, path, query, q):
        extra = {}
        if path == "/":
            return 200, "text/html", PAGE, {}
        if path == "/static/app.js":
            return 200, "application/javascript", BUNDLE, {}
        if path == "/static/app.js.map":
            return 200, "application/json", BUNDLE_MAP, {}
        if path == "/static/app.css":
            return 200, "text/css", CSS, {}
        if path == "/api/config":
            # VULN (by design): a reflected CORS allow-origin, and a bucket host
            # named in a response header, which is one of the harvest sources.
            extra = {"Access-Control-Allow-Origin": self.headers.get("Origin", "*"),
                     "Access-Control-Allow-Credentials": "true",
                     "X-Asset-Host": "mythos-lab-assets.s3.amazonaws.com"}
            return 200, "application/json", json.dumps(
                {"bucket": "mythos-lab-public",
                 "blob": "https://mythoslabstorage.blob.core.windows.net/uploads"}), extra

        if path.startswith("/s3/"):
            return self.s3(path[len("/s3"):], q)
        if path.startswith("/gcs/"):
            return self.gcs(path[len("/gcs"):], q)
        if path.startswith("/azure/"):
            return self.azure(path[len("/azure"):], q)
        if path.startswith("/lambda"):
            # VULN (by design): a Lambda function URL with AuthType NONE. It
            # answers anyone, and the response carries the AWS request id that
            # fingerprints it.
            return (200, "application/json",
                    json.dumps({"ok": True, "event": {"rawPath": path},
                                "env": {"AWS_LAMBDA_FUNCTION_NAME": "mythos-lab-fn"}}),
                    {"x-amzn-RequestId": "11111111-2222-3333-4444-555555555555",
                     "x-amzn-Remapped-Content-Length": "0"})
        if path.startswith(("/prod/", "/dev/")):
            # API Gateway puts the stage in the first path segment, so these sit
            # at the root rather than behind a prefix.
            return self.apigw(path)

        # ---- orchestrator shapes, at the root like the real daemons ----
        if path == "/pods":
            return 200, "application/json", POD_LIST, {}
        if path == "/metrics":
            return 200, "text/plain", KUBELET_METRICS, {}
        if path == "/healthz":
            # VULN (by design): version disclosure on an unauthenticated healthz.
            return 200, "text/plain", "ok\nkubelet v1.29.4\n", {}
        if path == "/spec":
            return 200, "application/json", json.dumps(
                {"num_cores": 4, "memory_capacity": 8589934592,
                 "machine_id": "mythoslab"}), {}
        if path == "/version":
            return 200, "application/json", json.dumps(
                {"major": "1", "minor": "29", "gitVersion": "v1.29.4"}), {}
        if path == "/v1/status/leader":
            return 200, "application/json", '"10.0.0.5:8300"', {}
        return 404, "text/plain", "not found\n", {}

    def s3(self, path, q):
        bucket, _, key = path.lstrip("/").partition("/")
        if bucket == "mythos-lab-missing":
            return s3_error("NoSuchBucket", "The specified bucket does not exist",
                            404) + ({},)
        if bucket == "mythos-lab-private":
            return s3_error("AccessDenied", "Access Denied", 403) + ({},)
        if bucket != "mythos-lab-public":
            return s3_error("NoSuchBucket", "The specified bucket does not exist",
                            404) + ({},)
        if "acl" in q:
            return 200, "application/xml", ACL_XML, {}
        if "cors" in q:
            return s3_error("NoSuchCORSConfiguration",
                            "The CORS configuration does not exist", 404) + ({},)
        if "policy" in q:
            return 200, "application/json", BUCKET_POLICY, {}
        if "policyStatus" in q:
            return (200, "application/xml",
                    "<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>", {})
        if not key:
            # VULN (by design): anonymous bucket listing.
            return 200, "application/xml", LIST_XML, {}
        if key == "public.txt":
            return 200, "text/plain", "public object\n", {}
        if key == "private.txt":
            # The bucket lists, but this object does not read: the
            # `bucket` versus `bucket/*` distinction, live.
            return s3_error("AccessDenied", "Access Denied", 403) + ({},)
        return s3_error("NoSuchKey", "The specified key does not exist", 404) + ({},)

    def gcs(self, path, q):
        if path.startswith("/storage/v1/b/"):
            rest = path[len("/storage/v1/b/"):]
            bucket, _, tail = rest.partition("/")
            if bucket != "mythos-lab-gcs":
                return (404, "application/json", json.dumps(
                    {"error": {"code": 404, "message": "The specified bucket does "
                                                       "not exist.",
                               "errors": [{"reason": "notFound"}]}}), {})
            if tail.startswith("iam"):
                return (403, "application/json", json.dumps(
                    {"error": {"code": 403, "message":
                        "anonymous caller does not have storage.buckets.getIamPolicy "
                        "access to the Google Cloud Storage bucket.",
                               "errors": [{"reason": "forbidden"}]}}), {})
            # VULN (by design): anonymous object listing.
            return (200, "application/json", json.dumps(
                {"kind": "storage#objects", "items": [
                    {"name": "logo.svg", "size": "921"},
                    {"name": "private/export.csv", "size": "4096"}]}), {})
        return (404, "application/json",
                json.dumps({"error": {"code": 404, "message": "Not Found"}}), {})

    def azure(self, path, q):
        container = path.strip("/").split("/")[0]
        if container != "uploads":
            return (404, "application/xml",
                    '<?xml version="1.0" encoding="utf-8"?><Error>'
                    "<Code>ContainerNotFound</Code><Message>The specified container "
                    "does not exist.</Message></Error>", {})
        if "sig" in q and "sv" in q:
            # A SAS token is presented, so the listing answers.
            return (200, "application/xml",
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<EnumerationResults ContainerName="uploads"><Blobs>'
                    "<Blob><Name>readme.txt</Name></Blob></Blobs>"
                    "<NextMarker /></EnumerationResults>", {})
        # The error body the brief names: anonymous access with no SAS.
        return (403, "application/xml",
                '<?xml version="1.0" encoding="utf-8"?><Error>'
                "<Code>AuthenticationFailed</Code><Message>Server failed to "
                "authenticate the request. Make sure the value of Authorization "
                "header is formed correctly including the signature."
                "</Message></Error>",
                {"x-ms-error-code": "AuthenticationFailed"})

    def apigw(self, path):
        if path.startswith("/prod/"):
            # VULN (by design): the prod stage has no authorizer on this route.
            return 200, "application/json", json.dumps(
                {"items": [{"id": 1, "owner": "alice"}]}), {}
        if path.startswith("/dev/"):
            return (401, "application/json", json.dumps({"message": "Unauthorized"}),
                    {"x-amzn-ErrorType": "UnauthorizedException"})
        return (403, "application/json",
                json.dumps({"message": "Missing Authentication Token"}),
                {"x-amzn-ErrorType": "MissingAuthenticationTokenException"})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=5025)
    # Loopback by default. The only reason to change it is a container, whose
    # own namespace has no 127.0.0.1 route from outside: compose then publishes
    # it on the host's loopback (MYTHOS_LAB_BIND). Never pass 0.0.0.0 on a host.
    ap.add_argument("--bind", default="127.0.0.1",
                    help="interface to bind (default 127.0.0.1; use 0.0.0.0 only "
                         "INSIDE a container whose port is published on loopback)")
    a = ap.parse_args()
    with Server((a.bind, a.port), Handler) as srv:
        print(f"cloudexplab on http://{a.bind}:{srv.server_address[1]}/")
        srv.serve_forever()


if __name__ == "__main__":
    main()
