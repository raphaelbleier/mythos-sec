# Backend-as-a-Service and Cloud Storage (Supabase, Firebase, S3/blob, presigned URLs)

**Class:** access control / misconfiguration  **Updated:** 2026-11-15

## What it is
Front-end apps talk to a hosted backend directly, so the browser holds a
project URL and a public key, and authorization lives in database policies
(Postgres row-level security, Firebase rules) or bucket policies, not in app
code. The public key is meant to be public; the bug is a missing or too wide
policy. UpGuard fingerprinted Supabase URLs and key names in public JavaScript
for about 300,000 domains and found 16,326 databases with readable tables;
root causes it names: RLS off on tables created through the API (RLS is on by
default only for tables made in the Table Editor), policies that exist but do
not restrict, and public keys treated as secrets. Lovable CVE-2025-48757
(NVD, published 2025-05-30, CWE-863) is the same failure in generated apps:
insufficient RLS policies in Lovable through 2025-04-15 let unauthenticated
callers read or write tables of generated sites.

## How Mythos detects it
- Pull the project URL and key out of the JS bundles `scripts/probe` and the
  browser agent saved: `https://<ref>.supabase.co`, `apikey`/`sb_publishable_`
  / `eyJ...` JWT whose payload has `"role":"anon"`, `firebaseConfig`
  (`apiKey`, `projectId`, `databaseURL`), bucket names and `*.s3.amazonaws.com`
  or `*.blob.core.windows.net` hosts in network logs.
- A JWT with `"role":"service_role"` (or a Firebase admin credential) in a
  client bundle is a critical finding on sight: it bypasses RLS. Report the
  presence, do not use it.
- nuclei `-tags supabase,firebase,s3` for known exposures (candidates only).
- `scripts/cloudexp harvest <url>` does the pull above deterministically, from
  the page, its CSS, its JS, its source maps and its response headers, and
  keeps the source of every name (a bucket that only `sourcesContent` mentions
  was stripped from the shipped bundle and is still in the map). Then
  `scripts/cloudexp buckets`, `presigned`, `serverless` and `clientcreds`
  classify what each one permits. All of it is GET/HEAD/OPTIONS; the script
  contains no write verb at all. `skills/cloud-exposure/SKILL.md` is the
  step order.

## A bucket the page links is not in scope because the page links it
A storage endpoint is a third party, and a request to it is a request we made
(AGENTS.md: "a request the target makes on your behalf counts as yours" — the
same reasoning applies to one we send ourselves). `vendor-assets.s3.amazonaws.com`
in an `<img>` is usually a vendor's bucket in a vendor's account, and probing it
is testing a company nobody authorized us to test; `<project>.supabase.co` and
`<app>.azurewebsites.net` are the target's own tenancy on someone else's
infrastructure, which the programme may still exclude. So every destination is
checked against `engagements/<dir>/scope.yaml` before the socket opens, a
refused one is reported as refused rather than probed, and widening is a human
action in an editor. `scripts/cloudexp` implements that as a refusal, not a
warning, and lists every destination it declined. Name the ones you left alone
in `recon.md`: an unprobed vendor bucket is a decision, and a silent gap is not.

## How to confirm (non-destructive)
Read counts and headers only; never dump rows, never print personal data into
the finding. Redact values in the evidence.

```
# Supabase REST (PostgREST). Count only, no rows:
curl -sI "https://<ref>.supabase.co/rest/v1/<table>?select=id" \
  -H "apikey: <anon>" -H "Authorization: Bearer <anon>" -H "Prefer: count=exact" -H "Range: 0-0"
#   Content-Range: 0-0/1523   -> readable by anon; the count is the proof
# Table list from the OpenAPI doc (anon):
curl -s "https://<ref>.supabase.co/rest/v1/" -H "apikey: <anon>"
# Firebase RTDB shallow read (keys only), Firestore listing:
curl -s "https://<project>.firebaseio.com/.json?shallow=true&limitToFirst=1"
# S3 / blob: listing and HEAD
curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2&max-keys=1"
curl -sI "https://<bucket>.s3.amazonaws.com/<key>"
```

Row-level security, three principals on the agent's own rows:
1. anonymous (anon key, no user token), 2. userA (own JWT from sign-up with a
self-created account), 3. userB. Create one row per user with a canary, then
as userA request B's row by id and by filter (`?id=eq.<B_id>`,
`?owner_id=eq.<B_uid>`), and try the write verbs on B's canary row only
(`PATCH` with `Prefer: return=minimal`, read back as B). Controls: userA reads
its own row, anon on an auth-required table is refused (empty array or 401), a
filter for a non-existent id returns `[]`. A `200 []` is silent enforcement,
not a finding; a `200` with a count above zero where the table should be
private is.

### Per permission, not per bucket
`list` and `get` are different permissions on different resources, and
conflating them is the common reporting error:

| what you probed | S3 permission | resource |
|---|---|---|
| `GET /?list-type=2&max-keys=1` | `s3:ListBucket` | `arn:aws:s3:::bucket` |
| `GET /<key>` | `s3:GetObject` | `arn:aws:s3:::bucket/*` |
| `GET /?acl` | `s3:GetBucketAcl` | `arn:aws:s3:::bucket` |
| `GET /?policy` | `s3:GetBucketPolicy` | `arn:aws:s3:::bucket` |

A policy granting `GetObject` on `bucket/*` with no `ListBucket` on `bucket`
gives an attacker every object whose key they can guess, and reads as secure to
a listing-only check — so a successful listing is never "the bucket is
readable", and a denied listing is never "the objects are safe". On GCS the
pair is `storage.objects.list` versus `storage.objects.get`; on Azure the
container's public access level is `Container` (list + read) or `Blob` (read
only, no list) or off.

### Public write, shown by reading
Never prove write by writing: a test object is data created in someone else's
account. Three read-only sources, in order of strength:
- `GET /?policy` — a `Statement` with `Effect: Allow`, `Principal: "*"` (or
  `{"AWS":"*"}`) and an `s3:PutObject`/`s3:DeleteObject`/`s3:*` action. The
  statement text *is* the finding; quote its `Sid`, actions and resource.
- `GET /?acl` — a `Grant` whose `Grantee` URI is
  `http://acs.amazonaws.com/groups/global/AllUsers` (or `AuthenticatedUsers`,
  which means any AWS account, not "logged in to this app") with `WRITE`,
  `WRITE_ACP` or `FULL_CONTROL`.
- `GET /?policyStatus` — `<IsPublic>true</IsPublic>`, which says public but not
  which verb.
On GCS the equivalent is the bucket IAM policy (`/storage/v1/b/<b>/iam`) binding
`allUsers` or `allAuthenticatedUsers` to a role containing admin/creator/writer
/owner. On Azure neither the public access level nor a SAS's permissions are
readable from the wire: read `sp` off a SAS the operator holds instead. Where
none of these reads, the verdict is `inconclusive` with "proving it would need a
write" — not a write.

### Why a denial is usually `inconclusive`
From outside, `AccessDenied` can be a bucket policy, an identity policy, an
organization SCP, an S3 Block Public Access setting or a bucket in another
account entirely; on GCS a missing IAM binding, a VPC Service Controls
perimeter and an org policy look identical; on Azure the container's access
level, the account's allow-blob-anonymous-access switch and an absent SAS all
answer `AuthenticationFailed`. Report `inconclusive` and name the possibilities
rather than asserting the control. The error codes worth telling apart:
`NoSuchBucket` (the name is unused in this region) and `NoSuchKey` (the bucket
answered, the key is gone) are absence, not denial; `PermanentRedirect` or
`AuthorizationHeaderMalformed` is the wrong region and the right one is in
`x-amz-bucket-region`; `AllAccessDisabled` is Block Public Access.

Presigned URLs (S3, GCS, Azure SAS): the URL is a bearer token bound to
method, bucket, key and expiry, signed by whoever issued it. Test only URLs
the agent's own account was issued:
- key tampering: change the key in the path; expect `SignatureDoesNotMatch`.
  Success means the signer does not bind the key;
- content-type and size: upload with a different `Content-Type` than was
  signed; check whether the issuing endpoint allows `.html`/`.svg` served
  inline from the app origin (stored XSS, see `knowledge/web/file-upload.md`);
- expiry: an `X-Amz-Expires` or `se=` change must fail; the S3 docs say
  Signature V4 URLs from IAM user credentials last up to 7 days, and role
  credentials end the URL when the session ends, so a very long expiry in a
  URL for sensitive data is a design note, not a bypass;
- IDOR on the issuing endpoint: `POST /api/files/presign {"key":"<B key>"}` as
  userA (BOLA, see `knowledge/web/multi-tenant-isolation.md`).

`scripts/cloudexp presigned <url>` reads all of the following off the URL with
no request at all, and `--probe` sends the four read-only arms (baseline,
swapped key, raised expiry, one signed parameter dropped) as `GET` with
`Range: bytes=0-0`, because the question is whether the signature is accepted
and the bytes are not ours to pull:
- **signature version and scope.** SigV4 carries
  `X-Amz-Credential=<keyid>/<date>/<region>/<service>/aws4_request`, so the key
  id, the region and the service are in the URL. `AWSAccessKeyId` + `Expires` +
  `Signature` instead is SigV2, SHA-1 based and deprecated. GCS V4 is the same
  shape under `X-Goog-*`.
- **expiry.** Absolute expiry is `X-Amz-Date` + `X-Amz-Expires`; the SigV4
  query-signing ceiling is 604800s, so a larger value was rejected at issue.
  An `X-Amz-Security-Token` in the URL means role credentials, and the URL dies
  with that session whatever the expiry says — a long expiry there is cosmetic.
  For a SAS, `st`/`se` are the window, `sp` the permissions, `sr` the resource
  and `si` a stored access policy; **without `si` a SAS cannot be revoked
  before `se` without rotating the account key**, which is the finding on a
  long-lived SAS.
- **extension is not a bypass.** The expiry is part of the string to sign in
  SigV4, SigV2 and a SAS, so editing it yields `SignatureDoesNotMatch` /
  `AuthenticationFailed`. The finding is the lifetime the signer chose. The real
  test is truncation: drop a signed parameter (`X-Amz-SignedHeaders`, `sp`) and
  an endpoint that still answers is not verifying the whole signed set.
- **the leak is structural.** The credential is in the query string, so the URL
  is in access logs, in browser history, and in the `Referer` of any
  cross-origin subresource a page embedding it requests unless that page sends
  `Referrer-Policy: no-referrer` or `same-origin`. A presigned URL found in a
  page or a bundle by `cloudexp harvest` has already leaked to everyone who
  loaded it, and `X-Amz-SignedHeaders=host` alone means every other header,
  including the served `Content-Type` and `Content-Disposition`, is free (see
  `knowledge/web/file-upload.md`).

## Serverless front doors and the keys that guard them
The same class, one layer out: the bucket's neighbours in the client bundle.
- **Lambda function URL** (`<id>.lambda-url.<region>.on.aws`) has exactly two
  auth types. `NONE` answers an unsigned request and is public to everyone;
  `AWS_IAM` answers `403 {"Message":"Forbidden"}`. No API key, no authorizer, no
  WAF in between. `x-amzn-RequestId` proves the answer came from Lambda.
- **API Gateway** (`<id>.execute-api.<region>.amazonaws.com/<stage>`): the error
  vocabulary is the oracle. `Missing Authentication Token` is a **route that
  does not exist on that stage**, not an authorizer — misreporting it as
  "authentication required" is the standard mistake. `Forbidden` is an API key
  or a resource policy, `Unauthorized` is a Lambda or Cognito authorizer
  rejecting, and `Not Found` is an HTTP API with no matching route. An HTTP API
  with a `$default` route answers *every* path, so one unguarded route is every
  path, while a REST API routes each resource separately. One stage open while
  another is guarded is the finding; guessing stage names is a sweep, so probe
  only the names the operator knows.
- **Cloud Run / Cloud Functions**: anonymous `403 "Your client does not have
  permission to get URL"` is `--no-allow-unauthenticated` working; anything
  under 400 is `allUsers` on the invoker role.
- **Azure Functions**: the `?code=` key *is* the authorization. A function key
  opens one function, a host key every function in the app, the master key the
  admin API — so a key in a bundle means no authorization at all. Report the
  presence; use it only against the operator's own function.

## Orchestrator ports reachable from the same surface
A kubelet or a Docker socket on a routable address is in this class because the
application's own host exposes it, and each one needs a fingerprint, not just an
open port (`scripts/cloudexp orchestrator`). `/pods` on the kubelet read-only
port 10255 is every pod with its environment and service-account mounts, with no
authentication by design (off by default since Kubernetes 1.10, so it was turned
on deliberately); a `PodList` instead of a `401` on 10250 is
`anonymous-auth=true`, which is worse because `/run` and `/exec` are on that
port. `/metrics` and `/healthz` disclose the version that `scripts/cvefeed
match` needs. etcd on 2379 holds every Secret in plaintext unless encryption at
rest is on, so `/version` answering is the whole finding and no key needs
reading. The Docker API on 2375 is root on the host. Consul's default ACL policy
is allow and Nomad's ACLs are off by default. A `401` or `403` from any of these
is the correct answer and is not a finding; a 200 whose fingerprint does not
match is `inconclusive`, because something else may be on the port.

## Proof standard
`reproduced` = the request above returns data or a count as a principal that
should be refused, with the three-principal controls. `validated(proof)` =
the stored PoC re-run in a fresh context returns the same count or the same
canary. State the table, the policy gap (anon read, userA reads B, write
allowed) and the count, never row contents.

Does NOT count: the anon key itself in a bundle; a published Firebase config or
an `AIza` browser API key on its own (the finding is the rules, or the key being
unrestricted); a Cognito user-pool id; a table that is public by design (check
the app's UI); a bucket that lists only intentionally public assets; a presigned
URL that works for the key it was issued for; an edited expiry that fails
(it is signed); `Missing Authentication Token` from API Gateway read as an
authorizer; a `401`/`403` from a kubelet, Dashboard or Docker API; an open port
with no matching fingerprint; `service_role` or admin credentials "tried" to
prove they work (stop at presence).

## Remediation
Block public ACLs and public bucket policies account-wide (S3 Block Public
Access, Azure's allow-blob-anonymous-access switch off, GCS public access
prevention); grant object read without bucket list where a listing is not
needed; sign presigned URLs for one key, one method and minutes rather than
days, and back every SAS with a stored access policy so it can be revoked; set
`Referrer-Policy: no-referrer` on pages that embed a presigned URL; put every
Lambda function URL behind `AWS_IAM` or an API Gateway with an authorizer on
every stage and no unintended `$default` route; keep Azure Functions keys
server-side; disable the kubelet read-only port and `anonymous-auth`, require
client certificates on etcd and never expose the Docker API over TCP.
Enable RLS on every table in an exposed schema and write explicit policies per
role; keep `service_role` and admin keys server-side only; sign presigned URLs
for one key, method and short expiry and check ownership before signing; block
public bucket listing.

## Sources
- UpGuard, "Everything, Everywhere: Systemic Data Exposure in Supabase Apps"
  (Greg Pollock; UpGuard page dated 2026-10-14, press coverage from 2026-09-25;
  the two dates disagree, treat the month as 2026-09/10).
- NVD, CVE-2025-48757 (Lovable, published 2025-05-30; disclosed by Matt Palmer).
- Supabase docs, Row Level Security (accessed 2026-11-13): `anon` vs
  `authenticated` roles, `service_role` bypasses RLS.
- AWS docs, "Download and upload objects with presigned URLs" (accessed 2026-11-13).
- AWS S3 API Reference error responses, AWS IAM policy reference for the
  `bucket` versus `bucket/*` resource split, AWS Lambda function URL auth types,
  API Gateway REST versus HTTP API error responses, Azure Storage REST error
  codes and SAS parameters, Google Cloud Storage JSON API errors and IAM
  (all general knowledge, not re-verified against a dated source in this
  update — check the current docs before quoting a limit).
