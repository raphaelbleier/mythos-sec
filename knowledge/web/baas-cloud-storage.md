# Backend-as-a-Service and Cloud Storage (Supabase, Firebase, S3/blob, presigned URLs)

**Class:** access control / misconfiguration  **Updated:** 2026-11-13

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

## Proof standard
`reproduced` = the request above returns data or a count as a principal that
should be refused, with the three-principal controls. `validated(proof)` =
the stored PoC re-run in a fresh context returns the same count or the same
canary. State the table, the policy gap (anon read, userA reads B, write
allowed) and the count, never row contents.

Does NOT count: the anon key itself in a bundle; a table that is public by
design (check the app's UI); a bucket that lists only intentionally public
assets; a presigned URL that works for the key it was issued for; `service_role`
or admin credentials "tried" to prove they work (stop at presence).

## Remediation
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
