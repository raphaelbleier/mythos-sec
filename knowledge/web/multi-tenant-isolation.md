# Multi-Tenant Isolation (cross-tenant read, write, enumeration)

**Class:** access control / business logic  **Updated:** 2026-11-13

## What it is
A SaaS keeps many customers ("tenants", orgs, workspaces) in one deployment.
Isolation is enforced per layer (database row, object store key, search index,
cache key, queue, job runner, webhook target), and each layer can forget the
tenant. One missing tenant filter at any layer is a cross-tenant leak, and it
pays more than a single-object IDOR because it usually exposes a whole
customer. It needs no AI and no exotic tooling: two accounts and a canary.
This note extends `knowledge/web/access-control.md` from "object of another
user" to "object of another tenant".

## How Mythos detects it
- Build the layer map first: every place a tenant's data is stored or
  processed, from the SPA's network log and the docs. Typical layers: record,
  file/attachment, search index, cache, export/report job, audit log,
  notification, webhook target, background-job result, RAG/embedding index.
- Run `skills/tenant-isolation` (tenant-scoped matrix on top of
  `scripts/bola-diff`).
- Candidate vectors, each tried with tenant B's identifiers while logged in as
  tenant A:
  - tenant selector in a header (`X-Tenant-Id`, `X-Org-Id`, `X-Workspace`), a
    subdomain (`b.app.example`) or the `Host` header, overridden while the
    session belongs to A;
  - org id in the path (`/orgs/<id>/...`), body or GraphQL variable;
  - tenant claim in a JWT or a cookie the client can edit (see
    `knowledge/web/jwt-oauth.md`);
  - cache key without a tenant prefix: same URL, different tenant, served
    from cache (see `knowledge/web/cache-poisoning.md`, deception variant);
  - export, report and "download all" jobs that take a job id or a filter
    and re-read data later with the worker's own privileges;
  - shared search index, autocomplete and "recent items" endpoints;
  - SSO/SCIM: provisioning a user into a tenant, email change that skips
    verification, and context switching after login so a session reaches every
    tenant the identity belongs to (Doyensec, SCIM Hunting, 2025-05-08).

## How to confirm (non-destructive)
Only with two tenants the agent created. Seed a unique canary per layer in
each tenant, for example `CANARY-B-<layer>-<rand>` in a record title, a file
name and body, a search-indexed field, a cached response, a webhook URL path,
an export, an audit note. Tenant A must never see any B canary. Then, as A:

```
GET /api/records/<B_record_id>                 -> expect 403/404
GET /api/records?org=<B_org_id>                -> expect A's own list only
GET /api/search?q=CANARY-B                     -> expect zero hits
GET /api/records  with  X-Tenant-Id: <B>       -> expect A's data or 4xx, never B's
POST /api/exports {"org":"<B_org_id>"}         -> expect 403
GET /api/exports/<B_job_id>/download           -> expect 403/404
```

Controls that must pass before any result counts:
1. A reads A's own object and canary: succeeds (the request is well formed).
2. Unauthenticated read of the same URL: refused.
3. B's canary is absent from every list, search, autocomplete and export that
   A runs on its own data (leak check without any override at all: a shared
   index or cache can leak with no attacker input).
4. The same request with a random non-existent id returns the app's normal
   "not found", so an empty 200 is distinguishable from silent enforcement.

Finding = a B canary, or B's object body, appears in an A response, or an A
request changes state that B then reads back. For writes, change only B's
canary field on B's own test object and read it back as B. For enumeration
(IDs, member lists, which org names exist), the proof is a B-only value in an
A response, not a status-code difference alone.

## Proof standard
`validated(proof)` needs: invariant named ("tenant A never reads tenant B
data"), the A request and the response excerpt carrying B's canary, control 1
and 2 results, durable state read back as the owning tenant for writes, and
the layer that failed (database, cache, index, job). One layer failing is one
finding; a different layer failing is a separate finding.

Does NOT count: an A response containing public or shared-by-design data
(plan names, global templates); a 200 with an empty body; B's id echoed back
without B's data; a tenant switch that only works for an identity that is
already a member of both tenants; anything observed with a tenant the agent
did not create.

## Hard rule
Only identities and tenants created for the engagement. Never probe, list or
read a real customer's tenant, even to "check whether the id exists". If the
program provides no self-serve tenant creation, ask for two test tenants.

## Remediation
Derive the tenant from the verified session, never from a client-supplied
header, path or body field; enforce it centrally (row-level security, a scoped
repository layer); include the tenant in every cache, index and object-store
key; run jobs with the requesting tenant's identity and re-check on download.

## Sources
- Doyensec, "SCIM Hunting - Beyond SSO" (Francesco Lacerenza, 2025-05-08):
  tenant-isolation gaps in SCIM, forced tenant join, multi-SSO context
  switching; cites GitLab CVE-2022-1680 (SCIM email change takeover).
- Doyensec, "The Danger of Multi-SSO AWS Cognito User Pools" (2026-05-05):
  shared identity pool, tenant attributes mapped from a tenant's IdP.
- OWASP API Security Top 10 2023, API1 BOLA, API5 BFLA.
- Not verified: a Doyensec write-up specific to GitLab multi-SSO context
  switching was not found; the SCIM post describes the behaviour for an
  unnamed client platform.
