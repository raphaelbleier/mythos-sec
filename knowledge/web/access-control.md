# Broken Access Control (BOLA/IDOR, BFLA, BOPLA, tenant boundaries)

**Class:** access control  **Updated:** 2026-11-13

## What it is
The server does not check, on the request itself, that this principal may
perform this action on this object. Authentication succeeded; authorization
is missing, partial or client-side only.

| class | the missing check | OWASP API 2023 |
|---|---|---|
| BOLA / IDOR (horizontal) | caller owns this object id | API1 |
| BFLA (vertical) | caller's role may call this function | API5 |
| BOPLA, read | caller may see this property | API3 |
| BOPLA, write | caller may set this property | API3 (`mass-assignment.md`) |
| Tenant boundary | object belongs to the caller's tenant | API1 across tenants |
| Forced browsing | caller may reach this unlinked URL or file | WSTG-ATHZ |
| Unauthenticated access | any principal is required | API2/API5 |

## Where this note ends
This note is the canonical reference for the class: what to try and what
proves it. `techniques/auth-matrix.md` builds the subject x object x action
table that says which cells to test. `skills/business-logic` carries the
tools (`bola_diff.py`, `mass_assign.py`, `race.py`) and the run order.
`mass-assignment.md` owns the write side of BOPLA, `race-conditions.md` and
`techniques/state-machine-abuse.md` own ordering and concurrency.
(The skill still holds its own copy of the method in sections 1 and 2; that
copy should shrink to a pointer here, which its owner has to do.)

## How Mythos detects it
- Matrix first (`techniques/auth-matrix.md`), then triage with
  `bola_diff.py`: owner, other user and anonymous classified SAME / SIMILAR /
  DIFFERENT. Output is candidates only.
- Object references are everywhere, not just the path: query, JSON body,
  headers (`X-Tenant-ID`), cookies, JWT claims (`sub`, `tid`, `org`),
  GraphQL arguments, WebSocket messages, file names, export and job ids,
  signed URLs, arrays of ids in batch calls, nested objects
  (`{"order":{"id":...}}`).

## How to confirm (non-destructive)
Principals are only the agent's own: two same-role users, and for tenants two
tenants it created. Never request an id belonging to anyone else. "Neighbour
id" means `userB`'s id, arranged to sit next to `userA`'s. If a response ever
contains a third party's data, stop, note the status and endpoint, do not
store the body.

**Oracle:** an owner-only marker (A's email, an object field set by A, a
unique string `mythos-<token>` created on A's object) appears in the response
to B's request. Baseline: A gets it as owner. Negative control: B on B's
own object works and B on an enforced endpoint is denied.

Variations on the request that carries the id, each against a candidate and
each against the enforced control:
1. **Location and form:** path vs query vs body; `id[]=`, `id=B&id=A`
   (parameter pollution), `{"id":{"id":B}}`; `/me` vs `/<id>`.
2. **Representation:** numeric, UUID from a leak (list, share, email, error),
   base64 or hashed integer, case, trailing slash, `.json`.
3. **Verb:** GET denied, PUT/PATCH/DELETE not checked (write verbs only on
   objects created by the agent).
4. **Version, content type, transport:** `/v1/` vs `/v2/`, JSON vs form,
   REST vs GraphQL vs WebSocket. A candidate holding on **two transports** is
   systemic.
5. **Path-rule bypass (BFLA):** `/admin` vs `/ADMIN`, `/admin;x`, `//admin`,
   `/%2e/admin`, `X-Original-URL` / `X-Rewrite-URL` on a front proxy.
6. **Client-only hiding:** the UI hides the button; call the API with the
   lower role. Routes found in JS bundles or the OpenAPI spec that the UI
   never links are the usual BFLA yield.
7. **Indirect references (second order):** create an object under A that
   references B's id (`attachment_id`, `file_id`, `parent_id`, share target)
   and read it back as A.
8. **Read-side BOPLA:** diff the fields returned to owner, other user, list
   view and detail view against what the UI renders; password hashes, tokens,
   other users' emails or internal ids in a list are the finding.

**Tenant boundary.** With tenants T1 and T2 (agent-created, one user each):
swap the tenant carrier (`X-Tenant-ID`, subdomain, path org id, `tid`/`org`
claim, body `tenantId`) while keeping T1's session; request T2's object ids
from T1; and check aggregating features that bypass per-object checks:
search, autocomplete, exports and reports, audit logs, webhooks, invites,
cache keys. Cross-tenant read or write is the highest-impact result in this
class; report it separately from same-tenant IDOR.

**Forced browsing.** Unlinked admin paths, `/uploads/<userid>/`, backups,
signed or pre-signed URLs reused across users or after expiry. Proof is a
file only the agent's own account created, fetched by the wrong principal or
anonymously.

## False positives (do not report)
Public-by-design data; idempotent metadata; an empty or `null` `200` for
another user's object (silent enforcement: compare with the owner's view);
GraphQL `data:{field:null}` plus an error on that field; shared objects the
product intends two users to see (org membership, explicit shares); admin
"view as" features; identical cached responses; `403` vs `404` differences
alone (an enumeration note at most).

## Proof standard
Same five points as `skills/business-logic` (invariant named, baseline vs
abuse, negative control, durable read-back, quantified impact). Quantify by
structure ("ids are sequential integers, T2 exports include all T2 users"),
never by iterating real ids.

## Remediation
Authorize on the server for every object and function from the authenticated
principal, not from a client-supplied id or role; scope queries by owner and
tenant in the data layer; deny by default; allowlist returned properties per
role; do not rely on unguessable ids as authorization.

## Sources
- OWASP API Security Top 10 2023: API1, API3, API5 (2023-06)
- OWASP WSTG-ATHZ; OWASP Authorization Testing Automation Cheat Sheet
- Strix idor.md (usestrix/strix, Apache-2.0), false-positive list and
  two-transport rule; PortSwigger/auth-analyzer SAME/SIMILAR/DIFFERENT triage
