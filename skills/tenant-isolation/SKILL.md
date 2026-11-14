---
name: tenant-isolation
description: Multi-tenant isolation testing for a Mythos engagement - create two tenants you own (A and B), seed a unique canary at every layer (record, file, search index, cache, export job, webhook target, audit log, notification, RAG index), then attempt cross-tenant read, write and enumeration through tenant headers, subdomains, org-id parameters, JWT claims, cache keys and export jobs, proven by a canary crossing the boundary with controls. Use after auth-session when the target is a SaaS with organizations, workspaces, teams or SSO/SCIM, and the program allows creating test tenants.
---

# Tenant isolation: a canary crosses the boundary, or nothing happened

The widest payout on SaaS targets and it needs no AI: one missing tenant
filter at one layer exposes a whole customer. Method notes and vectors live in
`knowledge/web/multi-tenant-isolation.md`; read it before starting. Per-object
BOLA mechanics (owner/other/anon diff, two transports) are in
**business-logic**; this skill adds the tenant dimension and the layer map.

Triage selects this skill (`skills/registry.yaml`) when the surface shows an
organization, workspace, tenant, team, account, company or project identifier
in a path or a parameter, or one of those names in a session cookie. It drives
`bola-diff` and `session-check`, and needs **auth-session** first. A tenant
claim inside a token is not visible to triage: once **auth-session** holds a
token, read its claims yourself and add the claim to the override vectors in
step 3.

## Hard rules

- **Only tenants and identities you created.** Two self-created tenants, A and
  B, each with its own owner account (and one member each if roles matter).
  Never use, list or probe a customer's tenant, never guess real org ids to
  "see if they exist". No self-serve tenant creation: ask the user or the
  program for two test tenants and stop until you have them.
- Requires `scope.rules.allow_active`. Write checks (step 4) only on B's own
  canary objects. Exports and bulk jobs: one small job, no repeats.
- Respect `rules.rate_limit_rps` and `rules.max_requests`. No brute-forcing ids.

## 1. Two tenants, two sessions

Create tenants A and B by the normal signup flow, then log each owner in with
**auth-session** (`S=engagements/<dir>/sessions`, roles `userA` = owner of A,
`userB` = owner of B; add `userA2` if the app has an in-tenant role to test).
Record tenant id, org slug, subdomain and the user ids of both tenants in
`scope.yaml` `identities`. Run `session-check` before every batch.

## 2. Seed canaries at every layer

Canary format `MYTHOS-TI-<tenant>-<layer>-<rand6>`; keep the map in
`engagements/<dir>/scan/tenant-canaries.jsonl` (`tenant, layer, canary,
object id, request`). Seed in B (the victim) at least:

| layer | how to seed |
|---|---|
| record | title/name/description field of every object type |
| file | upload `<canary>.txt` whose body is the canary |
| search index | canary in an indexed field; confirm B finds it by search |
| cache | an authenticated GET of B's canary object (so a cache could key it) |
| export / report job | start one export in B, keep the job id and download URL |
| webhook target | register a webhook in B whose URL path carries the canary (OAST base, not a third party) |
| audit log, notification | any action in B that writes a log or notification line |
| background job result | trigger one job (import, report, AI summary) in B |
| RAG / embedding index | upload a document with the canary, ask B's assistant for it |

Seed a different canary in A so a leak is attributable to the right direction.

## 3. Attempt every cross-tenant read

As `userA`, with B's identifiers (ids are yours, from step 2, never guessed):
list endpoints, object GETs, search and autocomplete, export download by B's
job id, file URL by B's file id, audit and notification feeds, webhook list,
the assistant's retrieval. Then the override vectors, each on an endpoint that
returns A's data normally:

```
curl -s $H -H 'X-Tenant-Id: <B>' <URL>        # also X-Org-Id, X-Workspace, X-Account
curl -s $H <URL with ?org=<B>> ; path /orgs/<B>/... ; body {"orgId":"<B>"}
curl -s $H -H 'Host: <b-subdomain>' <URL>     # Host/X-Forwarded-Host override
```

Also: edit the tenant claim in a token or cookie you hold (only on a token
whose signature the app verifies badly, see **exploit** JWT notes), and a
cache probe: A and B request the same URL; if A is served B's body, note
`Age`/`X-Cache`. For bulk triage run
`bola-diff --a $S/userA.headers --b $S/userB.headers --marker <A canary>`
against B's object URLs with the roles read as "attacker = A".

## 4. Cross-tenant write and enumeration

Writes: as A, change only B's own canary field on B's own object
(`PATCH`/`PUT` with B's id), then read it back as B. Enumeration: member list,
invite-by-email "does this org exist" differences, subdomain existence; the
proof is a B-only value in an A response.

SSO/SCIM, if enabled in your own tenants: provision a user into A by SCIM,
change its email to one that belongs to B's owner (an identity you own), and
check whether login reaches B. See `knowledge/web/saml-scim-sso.md` when it
exists in this repo.

## 5. Controls (all four, per finding)

1. A reads A's canary: succeeds. 2. Unauthenticated: refused.
3. No B canary in A's own lists, search, exports without any override.
4. Random non-existent id: the app's normal not-found (separates silent
enforcement from an empty 200).

## Closure state (per **exploit**)

| state | here |
|---|---|
| `candidate` | an override or id returned 200 or a different length; no canary seen |
| `reproduced` | B canary/body in an A response, controls 1 to 4 done, request re-sent by hand |
| `validated(proof)` | a fresh context re-ran `findings/<id>.poc.sh` and got the same canary; for writes, B read the change back |
| `rejected(reason)` | public-by-design data, identity belongs to both tenants, not reproducible |

Write `findings/<id>.md` with `status:`, `proof:`, `negative_control:`, the
failing layer, the A request and the response excerpt carrying B's canary.
One layer = one finding. Leave canary objects in place until triage, then
delete the tenants or objects you created. Hand all to **exploit** and then
**report**.
