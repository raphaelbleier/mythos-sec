# GraphQL & Modern API Testing (REST/OpenAPI, BOLA/BFLA matrix)

**Class:** server-side  **Updated:** 2026-10-25

## What it is
GraphQL endpoints (`/graphql`, `/api/graphql`) have their own attack surface:
introspection leak, missing cost/depth limits → resource exhaustion, batched
query amplification, field-level authz failures (BFLA is per-field), mutations
as privilege escalation. Parallel concern for REST: schema-driven testing
instead of guessing. 2026 status: several open-source frameworks handle
GraphQL/WS natively only poorly — a known Mythos gap; this note is the
detection baseline.

## How Mythos detects it
- Engine: discovery — `GET /graphql` with `{ __schema { types { name } } }`
  (unauthenticated introspection is itself a P1 finding), POST body probes,
  playground/GraphiQL paths, Apollo route fingerprints.
- Schema-driven checks: per-field authz (BOLA mapping over `id` arguments),
  query-cost depth bombs, batch array bodies (`[{},{}]`), SDL download →
  mutation fuzz with auth-zone matrix.
- Tools: graphql-voyager / InQL-style tooling (toolbox); `http_request` for
  in-board proofs.

## How to confirm (non-destructive)
Dump introspection structure only; BOLA field proof via two owned test accounts
(same sequence as the `bola` tool), never read real user data cross-account.

## Remediation
Introspection off in production (allowlisted UI only), depth/complexity limits,
field-level authz middleware (BFLA matrix), persisted queries, rate limits per
token + object ID.

## Sources
- OWASP WSTG-API; GraphQL Security Cheat Sheet; crAPI reference context (2026-10)
