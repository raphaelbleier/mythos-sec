# Auth matrix: tenants x roles x objects x actions

**Class:** methodology  **Updated:** 2026-11-13

## What it is
A scanner cannot know who is allowed to do what. The matrix writes that
policy down as a table, so every authorization test is a cell with an
expected result and an observed result, and a mismatch is a candidate. It is
the planning step for `web/access-control.md` (what proves a cell) and the
input to `skills/business-logic` (which tools run it). It generalizes the
subject x object x action table in that skill's section 1 to tenants,
transports and non-human callers.

## Axes
- **Subjects (columns).** Not every user. Per object type use the five
  relations that matter: *owner* (`userA`), *peer* (`userB`: same role, same
  tenant, someone else's object), *lower* (a less privileged role), *cross-tenant*
  (`userC`, a user in a second tenant the agent created), *anonymous*. Add
  non-human callers when they exist: API keys, OAuth client credentials,
  SCIM provisioning tokens, webhook secrets. Roles come from `auth-session`
  (`--role userA|userB|userC|admin`); a second tenant is a second
  self-registered org.
- **Objects (rows).** Every resource type with an identifier, plus the
  property-level split (`User.role`, `Order.price`) for BOPLA.
- **Actions.** read, list, search, create, update, delete, plus the workflow
  verbs (approve, refund, transfer, redeem, invite, export, impersonate) and
  configuration verbs (change role, rotate key, manage billing).
- **Transport (one more dimension on each row).** REST per API version,
  GraphQL, WebSocket, file and signed-URL endpoints, exports, webhooks. The
  same (object, action) is a separate row per transport; a cell that falls on
  two transports is systemic.

## Expected value
Derive it from the application, never from the test result. Sources in order
of reliability: the spec's `security` and scope fields; role descriptions in
docs or the admin UI; what each role's UI shows (an action absent from the
lower role's UI is expected-deny); then common sense. Unknown stays `?` and
is resolved by asking, not by guessing. A test run against a guessed
expectation produces false findings.

## Populate it
All inputs feed one table (`engagements/<dir>/scan/matrix.md`).

**From `scripts/probe`.** `scripts/probe <target> --json` emits
`api_endpoints` (strings `GET /orders/{id}` from OpenAPI, and
`query name(args)` / `mutation name(args)` from GraphQL introspection) and
`parameters` with hypotheses. Seed rows from the first, and mark rows whose
parameters carry `idor/bola` or `business-logic, mass-assignment`:
```
scripts/probe <target> --json | jq -r '.api_endpoints[] | "| \(.) | | | | | | | |"'
# columns: endpoint | object | action | anon | peer | lower | x-tenant | state
```
`probe` reads only the documented endpoints and `application/json` bodies; it
does not record `security` requirements or roles, so fill expected values by
hand.

**From an OpenAPI spec.** Every `paths` x method is a row; `{id}` path
parameters name the object; `security` and scopes per operation give
expected-deny for anon and lower roles:
```
jq -r '.paths|to_entries[]|.key as $p|.value|to_entries[]
  |select(.key|test("^(get|post|put|patch|delete)$"))|"\(.key|ascii_upcase) \($p)"' openapi.json
```
Also list operations the UI never calls: routes in the spec but absent from
recorded UI traffic are where vertical bugs live.

**From a GraphQL schema.** Each `Query` field is a read, each `Mutation` field
a write; arguments named `id` or `*Id` are object references. Authorization is
per field and per path, so a type reachable through two parents is two rows.
Run each field as each subject. See `web/graphql-api.md` for batching and
introspection limits.

**From recorded traffic.** Browse as each role with the browser agent (or
export a HAR), then template identifiers and de-duplicate:
```
jq -r '.log.entries[]|"\(.request.method) \(.request.url)"' as-userA.har \
  | sed -E 's#\?.*##; s#/[0-9]+(/|$)#/{id}\1#g; s#[0-9a-f]{8}-[0-9a-f-]{27}#{uuid}#g' | sort -u
```
Diff the sets across roles: requests only `admin` made are expected-deny for
the others; requests all roles made are shared and need object-level checks.

**From WebSocket.** Record frames per role. Each message `type` is an action;
fields carrying room, channel or object ids are object references. Authorization
may be checked at handshake, at subscribe time, or per message: test each
separately (join another tenant's channel; send an action with another user's
object id on an already-open socket).

## Fill and run
1. Collect real ids per principal first (`auth-session`: own objects only).
2. Order of work, cheapest first: anonymous sweep of every row; peer swap
   (`bola_diff.py`); lower-role calls (BFLA, `--a admin --b userA`);
   cross-tenant; then write verbs.
3. Write verbs only on objects the agent created; delete last.
4. Prioritize rows where deny is expected and the object is money, PII,
   credentials, admin configuration or another tenant.
5. Each cell records `expected/observed`, e.g. `deny/200`. Mismatch means
   candidate; follow the proof procedure in `web/access-control.md`. An empty
   `200` is `review`, not a mismatch.

Example rows:

| endpoint (transport) | object | action | anon | peer | lower | x-tenant | state |
|---|---|---|---|---|---|---|---|
| GET /api/orders/{id} (REST v2) | order | read | deny/401 | deny/403 | n/a | deny/404 | rejected(enforced) |
| mutation refundOrder(id) (GraphQL) | order | refund | deny/401 | deny/200 | deny/200 | deny/200 | candidate |

## Output
The matrix is the evidence of coverage: untested cells stay `untested`, not
blank, and the table feeds the bola and bfla rows of
`scan/coverage.md`. Each `candidate` row gets a finding file; closure states
follow `skills/exploit`.

## Sources
- OWASP API Security Top 10 2023 (API1, API3, API5) (2023-06); OWASP WSTG-ATHZ
- PortSwigger/auth-analyzer, SAME/SIMILAR/DIFFERENT triage
- Strix idor.md and business_logic.md (usestrix/strix, Apache-2.0)
