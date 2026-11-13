# GraphQL & Modern API Testing (REST/OpenAPI, BOLA/BFLA matrix)

**Class:** server-side  **Updated:** 2026-11-13

## What it is
GraphQL endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`) put
many operations behind one URL and one status code, so per-request controls
(rate limits, WAF rules, per-route auth) see a single request while the server
runs many. Attack surface: schema leak, batching, per-field authorization,
subscriptions, GET-based queries. Honest limits of this note: schema-driven
fuzzing of mutations is manual here; Mythos has no GraphQL-aware scanner, so
use InQL or Clairvoyance output as input and test by hand.

## How Mythos detects it
- Discovery: `POST /graphql {"query":"{__typename}"}` returns `{"data":{"__typename":"Query"}}`.
  Also try `GET /graphql?query={__typename}`, `/graphiql`, `/playground`,
  `/altair`, and Apollo/Hasura/Yoga error shapes.
- Introspection: `{__schema{types{name fields{name args{name}}}}}`. Open
  introspection in production is a finding only with sensitive types or
  mutations in it; otherwise a hardening note.
- Introspection off: send a near-miss field `{usr}`; a `Did you mean "user"?`
  error is field suggestion. Clairvoyance (originally Nikita Stupin, now
  maintained by Escape) rebuilds a schema from these errors with a wordlist.
  Report suggestions as a separate low finding.

## Batching is more than amplification
- Alias batching, one HTTP request, N evaluations:
  `query{a:login(u:"mythos-a",p:"w1"){ok} b:login(u:"mythos-a",p:"w2"){ok}}`.
  Array batching: `[{"query":"..."},{"query":"..."}]`.
- Rate-limit or OTP bypass test: only your own account, N <= 10, with codes you
  know are wrong. Proof = the response shows N evaluated results (N `false` or
  N error entries) in one request, while the rate-limit counter or lockout
  fires after fewer single requests (control: N separate requests get
  blocked). Never iterate a real code space or a real user's account.
- Batch a mutation with itself once on an object you own (idempotency): same
  as a race, see `race-conditions.md`.

## Authorization and transport
- Per-field authz: call each Query and Mutation field as anon, userA and userB
  on userA's object ids; BOLA/BFLA oracle as in `access-control.md`. Check
  nested paths too (`order{customer{email}}`), and the same object via REST.
- Cross-tenant ids in arguments and `node(id:)` relay lookups:
  `multi-tenant-isolation.md`.
- Subscriptions (WebSocket, `graphql-ws` / `subscriptions-transport-ws`): auth
  may be checked once at `connection_init`; subscribe as userA, mutate as
  userB-owned data in your second tenant, and see whether events leak across
  principals. Missing `Origin` check on the WebSocket is cross-site hijacking.
- GET queries or `application/x-www-form-urlencoded` accepted: CSRF-able
  mutations. Test with a harmless mutation on your own object and no CSRF
  token; JSON-only with `Content-Type` enforcement is not exposed.
- Persisted queries: if arbitrary queries are accepted despite a persisted-query
  allowlist, or the hash map is disclosed, note which path is open.
- Depth and cost: nest a self-referencing type to depth 8 on your own data,
  observe a rejection or latency growth; no exponential bombs against a shared
  target. Missing limits are a finding only with demonstrated cost growth.

## How to confirm (non-destructive)
Dump schema structure only. BOLA proof via two owned accounts (same sequence as
`bola`), never read real user data. State the introspection and suggestion
status separately. Does NOT count: introspection alone on a public API,
a depth limit error, a 200 with `errors` and no data, one batch result without
a control showing the single-request limit applies.

## Remediation
Introspection and field suggestions off in production, field-level authz
middleware, per-operation cost accounting that counts aliases and batch
entries, persisted queries, `Content-Type` and `Origin` enforcement, auth on
every subscription event.

## Sources
- OWASP WSTG-API, Testing GraphQL; OWASP GraphQL Cheat Sheet (2026-10)
- PortSwigger Web Security Academy, GraphQL API vulnerabilities (2026-10)
- Clairvoyance (PyPI/GitHub), schema recovery with introspection disabled (verified to exist; exact release date not checked)
