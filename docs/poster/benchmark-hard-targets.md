# Benchmark — hard, real-world targets

Beyond the ground-truth app and Juice Shop, Mythos (skill-driven, Claude Code +
Kali toolbox) was run against targets that exercise the bug classes experienced
testers most often miss: **GraphQL code execution** and **API business logic**.
Every confirmed finding has real tool evidence; one BOLA was tested and
**honestly reported as not vulnerable** after verification — the framework's
"prove impact before claiming" discipline catching a would-be false positive.

## Why these are hard

Automated scanners rarely find these: GraphQL needs introspection + schema
reasoning to reach the injectable operation, and API logic flaws (BOLA, mass
assignment, debug endpoints) have no signature — they require understanding what
the endpoint _should_ allow. This is where an LLM agent earns its place.

## Target 1 — Damn Vulnerable GraphQL Application (DVGA)

GraphQL API (`/graphql`, port 5013). Flow: fingerprint → introspection → map
mutations/queries → exploit.

| Finding                                                                              | Severity | Status    |
| ------------------------------------------------------------------------------------ | -------- | --------- |
| **Unauthenticated RCE** via `importPaste` mutation (SSRF → OS command injection)     | Critical | Confirmed |
| Broken access control: `pastes(public:false)` returns private pastes unauthenticated | High     | Confirmed |
| GraphQL introspection enabled → full schema + `system*` operations disclosed         | Medium   | Confirmed |

**RCE proof** — the mutation runs the injected shell command and returns output:

```
mutation { importPaste(host:"localhost", port:80, path:"/ ; id", scheme:"http"){ result } }
-> {"data":{"importPaste":{"result":"uid=1000(dvga) gid=1000(dvga) groups=1000(dvga)\n"}}}

# file read (non-destructive impact proof)
path:"/ ; cat /etc/passwd | head -2 ; hostname"
-> root:x:0:0:root:/root:/bin/bash ...  39591d151b2f
```

The agent reached this by introspecting the schema, spotting `importPaste(host,
path, port, scheme)` as a request-building operation, and injecting `;` into
`path` — a GraphQL → SSRF → command-injection chain, not a signature match.
(`systemDiagnostics(cmd)` and `systemDebug(arg)` are additional RCE surface,
gated by credentials / input handling.)

## Target 2 — VAmPI (vulnerable REST API)

| Finding                                                                           | Severity | Status                     |
| --------------------------------------------------------------------------------- | -------- | -------------------------- |
| `/users/v1/_debug` dumps every user with **plaintext passwords**, unauthenticated | Critical | Confirmed                  |
| BOLA on `PUT /users/v1/{username}/email` (update another user's email)            | —        | **Tested, not vulnerable** |

**Honest negative on the BOLA:** account A's token on
`PUT /users/v1/victimB/email` returned `204`, but verification via `_debug`
showed **A's own** email changed, not B's — the endpoint keys on the token
identity, not the path. Reported as not-vulnerable rather than claimed. A basic
`' OR '1'='1` login-bypass payload also failed and was not claimed.

## Target 3 — Vuln Bank (modern banking app, 2025/26)

A current, deliberately vulnerable banking platform (Flask + PostgreSQL +
GraphQL), chosen as a harder, newer analogue to Juice Shop. The flow produced a
textbook multi-step chain plus a GraphQL-resolver SQLi.

| Finding                                                                                                | Severity | Status    |
| ------------------------------------------------------------------------------------------------------ | -------- | --------- |
| `/.env` exposed → `JWT_SECRET`, `SECRET_KEY`, DB credentials                                           | Critical | Confirmed |
| **JWT forgery → admin takeover** (server accepts an HS256 token signed with the leaked secret)         | Critical | Confirmed |
| SQL injection in the GraphQL `transactionSummary(accountNumber)` resolver (Postgres error-based)       | High     | Confirmed |
| Verbose debug disclosure (`FLASK_DEBUG=true`): register/login leak `is_admin`, raw password, `user_id` | Medium   | Confirmed |

**The chain** (what a scanner won't assemble, and the point of the agent):

```
GET /.env                       -> JWT_SECRET=00af85...   (unauth info disclosure)
decode a real login JWT         -> {user_id, username, is_admin, iat}  HS256
forge {is_admin:true} w/ secret -> server accepts it on /graphql (which rejects a missing token)
                                -> authenticated admin access  (privilege escalation)
```

**GraphQL SQLi proof** — `transactionSummary(accountNumber:"1'")` returns the DB
error `unterminated quoted string ... FROM users WHERE account_number=...`,
exposing a concatenated query. (Error-based proof only; no data dumped.)

## Aggregate scorecard

Confirmed, evidence-backed findings across six targets / five stacks, run
through the skill-driven toolbox flow (DOM XSS via the Playwright browser agent):

| Target                 | Stack                        | Headline confirmed classes                                                                                                       |
| ---------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| vulnapp (ground truth) | Flask                        | XSS, SQLi, open-redirect, traversal, CORS, exposure (7, self-test)                                                               |
| OWASP Juice Shop       | Node SPA + REST              | UNION SQLi (Users dump), `/ftp` disclosure, null-byte filter bypass, open redirect, config leak, **DOM XSS (browser-confirmed)** |
| DVGA                   | Python GraphQL               | **unauth RCE** (introspection→SSRF→cmd-injection), broken access control, introspection                                          |
| VAmPI                  | Python REST                  | `_debug` plaintext-password dump; BOLA tested & disproven                                                                        |
| Vuln Bank              | Flask + PostgreSQL + GraphQL | `.env` leak → **JWT forge → admin**, GraphQL-resolver SQLi, debug disclosure                                                     |

Classes demonstrated end to end: reflected/DOM/stored-surface XSS, error- and
UNION-based SQLi, GraphQL-resolver SQLi, unauthenticated RCE (command injection),
SSRF, path traversal + filter-evasion, open redirect, CORS, sensitive-file
exposure, verbose-debug disclosure, JWT forgery / privilege escalation, broken
access control, and a correctly-disproven BOLA.

## Takeaway

- **Mythos handles the hard classes.** It chained GraphQL introspection → SSRF →
  RCE unauthenticated (DVGA), `.env` → JWT forge → admin takeover (Vuln Bank),
  and found GraphQL-resolver SQLi and a credential-dumping debug endpoint — the
  multi-step chains that stall scanners and less-experienced testers.
- **Repro (Vuln Bank):** `git clone https://github.com/Commando-X/vuln-bank &&
cd vuln-bank && docker compose up -d db web` (web on `:5000`).
- **It does not over-claim.** The VAmPI BOLA was disproven by impact
  verification. Findings are evidence-backed, negatives are stated.
- **Known limits (honest):** full crAPI (7-container API-logic chain: VIN-based
  BOLA, mass assignment, JWT, SSRF) does not fit this RAM-limited WSL host
  (~3.7 GB), so the hardest multi-service logic chains are future work on a
  larger host. DOM/client-side classes need the `mythos-browser` (Playwright)
  agent. "Performs on _any_ web application" is not literally provable without
  authorized access to each target; the evidence here spans four stacks (Flask,
  Node SPA, Python GraphQL, Python REST) and the headline hard classes.
