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

## Takeaway

- **Mythos handles the hard classes.** It chained GraphQL introspection → SSRF →
  RCE unauthenticated, and found a critical credential-dumping debug endpoint —
  both the kind of thing that stalls scanners and less-experienced testers.
- **It does not over-claim.** The VAmPI BOLA was disproven by impact
  verification. Findings are evidence-backed, negatives are stated.
- **Known limits (honest):** full crAPI (7-container API-logic chain: VIN-based
  BOLA, mass assignment, JWT, SSRF) does not fit this RAM-limited WSL host
  (~3.7 GB), so the hardest multi-service logic chains are future work on a
  larger host. DOM/client-side classes need the `mythos-browser` (Playwright)
  agent. "Performs on _any_ web application" is not literally provable without
  authorized access to each target; the evidence here spans four stacks (Flask,
  Node SPA, Python GraphQL, Python REST) and the headline hard classes.
