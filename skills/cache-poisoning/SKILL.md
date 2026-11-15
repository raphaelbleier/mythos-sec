---
name: cache-poisoning
description: Web cache poisoning, cache deception, fat GET and edge-versus-origin normalization for a Mythos engagement — discover the cache key input by input, poison only a key the operator isolated with a cache buster, prove a second independent client was served an inert marker, then bust the entry and verify it is gone. Use when recon finds a CDN, reverse proxy or cache in front of the target (Via, X-Cache, CF-Cache-Status, Age, Fastly-Debug, a Server header naming Cloudflare, Akamai, Varnish, Fastly, CloudFront or Squid), or when a private page sits under a path a cache could read as static.
---

# Cache poisoning: the class where the proof is the harm

Triage selects this skill when the response headers show a cache or a proxy
chain. It drives `scripts/cache`, `verify` and `evidence`, and
`knowledge/web/cache-poisoning.md` carries the technique table, the oracle
standard and why `X-Cache: HIT` is not one. Read that note before step 2.

Everything else in this suite tests the target. This one **changes what other
people are served**. A poisoned entry on a shared cache reaches every real user
who requests that key, for as long as the entry lives, and you cannot take it
back by apologising. So the rules below are not advice, they are what the script
enforces, and the two refusals are refusals in code.

## Hard rules

- **Never poison a bare key.** `scripts/cache` appends a unique cache-buster
  parameter (`--buster-param`, default `cb`) to every key it stores anything
  under, so the only entry touched is one no real client will ever request.
  `--no-buster` — the key real users hit — is refused unless
  `--i-own-this-cache` is also passed. **Pass `--i-own-this-cache` on your own
  lab and nowhere else.** On a bug-bounty target it is the wrong flag even when
  the programme is generous: the programme's users did not opt in.
- **The marker is inert.** `[A-Za-z0-9._-]{4,64}`, generated under the reserved
  `.invalid` TLD when it has to look like a host. No script, no redirect target,
  no CRLF, nothing executable, nothing that names a real third party. A
  `--marker` that is not inert is refused. If the finding needs an executable
  payload to be interesting, write that down as unexecuted impact instead.
- **Clean up, and verify the cleanup.** Every candidate carries a `cleanup`
  block: the revalidation that evicted the entry and the read that shows it is
  gone. Do not stop at the proof.
- **A cleanup that failed is collateral.** `scripts/cache` exits 5, prints the
  key and says to disclose it. Do exactly that: put the key, the marker and the
  time in the finding, tell the programme it needs a purge, and poison nothing
  else on that host until it is cleared. A quiet run that left an entry behind
  is worse than no finding at all.
- No DoS, no brute force, no flood. `--n` is small and `--max-requests`
  (default 150) is a hard cap; exceeding it exits 4. Pacing comes from
  `rules.rate_limit_rps`.
- The victim role in `deception` is **you**: your own session, in a second
  browser context or a second request with no cookies. Never another user's.
- You may write `candidate`, `tested` or `skipped`. Never `confirmed`.

## 0. Is there a cache at all

From recon, in `surface.json` and the recorded headers: `Via`, `X-Cache`,
`X-Cache-Hits`, `CF-Cache-Status`, `Cache-Status` (RFC 9211), `Age`,
`Fastly-Debug`, `X-Served-By`, `X-Varnish`, `Akamai-Cache-Status`,
`X-Vercel-Cache`. No signal anywhere and no `Server` naming a cache is a
legitimate `skipped`: "no cache observed in the response headers, class not
applicable" — write it and move on. A cache you cannot observe is also one
whose behaviour you cannot prove, and an unprovable poisoning claim is the
worst kind.

## 1. Find the key

```
script: name "cache", args ["keys", "<url>", "--dir", "engagements/<dir>",
                            "--n", "12", "--json"], out: "cache-keys.json"
```

`keys` first measures whether the key caches at all (two reads of one busted
key), then varies one input at a time and classifies each as
`unkeyed-and-reflected`, `unkeyed`, `keyed`, `ignored` or `inconclusive`, with
the cache signal the verdict rests on and how much that signal is worth
(`explicit`, `weak`, `none`). It covers a curated header list, the query
parameters (`--param <name>`, repeatable; the URL's own by default) and the
key's *shape*: the port in `Host`, path case, a trailing slash, a path
parameter, a trailing `%0a`, a static-looking suffix.

Read `inputs[].verdict` and `key_shape[].verdict`, not the summary.
`inconclusive` is the common answer and it is an answer: it means the cache
said nothing this pass could rest on. Narrow with `--only <HeaderName>` when
you want one input's story in detail.

Exits 1 when something unkeyed turned up, and `next` names the poison command
to run.

## 2. Poison one unkeyed input

```
script: name "cache", args ["poison", "<url>",
                            "--header", "X-Forwarded-Host: AUTO",
                            "--dir", "engagements/<dir>", "--json"],
        out: "cache-poison.json"
```

`AUTO` generates the inert host marker; `--header 'Name: <value>'` uses yours
(checked for inertness), and `--param <name>` carries the marker in a query
parameter instead. The sequence is fixed: prime the isolated key with the
input, read the same key as a second independent client (fresh socket, its own
User-Agent, no cookies, none of the inputs), control on a key that was never
primed, then bust and verify.

The oracle is **the marker in a response to a request that did not carry it**,
with the unprimed key clean. The hit/miss signal is reported and is never the
oracle on its own. If the control carries the marker too, the target reflects
it unconditionally and the verdict is `inconclusive` — that is a reflection, not
a cache finding.

Exit 1 is a candidate with a verified cleanup. **Exit 5 is a candidate with a
failed cleanup**: go read rule four again.

## 3. Cache deception on a private page

```
script: name "cache", args ["deception", "<url>/account",
                            "--owner-header", "Cookie: session=<your own>",
                            "--dir", "engagements/<dir>", "--n", "9", "--json"],
        out: "cache-deception.json"
```

Nine path variants: `/account/profile.css`, `/account.css`, `/account;.js`,
`/account%0a.js`, `/account%0d.css`, `/account%3f.css`, `/account%23.css`,
`/account/..%2fprofile.css` and a plain dot-segment form. The owner (you)
primes each one, an anonymous reader fetches it, and an unprimed key of the same
shape is the control. The oracle is an owner-only string — `--marker <string>`,
or derived from the owner and anonymous baselines and reported either way.

`not cached` is a result worth reporting on its own: the origin served the
private page under a static-looking path and the edge happened not to store it.
That is one cache rule away from the full bug, and a triager should know.

## 4. Fat GET

```
script: name "cache", args ["fatget", "<url>/api/item",
                            "--override-method", "POST",
                            "--dir", "engagements/<dir>", "--json"],
        out: "cache-fatget.json"
```

Six variants: a GET carrying a body, `X-HTTP-Method-Override`,
`X-Method-Override`, `X-HTTP-Method`, `?_method=POST` and `_method=POST` in a
form body. `--override-method` accepts POST, GET, HEAD and OPTIONS only; PUT,
PATCH and DELETE are refused in code, because an override to a write verb is a
write against an endpoint whose behaviour you do not know yet. `--body` is
capped at 4 KiB.

The oracle is the POST-shaped response served back to a plain GET that carried
neither a body nor an override header, with an unprimed key still answering the
plain GET's status. Pick a **read** endpoint: a POST handler that changes state
is out of bounds here, and if the only POST route is a write, record `skipped`
with that reason.

## 5. Normalization: where the two tiers disagree

```
script: name "cache", args ["normdiff", "<url>",
                            "--origin", "<origin url, if in scope by name>",
                            "--dir", "engagements/<dir>", "--n", "12", "--json"],
        out: "cache-normdiff.json"
```

Twelve variants, each written byte for byte on a fresh socket: `%2f`, encoded
and plain dot segments, double-encoded dots, a double slash, a path parameter, a
trailing dot, `/..;/`, duplicate parameters, an obs-fold header, and two
framing variants (`Content-Length` with `Transfer-Encoding`, and two
`Content-Length` headers).

The finding here is always **"the edge and the origin disagree"** — that is the
bug. It is not a bypass, nothing is scored by whether it got past a filter, and
none of it is framed as detection evasion; a WAF that parses differently from
the thing it protects is the same normalization defect seen from one side.

Three oracle shapes, and the script says which one each variant was judged by:

- **path** — the edge stored an entry under the unresolved target while the
  response is the one for the resolved path, with a control at a path that does
  not exist to show the shape is actually being resolved.
- **cloak** — `?x=A&x=B` primed, then `?x=A` alone served from cache carrying
  B's effect: the edge keyed the first occurrence and the origin read the last.
- **fold** — the same folded bytes answered differently at the edge and at the
  origin, which needs `--origin`; without it the difference cannot be
  attributed to a tier and stays `inconclusive`.

The two framing variants are **always `inconclusive` here**, by design. Accepted
ambiguous framing is a normalization fact, not a desync proof. Hand it to
`skills/desync` and the `raw` tool, which run the baseline/trigger pair on fresh
connections that this script deliberately does not.

## 6. Write it down

Verdict front matter as every worker writes it, and `candidates/<id>.md` with:

- the subcommand and its exact arguments, and the `--json` output as the
  artifact;
- the **key**, verbatim, including the buster value;
- the traffic ids of the prime, the read that proves it and the negative
  control (`traffic/<id>`), which the `--dir` run recorded as byte-exact
  `kind: "raw"` records;
- the cache signal and its confidence, said out loud: "the content oracle
  stands; `X-Cache: HIT` supports it and would not be enough alone";
- the **cleanup**, its state and the id of the read that verified it;
- the impact in one sentence, and the step you did not take. "An attacker could
  have stored a redirect to a host they control on the bare key, which would
  reach every visitor of this page; it was not done, and the proof is confined
  to a buster key" is a finding. Doing it is not.

```
script: name "evidence", args ["build", "engagements/<dir>", "--id", "<id>"]
script: name "evidence", args ["check", "engagements/<dir>"]
```

Note in the finding that a straight replay of the stored prime will not
re-poison the key, because the cleanup left a fresh clean entry there. That is
rule three doing its job. The bytes are stored for inspection and diffing, and
reproduction is the same subcommand on a new buster key — which the `replay`
block of the `--json` output spells out for the triager.

## 7. The lab

`lab/cachelab/` is the fixture: an origin that reflects `X-Forwarded-Host`, a
cache in front of it that keys on no header at all, `/account` stored under a
`.css` suffix, `/api/item` honouring a method override, and an edge that
forwards `%2e%2e` and `;` verbatim. Loopback only, every fake credential is
`MYTHOS_LAB_CANARY`.

    python3 lab/cachelab/cachelab.py          # edge 5027, origin 5028
    python3 scripts/cache selftest            # offline asserts + a real poisoning

`selftest` stands up that fixture on ephemeral ports, proves an unkeyed-header
poisoning end to end, and asserts the cleanup was verified. Running against this
fixture, or another cache you own outright, is the only place
`--i-own-this-cache` belongs.
