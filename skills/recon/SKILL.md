---
name: recon
description: Reconnaissance playbook for a Mythos web engagement — map the in-scope attack surface with real tools (whatweb, subfinder, httpx, katana, ffuf, gau, arjun) run in the Kali toolbox. Use at the start of an engagement, after scope is set, to enumerate hosts, endpoints, parameters, forms, technologies and exposed files before any active scanning.
---

# Recon — map the attack surface

You are mapping what exists before you attack it. Touch only hosts the engagement
`scope.yaml` authorizes. All tools run in the Kali toolbox via `scripts/mythos`
(see the `toolbox` skill). Write everything under `engagements/<dir>/recon/`.

A lab target on the host's `localhost:PORT` is reached from the toolbox as
`http://host.docker.internal:PORT`. A public target is reached by its real host.

## 0. Read the app by hand first

Start with one call: `scripts/probe <target> --depth 2`. It runs on the host,
needs no container, and returns the pages, forms, interesting headers, weak
cookie flags, reachable paths like `/.env` or `/graphql`, the technology it
could fingerprint, and every parameter with the bug class its name suggests.
When it finds an OpenAPI or Swagger document it reads it too, so on a JSON API
you get every documented endpoint, query parameter, path parameter and request
body field as an aim point. Add `--header 'Cookie: ...'` to map the
authenticated surface, `--json` to feed it to another tool. Then read it and only chase what it could not see.

Cheapest evidence first, tools after.

1. `curl -sS -D- <URL>` the entry point. Read the body and the headers.
2. Fetch every link and form you saw. Note each parameter, id, redirect,
   error message, and the auth mechanism.
3. Extract the parameters and ids from the responses you actually read, not
   from a wordlist. Rank what each one suggests.
4. If that is the whole surface — one host, a handful of pages — the map is
   done. Hand it to **web-scan** and skip the steps below.

Start the toolbox only when you need a tool from it:

```
scripts/mythos up
```

katana, ffuf, arjun and subfinder earn their cost on a large or unknown
surface: many hosts, an SPA, an API, content you cannot reach by reading
links. A broad crawl of a handful of pages is wasted budget — the parameters
and ids are already in the responses you read.

## 1. Fingerprint the technology

```
scripts/mythos whatweb -a 3 <URL>
scripts/mythos sh 'httpx -u <URL> -title -tech-detect -status-code -server -json'
scripts/mythos wafw00f <URL>
```

Record: server, framework, language, CMS, WAF, notable headers. The stack drives
which bug classes matter (e.g. Flask/Jinja → SSTI; PHP → LFI/SQLi; Node → proto
pollution; Spring → actuator/SpEL).

## 2. Subdomains + liveness (domain targets only; skip for a single host/IP)

```
scripts/mythos subfinder -d <domain> -silent          > engagements/<dir>/recon/subs.txt
scripts/mythos sh 'cat engagements/<dir>/recon/subs.txt | httpx -silent -title -tech-detect -status-code' \
    > engagements/<dir>/recon/live.txt
```

Keep only in-scope subdomains (check each against `scope.yaml`).

## 3. Crawl — links, forms, parameters, JS endpoints

```
scripts/mythos katana -u <URL> -jc -kf all -d 3 -silent  > engagements/<dir>/recon/urls.txt
scripts/mythos sh 'gau --threads 4 <host> 2>/dev/null | anew engagements/<dir>/recon/urls.txt' || true
```

`katana -jc` parses JavaScript for endpoints (crucial for SPAs). For a client-
rendered SPA where katana under-collects, hand off to the **mythos-browser**
agent to render the DOM and capture `fetch`/XHR endpoints.

## 4. Parameter discovery on interesting endpoints

```
scripts/mythos arjun -u '<URL-with-endpoint>' -m GET          # and -m POST
```

Use on endpoints with no obvious params but dynamic behaviour. Capture any
hidden parameters.

## 5. Content / sensitive-path discovery

```
scripts/mythos ffuf -u '<URL>/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -mc 200,204,301,302,307,401,403,405 -fs 0 -t 40 -ac -s
```

Then probe the classic exposures directly (don't fuzz what you can just GET):
`/.git/HEAD`, `/.env`, `/.git/config`, `/backup.zip`, `/.DS_Store`,
`/actuator`, `/swagger.json`, `/openapi.json`, `/graphql`, `/robots.txt`,
`/.well-known/security.txt`.

```
scripts/mythos sh 'for p in .git/HEAD .env actuator/env swagger.json openapi.json graphql robots.txt; do \
  printf "%-20s " "/$p"; httpx -silent -status-code -u <URL>/$p; done'
```

## 6. API spec import

If you find an OpenAPI/Swagger or GraphQL endpoint, pull it and enumerate every
operation/field — those are high-value, often under-tested surface. Note each
endpoint + its parameters for the scan phase. Save the spec as
`engagements/<dir>/recon/openapi.json`; **business-logic** diffs it for mass
assignment and takes its id-bearing paths for BOLA. For GraphQL run introspection:

```
scripts/mythos sh "curl -s <URL>/graphql -H 'Content-Type: application/json' \
  -d '{\"query\":\"{__schema{types{name fields{name}}}}\"}'"
```

## Output

Write `engagements/<dir>/recon/surface.md` summarizing:

- technologies / server / WAF;
- live in-scope hosts;
- endpoints grouped by interest: auth, admin, API, upload, redirect-like, file-like, numeric-id (IDOR), reflected;
- forms and their parameters;
- exposed files found;
- **the most promising injection points** and which bug class each suggests;
- the login mechanism (form, JSON API, SPA, SSO/OAuth) and the endpoints that
  carry per-user objects.

Respect the rate limit in `scope.yaml` (throttle `-t`/`-rate` flags). Do not run
injection attacks here — that is the **web-scan** / **exploit** phase.

If there is a login: run **auth-session** next (one session per role), then
repeat steps 3 to 6 authenticated (`katana -H engagements/<dir>/sessions/userA.headers`,
or `-headless -xhr` for an SPA) and add what only a logged-in user sees to
`surface.md`. Then hand the surface to the scanner.
