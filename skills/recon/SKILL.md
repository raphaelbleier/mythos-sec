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

## 0. Toolbox up

```
scripts/mythos up
```

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
endpoint + its parameters for the scan phase. For GraphQL run introspection:

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
- **the most promising injection points** and which bug class each suggests.

Respect the rate limit in `scope.yaml` (throttle `-t`/`-rate` flags). Do not run
injection attacks here — that is the **web-scan** / **exploit** phase. Hand the
surface to the scanner.
