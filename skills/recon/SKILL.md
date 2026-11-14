---
name: recon
description: Reconnaissance playbook for a Mythos web engagement — map the in-scope attack surface with real tools (whatweb, subfinder, httpx, katana, ffuf, gau, arjun) run in the Kali toolbox. Use at the start of an engagement, after scope is set, to enumerate hosts, endpoints, parameters, forms, technologies and exposed files before any active scanning.
---

# Recon — map the attack surface

You are mapping what exists before you attack it. Touch only hosts the engagement
`scope.yaml` authorizes. Kali tools run in the toolbox through the `shell` tool
(see the `toolbox` skill), and the target's address inside the container is in
your system prompt.

This phase owes the next one three files in the engagement directory:
`surface.json`, `cve-candidates.json` and `recon.md`. The phase does not close
without `surface.json` and `recon.md`, and an empty map does not count. Raw tool
output goes under `recon/`.

## 0. Read the app by hand first

Start with one call: the `script` tool, name `probe`, args
`["<target>", "--depth", "2"]`. It runs on the host, needs no container, and
returns the pages, forms, interesting headers, weak
cookie flags, reachable paths like `/.env` or `/graphql`, the technology it
could fingerprint, and every parameter with the bug class its name suggests.
When it finds an OpenAPI or Swagger document it reads it too, so on a JSON API
you get every documented endpoint, query parameter, path parameter and request
body field as an aim point. Add `--header 'Cookie: ...'` to map the
authenticated surface, `--json` to feed it to another tool. Then read it and only chase what it could not see.

Keep the map: run `probe` again with `--json` and write the result to
`surface.json` with the `files` tool. Everything downstream counts endpoints
from that file: the exploit phase needs a verdict for each one and
`scripts/coverage` checks the report against it, so a thin map silently shrinks
the whole engagement and a whole surface cannot be skipped without the report
saying so.

Cheapest evidence first, tools after.

1. The `request` tool on the entry point. Read the body and the headers.
2. Fetch every link and form you saw. Note each parameter, id, redirect,
   error message, and the auth mechanism.
3. Extract the parameters and ids from the responses you actually read, not
   from a wordlist. Rank what each one suggests.
4. If that is the whole surface — one host, a handful of pages — the map is
   done. Write it down and skip the steps below; the scan phase reads your
   files.

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

### 1a. The AI / automation stack

Self-hosted LLM and workflow tooling is where unauthenticated RCE keeps landing,
and it gets exploited within hours of disclosure (Langflow alone has collected a
handful of CISA KEV entries; see `knowledge/techniques/cve-triage-2026.md`).
`whatweb` does not know
any of it, so ask directly. **Get the exact version** — it is the difference
between a candidate you can rank and a guess:

The `script` tool, name `cvefeed`, args `["products"]`, prints the full list
with the version endpoint for each.

| Product | Default port | Where the version is |
|---|---|---|
| Langflow | 7860 | `GET /api/v1/version` → `{"version": ...}`; `/api/v1/auto_login` |
| Flowise | 3000 | `GET /api/v1/version`; `GET /api/v1/ping` |
| Dify | 5001 | `GET /console/api/version?current_version=0.0.0` |
| Open WebUI | 8080 | `GET /api/config` → `{"name": "Open WebUI", "version": ...}` |
| Ollama | 11434 | `GET /api/version`; `/` → `Ollama is running`; `/api/tags` |
| vLLM | 8000 | `GET /version`; `/v1/models`; `/openapi.json` → `info.version` |
| LiteLLM | 4000 | `GET /health/readiness` → `litellm_version` |
| n8n | 5678 | `GET /rest/settings` → `data.versionCli` |
| ComfyUI | 8188 | `GET /system_stats` → `system.comfyui_version`; `/object_info` |
| Gradio | 7860 | `GET /config` → `{"version": ...}`; `/info`; `/file=` paths |
| MCP gateway | — | `GET /sse` or `/mcp` (`text/event-stream`); POST JSON-RPC `initialize` → `result.serverInfo` |

One `shell` pipeline covers it, one GET per path:

```
for p in api/v1/version api/config api/version version config system_stats \
         rest/settings health/readiness console/api/version info object_info; do
  printf '%-26s ' "/$p"
  curl -sS -m 5 -o /tmp/v -w '%{http_code} %{size_download} ' <URL>/$p; head -c 120 /tmp/v; echo
done
```

An exposed MCP endpoint is its own class of surface: enumerate the tools it
offers (`tools/list`) and treat every one that touches a shell, a file or an
HTTP client as an injection sink. Record the server name and version from
`initialize`.

Note the version **and how you got it**: read off a `/version` endpoint is
`--fingerprint`, scraped from a banner or a bundle is `--banner`. Step 1b needs
that distinction.

## 1b. CVE candidates for what you just fingerprinted

Fresh CVEs are the cheapest high-severity finding on modern self-hosted
software, and the ids rot too fast to keep in a skill. `scripts/cvefeed` holds
the live data (CISA KEV, EPSS, NVD, nuclei templates, GHSA, OSV) and ranks it
by the pipeline in `knowledge/techniques/cve-triage-2026.md`.

Run it with the `script` tool, name `cvefeed`, and write the JSON it prints to
`cve-candidates.json` with the `files` tool:

```
args: ["match", "--fingerprint", "langflow@1.6.0", "--banner", "nginx@1.18.0",
       "--product", "mcp", "--json"]
args: ["match", "--fingerprint", "langflow@1.6.0"]            # the readable version
```

`--fingerprint NAME@VERSION` for a version you read off the product,
`--banner NAME@VERSION` for one you guessed from a header, `--product NAME`
when you have no version at all. The confidence it prints depends on which you
used, so do not promote a guess. `--from-probe` reads a probe map on stdin, so
it needs a `shell` pipeline rather than the `script` tool:
`python3 /repo/scripts/probe <target> --depth 2 --json | python3
/repo/scripts/cvefeed match --from-probe --json` (everything probe reads off a
header counts as a banner).

It refreshes from the feeds at the start of the engagement and falls back to the
committed snapshot in `knowledge/cve/` with its age printed. Read that header:
if it says `** STALE **`, say so in the report. It contacts third-party CVE
APIs, never the target — a scope-guard warning naming `services.nvd.nist.gov`
or `api.first.org` is this step, not a scope slip.

Write `cve-candidates.json` into the engagement directory and name its top rows
in `recon.md`. It is a ranked list of **what is worth testing**, never a verdict: a KEV entry means exploited in the wild
somewhere, EPSS is a prediction, and a version match is worth what your
fingerprint is worth. A row with `nuclei_template` has a non-destructive check
ready (`nuclei -id <cve> -u <URL>` through `shell`); a KEV row without one goes
to the `cve-deep-dive` skill.

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

`katana -jc` parses JavaScript for endpoints, which is what an SPA needs. Where
katana under-collects on a client-rendered surface, use the `browser` tool: its
rendered DOM and request log show the `fetch`/XHR endpoints curl never sees.

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

Write `recon.md` in the engagement directory summarizing:

- technologies / server / WAF, each with its version and how the version was
  obtained;
- the top CVE candidates from `cve-candidates.json` with their KEV/EPSS flags
  and match confidence, plus the age and source of the CVE data;
- live in-scope hosts;
- endpoints grouped by interest: auth, admin, API, upload, redirect-like, file-like, numeric-id (IDOR), reflected;
- forms and their parameters;
- exposed files found;
- **the most promising injection points** and which bug class each suggests;
- the login mechanism (form, JSON API, SPA, SSO/OAuth) and the endpoints that
  carry per-user objects.

Respect the rate limit in `scope.yaml` (throttle `-t`/`-rate` flags). Do not run
injection attacks here — that is the **web-scan** / **exploit** phase.

If there is a login: follow **auth-session** (one session per role), then
repeat steps 3 to 6 authenticated (`katana -H engagements/<dir>/sessions/userA.headers`,
or `-headless -xhr` for an SPA) and add what only a logged-in user sees to
`surface.json` and `recon.md`. Say which accounts you created: a second identity
is what an access-control test needs.
