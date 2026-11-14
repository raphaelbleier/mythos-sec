<p align="center">
  <img src="docs/assets/logo.png" alt="Mythos" width="460">
</p>

<p align="center">
  <b>Mythos</b> — an autonomous web red-team agent for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point it at a target you are allowed to test. It maps the surface, reasons about the
  stack, drives real security tools in a Kali container, proves what it finds, and writes
  the report. Four phases enforced in code, every endpoint accounted for, your model behind it.</i>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-can-do">What it can do</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#models-and-providers">Models</a> ·
  <a href="#scope-and-safety">Safety</a> ·
  <a href="#what-this-does-not-claim">Limits</a>
</p>

<p align="center">
  <a href="https://github.com/raphaelbleier/mythos-sec/actions/workflows/check.yml"><img src="https://github.com/raphaelbleier/mythos-sec/actions/workflows/check.yml/badge.svg" alt="check"></a>
  <a href="https://github.com/raphaelbleier/mythos-sec/actions/workflows/toolbox.yml"><img src="https://github.com/raphaelbleier/mythos-sec/actions/workflows/toolbox.yml/badge.svg" alt="toolbox image"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-f0a52a" alt="MIT"></a>
</p>

---

> ### Authorized testing only
>
> Bug-bounty programs whose scope covers the host, systems you own, or lab targets.
> "Allowed" means written authorization or a published program scope, not your own
> judgement that nobody will mind.
>
> `engagements/<dir>/scope.yaml` is the authorization boundary and nothing in a run widens
> it. The scope guard **warns** by default, which means the request is already out when you
> read the warning. Set `MYTHOS_SCOPE_ENFORCE=ask` for anything that is not a lab and the
> call is refused instead.

```bash
mythos -t https://target.example.com --scope engagements/acme/scope.yaml
```

<p align="center">
  <img src="docs/assets/cli.png" alt="Mythos running an engagement: the phase rail, two parallel exploit workers and the guard output" width="880">
</p>

---

## Contents

- [What it can do](#what-it-can-do)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [How it works](#how-it-works)
- [What a run produces](#what-a-run-produces)
- [Models and providers](#models-and-providers)
- [Scope and safety](#scope-and-safety)
- [Continuous testing](#continuous-testing)
- [What this does not claim](#what-this-does-not-claim)
- [Layout](#layout)
- [Contributing and license](#contributing-and-license)

---

## What it can do

### Run a whole assessment without you

One command maps the surface, decides what is worth attacking, attacks it, proves what
holds, and writes a report a triager can read. Nothing is asked mid-run: there is one human
gate and it is the scope file, settled before the run starts. On a lab target with 36
mapped endpoints, a run took 50 minutes and closed every phase.

### Find and prove these classes

The skills and the per-class playbooks in `knowledge/` cover:

| Area | Classes |
|---|---|
| Injection | SQL (error, boolean, blind, UNION, and via sqlmap), NoSQL, OS command (reflected and blind over OOB), SSTI through to RCE, XXE, CRLF and response splitting, deserialization |
| Access control | IDOR and BOLA with two identities, privilege escalation, multi-tenant isolation, mass assignment, broken function-level authorization |
| Client side | Reflected, stored and DOM XSS proven by execution in a real Chromium, CSRF, clickjacking, WebSocket abuse, client-side supply chain, client-side path traversal |
| Authentication | JWT forgery, weak signing keys and `alg` confusion, OAuth 2.0 and OIDC flow abuse (`redirect_uri`, `state`, PKCE), SAML and SCIM, session fixation, account-takeover chains |
| Server side | SSRF with out-of-band confirmation, path traversal and LFI with filter evasion, file upload, request smuggling, web cache poisoning, race conditions, parser differentials, gateway bypass |
| APIs | GraphQL introspection, resolver injection and batching abuse, OpenAPI-driven parameter coverage, excessive data exposure, webhooks, BaaS and cloud-storage exposure |
| AI applications | Prompt injection, unsafe tool invocation, output handling, MCP server exposure |
| Configuration | Exposed secrets and `.env`, verbose debug endpoints, CORS, security headers and cookie flags, subdomain takeover |
| Known CVEs | Live triage of the fingerprinted stack against KEV, EPSS, NVD, GHSA, OSV and nuclei templates |

This is what the methodology aims at, not a measured success rate. Each class has a
confirmation playbook that says what counts as proof and what does not.

### Prove findings instead of listing suspicions

Every finding carries the exact request, the response that proves it, a negative control,
the CVSS vector and the score computed from that vector rather than typed next to it. A
canary that merely appears in a response is a reflection and is reported as one. Before the
report is written a second model reviews the findings: a model approves its own errors 11.9
percentage points more often when it wrote them, so the validator tier has to be a
different model, and a profile that cannot provide one makes the report say so.

### Account for every endpoint, not just the hits

Exploitation closes on coverage. Each endpoint in the surface map needs an explicit
verdict: **confirmed** with evidence, **tested** against the classes its shape suggests, or
**skipped** with a reason a reader can check. Endpoints without one are work still owed and
the driver keeps assigning workers until there are none. "Tested, not vulnerable" and
"never looked at" are different sentences, and only one of them is honest about a gap.

### Drive real tools, not only a model

nuclei, sqlmap, ffuf, httpx, katana, dalfox, nikto, whatweb, arjun, wafw00f, commix,
jwt_tool, interactsh and subfinder, all inside a signed Kali container, plus a real
Chromium for anything client-rendered. Nine deterministic Python tools do the mechanical
work in one call each, instead of dozens of model round trips:

| Tool | What it does |
|---|---|
| `probe` | maps the surface, GET only except the GraphQL introspection POST |
| `verify` | sends benign canaries at every parameter and judges each against an oracle |
| `cvefeed` | ranks CVE candidates for the fingerprinted stack from six live feeds |
| `coverage` | lists the mapped paths the report does not account for |
| `findings` | builds `findings.json` and SARIF, computes CVSS from the vector, dedups, redacts |
| `sourcemap` | routes, missing guards and sinks from a source tree, for grey-box work |
| `traffic` | what was sent, byte-exact replay, HAR export for Burp or Caido |
| `watch` | what changed on a tested target since last time |
| `lessons` | class priors from past engagements |

### Record everything it sends

A recording proxy captures every request and response of a run, byte for byte. Any one of
them can be replayed and the response diffed, or the lot exported as HAR into Burp. The
report references findings by traffic id, so a triager can re-send the proof.

### Fit a pipeline

`findings.sarif` drops into a CI annotation. `findings --diff` compares against a previous
run for a retest: fixed, still present, new. `scripts/watch` keeps a tested target under
observation between engagements.

### Refuse to break the target

Data destruction, brute force and denial of service are refused in code, in every mode, and
no scope rule overrides it. One exception is deliberate: deleting an object you created
yourself is how an access-control finding gets proven without touching anyone else's data,
so that is warned about and allowed.

---

## Install

Node 20 or newer, Python 3.11 or newer, Docker.

```bash
git clone https://github.com/raphaelbleier/mythos-sec
cd mythos-sec/cli
npm ci && npm run build
npm link                      # puts `mythos` on your PATH
cd .. && mythos doctor        # checks the machine before a run
```

`mythos doctor` pulls and starts the signed Kali toolbox image on first run, which takes a
few minutes, and reports whether your model profile has an independent validator.

For the browser tool:

```bash
npx playwright install chromium
```

<details>
<summary>If the toolbox image will not pull</summary>

`scripts/mythos` pulls the digest pinned in `toolbox/IMAGE_DIGEST` and verifies its cosign
signature. If the registry refuses the pull, build the image locally instead:

```bash
MYTHOS_BUILD=1 scripts/mythos up
```

A locally built image is named `mythos-toolbox` and skips the signature check, because
there is no signature to check. To use an image you already have, set
`MYTHOS_IMAGE=<name-or-digest>`.
</details>

---

## Quick start

Against a lab target, with a scope file generated for that host and port alone:

```bash
docker compose -f lab/docker-compose.yml up -d vulnapp
mythos -t http://127.0.0.1:5001
```

Against a real program, with your own scope file:

```bash
mythos -t https://target.example.com \
  --scope engagements/acme/scope.yaml \
  --budget 7200 --workers 4
```

Quietly, for cron or CI:

```bash
mythos -t https://target.example.com -s engagements/acme/scope.yaml -n
```

While a run is up: `p` pauses, `h` sends the agents a hint ("the admin panel is on 8443"),
`q` aborts. Nothing ever waits for you.

---

## Commands

| Command | What it does |
|---|---|
| `mythos -t <url>` | run an engagement |
| `mythos login <provider>` | OAuth for OpenRouter, `--api-key` for the rest |
| `mythos providers` | what is reachable, and how |
| `mythos doctor` | check the machine before a run |
| `mythos verdicts [dir]` | the endpoint ledger of an engagement |
| `mythos demo` | replay a scripted run through the view |

| Option | Default | Meaning |
|---|---|---|
| `-t, --target <url>` | | the target; a scope file is generated for this host and port alone |
| `-s, --scope <file>` | | an existing `scope.yaml`, the authorization boundary |
| `-b, --budget <s>` | 3600 | whole-run wall clock |
| `-w, --workers <n>` | 3 | parallel exploit workers |
| `--retries <n>` | 2 | attempts per phase before it is recorded incomplete |
| `-m, --model <spec>` | | pin every tier, e.g. `openrouter/z-ai/glm-5.3` |
| `--profile <name>` | | a profile from `models.json` |
| `--skip <list>` | | phases to skip |
| `--rps <n>` | 5 | rate limit for a generated scope file |
| `--headed` | | show the browser instead of running it headless |
| `-n, --no-tui` | | one line per event instead of the full-screen view |
| `-v, --verbose` | | with `-n`, also log tool results and agent prose |

---

## How it works

```
scope.yaml ──► recon ──► scan ──► exploit ──► report
                 │         │       │ │ │         │
                 │         │       └─┴─┴─ parallel workers,
                 │         │              one verdict per endpoint
                 ▼         ▼                     ▼
          surface.json   candidates.md     report.md + findings.json
          cve-candidates.json              + an independent validator pass
```

Three things make this different from pointing a coding agent at a target.

**The phases are in code, not in a prompt.** Each runs as a separate agent with fresh
context and closes on a file it has to produce, not on its own opinion that it is finished.
A phase that does not produce its artifact runs again, then is recorded `incomplete` and
the run carries on, because a half-finished engagement that says so beats one that hangs.

| Phase | Closes when |
|---|---|
| recon | `surface.json` maps at least one endpoint, and `recon.md` exists |
| scan | `candidates.md` exists |
| exploit | every endpoint in the surface has a verdict |
| report | `report.md` and `findings.json` exist |

**Exploitation closes on coverage, not on satisfaction.** This exists because of a
measurement: on a target with 76 documented vulnerabilities, agents stopped after a quarter
of their budget having found a third, with whole surfaces never receiving a single request.
A gate that merely nudged changed nothing, so a ledger decides instead.

**The guards cannot be absent.** Scope checking, rate limiting and the destructive denylist
run inside the tool layer, so every path to the network goes through them. They used to be
host plugin hooks, and a configuration that loaded no plugin silently measured the framework
with all of them inert.

The agent has six tools: `shell` (a pipeline in the Kali container), `request` (one HTTP
request), `script` (the deterministic tools above), `browser` (a real Chromium with its
console and network log), `files` (the engagement directory) and `reference` (the skills
and the knowledge base). The set is small on purpose: the published evidence is that the
tool layer decides the outcome, so the work went into making a few tools carry a lot.

[`docs/architecture.md`](docs/architecture.md) has the detail.

---

## What a run produces

```
engagements/<host>-<date>/
  scope.yaml            the authorization boundary
  surface.json          the surface map
  cve-candidates.json   ranked CVE candidates for the fingerprinted stack
  recon.md              stack, identities, promising surfaces
  candidates.md         what is worth an exploitation attempt
  findings/<id>.md      one file per finding, with its evidence pair
  verdicts/             one verdict per endpoint, with its reasoning
  verdicts.json         the ledger
  validation.md         the independent review pass
  report.md             the deliverable
  findings.json         machine-readable, CVSS computed from each vector
  findings.sarif        SARIF 2.1.0, for a CI annotation
  traffic/              every request and response, replayable, HAR-exportable
  run-events.jsonl      the whole run as an event stream
```

---

## Models and providers

```bash
mythos login openrouter                  # OAuth, mints a real key
mythos login anthropic --api-key sk-ant-...
mythos providers                         # what is reachable, and how
mythos -t <url> --model openrouter/z-ai/glm-5.3
mythos -t <url> --profile anthropic
```

Sixteen providers by API key: OpenAI, Anthropic, Gemini, OpenRouter, Z.ai, Moonshot,
DeepSeek, xAI, Mistral, Groq, Cerebras, Together, Nebius, Ollama and LM Studio locally, and
any OpenAI-compatible endpoint.

`models.json` assigns a tier to each agent and maps tiers to models per profile, so recon
can run on a cheap model while exploitation and validation do not. `--model` pins every
tier except the validator, because pinning that one would turn the independent check into a
self-check without saying so.

**On subscription logins.** OpenRouter's OAuth flow is implemented, because OpenRouter
publishes it for third-party clients and it hands back a real API key. Consumer plan logins
for ChatGPT, Claude and Copilot are not, and will not be: those flows work by presenting
another client's OAuth credentials, the providers either forbid them outright or merely
tolerate them, and the account that gets suspended belongs to the user. One OpenRouter
login reaches most of the models above.

[`docs/models.md`](docs/models.md) has the per-tier table and the data-handling notes.

---

## Scope and safety

`engagements/<dir>/scope.yaml` names the hosts, the ports and the rate limit. The run never
widens it.

| Rule | Mode | Why |
|---|---|---|
| out-of-scope host | warns, or refuses with `MYTHOS_SCOPE_ENFORCE=ask`/`block` | scope is a judgement about authorization, and it is yours |
| rate limit | warns, and paces single calls | a program's limit is a courtesy you may have negotiated |
| data destruction, brute force, denial of service | refused, in every mode | the one hard line |

The hard line is not a setting because a prompt rule did not hold. During benchmarking a run
sent `{deleteAllPastes}` in a GraphQL body, received `{"data":{"deleteAllPastes":true}}` and
emptied the target's table. The guard at the time read the shell and never saw a destructive
operation named inside a request body. It does now.

There is no request ceiling and no exploitation gate. This is a bug-bounty suite: proving a
finding is the work, not an exception to it.

**A request the target makes on your behalf counts as yours.** During benchmarking a run
placed `169.254.169.254` in an SSRF payload and the target made the connection to the cloud
metadata service. The destination of an SSRF probe has to be in scope too.

Testing an application you are not authorized to test is a crime in most jurisdictions,
whatever tool sent the request. The scope file exists so that decision is explicit, written
down and dated. To report a vulnerability in Mythos itself, see [`SECURITY.md`](SECURITY.md).

---

## Continuous testing

Between engagements, `scripts/watch` keeps a tested target under observation: it diffs the
surface, matches new CVEs against the known stack and lists stored proofs worth replaying.
The `continuous` skill works that list. It is pinned to the engagement's scope file and
holds all traffic when that file changes or the authorization confirmation is older than 30
days, because a scheduled job testing a program whose scope moved is how a tester ends up
unauthorized. See [`docs/continuous.md`](docs/continuous.md).

---

## What this does not claim

The project measured itself against a bare agent with the same model on three deliberately
vulnerable applications, 106 paired vulnerabilities, two blinded raters. It found **no
detectable difference in recall** (p = 1.0000 and p = 0.1435), with the minimum detectable
difference at that sample size being 15 percentage points. It did find that the two arms
covered *different* vulnerabilities at equal totals, which is a smaller and more honest
claim.

That benchmark harness is no longer in the repository, and none of those numbers describe
the current code: the agent was rebuilt from a host plugin into this CLI, and the phase
driver and the verdict ledger are new. Treat the published figures as what motivated the
rebuild, not as its result. They are in the git history.

What the current code has been shown to do is narrower and unblinded: one run against the
local lab target, 50 minutes on GLM 5.3, all four phases closing on their artifacts, 21
findings with evidence, a verdict for all 36 mapped endpoints, and 534 recorded request and
response pairs. That is a working pipeline, not a measurement: one target, one run, no
control arm, no blinded rater.

Other limits worth knowing before you trust it:

- The coverage check is a text check over the report. It cannot tell a real test from a
  mention, so it is a floor on coverage, never evidence of it.
- `scripts/lessons` reports precision among reported findings, not yield, because nothing
  records "I tested this class and found nothing". It is a tie-breaker.
- All three benchmark targets are public repositories with public write-ups, and nothing
  measures how much of them is in a model's training data.
- `scripts/sourcemap` produces a hypothesis list, not findings.
- A target bound to `127.0.0.1` forces the toolbox onto the host's network namespace, which
  removes the isolation between the container and your machine. That is for a local lab and
  nothing else.

---

## Layout

```
cli/               the agent: phase driver, tool layer, providers, full-screen view
  src/driver.ts      phase order, artifact gates, exploit fan-out
  src/agent/         the loop, the six tools, the guard call site
  src/providers/     sixteen providers, OpenRouter OAuth, credential store
skills/            the methodology, one directory per phase and per class
knowledge/         per-class confirmation playbooks and CVE technique notes
hooks/             scope-guard and budget-guard, called by the tool layer
scripts/           the deterministic tools, each with a --selftest
toolbox/           the two-stage Kali toolbox Dockerfile
lab/               vulnerable targets, an OAST catcher and an admin bot
docs/              architecture, model policy, continuous mode, research notes
AGENTS.md          the rules every agent in a run is given
```

---

## Contributing and license

Pull requests are welcome; read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. Every
deterministic tool has a `--selftest`, every guard rule has a selftest case, and
`scripts/selftest.sh` runs the lot offline in about ten seconds.

MIT, see [`LICENSE`](LICENSE). Built for security engineering research into AI pentest
agents.
