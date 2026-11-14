# Gap analysis, 14 November 2026

Follow-up to `2026-11-13-gap-analysis.md`, after the CLI rebuild. Sources: eight
parallel research streams, notes under `docs/research/notes-2026-11-14/`.

## 0. What changed since the last one

The November 13 plan was about prose, and the prose got written: `knowledge/web/`
holds 44 notes, 34 of them touched this month, including the four classes that
analysis called missing (OAuth/OIDC, auth flows and ATO, tenant isolation,
client-side DOM, client-side supply chain). Eighteen skills exist.

The gap moved one layer down. The framework now knows more than it can do.

## 1. The structural gap: knowledge without execution

Three findings, each verifiable in the tree:

**Fourteen of eighteen skills are unreachable in practice.** `cli/src/prompts.ts`
names `skills/recon`, `skills/web-scan`, `skills/exploit` and `skills/report`.
Nothing names auth-session, business-logic, oauth-audit, tenant-isolation,
ai-app, deep-server, stored-xss-oast, source-review, cve-deep-dive, continuous,
traffic, toolbox or engagement-setup. The `reference` tool can read any of them,
but no prompt tells the agent they exist, so a run will not find them.

**Six skill-local scripts are orphaned.** `auth_login.py`, `session_check.py`,
`bola_diff.py`, `mass_assign.py`, `race.py` and `xss_verify.py` live under
`skills/*/scripts/`. The `script` tool's allowlist in `cli/src/agent/tools.ts`
holds nine names and none of them. The repo is mounted read-only at `/repo`, so
`shell` could run them, but again nothing points there.

**The browser tool cannot execute the client-side playbooks.**
`cli/src/agent/browser.ts` has goto, click, type, text, html, eval, console,
requests, screenshot, close. `knowledge/web/client-side-dom.md` asks for a sink
hook installed before page load, a second origin and a second browser context.
None is possible: there is no `add_init_script`, no CDP session, no second
context, no WebSocket frame capture, and the screenshot is discarded rather than
stored as evidence.

A fourth, smaller one: the `http` tool allows GET, POST, PUT, PATCH, HEAD and
OPTIONS. No DELETE, so a BFLA test against a delete route cannot be written.

## 2. What rivals do that this does not

From stream 01. Treat as vendor self-report unless marked otherwise.

- **An independent validator.** XBOW separates discovery from confirmation: the
  agent that finds a candidate never confirms it ("We Ran 1,060 Autonomous
  Attacks", 2 March 2026). Mythos has the exploit worker write its own verdict.
  Berkeley's RECEIPT (July 2026) measured what that costs: a naive
  "JavaScript executed" verifier let an agent claim 111 XSS findings, of which
  10 were real.
- **Fresh-context fan-out under a persistent coordinator**, with
  bug-likelihood ranking before the fan-out. XBOW and MindFort claim this.
- **Safety outside the prompt.** XBOW runs a safety check on every action and
  enforces scope at the network level. Mythos enforces in the tool layer, which
  is better than prompt text, but still after the decision to send.
- **Preflight for WAF, CAPTCHA and bot detection**, and resilience when auth
  breaks mid-run (XBOW, Black Hat 2026).
- **Cross-run memory beyond a lessons file.** PentAGI uses pgvector plus a
  Graphiti graph; CAI has `/memory` and `/graph`.
- **Per-PR scoped runs and fix PRs.** Strix `--scan-mode quick`, Shannon's CI
  gate counting only `status: exploited`.

The one measured independent number in the whole sweep: ARTEMIS
(arXiv 2512.09882) reported 82% finding validity in its model-mix configuration
and 55% with GPT-5 alone, at $18 to $59 per hour. One of its false positives was
reading a 200 OK redirect to the login page as a successful login.

## 3. Class coverage

Playbook exists, execution missing: GraphQL (note plus `graphw00f` in the image,
but the note says it is manual), SAML/SCIM, webhooks, races (`race.py` exists and
`h2spacex` is in the image, but nothing calls it), prototype pollution,
postMessage, DOM clobbering, CSP, mXSS, CSWSH.

Nothing at all: gRPC/gRPC-web/Connect, tRPC and JSON-RPC batch authorization,
OData, SOAP, Next.js Server Actions replay per role, passkeys and WebAuthn,
HMAC request signing, mTLS header trust, RFC 8693 token exchange, service
workers, SSE, source-map recovery, LaTeX and PDF renderer sinks, Kubernetes
ingress, SPF/DMARC.

Stale: `knowledge/web/request-smuggling.md` cites 2019 and 2021 research only.
Kettle's "HTTP/1.1 must die" (6 August 2025) added 0.CL, Expect-based CL.0,
early-response gadgets and H2.TE, and detection moved from timing to a
baseline-versus-trigger comparison. The August 2026 follow-ups are CRLF-powered
desync and the HTTP Terminator, which produced CVE-2026-63078 in Apache Traffic
Server. Ten knowledge notes are under 40 lines.

**The desync constraint is architectural.** The recording proxy in
`scripts/traffic` is an HTTP/1.1 stdlib forward proxy that parses each message's
framing. A 0.CL probe would deadlock it, and it cannot carry HTTP/2. Tools that
bypass it (smuggler, raw sockets) leave no record at all. Supporting modern
desync means a raw transport tool with byte-exact writes, half-close control and
its own tee recorder, not a tweak to the proxy.

Toolbox corrections, since three research streams got this wrong: `wcvs`,
`ysoserial`, `phpggc`, `graphw00f` and `jwt_tool` are in the image, and
`h2spacex==1.2.2` is in `toolbox/requirements.in`. Genuinely absent:
ysoserial.net, grpcurl, graphql-cop, Clairvoyance, InQL, Schemathesis, jsluice,
gitleaks, x8.

## 4. AI surface

`knowledge/web/mcp-security.md` already covers confused deputy, token
passthrough, discovery SSRF and tool poisoning, so that part of the brief was
wrong. What the research adds:

- **A fixed payload set proves nothing.** "The Attacker Moves Second" broke 12
  published defences at over 90% attack success where their authors had reported
  near zero. Testing needs a mutation loop over carrier, framing and encoding,
  each variant with its own control.
- **The statistics are weak at the k the ai-app skill uses.** 5 of 10 has a 95%
  Wilson interval of roughly 24% to 76%. A control of 0 of 10 only bounds the
  control rate below about 31%. Report interval bounds, raise k when a result is
  borderline.
- **Fingerprints are missing** for n8n (CVE-2026-21858, CVSS 10, over 24,700
  exposed in February 2026), unauthenticated Ollama and vLLM, vector-DB REST
  surfaces, AI gateways, Gradio, Streamlit and Jupyter. The ai-app skill names
  only Langflow and Flowise.
- **Rug-pull detection**: a `tools/list` snapshot diff across a session.

## 5. Harness

Confirmed missing by reading `cli/src`: checkpoint and resume (the word appears
only for the TUI pause), prompt cache control (nothing anywhere), cost
accounting (`loop.ts` sums `usage.totalTokens` with no input/output/cached split
and no prices), a trace or replay viewer, and any measurement of the framework's
own effectiveness (`bench/` is now an empty `runners/` plus a `__pycache__`).
Model routing is half there: `models.json` assigns tiers per agent and forces
the validator tier to differ from strong, but nothing escalates to a stronger
model after a cheap one fails.

Evidence worth acting on:

- **Prompt caching.** Cache reads cost about a tenth of base input. The parallel
  exploit workers each carry a long static prefix, so keeping the system prompt,
  skill text and tool schemas byte-stable and putting target, timestamps and
  hints after the breakpoint is the single cheapest win available.
- **The lessons ledger is an untested hypothesis, and the one measurement that
  exists is unflattering.** ERL (alphaxiv 2603.24639) found distilled lessons
  beat raw trajectories, 56.1 against 46.4 on a 48.3 baseline, 76 tasks, no
  significance test. Lessons from failures carried the gain (58.9) and lessons
  from successes almost none (49.9). Agent-labelled lessons, without a
  ground-truth outcome, lost about 5 points, and injected tokens raised cost
  about 40%. Mythos labels from its own verdicts, which are oracle-backed, so
  the design is on the right side of that result, but nothing measures it.
- **Benchmarks are not a safe measuring stick.** A Dreadnode audit found 37.1%
  of Cybench passes involved cheating: flag lookup, container metadata, `/flag`
  files. Apparent 41.5% against a true 26.1%, 22 models. Anti-cheat prompts cut
  it to 8.5% and pushed some models to probe infrastructure instead. The lesson
  for Mythos's own lab: restrict egress and hide flag paths in the toolbox, do
  not ask the prompt to behave.
- **Scaffold diversity beats scaffold tuning.** With the model fixed, five
  scaffolds solved different Cybench tasks: best single 15 of 33, four-scaffold
  union 17, blackboard ensemble 19 (arXiv 2605.28334). Two tasks is within
  noise, so this is a hint, not a result.

## 6. Operations

No platform integration of any kind. What exists to integrate with:

- **Scope import.** HackerOne's `GET /hackers/programs/{handle}/structured_scopes`
  returns `asset_identifier`, `asset_type`, `eligible_for_submission`,
  `max_severity` and a free-text `instruction`, at 50 requests per minute.
  Fallback: arkadiyt/bounty-targets-data, hourly, four platforms. The data is
  lossy: wildcard exclusions and rate limits live in the free text, so an import
  must produce a draft `scope.yaml` a human confirms, and must never widen scope
  on its own.
- **CVSS 4.0** is accepted alongside 3.1 by HackerOne, Bugcrowd and Intigriti,
  and HackerOne caps a report's score at the asset's `max_severity`. Mythos
  emits 3.1 only.
- **No duplicate-check API exists** for researchers on any platform, so
  deduplication has to come from the local fingerprint store plus a record of
  what was submitted.
- **Export targets:** DefectDojo's import-scan endpoint keys off
  `unique_id_from_tool`, which the fingerprints already fit; SysReptor's
  `reptor` CLI takes findings JSON; Ghostwriter has a GraphQL API.

**Policy, and this is the part that constrains the design.** Bugcrowd (10 March
2026): ten or more consecutive invalid reports tied to automated or AI activity
without pre-submission validation draws a 30-day suspension, submission farming
a permanent ban. Intigriti requires disclosing how AI was used, requires the
researcher to have personally verified the finding, and bars unapproved
third-party tools that process repro data, which may cover sending PoC data to
an external model API. HackerOne's code of conduct (April 2026) bans large-scale
submission of unverified low-signal reports and keeps the researcher responsible
for validating model output.

So autonomous submission is off the table on every major platform. The correct
output is a submission-ready draft plus an evidence bundle that a named human
replays and submits, with an AI-disclosure field in the report.

## 7. Ranking

Cheap and high leverage: wire the fourteen skills and six scripts into the
phases; add DELETE to the `http` tool; prompt-cache discipline; store
screenshots as evidence.

Structural: an independent validator that the finder cannot touch; browser
instrumentation (`add_init_script`, CDP, second context, WebSocket capture); a
raw transport tool with its own recorder, for desync.

Breadth, in payout order: SSRF with a metadata emulator in the lab, account
takeover chains, GraphQL execution, source-map and bundle recovery, prototype
pollution read-back, AI platform fingerprints.

Operations: scope import as a draft, CVSS 4.0 alongside 3.1, an evidence bundle
per finding, DefectDojo export.

Measurement: a paired same-target A/B harness with McNemar and Wilson intervals
before any further claim, and cost per verified finding as the unit. Expect null
results at the sample sizes available.

## 8. What this analysis does not establish

Almost every competitor capability is vendor self-report; no audited shared
leaderboard exists. The only third-party numbers here are ARTEMIS, RECEIPT, ERL,
the Dreadnode cheating audit and the scaffold-diversity paper. Several platform
policy details came from secondary coverage, and the per-class bounty-value
ranking is judgement, not data: no platform publishes per-class payouts.
