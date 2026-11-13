# Gap analysis, November 2026

> **Working notes, not documentation.** This file records what was true when it
> was written and is not kept in sync with the code. For maintained
> documentation see `README.md`, `AGENTS.md` and `docs/architecture.md`.

Five parallel reviews of the public tree at `ef072d2`: competitive landscape,
web vulnerability-class coverage, supply chain (own hygiene and as a testing
capability), AI-application and modern API surfaces, and an internal
engineering audit. Findings are ordered by severity, not by topic. Claims about
this repository were verified against the files; external claims carry a source
and a date, and secondary sourcing is marked.

## 1. Benchmark integrity

The published Vuln Bank separation is not currently defensible.

- `bench/runners/claude_mythos.py:33-35` starts the mythos arm with
  `--add-dir <REPO>`, which includes `bench/data/ground_truth/*.json`.
  `bench/runners/claude_control.py:13-17` gives the control arm an empty
  working directory and no `--add-dir`. The arm that produced the project's one
  positive result had read access to the scoring key. For the flagless labs
  `bench/labs.py` never computes `suspect`, and the `SUSPECT` regex in
  `bench/score.py:21` would not match a ground-truth path, so nothing detected
  it either.
- `bench/score.py:216-223` assigns `rate_limited`, `runner_failed`,
  `provider_stalled` and `classifier_blocked` only `if not r["solved"]`.
  Excluding cells conditional on the outcome can only raise a rate: 0.70 to
  0.90 on sweep A. The criteria are regexes over the transcript including tool
  output, so a target answering `429` unscores a failed cell, and
  `CLASSIFIER_BLOCK` is matched against the agent's own final report.
- Precision 1.00 was never measured. No row in any `triage.json` carries status
  `fp`.
- `docs/poster/poster.md:220` reports 27 findings on Vuln Bank. The triage files
  give 28, 29, 30 and 29. No run produced 27.
- No field records whether the coverage gate was on. The condition behind the
  headline result exists only as a directory name.
- Flagless recall is set by one unblinded rater, keyword-prefilled from the
  arm's own report (`bench/labs.py:180-185`), and the run path carries the arm
  name.
- Nothing is reproducible from the repository alone: no `results.jsonl`, no
  transcripts, no `triage.json`. Results default to
  `/mnt/linux-data/mythos-bench/results`, hardcoded in `bench/xben.py:17` and
  `bench/runners/strix.py:16`.
- `docs/poster/eval.json`, `eval-native.json`, `eval-live-multitool.json` and
  `eval-real-apps.json` publish recall, precision and f1 of 1.00 from the
  deleted engine, with no superseded marker.
  `docs/poster/benchmark-xbow.md` cites a harness that no longer exists and is
  linked from `README.md:351-352` as evidence.
- `bench/runners/cai.py` and `bench/runners/pentestgpt.py` raise
  `NotImplementedError`, yet `poster.md:8-10` cites their published scores.

External context: XBEN is saturated. XBOW's own repository now describes it as
trained into the models and kept for historical purposes. A null result there
is the expected outcome and should not carry the project's argument.

## 2. Promise versus code

| Promised | Where | Enforced by |
|---|---|---|
| non-destructive, no DoS, no brute force | `.opencode/agent/mythos.md:215-218`, `AGENTS.md:46-47` | nothing. `skills/business-logic/scripts/mass_assign.py:123-145` writes an escalated field to a live object and never restores it. `skills/stored-xss-oast/scripts/xss_verify.py:25` exfiltrates `document.cookie` to the OAST host whenever `--oast` is set, including against internet targets. |
| `rules.rate_limit_rps` | `README.md:218`, `skills/engagement-setup/SKILL.md:30` | nothing reads it. `scripts/verify` paces from its own `--rate`; `scripts/probe:188-280` sends up to 40 page fetches, 16 common paths and a GraphQL POST with no pacing. |
| `rules.max_requests` | `README.md:219` | nothing counts requests anywhere. `engagements/audit.jsonl` logs execs, not requests. |
| `ports:` | written into every benchmark scope by `bench/run.py:44` | no code reads it; the guard has no port awareness. |
| `allow_active` / `allow_exploit` | `skills/web-scan/SKILL.md:9`, `skills/exploit/SKILL.md:9` | prose only. `hooks/scope-guard.py:60-61` reads only `in_scope` and `out_of_scope`. |
| no data dumping, minimal PoC, PII handling | `skills/exploit/SKILL.md:69` | nothing blocks `--dump`. `skills/report/SKILL.md:27` requires pasting raw request and response with no redaction rule. `skills/auth-session/scripts/auth_login.py:212` writes `argv` including `--password` to disk. |
| closure states | `skills/exploit/SKILL.md:28` | convention. `xss_verify.py:100` prints `validated` itself. |
| anti-give-up | `.opencode/agent/mythos.md:99-125` | the one rule with real code (`hooks/coverage-gate.py`), capped at 3 nudges and defeated by substring matching (see 3). |

### Scope guard

Verified bypasses against `in_scope: app.example.com`. Only
`https://evil.test/x` is detected, and in `warn` mode even that request has
already been sent:

```
http://app.example.com@evil.test/        # userinfo
curl evil.test                           # bare host, no scheme
nmap evil.test ; dig evil.test
http://[2001:db8::1]/                    # IPv6 literal
http://3232235777/                       # decimal IP
curl --resolve a:80:1.2.3.4 http://a/
```

Structural problems beyond parsing:

- `hooks/scope-guard.py:37-38` `SAFE_HOSTS` exempts `127.0.0.1`, `localhost`,
  `0.0.0.0`, `::1` and `host.docker.internal` unconditionally. On a customer
  engagement every request to the operator's own loopback is invisible.
- `extract_hosts` (`:113-116`) sees only URLs and seven flags, so
  `nuclei -l targets.txt`, `sqlmap -r req.txt`, a `Host:` header and any
  positional host pass unseen.
- Empty `in_scope` silently authorizes everything (`:127-128`); no scope file
  means silence (`:123-124`).
- The active scope is the newest `engagements/*/scope.yaml` by mtime
  (`:69-74`), and `MYTHOS_SCOPE` is set only by the bench harness and the
  self-test, never by the orchestrator. A stale benchmark engagement directory
  in the working tree can become the authorization boundary of a live run.
- The docstring at `:16` claims "the engine's HttpClient enforces scope
  itself". There is no engine.
- `hooks/coverage-gate.py:67-71` runs `scripts/probe` against `target:` from a
  `Stop` hook, outside the `PreToolUse` guard and outside any rate limit or
  request budget.

## 3. Reproduced defects

1. `scripts/coverage:80` matches substrings with no word boundaries. With
   surface `param:id` and a report saying "identified nothing", `param:id` is
   marked covered. Every coverage-gate number depends on this.
2. `scripts/verify:92-96` builds `ctx` and never passes it; both branches call
   `opener.open(req, timeout=timeout)`. `--insecure` is a no-op.
3. `scripts/probe:275` assigns `endpoints = from_openapi(...)` instead of
   extending. A target serving both `/openapi.json` and `/swagger.json` loses
   the first spec.
4. `scripts/probe:14-15` promises GET-only; `from_graphql:130` POSTs a body.
5. `scripts/probe:349` and `scripts/verify:229` crash with a raw `ValueError`
   on `--header 'Cookie a=b'`.
6. `hooks/coverage-gate.py:113` crashes on a non-numeric `.coverage-gate`: a
   `Stop` hook that throws.
7. `scripts/mythos:94` runs `docker exec` with no timeout. A hung sqlmap
   consumes an unattended engagement's whole budget.
8. `skills/business-logic/scripts/bola_diff.py:58` treats an empty body as
   "enforced", so a 204 write by user B reads as access control working.
9. `skills/auth-session/scripts/auth_login.py:103` ignores the login POST
   status, so a pre-login session cookie records a failed login as valid.

## 4. Own supply chain

- `scripts/mythos:81,83` mounts `{REPO}:/repo` read-write as the host uid.
  Anything in the container can overwrite `hooks/scope-guard.py`,
  `scripts/mythos` and `skills/*`, which the host later executes outside
  Docker. Chromium runs with `--no-sandbox` (`toolbox/Dockerfile:109-110`).
- Every GitHub Action is pinned to a floating tag, including
  `sigstore/cosign-installer@v3`. This is the tj-actions/changed-files pattern
  (CVE-2025-30066, 14 Mar 2025). The exposed jobs hold `packages: write` and
  `id-token: write`.
- `main` has no branch protection, no rulesets and no tag protection. Tags are
  annotated but unsigned. Dependabot, secret scanning and push protection are
  disabled. Plugin install (`README.md:138`, `.claude-plugin/marketplace.json`)
  tracks the default branch with no pin, and `hooks/hooks.json` runs
  `scope-guard.py` on the host before every Bash and WebFetch call.
- The image is signed with cosign and nothing verifies it. The default is the
  mutable `:latest`, and `scripts/mythos:62` never refreshes an image already
  present locally.
- Unpinned, unhashed pip installs in `toolbox/Dockerfile:75-77`, including the
  near-name pair `wafw00f` and `graphw00f`. Every install is `|| echo "skip"`,
  so a failure ships a smaller image that is still signed and published.
  `ysoserial-all.jar` is fetched with no checksum (`:91`).

## 5. Capability coverage

### Web classes

Solid: race conditions, mass assignment, XXE, cache poisoning, command
injection, classic deserialization, CL.TE/TE.CL smuggling, CVE triage, patch
diffing.

Thin or contradictory:

- `knowledge/web/jwt-oauth.md` is named for OAuth and contains only JWT. No
  OAuth flow test exists anywhere in the repository.
- `skills/web-scan/SKILL.md:169-171` requires CSRF coverage per write. No file
  or skill explains how to test it.
- `knowledge/web/ssti.md` says "stop before RCE"; `skills/exploit` escalates to
  RCE. The two contradict each other.
- Stubs at 15 to 19 lines: `access-control` (depth lives only in
  `skills/business-logic`), `ssti`, `headers-cors`, `jwt-oauth`.
- `sql-injection.md` is sqlmap flags with no manual oracle, no second-order, no
  ORM or NoSQL. `ssrf.md` says "metadata IP" and nothing about filter bypasses,
  redirects, IMDSv2 PUT tokens or the GCP and Azure header requirements.
  `xss.md` is reflected only. `graphql-api.md` calls itself a known gap.
- `request-smuggling.md` is titled "H2 downgrade" but tests only CL.TE and
  TE.CL. No 0.CL, CL.0, Expect, TE.0 or HTTP/2 tests.

Missing, ranked by payout frequency times how badly an agent needs a playbook:
OAuth/OIDC/SAML flows; authentication-flow logic and account takeover (reset,
2FA, session fixation, email change); CSRF, SameSite, cross-site WebSocket
hijacking, clickjacking; framework and middleware bugs (Next.js
CVE-2025-29927, React2Shell CVE-2025-55182); BaaS and cloud storage (Supabase,
Firebase, presigned URLs); client-side DOM (source-to-sink, postMessage, DOM
clobbering, client-side prototype pollution, CSP bypass); server-side prototype
pollution; multi-tenant isolation; modern injection oracles (ORM leaks, NoSQL,
LDAP, Unicode normalization, parser differentials).

Missing methodology notes: oracle building and differential testing; auth
matrix construction; state machine abuse; parser differential and
normalization; framework fingerprint to probe; false-positive triage per class.

### AI applications

The money is in self-hosted AI platforms, not in prompt injection: Langflow
CVE-2026-33017 (unauthenticated RCE, exploited within 20 hours), Langflow
CVE-2026-5027 on CISA KEV, Flowise CVE-2025-59528 (CVSS 10, 12k+ instances).
These are classic bugs in new software, which `skills/cve-deep-dive` already
handles; what is missing is a fingerprint for Langflow, Flowise, Dify, Open
WebUI, Ollama, vLLM, LiteLLM, n8n and ComfyUI in recon.

Prompt injection pays only with the lethal trifecta: private data, untrusted
content and an exfiltration channel. Google's AI VRP excludes jailbreaks and
direct injection; OpenAI's safety programme requires at least 50 per cent
reproducibility. A finding therefore needs k replays with a per-trial nonce and
an OAST-confirmed hit, not the model's own claim that it complied.

`lab/` has no AI, OAuth or multi-tenant target, so none of this can be
self-tested today.

### Supply chain as a testing capability

Only two families are fully black-box testable and reliably paid: client-side
supply chain (third-party scripts, missing SRI, dead or sold CDN domains, the
Polyfill.io class) and subdomain takeover with dangling DNS. Dependency
confusion is detection only, and must never publish: this needs
`rules.allow_publish: false` as a default the agent cannot override.
Typosquatting, worms and stolen maintainer tokens are threat intelligence, not
web testing.

## 6. Decided plan

Decisions taken on 2026-11-13.

**Benchmark.** Mark the Vuln Bank claim in `README.md` and
`docs/poster/poster.md` as not defensible pending re-measurement, now. Then fix
the harness (ground truth outside the repository, symmetric arm permissions,
outcome-independent exclusions, gate on/off as a recorded field, `fp` rows in
triage, committed raw artifacts) and re-run.

**Scope guard.** Fix the parsing only; `warn` stays the default. Noted and
accepted: the class of incident that already occurred remains possible, because
in `warn` mode the request has been sent by the time the warning is read.

**Work streams, all four:** enforcement in code, own supply-chain hardening,
capability breadth, and a CVE freshness pipeline.

**Capability order:** OAuth/OIDC plus auth flows and account takeover, then
tenant isolation, then AI platforms with prompt injection, then client-side DOM
with client-side supply chain.

**CVE freshness.** Feeds: CISA KEV, EPSS, NVD 2.0 for the recent window,
nuclei-templates mapping, GHSA and OSV. GHSA needs a token at run time.
Freshness: a scheduled workflow commits a snapshot under `knowledge/cve/`, and
`scripts/cvefeed` attempts a live refresh at engagement start, falling back to
the snapshot with its age shown. Placement: in `recon`, after fingerprinting.
The fingerprint set grows to include the AI platforms above; matches land in
`engagements/<dir>/cve-candidates.json`, which the planner reads to spawn
targeted agents.

## 7. Positioning

Where a skills-first, bring-your-own-model framework can win: it inherits model
improvements without an engine to maintain; it can be the honest, reproducible
evaluation in a field where competitors publish numbers that cannot be
reproduced; it has no vendor server and no telemetry.

Fights not worth picking: XBEN leaderboards (saturated), platform features
(continuous scanning, SOC 2, ticketing, deterministic production-safe exploit
libraries), memory-safety zero-day work, and raw model capability.

Naming: Anthropic announced "Claude Mythos Preview" on 7 April 2026. Searches
for this project's name collide with it.
