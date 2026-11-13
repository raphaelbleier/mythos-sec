<p align="center">
  <img src="docs/assets/logo.png" alt="Mythos" width="460">
</p>

<p align="center">
  <b>Mythos</b> — a skill-driven web red-team framework for OpenCode and Claude Code, for authorized pentesting and bug bounty.
</p>

<p align="center">
  <i>Point <code>/cybersecurity</code> at a target you're allowed to test. Your agent host <b>is</b> the agent: it reasons like a pentester and drives real security tools in a Kali toolbox to find — and prove — web vulnerabilities. No API key of its own.</i>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="#scope--safety">Scope &amp; safety</a> ·
  <a href="#responsible-use">Responsible use</a>
</p>

<p align="center">
  <a href="https://github.com/raphaelbleier/mythos-sec/actions/workflows/check.yml"><img src="https://github.com/raphaelbleier/mythos-sec/actions/workflows/check.yml/badge.svg" alt="check"></a>
  <a href="https://github.com/raphaelbleier/mythos-sec/actions/workflows/toolbox.yml"><img src="https://github.com/raphaelbleier/mythos-sec/actions/workflows/toolbox.yml/badge.svg" alt="toolbox image"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-f0a52a" alt="MIT"></a>
</p>

---

> **For authorized testing only.** Bug-bounty programs in scope, systems you own,
> or lab targets. "Permitted" means written authorization or a program whose scope
> covers the host, not your own judgement that nobody will mind.
>
> `scope.yaml` is the authorization boundary and a hook watches it, but in the
> default `warn` mode the request is already out when the warning arrives. Set
> `MYTHOS_SCOPE_ENFORCE=ask` for anything that is not a lab. With `--scope <file>`
> the engagement then runs unattended, with shell access, until it writes a report.

## Results at a glance

**The benchmark is being re-measured.** An audit on 13 November 2026 found faults
in the harness that make part of the published numbers indefensible. The harness
is fixed; the affected claims are withdrawn until the sweep has been run again.
What each fault was and how it is now prevented:
[`bench/METHODOLOGY.md`](bench/METHODOLOGY.md).

Withdrawn:

- **The Vuln Bank coverage-gate separation** (Mythos with the gate 34 and 33
  entries, the control 30 and 29). The Mythos arm ran with `--add-dir <repo>` and
  `--plugin-dir <repo>`, so the scoring key for that measurement,
  `bench/data/ground_truth/vulnbank.json`, sat inside a directory the arm was
  invited to read, and its toolbox mounted the same repository at `/repo`. The
  control arm got an empty working directory and no such grant. No check in the
  harness tested for that, and the transcript detector would not have matched a
  ground-truth path, so the transcripts neither show that the key was read nor
  show that it was not. The gate's coverage score came from `scripts/coverage`,
  which counted a substring match in the report as a mapped path having been
  covered. Two runs per condition, no interval and no test.
- **Precision 1.00**, everywhere it appears. No triage row could carry the status
  `fp`: the schema listed the documented vulnerabilities and asked the rater to
  mark each one found or missed, so a false positive the arm reported had nowhere
  to go. The number is a property of the schema, not a measurement.
- **"All 42 mapped paths accounted for."** The hook handed the agent the path
  list and the scorer counted a mention of a path as coverage of it, so the claim
  restates its own input.
- **Every solve rate on the Claude Code host.** A cell was dropped from the
  denominator only if it had also failed, so an exclusion could only raise the
  rate. The 40-challenge control arm reads 0.69 with no exclusions at all, 0.90
  under the published rule, and 0.96 under a rule that decides infrastructure
  failure from the host's own `safety_stops` counter without looking at whether
  the cell solved.

What survives, with its limits:

- On single-flag CTF challenges the paired comparison shows no detectable
  difference under any of those three exclusion rules, because it was never able
  to show one. With 26 paired challenges and a discordance rate of 0.3, the
  smallest difference the exact test detects with 80% power is 0.29, and the
  sweep saw 1 discordant pair. Published work on the same XBOW benchmark
  ("Baselines Before Architecture", arXiv 2607.13085) puts the scaffold
  advantage at 5 to 10 percentage points at a matched model, so this design was
  underpowered against the plausible effect by roughly a factor of three. The
  honest statement is: underpowered, no detectable difference, minimum
  detectable difference about 0.29. Not a null result. `bench/stats.py --selftest`
  recomputes those power figures.
- On GLM 5.3 both arms solved all 10 scored cells of 12 (two per arm were rate
  limited). Ten cells per arm, a ceiling at 1.00, no test.
- Every solved cell's flag came back from the target. Re-scoring all four stored
  sweeps, 79 of 79 solved cells had the flag first appear in tool output after a
  request to the target, and none had it first appear in the agent's own text.
  Audits of other CTF harnesses find 17 to 23 points of inflation from flags
  that were never exploited for; that does not reproduce here. The check is a
  necessary condition, not proof that the intended vulnerability was the path.
- The flagless recall figures (VAmPI 8/9 against 8/9, DVGA 12/21 against 11/21,
  Vuln Bank without the gate 28 and 29 against 30 and 29) carry the same
  ground-truth access problem and are withdrawn as measurements of the
  scaffolding. Their direction is "no separation", which a leak toward the Mythos
  arm would not have produced.

Two things no number here controls for. The targets are public: XBEN and all four
real apps are public repositories with public write-ups, and for the flagless
targets the ground truth is each app's own README, so a model may have read it.
XBOW's own repository now describes the validation benchmarks as trained into
current models and kept for historical purposes, which makes XBEN a regression
check rather than evidence of capability. And "scaffolding" is one undifferentiated
condition: skills, sub-agents, toolbox, prompt and tool access all change at once
between the arms.

The scope guard is a safety net, not a sandbox. In its default `warn` mode it reports
an out-of-scope request after the request has already gone out, and it has let one
through: a `169.254.169.254` SSRF payload that the target then connected to. Set
`MYTHOS_SCOPE_ENFORCE=ask` when a single such request is unacceptable.

Full tables, parameters and what the numbers do not cover: [Benchmarks](#benchmarks),
[`bench/METHODOLOGY.md`](bench/METHODOLOGY.md),
[`docs/poster/poster.md`](docs/poster/poster.md) (German),
[`docs/poster/LIMITATIONS.md`](docs/poster/LIMITATIONS.md).

## What it is

Mythos is in the spirit of CAI / Strix / HexStrike / PentestGPT, but
**skill-driven, with no separate engine and no LLM runtime of its own.** The
agent host (OpenCode first, Claude Code second) is the agent loop. Mythos
supplies the methodology (skills), the orchestration (one orchestrator, six
sub-agents), a Kali tool belt (Docker), a per-bug-class knowledge base, and a
scope guard.

- **`/cybersecurity` command**: the orchestrator. Sets up a scoped engagement,
  then runs recon, scan, exploit, report.
- **Phase skills**: `engagement-setup`, `recon`, `web-scan`, `exploit`,
  `report`, `toolbox`, plus capability skills `auth-session`,
  `business-logic`, `stored-xss-oast`, `deep-server` and the maintenance skills
  `research-ingest` and `cve-deep-dive`. Findings carry a closure state
  (candidate / confirmed / ruled_out / open_proof_gap).
- **Sub-agents**: planner, recon, scanner, browser, exploiter, reporter, using
  the session model.
- **Kali toolbox** (Docker): nuclei, sqlmap, dalfox, ffuf, katana, subfinder,
  httpx, nikto, commix, interactsh, jwt_tool and more, run through
  `scripts/mythos`; headless Chromium for the browser agent.
- **Knowledge base** (`knowledge/`): per-class confirmation playbooks read at
  runtime to cut false positives.
- **One canonical source**: `AGENTS.md`, `.opencode/` and `skills/` are
  hand-edited; `python3 scripts/build-hosts.py` generates the Claude Code files
  (`CLAUDE.md`, `agents/`, `commands/`).

## Architecture

![Mythos architecture](docs/assets/architecture.svg)

The host is the agent; skills are the playbooks; the shim runs real tools in
the Kali container against the target; the scope guard watches bash/webfetch
calls. (Source: `docs/assets/architecture.dot` — `dot -Tsvg` renders it.)
Full write-up: [`docs/architecture.md`](docs/architecture.md). Status and open work:
[`docs/plan/ROADMAP.md`](docs/plan/ROADMAP.md).

## Install

**Prerequisites**

- [OpenCode](https://opencode.ai) (1.x >= 1.18.29 or 2.x), primary, or
  [Claude Code](https://docs.claude.com/en/docs/claude-code), secondary.
- A model for the host: any provider the host supports. On OpenCode the default
  is GLM 5.3 on the Z.AI Coding Plan, which needs `ZHIPU_API_KEY` or
  `opencode auth login`; `models.json` assigns a tier per agent and
  [`docs/models.md`](docs/models.md) covers every provider, including Anthropic,
  OpenAI and a local one. To run the whole suite on another provider:
  `OPENCODE_CONFIG_CONTENT="$(scripts/models anthropic)" opencode`. Plain
  `--model` moves only the orchestrator, because the sub-agents carry their own
  model. On Claude Code the host's own model is used.
- **Docker**, with your user able to run `docker`. `git`, and Python 3 (stdlib
  only) for the shim.

**1. Get the repo**

```bash
git clone https://github.com/raphaelbleier/mythos-sec
cd mythos-sec
```

**2a. OpenCode (primary)**: nothing to install. Run `opencode` in the repo; it
reads `opencode.json` (default agent `mythos`, `AGENTS.md`, the `skills/` path)
and `.opencode/` (agents, `/cybersecurity` command, scope-guard plugin).
Non-interactive:

```bash
opencode run --agent mythos --auto "https://target.example --scope scope.yaml"
```

**2b. Claude Code (secondary)**: install the plugin straight from GitHub (Claude
Code 2.1.275 or later)

```text
/plugin install mythos-sec --marketplace raphaelbleier/mythos-sec
```

From a clone, or on an older build:

```text
/plugin marketplace add /path/to/mythos-sec
/plugin install mythos-sec
```

**3. Toolbox**: `scripts/mythos up` pulls the prebuilt image from GHCR and starts
it (no local build):

```bash
docker pull ghcr.io/raphaelbleier/mythos-toolbox:latest   # optional, `up` does this
scripts/mythos up          # pull (or build) the image, start the container
scripts/mythos tools       # sanity-check the tool belt
```

Pin a tag for reproducibility (`MYTHOS_IMAGE=ghcr.io/raphaelbleier/mythos-toolbox:<tag>`;
tags are `vX.Y.Z`, `X.Y`, `YYYYMMDD`, `sha-...`; the workflow publishes amd64 and
arm64). `latest` and `v0.2.0` are published and pullable today. To build locally
instead: `MYTHOS_BUILD=1 scripts/mythos up` (first build takes minutes).

**4. (optional) practice lab**: see [`lab/README.md`](lab/README.md)

```bash
docker compose -f lab/docker-compose.yml up -d
scripts/mythos net mythos-lab     # let the toolbox reach lab targets by service name
```

**5. Verify** end to end:

```bash
scripts/selftest.sh                   # probe, verify, 7 vuln classes, 2 no-FP controls, scope-guard, coverage gate
scripts/selftest.sh --host opencode   # same checks, scored from the mythos agent's report
```

**Platform notes**

- **Linux**: Docker engine; add your user to the `docker` group.
- **macOS**: Docker Desktop. Local lab targets are reached from the toolbox as
  `http://host.docker.internal:<port>`. Untested by the maintainer.
- **Windows**: Docker Desktop with WSL integration; run the repo and the host
  inside WSL, or use Git Bash (the shim sets `MSYS_NO_PATHCONV` so `/repo` is not
  rewritten). Only the WSL path has been exercised; native Windows is untested.

You need a model for the agent host; Mythos itself needs no extra API key.

## Quick start

```text
/cybersecurity https://target.example
```

Mythos sets up `engagements/<target>-<date>/`, writes a `scope.yaml` you confirm
(or takes yours via `--scope`),
then runs recon → scan → exploit → report, driving the toolbox throughout, and
writes a bug-bounty-format `report.md`.

The model comes from the host. On Claude Code that is `/model` and every agent
uses it. On OpenCode `models.json` gives each agent a tier, so recon and
scanning run on a cheap model and the orchestrator, exploiter and validator on
the strongest one available. That split is a cost heuristic, not a measured
allocation: no model has been tested against the exploit skill's proof standard
except Claude Sonnet, and those runs are under re-measurement. See
[`docs/models.md`](docs/models.md).

The single human gate is the scope confirmation. With `--scope <file>` (also
with `opencode run --auto`) the file is the confirmation and nothing is asked;
after that the engagement runs unattended. The rules it follows (non-destructive,
no DoS or brute force, minimal PoC, no data dumping) are instructions to the model,
not limits enforced in code: on DVGA the control arm deleted another user's paste.
See [`docs/poster/LIMITATIONS.md`](docs/poster/LIMITATIONS.md).

A scope file you bring yourself looks like this. Put it anywhere and pass it with
`--scope`; Mythos copies it to `engagements/<target>-<date>/scope.yaml`, which is the
boundary for the whole run:

```yaml
target: https://target.example
in_scope:
  - target.example      # only the hosts or CIDRs the program lists; *.example.com for wildcards
out_of_scope: []        # every excluded host the program names
rules:
  rate_limit_rps: 5
  max_requests: 20000
  allow_active: false   # true only if active scanning is permitted
  allow_exploit: false  # true only if PoC exploitation is permitted
identities: []          # optional: two accounts, for BOLA and IDOR testing
notes: ""               # paste the program's testing rules verbatim
```

Useful sub-commands:

```text
/cybersecurity research CVE-2026-1234     # CVE deep-dive -> knowledge-base note
/cybersecurity research <topic>           # ingest a technique into knowledge/
```

## How it works

Everything runs in the `mythos-toolbox` Kali container via `scripts/mythos`:

```bash
scripts/probe <url> --depth 2          # surface map in one call, on the host, no container
scripts/probe <url> --depth 2 --json | scripts/verify --from-probe   # prove the aim points
scripts/mythos up                      # build (first run) + start the container
scripts/mythos <tool> [args]           # run one tool,  e.g. scripts/mythos nuclei -u URL
scripts/mythos sh '<pipeline>'         # run a shell pipeline in the toolbox
scripts/mythos tools                   # list the belt + versions
scripts/mythos net <network>           # attach the toolbox to a lab docker network
scripts/mythos down                    # stop + remove the container
```

The repo is mounted at `/repo`, so output lands under `engagements/`. A local
lab target on `localhost:PORT` is reached as `http://host.docker.internal:PORT`.
`toolbox/Dockerfile` (two-stage) builds the belt; a tool missing from a given
Kali snapshot is skipped, never fatal. Every exec is logged to
`engagements/audit.jsonl`.

## Classes the skills target

Reflected & DOM XSS, SQLi (error + blind + UNION, via sqlmap), GraphQL-resolver
SQLi, SSTI → RCE, OS command injection (reflected + blind/OOB), SSRF (out-of-
band via interactsh), path traversal / LFI + filter-evasion, open redirect,
CRLF, IDOR + two-account BOLA, CORS, JWT forgery / privilege escalation,
GraphQL introspection + code execution, API excessive-data-exposure,
sensitive-file exposure, verbose-debug disclosure, security headers/cookies;
authenticated flows (cookie/bearer, Playwright for SPAs); OpenAPI/GraphQL
import; CVE triage (KEV/EPSS, patch-diff); nuclei templated scanning.

This is what the skills aim at, not a measured success rate. Only the classes named
under [Benchmarks](#benchmarks) and in the self-test have numbers behind them.

## Benchmarks

**Controlled evaluation.** `bench/` runs Mythos and a bare-model control on the
XBOW validation-benchmarks with the same model, prompt, budget and sandbox, a
random flag per run, scoring on the harness side, Wilson intervals and paired
McNemar tests. Design, scoring rules, exclusions, blinding and reproduction
steps: [`bench/METHODOLOGY.md`](bench/METHODOLOGY.md); usage and isolation:
[`bench/README.md`](bench/README.md).

**The published figures below are under re-measurement.** The audit of
13 November 2026 found that the Mythos arm could read the flagless targets'
scoring key, that infrastructure exclusions were applied only to failed cells,
that no triage row could record a false positive, and that the coverage gate was
scored by substring match. The harness fixes are described in
`bench/METHODOLOGY.md`; the tables are kept here so the record is visible, each
with what the audit leaves of it.

Vuln Bank, the only measurement in which the scaffolding separated from the
control:

| Vuln Bank, 76 documented vulnerabilities (Claude Code, Sonnet, 3600 s budget) | found | recall | precision | tool calls | USD |
|---|---|---|---|---|---|
| Mythos + coverage gate | 34, 33 | 0.45, 0.43 | not measured | 32, 31 | 0.61, 0.67 |
| Mythos without the gate | 28, 29 | 0.37, 0.38 | not measured | 18, 20 | 0.42, 0.39 |
| control (bare model with a shell) | 30, 29 | 0.39, 0.38 | not measured | 15, 14 | 0.29, 0.25 |

**Not currently defensible.** The Mythos arm's readable roots included
`bench/data/ground_truth/vulnbank.json`, which is the key these recall numbers
are scored against, and the control arm's did not; the coverage score that the
gate acts on counted a substring match in the report as a covered path. Two runs
per condition, no interval and no test. The gate was also written in response to
the ungated runs and scored on the same target, so even with a clean harness it
is a fit to that measurement rather than a prediction confirmed by it. It will be
re-measured with the ground truth outside every root the arms are given, and with
the corrected coverage scorer.

**The same gate inverted the result on DVGA: 6 of 21 against 12 without it and 11 for
the control, at $0.77 instead of $0.27.** DVGA is a GraphQL app whose surface map held
eleven HTML pages while all 21 documented vulnerabilities sit behind `/graphql`, so the
agent closed out the pages and never reached the fields. Vuln Bank worked because it
publishes an OpenAPI document. The probe now introspects GraphQL schemas, but the
measurement with that map is still outstanding. The gate helps where the map captures
the real surface and hurts where it does not. These two numbers come from the same
harness as the Vuln Bank runs and are withdrawn on the same grounds.

The flag-capture sweeps. The Mythos column is the scaffolded arm, the control
column the bare model with a shell; `p` is the exact paired McNemar two-sided p
over the challenges both arms completed:

| sweep | model | Mythos | control | pairs, discordant | paired p |
|---|---|---|---|---|---|
| 40 challenges, scaffolding verified loaded | Claude Sonnet | 28/33 = 0.85 | 27/30 = 0.90 | 26, 1 | 1.0 |
| the same 40 challenges, plugin silently not loaded | Claude Sonnet | 28/33 = 0.85 | 27/30 = 0.90 | 25, 0 | 1.0 |
| 12 challenges | GLM 5.3 | 10/10 = 1.00 | 10/10 = 1.00 | 10, 0 | 1.0 |
| the seven challenges both arms had failed | Claude Sonnet | 2/5 = 0.40 | 2/5 = 0.40 | 3, 0 | 1.0 |

The two 40-challenge rows share one control measurement: the control arm was run
once, and the second sweep re-ran only the Mythos arm after the plugin manifest
was fixed. The control row is therefore the same 39 cells printed twice, not two
measurements.

A p of 1.0 on one discordant pair out of 26 is not a null result, it is an
absence of power. At 26 pairs and a discordance rate of 0.3, the smallest true
difference the exact test detects with 80% power is 0.29; at 30 pairs it is
0.27 and at 40 it is 0.24, and a true difference of 0.2 would be caught two
times in five at 30 pairs. The exact test cannot reject at all below six
discordant pairs. Against the 5 to 10 points that arXiv 2607.13085 reports for
scaffold advantage on this benchmark at a matched model, this design was short
by about a factor of three. Both arms also sit at 0.85 to 0.90 with three to
five unsolved cells each, so there is little room left for a difference to
appear in. `bench/stats.py` prints the minimum detectable difference with every
comparison, and `--selftest` pins these figures.

The denominators depend on an exclusion rule that the audit found invalid: cells
were dropped only when they had also failed, so an exclusion could only raise a
rate. Recomputed from the stored artifacts under the corrected, outcome-blind
rule, the 40-challenge arms read 0.87 [0.71, 0.95] for the control and 0.88
[0.72, 0.95] for Mythos, against the published 0.90 and 0.85. **The gap changes
sign**, which is the clearest evidence available that it was an artifact of the
rule and not a measurement. Over all cells with no exclusion at all the arms read
0.69 and 0.70. The harness now classifies infrastructure failure from signals the
agent cannot author, treats intention-to-treat as the primary analysis, and
prints both rates in the same row.

The same correction removes the Strix number entirely. Ten of its twelve cells
hit the stall deadline and two ended in a runner error, including both cells
previously reported as valid, which were kept only because they had solved.
Under the corrected rule Strix has **no scored cells**, not 2 of 2 at 1.00.
Wherever a Strix figure appeared, it was an artifact of the exclusion rule.

The flagless recall measurements:

| target | Mythos | control |
|---|---|---|
| VAmPI, 9 documented vulnerabilities | 8/9 = 0.89 | 8/9 = 0.89 |
| DVGA, 21 documented vulnerabilities | 12/21 = 0.57 | 11/21 = 0.52 |
| Vuln Bank, 76 documented vulnerabilities, no gate | 28 and 29 of 76 | 30 and 29 of 76 |

All three carry the ground-truth access problem and are withdrawn as
measurements of the scaffolding. Their direction is "no separation", which a leak
toward the Mythos arm would not produce, so a re-run is more likely to confirm
than to overturn them. On DVGA the arms also tie at 10 of 16 once the five
denial-of-service classes the engagement's safety rules forbid proving are
removed from the denominator. The precision of 1.00 previously reported for all
of these is withdrawn outright: the triage schema had no way to record a false
positive.

Cost direction is not stable. On the 40-challenge sweep the scaffolded arm spent
$20.88 against the control's $8.63 and 928 tool calls against 390, a factor of
2.4 either way; those are totals over all 40 and 39 cells, while the solve rates
above count only the scored ones, so the two sets of numbers do not describe the
same cells. Over the scored cells alone it is $19.97 against $7.82 and 901 calls
against 345. On DVGA the direction inverts: the scaffolded arm came in at $0.27
and 18 tool calls against the control's $0.81 and 43. On GLM 5.3 the scaffolded
arm was faster, median 135 s against 177 s, with ten cells per arm and no test.

An invalid plugin manifest kept the Claude Code Mythos arm unscaffolded until
5 November 2026, which is why the two 40-challenge sweeps exist. Full parameters
and the diagnosis from the transcripts:
[`docs/poster/poster.md`](docs/poster/poster.md) (German). What the numbers do not
cover: [`docs/poster/LIMITATIONS.md`](docs/poster/LIMITATIONS.md). Example
engagement reports from the earlier manual runs, including the full triage of two
of them: [`docs/poster/evidence/`](docs/poster/evidence/).

Nothing in the design controls for contamination. XBEN and all four real apps are
public repositories with public write-ups, and for the flagless targets the
ground truth is each app's own public README, so the model may have read it
already. The per-cell random flag only defeats precomputing the upstream
`sha256(UPPERCASE_DIRNAME)` flag. XBOW's own repository states that the set is
saturated, that the underlying vulnerabilities have been trained into the models
and that it is kept for historical purposes only, in a warning dated 7 July 2026,
so XBEN is a regression check here and not evidence of capability. The harness
records whether any of XBOW's canary strings appear in a transcript, as a leak
signal, and never copies them into a result file. That check cannot establish
non-contamination and is not claimed to: no published work estimates how much of
these apps sits in frontier training data, no study validates canary strings for
security data, and membership inference runs near chance even on open models of
known composition.

Construct validity is unestablished as well. No study correlates any security
benchmark score with a real-world outcome such as a bounty payout or a field CVE,
so every figure above describes performance on these targets under this harness
and nothing beyond that.

One more thing weakened the scanner side in every sweep. A supply-chain review of
the toolbox image found that the image as published during the sweeps shipped
`nuclei` with no templates, because pip's cache created `/home/pentester` as root
before `useradd` ran and the template update then failed silently at build time,
and that it carried the PyPI `graphw00f`, which is an inert placeholder rather
than the real tool. The second one bears on the DVGA figures in particular. Both
are fixed in the current `toolbox/Dockerfile`. Which sweep ran which image cannot
be established, because no sweep recorded an image digest; that is now recorded
per cell.

"Scaffolding" is also one undifferentiated condition. The control arm is denied
`edit`, `webfetch`, `websearch`, `task` and `skill` as well as the skills,
sub-agents and toolbox, so a difference cannot be attributed to any one of them;
on the flagless targets the control cannot write a file at all, so the two arms'
reports are produced through different media. The run record now carries each
treatment as its own field so an ablation is possible later.

```bash
python3 bench/xben.py check --out <build_results.tsv>
python3 bench/run.py --frameworks mythos,control --model <id> --sample 30 --seed 1 --runs 3 --dry-run
python3 bench/stats.py <results>/results.jsonl --compare mythos,control
python3 bench/labs.py list                       # flagless targets + ground truth
```

The four flagless real apps (crAPI, Vuln Bank, DVGA, VAmPI) are scored by recall
against their upstream documented vulnerability lists in
`bench/data/ground_truth/`, driven by `bench/labs.py`; VAmPI's secure instance
serves as a false-positive control. Build lists for the 104 XBOW challenges are
in `bench/data/`: 43 of 104 build from a clean clone, 102 of 104 once the harness
repoints the dead Debian apt mirrors (`--no-apt-fix` disables that).

The self-test is a regression test on this repo's own seeded lab app, not a target
result. `scripts/selftest.sh` prints its own `== result: N passed, M failed ==`
line; that line is the number, and the count is not quoted here because it depends
on the host and on which lab targets are reachable. The file holds 45 `assert`
calls plus two inline checks. The counts published earlier, 31 in the poster and
35 here, match neither the file nor each other and were wrong.

**Earlier manual engagements** (single runs, no control arm, from the earlier
skill-driven flow; evidence, not a measured advantage). Details:
[`docs/poster/benchmark-skill-driven.md`](docs/poster/benchmark-skill-driven.md),
[`docs/poster/benchmark-hard-targets.md`](docs/poster/benchmark-hard-targets.md).

| Target                  | Stack                        | Headline confirmed findings                                                                                                             |
| ----------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **OWASP Juice Shop**    | Node SPA + REST              | UNION SQLi (Users dump), `/ftp` disclosure, poison-null-byte filter bypass, open redirect, config leak, **DOM XSS** (browser-confirmed) |
| **DVGA**                | Python GraphQL               | **unauth RCE** (introspection → SSRF → command injection), broken access control, introspection                                         |
| **VAmPI**               | Python REST                  | `_debug` plaintext-password dump; a BOLA **tested and disproven** (not over-claimed)                                                    |
| **Vuln Bank** (2026)    | Flask + PostgreSQL + GraphQL | `.env` leak → **JWT forge → admin takeover**, GraphQL-resolver SQLi, verbose-debug disclosure                                           |

Honest limits: full crAPI does not fit a ~3.7 GB host. "Works on any web app"
is not provable without authorized access to each target.

## Scope & safety

- Scope is stated up front and watched by a warn-only scope guard
  (`hooks/scope-guard.py` as a Claude Code `PreToolUse` hook,
  `.opencode/plugin/scope-guard.ts` for OpenCode; set
  `MYTHOS_SCOPE_ENFORCE=ask` to decide per call, `=block` to hard-block
  out-of-scope hosts). It is a safety
  net, not a sandbox; coverage inside OpenCode sub-agents is not yet verified.
  The agent honors `scope.yaml` in every tool call.
- Non-destructive by default; exploitation only when `scope.rules.allow_exploit`
  is set; proofs are minimal (no data dumps, no DoS, no brute-force).
- Engagement data lives under `engagements/` and is git-ignored.

## Responsible use

Mythos is offensive security tooling. Use it only against systems you own,
bug-bounty programs within their stated scope, or lab targets, and only with
authorization in writing or in the program's published scope.

Unauthorized access is a criminal offence in most jurisdictions: the Computer
Fraud and Abuse Act in the United States, the Computer Misuse Act in the United
Kingdom, § 118a StGB in Austria, § 202a StGB in Germany, and equivalents
elsewhere. A bug-bounty program's safe-harbour terms protect you only inside the
scope they state.

Practical points a first run should know:

- Requests the toolbox sends come from your own IP and are attributable to you.
  There is no proxying and none is planned.
- `engagements/audit.jsonl` logs every toolbox command, before and after. It is
  your record of what was sent. Keep it.
- A request the target makes on your behalf, such as an SSRF probe, counts as
  yours. The destination has to be in scope too.
- The scope guard and rate limits reduce risk but do not grant permission, and in
  the default `warn` mode the guard cannot stop a request. What has gone wrong in
  practice is written down in
  [`docs/poster/LIMITATIONS.md`](docs/poster/LIMITATIONS.md): one out-of-scope
  SSRF payload that the target connected to, and seed-data changes on DVGA.

The software is provided as is, without warranty (MIT). Mythos is an independent
project and is not affiliated with Anthropic or with the OpenCode project.

## Layout

```
AGENTS.md          canonical project instructions (CLAUDE.md imports it)
opencode.json      OpenCode config (default agent, skills path)
.opencode/         canonical agents, /cybersecurity command, scope-guard plugin
commands/ agents/  generated for Claude Code by scripts/build-hosts.py
skills/            engagement-setup · recon · web-scan · exploit · report · toolbox
                   · auth-session · business-logic · stored-xss-oast · deep-server
                   · research-ingest · cve-deep-dive
hooks/             scope-guard (PreToolUse hook + shared --check logic)
                   coverage-gate (Stop hook: every mapped path must be accounted for)
toolbox/           two-stage Kali toolbox Dockerfile
.github/           toolbox image CI (GHCR, amd64 + arm64)
lab/               vulnerable targets, OAST catcher, admin bot
bench/             XBOW harness, flagless-lab runner, ground truth, build lists
scripts/           mythos (toolbox shim) · probe (surface map) · verify (canary proofs)
                   · selftest.sh · build-hosts.py
knowledge/         per-class confirmation playbooks + CVE technique notes
docs/              architecture, research, plan, poster/benchmark evidence
CONTRIBUTING.md    how to change the canonical files and run the self-test
SECURITY.md        how to report a vulnerability in Mythos itself
```

## License

MIT. See `LICENSE`. Built by raphaelbleier for Security Engineering research
into AI pentest agents.

Pull requests are welcome; read [`CONTRIBUTING.md`](CONTRIBUTING.md) first, since
the files in `agents/` and `commands/` are generated and must not be hand-edited.
To report a vulnerability in Mythos itself, follow
[`SECURITY.md`](SECURITY.md).
