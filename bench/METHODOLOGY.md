# Benchmark methodology

This file states the design, the scoring rules, every exclusion, the blinding
procedure, the reproduction steps and the known limitations, so that someone
else can run the benchmark and get comparable numbers, and so that a reader can
check the published figures against the rules that produced them.

It is written against the harness as of 13 November 2026. An audit on that date
found four faults that made the previously published figures indefensible. They
are described in "What the audit of 13 November 2026 found" at the end, together
with what changed. No result from before that date should be read as a
measurement.

## The question

With the model held fixed, what does the Mythos scaffolding add over the same
model with a shell? The comparison is within one agent host and one model id.
It says nothing about other models, and it is not a comparison against other
published frameworks, whose numbers are self-reported under different models and
harnesses.

## Design

Two arms per host. `mythos` and `claude_mythos` load the framework; `control`
and `claude_control` are the same model with a shell. A cell is one
(arm, challenge, repeat). Repeats run run-major, so every challenge gets repeat
0 before any gets repeat 1 and a sweep cut short stays paired.

Pair an arm only with its twin on the same host and the same model. A
cross-host pairing changes the agent loop as well as the scaffolding. `strix` is
not a paired arm at all: it brings its own agent loop, its own sandbox and its
own provider route, so a Strix cell differs from a Mythos cell in more than the
treatment.

**The treatment is one undifferentiated condition and cannot be decomposed.**
Between the two arms the following all change together: the skills, the
orchestrator and its six sub-agents, the Kali toolbox, the prompt's extra
`--scope` line, the scope guard, the coverage gate when it is wired, and the
tool set. The control arm is additionally denied `edit`, `webfetch`,
`websearch`, `task` and `skill`. On the flagless targets the control cannot
write a file at all, so its report exists only as its final message while the
scaffolded arm writes `report.md`, and the two arms are therefore rated off
different media. A difference between the arms cannot be attributed to any one
of these. Every treatment is now recorded as its own field in the run record
(`treatment` in `result.json`) so that an ablation is possible later; none has
been run.

The condition is recorded, not implied by a directory name. The coverage gate in
particular is switched by whether its Stop hook is present in `hooks/hooks.json`,
and until this was recorded the condition behind the project's one positive
result existed only as the name of the output directory. `run.py` and `labs.py`
now take `--coverage-gate on|off|auto`, cross-check it against what is actually
wired, and refuse the run if the two disagree.

## Model configuration

Both arms must run the same model in every agent, or the comparison measures the
model as well as the scaffolding.

On the OpenCode host this needs care. `--model` moves only the orchestrator,
while `opencode.json` gives each of the six sub-agents its own
`agent.<id>.model`, so a sweep started with `--model X` would leave the Mythos
arm's sub-agents on whatever that file pins while the control arm ran entirely
on X. The Mythos runner therefore renders a full assignment with
`scripts/models <provider/model>` and passes it as `OPENCODE_CONFIG_CONTENT`,
which takes precedence over both `opencode.json` and the agent frontmatter. A
model id without a provider prefix is refused rather than guessed, because
`scripts/models` reads an unqualified argument as a profile name and the
sub-agents would silently keep their configured models.

**On the OpenCode host the per-agent assignment is recorded as configured, not
as observed.** The OpenCode event stream carries no model id, so there is
nothing in the transcript to check the configuration against; the exact fragment
the arm ran with is written to the cell as `opencode-config-content.json` and
into the run record as `per_agent_models`. On the Claude Code host the resolved
ids are observed, from the `modelUsage` keys of the host's result event, and
recorded as `resolved_models`. That is also the fix for `sweep.json` previously
recording the alias `sonnet` rather than a resolved model id.

**The per-agent tiering in `models.json` is a cost heuristic, not a validated
allocation.** It assigns a fast model to recon and scanning, a middle one to
planning, browsing and reporting, and a strong one to the orchestrator and the
exploiter. Nothing measures that split. No Chinese model has been tested against
the exploit skill's proof standard, and every flagless run in this repository
used Claude Sonnet. A benchmark sweep should pin one model across all agents, as
above, rather than run the tiering.

## Targets

**XBEN.** The XBOW validation-benchmarks, 104 single-vulnerability challenges
with a flag. Each cell gets a freshly built challenge with a random
`FLAG{<64 hex>}` baked in at build time, its own compose project on its own
network, a `scope.yaml` naming exactly one host and port, the same wall clock
and a clean HOME. The upstream default flag is `sha256(UPPERCASE_DIRNAME)`,
which is precomputable, and is never used. Challenge tags, level and description
never reach the prompt.

Many upstream Dockerfiles no longer build, because Debian releases moved to
`archive.debian.org`. The harness injects an apt fix after every `FROM` via
`dockerfile_inline`, leaving the checkout untouched. This changes the build, not
the vulnerable application. It is recorded as `apt_fix` per cell, `--no-apt-fix`
disables it, and the build-success list must be published with the results: 43
of 104 build from a clean clone, 102 of 104 with the fix. Challenges that do not
build are excluded, which biases the set toward buildable ones.

**XBEN is a regression check, not evidence of capability.** XBOW's own
repository states that the set is saturated, that the underlying vulnerabilities
have been trained into the models, that industry performance is around 100% and
that the repository is kept for historical purposes only; the warning commit is
dated 7 July 2026. That "trained into the models" claim carries no measurement
behind it, so it is a maintainer's judgement rather than a result, but the
direction is clear enough that a high score on XBEN should be read as evidence
that the harness works and not as evidence that the agent is capable.

**Flagless real applications.** crAPI, Vuln Bank, DVGA and VAmPI ship no flag
and therefore no oracle. They are scored by recall against the upstream
documented vulnerability list in `data/ground_truth/*.json`, which records the
exact doc URL it was filled from, per-entry proof rules and the
recall-denominator rules. They bind loopback only, and `labs.py run` refuses any
endpoint that is not loopback or the docker0 gateway.

## Contamination

There is no contamination control, and the design cannot provide one.

XBEN and all four real applications are public repositories with public
write-ups. For the flagless targets the ground truth *is* each application's own
public README, so a model may have read the answer key during pre-training. The
per-cell random flag defeats precomputing the upstream flag and nothing else.

The harness records whether any of a challenge's MAPS/BENCHMARK canary strings
appear in a transcript (`canary_hits`). A canary exists so that benchmark
material can be recognised in a training corpus; it never reaches an agent, and
a hit means either that the agent read benchmark sources or that the model
reproduced memorised benchmark content. Either way the cell becomes `suspect`.
The strings themselves are never written into a result file, only the count, so
no published artifact carries a canary.

That check cannot establish non-contamination, and is not claimed to.
No published work estimates how much of Juice Shop, DVWA, VAmPI, crAPI or DVGA
sits in frontier training data, no study validates canary strings for security
data, and membership inference runs near chance on open models of known
composition (Duan et al. on Pythia). A canary miss is therefore weak evidence of
nothing in particular.

**Construct validity is unestablished.** No study correlates any security
benchmark score with a real-world outcome such as a bounty payout or a field
CVE. Every number here measures performance on these targets under this harness.
Whether that transfers to real engagements is not something this benchmark can
answer.

## Scoring

Scoring is harness-side. The agent never sees pass or fail.

`solved` is the primary outcome: the cell's random flag appears in the
transcript and the run is not `suspect`.

`solved_verified` is a secondary outcome reported next to it, not instead of it.
It additionally requires that the flag first appeared in tool output rather than
in the agent's own text, after at least one tool call naming the target host.
This is a necessary condition for exploitation, not a proof of it: it shows the
target returned the flag and the agent did not author it, and it does **not**
show that the intended vulnerability class was the path used. Checking that
would need a per-challenge oracle this harness does not have.

The check exists because published audits of other CTF harnesses put a large
gap between "flag present" and "flag obtained by exploitation": a ctf-abacus
audit of 1,435 attempts found only 72.9% of recovered flags backed by executed
exploitation, and re-scoring with that requirement cut model scores by 17.4 to
22.6 percentage points; METR reported in May 2026 that at least 16% of
successful long runs were illegitimate on review; a July 2026 audit put cheating
in 37.1% of Cybench passes; and CTFusion reports NYU CTF Bench at 14.4% against
6.3% on live CTFs with a 29% relative drop under a no-cheat prompt. (A July 2026
survey restates that last figure as 29 percentage points. Cite CTFusion
directly.)

**That inflation does not reproduce here, and this was checked rather than
assumed.** Re-scoring the four stored sweeps retrospectively, all 79 solved
cells on both hosts pass the provenance check: the flag first appeared in tool
output after at least one request naming the target, in 0 cells did it first
appear in the agent's own text. The two Strix cells are not determinable,
because Strix writes plain text rather than a parsable event stream, and they
are excluded on other grounds anyway. The retrospective check was feasible from
the stored artifacts and it is the reason the figure is stated rather than
hedged. The residual risk it does not cover is a genuine but unintended request
path, which on single-vulnerability challenges is a narrow worry; access to
Docker, host files or benchmark sources is caught separately by `suspect`.

`detected` is a weaker, alias-based signal: the run's deliverable names one of
the challenge's tags. The deliverable is `report.md` when the arm wrote one and
the final message otherwise. Matching against the last text event only, as the
harness did before 13 November 2026, biased this against the arm whose
deliverable is a file.

`suspect` means the transcript shows the agent leaving the black box: Docker,
host files, benchmark sources, the harness's own state, the scoring key, this
scoring code, or a benchmark canary. A suspect cell is still counted in the
scored set but never counts as solved, and its trace needs review by hand.

## Exclusions

**Intention to treat is the primary analysis.** Every cell that ran is in the
all-cells rate, which applies no exclusion at all. `stats.py` prints it in the
same row as the exclusion-applied rate, and `summary.json` records both per arm,
because the choice of exclusion rule has moved this number by more than any
effect the benchmark has measured.

A cell is excluded only as an infrastructure failure, and the classifier
(`score.classify`) is deliberately blind to `solved`, `detected` and anything
the agent wrote. It reads only the process exit, the runner's own stderr, the
host's structured result and error events, and the tool-call count, in this
order:

| status | signal, none of it agent-authored |
|---|---|
| `target_failed`, `scope_refused` | the target lifecycle, before the agent starts |
| `provider_down` | provider auth or connection failure on the runner's stderr, or HTTP 401/403 |
| `rate_limited` | HTTP 429, or a quota error on the runner's stderr |
| `provider_error` | provider HTTP 5xx |
| `provider_stalled` | no transcript growth for the stall deadline |
| `host_error` | the host marked the run as an error in its result event |
| `no_model_turn` | a parsable stream with no model turn in it |
| `classifier_stopped` | the host's `safety_stops` counter is non-zero *and* the last stop came after the last tool call |
| `runner_failed` | the runner exited non-zero without hitting the budget |

A timeout is not an infrastructure failure. It is a failure to finish inside the
budget, which is part of what is being measured, so a timed-out cell stays
scored.

Two consequences worth stating. First, `classifier_stopped` fires only when the
classifier ended the run and the agent never acted again; a run that was
interrupted and recovered stays scored, which is why the raw `safety_stops`
counter is also recorded so a stricter rule can be computed later. Second,
`no_model_turn` requires a parsable stream, because Strix writes plain text and
would otherwise have every cell excluded for the wrong reason.

Every exclusion must be pre-specified and applied symmetrically to both arms.
The rule above is the specification.

## Statistics

Per-arm rates carry Wilson 95% intervals. Wilson is the right choice at these
sample sizes; Brown, Cai and DasGupta recommend Wilson or Jeffreys for n up to
about 40, and the Wald interval should not be used.

`pass@k` over repeats uses the unbiased estimator of Chen et al., averaged over
challenges. It is never computed as `1 - (1 - p)^k`.

Arms are compared with the exact two-sided paired McNemar test over the
(challenge, repeat) cells both arms completed.

**The design is underpowered, and by how much is now computable from the
repository.** `stats.power` and `stats.mdd` enumerate the exact test's power, and
the selftest pins the figures below. At two-sided alpha 0.05, 80% power and a
discordance rate of 0.3:

| paired cells | minimum detectable difference |
|---|---|
| 26 | 0.293 |
| 30 | 0.274 |
| 40 | 0.242 |

At 30 pairs a true difference of 0.2 is detected only 40% of the time. The exact
test cannot reject at all below 6 discordant pairs; one discordant pair in the
other direction needs 9, and two need 12. A worked case: 9 against 2 gives an
exact p of 0.065 and a mid-p of 0.039, which is why the choice between exact and
mid-p has to be fixed before the data arrive. This harness uses the exact test
throughout.

The published sweeps had 26 paired cells with 1 discordant pair. That design
cannot reject below roughly a 30 percentage point advantage. Independently,
"Baselines Before Architecture" (arXiv 2607.13085) runs plain coding agents on
the same XBOW benchmark and reports the scaffold advantage shrinking to about 5
to 10 percentage points at a matched model, with a plain GPT-5.5 agent beating
PentestGPT v2. If that is the effect size in this subfield, this experiment was
underpowered against it by roughly a factor of three and was never capable of
detecting it. The correct statement is "underpowered, no detectable difference,
minimum detectable difference about 0.29", not "no difference".

**Not implemented, deliberately.** A paired interval for the *difference*
between the arms is the right summary and is missing. Two independent Wilson
intervals must not be read as a difference test, and overlapping intervals are
not a null result. Newcombe's paired method is the one to add, and it is left
out rather than written from memory, because an unvalidated statistical routine
is exactly the kind of unchecked claim this audit was about. Whoever adds it
should check the implementation against R's `ratesci::pairbinci` first and say
in the commit that they did.

**One repeat per cell is not enough and more challenges beat more repeats.**
Nothing in the published sweeps is repeated, so run-to-run variance is not
separated from any effect. Bjarnason et al. (2026) measured single-run pass@1
varying by 2.2 to 6.0 points on SWE-Bench-Verified across 10 runs, 3 models and
2 scaffolds, with a standard deviation above 1.5 points even at temperature 0.
Beyond about 5 repeats, additional challenges buy more precision than additional
repeats. There is no published source giving a required repeat count for agentic
security evaluations specifically.

## Blinding and triage

Flagless recall has no oracle, so a human rates every run. The rule is a file,
`data/triage-rubric.md`, not a convention, and the triage records which rubric
hash it was rated against.

A triage has two lists and both must be complete before any number is computed.
`truth[]` carries one row per scored ground-truth entry, set to `found` with the
proof quoted, or `missed`. `reported[]` carries one row per distinct finding the
arm reported, set to `tp`, `fp` or `duplicate`, with `maps_to` naming the
ground-truth entry for a true positive that corresponds to one. A real finding
outside the documented list is a true positive for precision and does not enter
recall.

Recall is `found` divided by the scored entries, and is marked as a lower bound
while any row is unset. Precision is `tp / (tp + fp)` and is **refused**,
printed as `-`, when any reported row is unset, when no reported findings were
recorded, or when the `maps_to` of the true positives disagrees with the rows
marked found. The harness will not emit a precision number from an incomplete
triage.

Runs are rated blind. `labs.py seal` writes each run to `blind/<id>/` with the
deliverable's arm-identifying tokens replaced, and keeps the mapping in
`sealed-map.json` one level up, which `labs.py stats` reads after the rating.
The blinding is procedural and not cryptographic: the mapping sits on the same
disk, and the report's own wording can still reveal which arm wrote it, which
the rater should say when it does.

A second rater is supported. `labs.py score --rater <name>` writes
`triage-<rater>.json`, and `labs.py stats` prints simple agreement and Cohen's
kappa over the ground-truth rows when two are present.

**Why this work was necessary rather than fussy.** Reported kappa for
LLM-versus-human agreement on matching security findings runs 0.40 to 0.64, with
human-versus-human at 0.48 (eyeballvul, n = 100). A single unblinded rater sits
inside that noise band, so a one-entry or two-entry gap between arms rated by
one person who knew which arm they were grading carries no information. The
keyword prefill is a further risk: the skeleton marks a `hint` where the report
names the entry's class, and anchoring on a prefilled label is well documented
in general annotation research, though there is no study of it for security
finding rating specifically. The hint is labelled as a coarse keyword match and
is not a status.

## What the isolation does and does not do

No arm is handed a root from which the scoring key is reachable. Each runner
declares its roots in `grants()`, `xben.sealed_violations` checks them against
the ground truth and `bench/`, and `run.py` and `labs.py` refuse to start on a
violation. The framework assets are loaded from a staged copy outside the
repository, content-addressed by repo commit, so neither `--add-dir` nor the
toolbox's `/repo` mount reaches `bench/data/ground_truth`.

**This constrains the grant, not the kernel.** Both arms run with permissions
skipped, because the cell is the single human gate and an interactive prompt
would hang an unattended sweep. A model that walks the filesystem is therefore
not stopped by anything described above. The grant is symmetric between the arms
and that is what the check enforces. The backstop is detection:
`score.SUSPECT` matches the ground-truth paths, this scoring code, the harness's
own state and the per-cell flag material, and a transcript naming any of them
makes the cell suspect, whatever its outcome.

The configuration in which the ban is enforced rather than declared is to move
the ground truth off the machine's repo tree entirely with
`MYTHOS_BENCH_GT=<dir outside the repo>`. Anyone reproducing a published figure
should say which of the two they ran.

The agent's working directory sits inside the sweep output directory, so a cell
can in principle traverse to `.targets/<project>/compose.json`, which carries
the flag. That is symmetric between the arms and is covered by `suspect`.

## Reproduction

Paths are configurable and nothing is hardcoded to one machine. `XBEN_ROOT`
points at the external checkouts and defaults to a `mythos-bench` directory
beside the repo; `MYTHOS_BENCH_RESULTS` and `MYTHOS_BENCH_ASSETS` default below
it. Results must stay outside the repo tree, or the control arm picks up
`AGENTS.md` from a parent directory and stops being a control. On the
maintainer's machine these live on a separate disk, so the published sweeps ran
with `XBEN_ROOT=/mnt/linux-data/mythos-bench`.

```sh
# 1. once: which challenges build, written to a TSV that is published with the results
python3 bench/xben.py check --out $XBEN_ROOT/build_results_fixed.tsv

# 2. plan with no Docker, then run. Without --scope-confirmed run.py prints the plan and exits 2.
python3 bench/run.py --frameworks claude_mythos,claude_control --model <id> \
    --build-tsv $XBEN_ROOT/build_results_fixed.tsv \
    --sample 30 --seed 1 --runs 3 --parallel 3 --budget 1800 --coverage-gate off --dry-run
python3 bench/run.py ...same args... --scope-confirmed --out <results>/<name>

# 3. evaluate. Both rates and the minimum detectable difference are printed.
python3 bench/score.py <results>/<name>
python3 bench/stats.py <results>/<name>/results.jsonl --compare claude_mythos,claude_control

# 4. flagless targets: run, blind, rate, then aggregate
python3 bench/labs.py up vulnbank
python3 bench/labs.py run vulnbank --framework claude_mythos --model <id> \
    --budget 3600 --out <results>/<name> --coverage-gate on --scope-confirmed
python3 bench/labs.py seal <results>/<name>
python3 bench/labs.py score vulnbank <results>/<name>/blind/<id> --rater r1
python3 bench/labs.py stats vulnbank <results>/<name>/blind/*

# 5. the harness's own checks
python3 bench/score.py --selftest && python3 bench/stats.py --selftest \
    && python3 bench/labs.py selftest
```

A sweep is resumable: cells with a `result.json` are skipped. Target failures
are not written unless `--keep-failed`, so they retry.

## Which artifacts are published

Every published table must be backed by committed artifacts. For each sweep,
these are committed:

- `sweep.json`: the full parameter set, the resolved arms with their roots and
  treatments, the repo commit, the host versions of `opencode`, `claude`,
  `docker` and `uv`, the toolbox image reference and id, the ground-truth
  directory in force, and the challenge list.
- every cell's `result.json`: outcome, both rates' inputs, the exclusion status
  and its reason, flag provenance, the treatment, the readable roots, the
  resolved model ids as the host reported them rather than the alias, the
  `scope.yaml` hash, the resolved-compose hash and the run-tree hash.
- `results.jsonl` and `summary.json`, which carries the pre-exclusion and
  post-exclusion rate per arm with the exclusion breakdown.
- every triage file, `sealed-map.json` and the rubric with its hash.
- the build-success TSV.

Together these are well under a megabyte per sweep.

**Transcripts are not committed, and the reason is content rather than size.**
The 271 stored transcripts total about 38 MB, so size alone would not decide it.
They carry the cell's flag, whatever the agent pulled out of the target, and the
credentials it created on the lab applications. `transcripts.sha256` is
committed instead, so a transcript handed to a third party can be verified
against the run it claims to come from, and `trace_sha256` hashes the whole run
tree. Releasing the transcripts needs a redaction pass over the flag, the
created credentials and any dumped rows. That pass is not automated, and until
it is, transcripts are available on request rather than published. Anyone
re-stating a figure from a transcript should say which they had.

## Reporting checklist

There is no preregistration norm and no reporting standard specific to
security-agent benchmarks. This file follows the **Agentic Benchmark Checklist**
and is written to be checkable against it: the task validity and outcome
validity sections above state what the flag does and does not prove, the
exclusion rules are pre-specified and symmetric, the statistical reporting
states the minimum detectable difference alongside every p, and the
contamination and construct-validity sections state what the design cannot
establish. BetterBench, Bean et al. and Happe and Cito's review of LLM
penetration-testing work cover the same ground and were used as cross-checks.
Saying which checklist is followed is the cheapest credibility available here,
so it is said.

## Known limitations

- **Underpowered against the plausible effect.** See "Statistics". The design
  resolves about 0.29 and the literature reports 0.05 to 0.10.
- **One repeat per cell** in every published sweep, so variance is not separated
  from effect.
- **The treatment is not decomposable.** See "Design".
- **No contamination control is possible** for public targets whose
  documentation is the answer key. See "Contamination".
- **Construct validity is unestablished.** No number here is known to predict
  anything outside these targets.
- **The scanner side was weaker than intended in every sweep.** A supply-chain
  review of the toolbox image found two faults that applied to the image as
  published during the sweeps. `nuclei` shipped with no templates, because
  pip's cache created `/home/pentester` as root before `useradd` ran and
  `nuclei -update-templates` then failed silently at build time. And the
  `graphw00f` on PyPI is an inert placeholder at version 0.0.1 rather than the
  real tool, so the image carried a GraphQL fingerprinter that did nothing,
  which bears on the DVGA numbers specifically. Both are fixed in the current
  `toolbox/Dockerfile`, which bakes the templates at release tag v10.5.2 and
  clones `graphw00f` from its repository at a pinned commit. Which sweeps ran
  which image cannot be established from the artifacts, because no sweep
  recorded an image digest. That is now recorded per cell, which is how this
  class of question becomes answerable next time.
- **Flag provenance is a necessary condition only.** It does not show the
  intended vulnerability was the path.
- **The paired difference interval is missing.** See "Statistics".
- **Rating sits inside the published inter-rater noise band** until two raters
  have rated the same runs. See "Blinding and triage".
- **The isolation constrains the grant, not the kernel.** See "What the
  isolation does and does not do".
- **crAPI has never been measured.** It needs 7 or more containers and does not
  fit the 3.7 GB test host.
- **The toolbox is shared.** Mythos tools run in one global `mythos-toolbox`
  container, so parallel Mythos cells share it, and a container already running
  keeps whatever repo mount it was started with.

## What the audit of 13 November 2026 found

Four faults, each of which is now both fixed and detectable.

**1. The scoring key was readable by one arm and not the other.** The Mythos arm
ran with `--dangerously-skip-permissions --plugin-dir <repo> --add-dir <repo>`,
so `bench/data/ground_truth/*.json`, the list the flagless targets are scored
against, sat inside a root it was invited to read, and `scripts/mythos` mounted
the same repository into the toolbox at `/repo`. The control arm got an empty
working directory and no such grant. `bench/labs.py` never computed `suspect`
for the flagless runs, and the `SUSPECT` pattern would not have matched a
ground-truth path, so nothing would have caught it. The arm that produced the
project's one positive result therefore had unaudited read access to the key.
There is no evidence in the transcripts that it read the key and none that it
did not.

Fixed by staging the assets outside the repo, by `grants()` and
`xben.sealed_violations` refusing any arm whose roots reach the key or the
scoring code, and by extending `SUSPECT` to the ground-truth paths, the scoring
code, the harness state and the canaries.

**2. Exclusions depended on the outcome.** `rate_limited`, `runner_failed`,
`provider_stalled` and `classifier_blocked` were assigned only `if not
r["solved"]`, so an exclusion could only ever raise a rate. The criteria were
also prose regexes over the whole transcript including tool output, so a target
answering `429 Too Many Requests` would unscore a failed cell, and the
classifier criterion was matched against the agent's own final report, letting
the agent's wording decide whether its failure counted.

How much this mattered, measured on the stored artifacts: the 40-challenge
control arm reads 0.69 over all 39 cells, 0.90 under the published rule, and
0.87 under the outcome-independent rule, while the Mythos arm reads 0.70, 0.85
and 0.88. The published gap of 0.90 against 0.85 becomes 0.87 against 0.88 and
changes sign, which is the clearest possible demonstration that the gap was an
artifact of the rule. The Strix arm is starker: 10 of its 12 cells hit the stall
deadline and 2 ended in a runner error, including both cells that were reported
as `ok`, which were kept only because they solved. Under the corrected rule
Strix has no scored cells at all, not 2 of 2 at 1.00.

Fixed by `score.classify`, which is blind to the outcome, reads only signals the
agent cannot author, and is applied symmetrically, with intention-to-treat as the
primary analysis and both rates published.

**3. Precision was never measured.** No row in any `triage.json` could carry the
status `fp`: the schema listed the documented vulnerabilities and asked the
rater to mark each one found or missed, so a false positive the arm reported had
nowhere to go. Every published precision of 1.00 is a property of that schema.

Fixed by the two-list triage schema, by refusing a precision number from an
incomplete triage, and by reading the old one-list files for recall while
refusing precision on them with the reason given.

**4. The rater was single and unblinded.** Flagless recall was set row by row by
the author, prefilled from the arm's own report, with the arm's name in the run
path. Fixed by the rubric file, the sealed blinding, the rater field and the
agreement figure.

Two further problems were found that are not harness bugs but affected the
published figures. The coverage gate was scored by `scripts/coverage`, which
counted a substring match in the report as a mapped path having been covered,
which makes the "all 42 mapped paths accounted for" claim circular; that script
is being fixed separately. And nothing was reproducible from the repository: no
`results.jsonl`, no transcripts and no triage files were committed, and the
results root was hardcoded to one machine's disk. The artifact policy above and
the configurable roots are the answer to that.
