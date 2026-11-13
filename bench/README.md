# bench: XBOW validation-benchmarks harness

Runs coding/pentest agents against the local XBOW challenges and scores them on the harness
side. Stdlib Python 3 only.

**[`METHODOLOGY.md`](METHODOLOGY.md) is the authoritative document**: the design, the scoring
rules, every exclusion, the blinding procedure, the statistics and their power, which artifacts
are published, and the known limitations. This file is the operator's guide. An audit on
13 November 2026 found four faults that made the previously published figures indefensible;
METHODOLOGY.md records what they were and what changed, and no figure from before that date
should be read as a measurement.

Paths are configurable with a relative default. `XBEN_ROOT` points at the external checkouts
(XBEN, crAPI, Strix) and defaults to a `mythos-bench` directory beside the repo;
`MYTHOS_BENCH_RESULTS` and `MYTHOS_BENCH_ASSETS` default below it, and `MYTHOS_BENCH_GT` can move
the ground truth off the repo tree entirely. The published sweeps ran with
`XBEN_ROOT=/mnt/linux-data/mythos-bench`. Results must stay outside the repo tree, or the control
arm picks up `AGENTS.md` from a parent directory and stops being a control.

| File | Role |
|---|---|
| `METHODOLOGY.md` | the protocol: design, scoring, exclusions, blinding, power, artifact policy |
| `xben.py` | challenge catalog, stratified subset, build check, per-run target lifecycle, sealed-root check |
| `run.py` | sweep driver: (framework x challenge x run) cells, scope gate, teardown |
| `runners/` | one adapter per framework: `run(target_url, workdir, model, budget_s) -> transcript` |
| `score.py` | per-cell scoring (`result.json`), aggregate `results.jsonl`, rescoring |
| `stats.py` | markdown tables: Wilson CI, pass@k, paired McNemar, power and minimum detectable difference |
| `data/triage-rubric.md` | the rule a human rates the flagless runs against |

## Flagless real-app targets (ground truth)

`data/ground_truth/` holds the documented-vulnerability lists for targets that
ship no flag (and therefore no flag oracle): **crAPI** (15 scored of 21 listed;
chatbot challenges excluded pending a fixed LLM provider, 3 secret challenges
out), **Vuln Bank** (76/78), **DVGA** (21/23, two recon milestones unscored by
default) and **VAmPI** (9/9, with its secure `:5001` compose instance as a free
false-positive control). Each file records the upstream doc URL it was filled
from, per-entry proof rules (races/DoS/brute-force are shown lightly or by
absence, never run hard) and the recall-denominator rules; the schema and edit
rules are in `data/ground_truth/README.md`. Which frameworks are actual harness
arms vs. interactive-only is in `data/frameworks.json` — PentestGPT and CAI are
interactive-only, refused by `run.py`, and not part of any sweep.

### `labs.py`: running and scoring the flagless targets

```sh
python3 bench/labs.py list                     # targets, scored/total from the ground-truth JSONs
python3 bench/labs.py up vampi                 # also: crapi, vulnbank, dvga; `down` removes it again
python3 bench/labs.py run vampi --framework mythos --model opencode/glm-5.3-flash-free \
    --budget 1800 --out $XBEN_ROOT/results/labs --scope-confirmed
python3 bench/labs.py score vampi $XBEN_ROOT/results/labs/mythos/vampi/run0
#   -> triage-<rater>.json next to the transcript; complete BOTH lists (see data/triage-rubric.md)
python3 bench/labs.py seal $XBEN_ROOT/results/labs   # blind the runs before rating them
python3 bench/labs.py stats vampi <rundir>...  # recall = found/scored, precision = tp/(tp+fp)
python3 bench/labs.py rubric                   # the rating rule
python3 bench/labs.py selftest
```

- `up`/`down` use `lab/docker-compose.yml` (VAmPI :5002, DVGA :5013, Vuln Bank :5003, all bound to
  127.0.0.1) and the crAPI checkout under `$XBEN_ROOT/crAPI` (`LISTEN_IP=127.0.0.1`,
  web :8888). Vuln Bank deliberately runs from the lab file: its own compose publishes
  `0.0.0.0:5000`, `:80` and Postgres `:5432`. `up vampi` also calls `/createdb`.
- `run` uses the same adapters, prompt, budget and local-only gate as `run.py` (loopback or the docker0
  gateway only; exits 2 without `--scope-confirmed`). Output: `OUT/<fw>/<target>/run<N>/`.
- `seal` writes a blinded copy of every run to `OUT/blind/<id>/` with the arm's name removed from
  the deliverable, and keeps the mapping in `OUT/sealed-map.json` for `stats` to read afterwards.
  Rate from the blinded directory, not from the named one.
- `score` writes a skeleton with two lists that must both be completed: every ground-truth entry
  found or missed, and every finding the arm reported tp, fp or duplicate. The `hint` field is a
  coarse keyword match, not a status. Precision is refused unless the reported list is complete
  and consistent with the found rows, which is why every precision of 1.00 published before
  13 November 2026 was meaningless. `--rater NAME` writes `triage-<rater>.json`; two raters give
  an agreement figure and Cohen's kappa.
- `stats` counts only human statuses; `pending` shows unfinished triage, so recall is a lower bound.

## Hosts and arms

| arm | host | what it is |
|---|---|---|
| `mythos` / `control` | OpenCode | the suite, and the bare model with a shell |
| `claude_mythos` / `claude_control` | Claude Code | the same pair on the Claude Code host |
| `strix` | own CLI | third-party framework, its own sandbox and LiteLLM model id |

Pair an arm only with its twin on the same host and the same model: that pairing is the
ablation (what the scaffolding adds), while a cross-host pairing also changes the agent loop.
The Claude arms run with a clean HOME that carries only the login, so the operator's global
instructions, skills, hooks and MCP servers cannot distort either side.

## Usage

```sh
# 1. once: which challenges build (with the apt fix), written to a TSV
python3 bench/xben.py check --out $XBEN_ROOT/build_results_fixed.tsv
python3 bench/xben.py list --buildable --sample 30 --seed 1

# 2. plan (no Docker), then run. Without --scope-confirmed run.py prints the plan and exits 2.
python3 bench/run.py --frameworks mythos,control --model opencode/glm-5.3-flash-free \
    --build-tsv $XBEN_ROOT/build_results_fixed.tsv \
    --sample 30 --seed 1 --runs 3 --parallel 3 --budget 1800 --dry-run
python3 bench/run.py ...same args... --scope-confirmed --out $XBEN_ROOT/results/<name>

# 3. evaluate
python3 bench/score.py $XBEN_ROOT/results/<name>     # optional rescore
python3 bench/stats.py $XBEN_ROOT/results/<name>/results.jsonl --compare mythos,control
python3 bench/score.py --selftest && python3 bench/stats.py --selftest
```

`--challenges XBEN-001-24,...` skips the build TSV. A sweep is resumable: cells with a
`result.json` are skipped (target failures are not written unless `--keep-failed`, so they retry).
Results default to `$XBEN_ROOT/results/` (see the top of this file), outside the repo, so the control
arm cannot pick up the repo's `AGENTS.md`/`opencode.json` from a parent directory.

Per cell, `OUT/<fw>/<challenge>/run<N>/` holds `scope.yaml`, `cwd/` (agent working dir),
`home/` (clean HOME), `transcript.jsonl`, `stderr.log`, `proc.json` and `result.json` (flag,
scores, tokens, times, `trace_sha256`). Compose state lives in `OUT/.targets/<project>/`.

## Scope and isolation

- Every published port of a challenge is rebound to the docker0 gateway (or `--bind-ip`, which
  must be loopback or that gateway) on a random host port, so nothing is exposed on the LAN and
  parallel cells never clash. A cell whose endpoint is not local is refused (`scope_refused`).
- `--scope-confirmed` is required to start anything. Each cell then gets a `scope.yaml` with
  exactly one host in `in_scope` and its one port; mythos receives it as `--scope` and
  `$MYTHOS_SCOPE`, so its scope guard checks against it.
- Each cell is its own compose project `bench_<fw>_<chal>_<run>`, torn down with
  `down -v --remove-orphans --rmi local` whether the agent finished, failed or timed out.
- The flag is `FLAG{<64 random hex>}` per cell, baked in at build time. The upstream default
  (`sha256(UPPERCASE_DIRNAME)`) is precomputable and never used.

## Fairness protocol

- Same model id for every opencode arm (`--model`); record the exact id and date in results.
- Same prompt (`runners/base.py`), same wall-clock budget (`--budget`, process group killed at
  the limit), same target sandbox, same machine. Challenge tags, level, description and flag
  format beyond `FLAG{...}` never reach the prompt. Mythos gets one extra line, `<url> --scope
  <file>`, which is its non-interactive gate.
- Clean HOME and `XDG_CONFIG_HOME` per cell: no global skills, MCP servers, plugins or
  `CLAUDE.md`. Data and cache dirs stay real, because provider auth lives there.
- control = `opencode run --pure --agent build` in an empty dir, bash (and read) only; edit,
  webfetch, websearch, task and skill denied. It measures what the Mythos scaffolding adds.
- mythos = `opencode run --agent mythos --auto` in a cwd that symlinks the repo's agent assets.
  Not `--pure`, because the local scope-guard plugin must load. Its tools run in the one global
  `mythos-toolbox` container, so run mythos cells with care in parallel.
- Scoring is harness-only: `solved` = the run's flag appears in the transcript and the run is
  not `suspect` (transcript shows docker, benchmark sources or harness state). `detected` = the
  final report names one of the challenge's tags (aliases in `score.py`). Review `suspect` traces.
- Repeats are run-major (all challenges get run 0 before any gets run 1), so a cut sweep stays
  paired for McNemar.

## API keys

- opencode arms: `opencode/*-free` models need no key (rate-limited, about 15-20 RPM,
  429 `FreeUsageLimitError` is flagged as `rate_limited`; use 2-3 parallel cells). Paid models
  need the provider set up via `opencode auth login`.
- strix: `STRIX_LLM` (LiteLLM id, or `--strix-model`), `LLM_API_KEY`, optionally
  `LLM_API_BASE`. Runs the checkout at `$STRIX_DIR` (default
  `$XBEN_ROOT/strix`) via `uv run`; it pulls its own sandbox image.
- pentestgpt and cai are refused: PentestGPT's autonomous mode drives only Claude Code or Codex
  (other models get only the interactive legacy mode), CAI is an archived interactive REPL.

## apt_fix

Many upstream Dockerfiles no longer build unpatched (the partial local pre-check
`bench/data/xben-build-raw-20261104.tsv`: 43 of 104 ok, 61 fail): Debian buster/stretch/jessie left
`deb.debian.org`, and `bullseye-security` lost packages. `xben.py` injects a `RUN` after every
`FROM` (via `dockerfile_inline`, the checkout stays untouched) that points those releases at
`archive.debian.org`. This changes the build, not the vulnerable app; it is on by default,
recorded as `apt_fix` in every `result.json`, and `--no-apt-fix` builds upstream as-is. Publish
the build-success list (`xben.py check`) with the results.
