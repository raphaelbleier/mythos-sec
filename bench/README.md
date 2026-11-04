# bench: XBOW validation-benchmarks harness

Runs coding/pentest agents against the local XBOW challenges in
`/mnt/linux-data/mythos-bench/validation-benchmarks` (override with `XBEN_ROOT`) and scores them
on the harness side. Stdlib Python 3 only.

| File | Role |
|---|---|
| `xben.py` | challenge catalog, stratified subset, build check, per-run target lifecycle |
| `run.py` | sweep driver: (framework x challenge x run) cells, scope gate, teardown |
| `runners/` | one adapter per framework: `run(target_url, workdir, model, budget_s) -> transcript` |
| `score.py` | per-cell scoring (`result.json`), aggregate `results.jsonl`, rescoring |
| `stats.py` | markdown tables: Wilson CI, pass@k, paired McNemar |

## Usage

```sh
# 1. once: which challenges build (with the apt fix), written to a TSV
python3 bench/xben.py check --out /mnt/linux-data/mythos-bench/build_results_fixed.tsv
python3 bench/xben.py list --buildable --sample 30 --seed 1

# 2. plan (no Docker), then run. Without --scope-confirmed run.py prints the plan and exits 2.
python3 bench/run.py --frameworks mythos,control --model opencode/glm-5.3-flash-free \
    --build-tsv /mnt/linux-data/mythos-bench/build_results_fixed.tsv \
    --sample 30 --seed 1 --runs 3 --parallel 3 --budget 1800 --dry-run
python3 bench/run.py ...same args... --scope-confirmed --out /mnt/linux-data/mythos-bench/results/<name>

# 3. evaluate
python3 bench/score.py /mnt/linux-data/mythos-bench/results/<name>     # optional rescore
python3 bench/stats.py /mnt/linux-data/mythos-bench/results/<name>/results.jsonl --compare mythos,control
python3 bench/score.py --selftest && python3 bench/stats.py --selftest
```

`--challenges XBEN-001-24,...` skips the build TSV. A sweep is resumable: cells with a
`result.json` are skipped (target failures are not written unless `--keep-failed`, so they retry).
Results default to `/mnt/linux-data/mythos-bench/results/`, outside the repo, so the control
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
  `/mnt/linux-data/mythos-bench/strix`) via `uv run`; it pulls its own sandbox image.
- pentestgpt and cai are refused: PentestGPT's autonomous mode drives only Claude Code or Codex
  (other models get only the interactive legacy mode), CAI is an archived interactive REPL.

## apt_fix

Many upstream Dockerfiles no longer build unpatched (the partial local pre-check
`build_results.tsv`, 85 of 104, has 49 fail; a secondary report claims 39 of 104): Debian buster/stretch/jessie left
`deb.debian.org`, and `bullseye-security` lost packages. `xben.py` injects a `RUN` after every
`FROM` (via `dockerfile_inline`, the checkout stays untouched) that points those releases at
`archive.debian.org`. This changes the build, not the vulnerable app; it is on by default,
recorded as `apt_fix` in every `result.json`, and `--no-apt-fix` builds upstream as-is. Publish
the build-success list (`xben.py check`) with the results.
