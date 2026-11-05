# Limitations and environment notes

Mythos is a skill-driven framework: the agent host's model reasons, skills
supply methodology, real tools run in a Kali container. The limits below follow
from that design and from the evaluation setup. Anything not measured is marked
as such.

## What the evaluation can and cannot show

- **The Claude Code mythos arm was not scaffolded before 5 November 2026.**
  `.claude-plugin/plugin.json` declared `author` as a string and `agents` as a
  string path. Claude Code rejects such a manifest silently, so
  `claude -p --plugin-dir <repo>` loaded no `/cybersecurity` command, no
  sub-agents and no plugin hooks. The arm still read `CLAUDE.md`/`AGENTS.md`
  from its working directory and had the full default tool set, so it was a
  bare model with project instructions, not the framework. Every Claude-host
  number below (sweeps A and C and the first VAmPI lab pair) therefore
  compares two near-identical controls; the OpenCode sweep B is unaffected
  (`opencode run --agent mythos` fails loudly on a missing agent). The manifest
  is fixed and `bench/runners/claude_mythos.py` now aborts a cell whose `init`
  event lists no `:cybersecurity` command.
- **Measured, and the result is a null.** Three sweeps are in: 40 challenges on
  Claude Sonnet, 12 on GLM 5.3, and a rerun of the seven challenges both arms
  had failed. The mythos arm never separates from the bare-model control
  (0.70 vs 0.69, 1.00 vs 1.00, 0.29 vs 0.29; every paired McNemar p = 1.0). On
  single-vulnerability flag-capture challenges the scaffolding adds nothing this
  sample can detect. Numbers and parameters: `poster.md`.
- **One run per cell.** Nothing is repeated, so run-to-run variance is not
  separated from any effect. The rerun shows how much that matters: both arms
  converted two of the seven previously failed challenges, although only the
  mythos arm had changed in between.
- **The flagless measurement is in, and it is also a null.** VAmPI, coverage
  objective instead of a flag hunt, Claude Sonnet: control 8 of 9 documented
  vulnerabilities, mythos 8 of 9 with the plugin verified loaded, precision
  1.00 in both arms, the same single miss (RegexDOS, declined in both arms to
  avoid a denial of service). The scaffolded arm reported one extra true
  finding outside the documented list. It also used no sub-agent, no toolbox
  and no deterministic probe: on a surface this small the orchestrator's
  "scale the work to the target" rule effectively switches the scaffolding off,
  which is a design question, not a model limit.
- **The benchmark measures the wrong thing for this question.** A flag is all
  or nothing, so multi-step chains and access-control findings score zero until
  they are complete. The seven shared failures carry tags such as
  `insecure_deserialization`, `business_logic` and `privilege_escalation`. The
  flagless targets with documented vulnerability lists are the measurement that
  could show a scaffolding effect; VAmPI is done (above), crAPI, Vuln Bank and
  DVGA are still missing.
- **Scaffolding effect vs model effect.** With one model for all arms, a
  difference measures the scaffolding (skills, orchestration, tools), not the
  model. It says nothing about other models.
- **Model dependence.** Results hold for the recorded model id and date only.
  Free-tier models are rate-limited (about 15-20 RPM) and may change silently;
  paid models cost money per cell.
- **Sample size.** A stratified subset (e.g. 30 challenges x 3 runs) gives wide
  Wilson intervals; small differences will not be significant. McNemar uses
  paired cells only.
- **XBOW is dated.** The set is described by its maintainers as outdated and
  saturated, and published scores of other frameworks are self-reported and
  were not independently replicated. Cross-paper comparisons are not valid;
  only same-harness, same-model arms are comparable.
- **Build modification.** Many upstream challenge Dockerfiles no longer build
  (Debian releases moved to `archive.debian.org`). The harness injects an
  apt fix; this changes the build, not the vulnerable app, and is recorded as
  `apt_fix` per result. The build-success list must be published; challenges
  that fail to build are excluded, which biases the set toward buildable ones.
- **Scoring.** `solved` means the per-run random flag appears in the transcript
  and the run is not flagged `suspect` (docker access, benchmark sources, harness
  state). `suspect` traces need manual review. `detected` (a report naming a
  challenge tag) is a weaker, alias-based signal.
- **Not compared:** PentestGPT (autonomous mode only drives Claude Code or
  Codex) and CAI (archived, interactive REPL) are refused by the harness.
  Strix ran on a shared GLM 5.3 endpoint. Across two sweeps only a handful of
  its cells stayed valid (2 of 12 in the final run; eight ended in a provider
  stall, two in a runner error), so its rate carries no weight.

## Capability limits

- **Business logic is hard.** Multi-step object ownership, mass assignment and
  race conditions are not reliably solved by any scanner. The `auth-session` and
  `business-logic` skills give the agent a method; no autonomous success rate is
  claimed, and no flag-capture sweep so far isolates these classes.
- **Stored XSS and server-side classes.** `stored-xss-oast` (OAST catcher +
  admin bot) and `deep-server` exist with lab support; re-measurement on the
  classes Strix missed (SSTI, smuggling, race, deserialization) is pending.
- **Closure states are conventions.** Evidence gating is enforced by skill
  instructions, not by code; a model can still mislabel a finding. The ablation
  (gating on/off) is not yet run.
- **Earlier numbers do not carry over.** Results in `benchmark-skill-driven.md`,
  `benchmark-hard-targets.md` and `benchmark-xbow.md` come from single manual
  engagements, not the controlled protocol. Single runs, no repeats.
- **crAPI** (7+ containers) does not fit the current 3.7 GB host; vehicle BOLA
  also needs crAPI's pre-seeded users.

## Safety limits

- **The scope guard is a net, not a sandbox.** Warn-only by default; a model can
  ignore a warning. `MYTHOS_SCOPE_ENFORCE=block` blocks. Coverage inside
  OpenCode sub-agents is unverified.
- **One human gate.** After scope confirmation the engagement runs unattended.
  Hard rules (non-destructive, no DoS or brute force, minimal PoC) rely on the
  model following instructions.
- **Toolbox is shared.** Mythos tools run in one global `mythos-toolbox`
  container; parallel mythos cells share it.
- **Authorized use only.** Do not point it at targets you may not test. Offensive
  tooling can be misused; the project provides no authorization of its own.

## Environment

- Test host: 3.7 GB RAM, so lab targets run one at a time and heavy nuclei
  template sets are scoped.
- Windows and macOS: the shim is stdlib Python and avoids path rewriting for Git
  Bash, but only Linux (and WSL) has been exercised. Native tests: pending.
- The GHCR image is published for amd64 and arm64 (tag v0.2.0, both platforms
  in the merged manifest, pullable without credentials). Provenance and SBOM are
  attached by CI; cosign signature verification and pull-rate behavior are
  unverified.
