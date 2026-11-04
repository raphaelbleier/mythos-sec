# Limitations and environment notes

Mythos is a skill-driven framework: the agent host's model reasons, skills
supply methodology, real tools run in a Kali container. The limits below follow
from that design and from the evaluation setup. Anything not measured is marked
as such.

## What the evaluation can and cannot show

- **Results pending.** The main comparison (mythos vs bare-model control vs
  Strix, same model) has not been completed. No performance claim is made until
  the table in `poster.md` is filled from `bench/stats.py` output.
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
  Strix ran on a shared GLM 5.3 endpoint and solved 4 of 5 valid cells in a
  12-challenge pilot; its remaining cells were lost to the provider's quota.

## Capability limits

- **Business logic is hard.** Multi-step object ownership, mass assignment and
  race conditions are not reliably solved by any scanner. The `auth-session` and
  `business-logic` skills give the agent a method; no autonomous success rate is
  claimed. Measured effect: pending (roadmap phase 3, ablation not run).
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
