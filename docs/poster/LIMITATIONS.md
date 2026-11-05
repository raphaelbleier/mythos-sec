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
- **A safety classifier ends cells, and that dominated the raw rates.** On the
  Claude Code host a classifier interrupted an assistant turn in about half of
  all cells. Where a cell ends on that, the agent correctly stops and says so,
  which measures the classifier rather than the agent: 7 to 9 of the 12
  unsolved cells per arm ended that way. Such cells now carry the status
  `classifier_blocked` and are unscored like a provider refusal, and every
  number here is rescored accordingly. Earlier drafts reported the raw rates
  (0.70 vs 0.69); they were floors set by the classifier, not by capability.
  The OpenCode arms are unaffected.
- **Rerun with the scaffolding verified loaded: still a null.** The same 40
  challenges, Claude Sonnet, paired against the unaffected control arm:
  28/33 = 0.85 vs 27/30 = 0.90, McNemar exact p = 1.0 over 26 pairs (0 only
  mythos, 1 only control). The loaded framework solves the same count as the
  arm that failed to load it and costs 2.4x the money and 2.4x the tool calls
  ($20.88 vs $8.63, 928 vs 390 calls). With both arms at 0.85-0.90 and three
  to five unsolved cells each, this sample has almost no headroom left in which
  a difference could appear.
- **Measured, and the result is a null.** Five sweeps are in: 40 challenges on
  Claude Sonnet (twice, before and after the plugin fix), 12 on GLM 5.3, a
  rerun of the challenges both arms had failed, and VAmPI recall. The mythos
  arm never separates from the bare-model control (0.85 vs 0.90, 1.00 vs 1.00,
  0.40 vs 0.40, recall 0.89 vs 0.89; every paired McNemar p = 1.0). On
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
- **DVGA, the larger flagless target, is a null too.** 21 documented
  vulnerabilities, hand triage with an evidence quote per row: mythos 12, control
  11, precision 1.00 in both arms. Five of the 21 are denial-of-service classes
  the engagement's own safety rules forbid proving, and both arms skip them;
  excluding those, both arms are 10 of 16. One entry went to each arm alone
  (field suggestions and array batching to the scaffolded arm, the traversal
  write path to the control, which located it with the code execution it had
  already gained), and eight went to neither. The cost direction inverts here:
  the control spent 43 tool calls and $0.81, the scaffolded arm 18 and $0.27.
- **This target cannot survive being tested.** DVGA deadlocks permanently once
  `importPaste` fetches the application's own address, and a hung process still
  accepts TCP, so a port healthcheck does not see it. Two earlier runs spent
  about 35 minutes each on a dead target and were discarded. The harness now
  restarts the target after 90s without an HTTP answer and logs every restart
  next to the transcript; the two scored runs needed three and two restarts. A
  run whose target is still down at the end is recorded as `target_failed` and
  not scored. Both arms also modified seed data although the objective requires
  non-destructive testing: the control deleted another user's paste and
  overwrote a second one's title, the scaffolded arm edited one paste and
  restored it. Both reported it unprompted, but the rule is stated in the
  prompt and is not enforced in code.
- **Two further unscored statuses were found this way.** The account's weekly
  usage cap is printed as prose and ends the turn, so a capped cell looked like
  a failed solve; it now counts as `rate_limited` (two DVGA runs were lost to
  it, one of them without a single tool call). A `labs.py score` call on a
  classifier-ended run is now refused as well, the same rule the flag sweeps
  use.
- **Vuln Bank is the third null, and then the first separation.** 76 documented
  vulnerabilities, two repeats per condition: mythos without the coverage gate
  28 and 29, control 30 and 29, mythos with the gate 34 and 33, precision 1.00
  in all six runs. The gate was built because of what the ungated runs showed
  (below), so it is a response to this measurement, not an independent
  prediction confirmed by it; one target, one condition, two repeats. It costs
  about twice the control's tool calls and money (31-32 calls and $0.61-0.67
  against 14-15 and $0.25-0.29) for four to five extra entries. The two gated
  runs reach different extra surfaces, so the gate does not dictate findings,
  it stops a mapped surface from being skipped silently. The scaffolded arm had the second SQL injection point
  and the debug headers, the control had the missing token expiry, the card
  details and the API keys in responses. What matters more than the two-entry
  gap is that neither arm ever sent a request to the target's GraphQL surface
  (6 entries), its merchant APIs (6), its bill payments (9) or its card logic
  beyond freezing a card (10). Both reported 13-15 findings and stopped after a
  few minutes of a 3600s budget: the ceiling here is the agent's decision to
  stop, not the target. That is what the coverage gate addresses, and it is
  also the one lever the control cannot have, since a bare model has no place
  to put a surface map.
- **The scope guard cannot stop a call in its default mode.** On the Claude Code
  host a PreToolUse hook's `additionalContext` reaches the agent together with
  the tool result, so in `warn` mode the request is already out when the warning
  arrives; the instruction "a warning means: do not run that command" was not
  enforceable as written. On Vuln Bank the mythos arm put `169.254.169.254` in
  an SSRF payload and the target made the connection. The agent reported it
  unprompted. `AGENTS.md` now states what `warn` can do, points at
  `MYTHOS_SCOPE_ENFORCE=ask` for engagements where one stray request is
  unacceptable, and says that a request the target makes on the agent's behalf
  counts as the agent's own. The harness records `scope_warnings` per run, so
  this no longer depends on the agent confessing. Warn-only remains the default
  by project decision, and this is the cost of that decision.
- **The benchmark measures the wrong thing for this question.** A flag is all
  or nothing, so multi-step chains and access-control findings score zero until
  they are complete. The seven shared failures carry tags such as
  `insecure_deserialization`, `business_logic` and `privilege_escalation`. The
  flagless targets with documented vulnerability lists are the measurement that
  could show a scaffolding effect; VAmPI, DVGA and Vuln Bank are done, crAPI is
  still missing.
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
