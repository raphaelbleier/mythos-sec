# Mythos — agent instructions

Mythos is a skill-driven web red-team / bug-bounty framework for **authorized**
testing only (bug-bounty programs in scope, systems the user owns or may test,
lab targets). The agent host's model is the agent: there is no separate engine
and no external API key. Mythos supplies the methodology (skills), the
orchestration (one orchestrator, seven sub-agents), a Kali tool belt in Docker,
a knowledge base and a scope guard.

Supported hosts: **OpenCode first** (1.x >= 1.18.29 and 2.x), Claude Code
second. Both read the same skills, agents and scope logic.

## Flow

Start an engagement with `/cybersecurity <target> [--scope scope.yaml]` (or
`opencode run --agent mythos "<target> --scope <file>"`). The `mythos`
orchestrator follows the phase skills in order and delegates the heavy phases:

`engagement-setup` → planner → `recon` (mythos-recon) → `web-scan`
(mythos-scanner, mythos-browser for SPA/DOM) → `exploit` (mythos-exploiter) →
`report` (mythos-reporter).

`recon` fingerprints the stack and then runs `scripts/cvefeed match`, writing
`engagements/<dir>/cve-candidates.json`. The planner reads that file and spawns
work from it. This matters more than it looks: an agent given the CVE
description reached 87% on a one-day benchmark against 7% without it, so
knowing what to look for is most of the result.

Between engagements, `scripts/watch` keeps a tested target under observation
(`docs/continuous.md`): it diffs the surface, matches new CVEs against the known
stack and lists stored proofs to replay, and the `continuous` skill acts on its
work list. It is pinned to the engagement's scope file and holds all traffic
when that file changes or the authorization confirmation is older than 30 days,
because a scheduled job testing a program whose scope moved is how a tester ends
up unauthorized.

Load a phase skill when you reach that phase; do not preload them all.
`knowledge/` holds per-class confirmation playbooks: read the relevant file
when a skill points to it.

## Toolbox

Every security tool runs in the `mythos-toolbox` Kali container through
`scripts/mythos` (see the `toolbox` skill): `scripts/mythos up` once, then
`scripts/mythos <tool> [args]` or `scripts/mythos sh '<pipeline>'`. The repo is
mounted at `/repo`, so tool output lands under `engagements/`. A lab target on
`localhost:PORT` is reached from the toolbox as
`http://host.docker.internal:PORT`.

## Scope rules

- `engagements/<dir>/scope.yaml` is the hard authorization boundary. Never
  widen it on your own; default `in_scope` to the target host only. Pin it with
  `export MYTHOS_SCOPE=...` in `engagement-setup`: without that, both guards
  fall back to the newest `engagements/*/scope.yaml` by modification time, and a
  leftover directory would authorize the run.
- The scope guard (`hooks/scope-guard.py`, wired as a Claude Code PreToolUse
  hook and as the OpenCode plugin `.opencode/plugin/scope-guard.ts`) warns on
  out-of-scope hosts in bash/webfetch calls. It is warn-only by design
  (`MYTHOS_SCOPE_ENFORCE` picks the mode: `warn` default, `ask` to refuse
  pending the user's decision, `block` to refuse outright). In `warn` mode the
  warning reaches you with the tool result, so the command has already run by
  the time you read it: treat a warning as a slip that already happened, stop,
  report it, and do not send that request again. Only `ask` and `block` can
  prevent the call, so set `MYTHOS_SCOPE_ENFORCE=ask` for any engagement where
  one out-of-scope request is unacceptable. Never widen the scope to silence a
  warning. A request the target makes on your behalf, for example an SSRF
  probe, counts as yours: the destination must be in scope too.
- Honor `rules.rate_limit_rps`. `hooks/budget-guard.py` enforces it: single
  calls are paced by sleeping, and a batch tool with no pacing flag is refused
  with the flag to add. There is no request ceiling and no exploitation gate,
  because this is a bug-bounty suite and exploitation is the work. The guard
  does refuse data destruction, brute force and denial of service outright, in
  every mode, and no scope rule overrides that.
- Keep all engagement artifacts under `engagements/<dir>/` (git-ignored).

## Single human gate

The only stop is the scope confirmation in Step 0 of the orchestrator. With
`--scope <file>` (including non-interactive `opencode run --auto`) the scope
file is the confirmation and nothing is asked. After that the engagement runs
recon → scan → exploit → report unattended. Safety is enforced by hard rules,
not by pauses: non-destructive only, no denial-of-service or brute force,
minimal proof of concept, no data dumping. What cannot be proven safely is
skipped and reported as "unconfirmed".

## Where things live (one canonical source)

| What | Canonical source | Generated for Claude Code |
|---|---|---|
| Project instructions | `AGENTS.md` | `CLAUDE.md` imports it (`@AGENTS.md`) |
| Orchestrator | `.opencode/agent/mythos.md` + `.opencode/command/cybersecurity.md` | `commands/cybersecurity.md` |
| Sub-agents | `.opencode/agent/mythos-*.md` | `agents/mythos-*.md` |
| Skills | `skills/*/SKILL.md` (OpenCode via `opencode.json` `skills.paths`) | used as-is by the plugin |
| Scope check | `hooks/scope-guard.py` | OpenCode plugin shells out to `--check` |

Edit only the canonical files, then run `python3 scripts/build-hosts.py`.
`python3 scripts/build-hosts.py --check` exits 1 on drift (use it in CI).
Never hand-edit `agents/*.md` or `commands/*.md`.

## Deterministic tools do the work the prompt cannot

The strongest published finding about agents in this domain is that the tool
layer decides the outcome, not the prose: in one study every model scored zero
without high-level actions, while small models with them succeeded where large
models without them did not. So reach for these before writing a paragraph.

| Script | What it is for |
|---|---|
| `scripts/probe` | map the surface, GET only except the GraphQL introspection POST |
| `scripts/sourcemap` | routes, missing guards and sinks from a source tree, correlated with the probe's surface. Grey-box only, and its output is a hypothesis list |
| `scripts/verify` | re-send one aim point and judge it against an oracle |
| `scripts/cvefeed` | KEV, EPSS, NVD, nuclei templates, GHSA and OSV, ranked for this stack |
| `scripts/coverage` | which mapped paths the report still does not account for |
| `scripts/findings` | `findings.json` and SARIF, CVSS computed from the vector, dedup, redaction, `--diff` for retest |
| `scripts/lessons` | class priors from past engagements; see its own caveat, it is an untested hypothesis |
| `scripts/watch` | what changed on a tested target since last time, and what that makes worth re-testing |

Every one of them has a `--selftest`. Run it after changing one.

## Proof standard

`skills/exploit` holds the rules. Two of them exist because of measurements
worth repeating here: about 44% of proofs of concept that passed exit-code,
marker and trace checks were invalid, so a deterministic oracle outranks any
reading of a transcript; and a model approves its own errors 11.9 percentage
points more often when it wrote them, so the validator pass wants a different
model (`models.json` has a `validator` tier) and must say so when it cannot
have one.

## Self-test

`scripts/selftest.sh` checks the toolbox flow and the scope guard against the
ground-truth lab app; `scripts/selftest.sh --host opencode` runs the same
checks through `opencode run --agent mythos`.
