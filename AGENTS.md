# Mythos — agent instructions

Mythos is a skill-driven web red-team / bug-bounty framework for **authorized**
testing only (bug-bounty programs in scope, systems the user owns or may test,
lab targets). The agent host's model is the agent: there is no separate engine
and no external API key. Mythos supplies the methodology (skills), the
orchestration (one orchestrator, six sub-agents), a Kali tool belt in Docker,
a knowledge base and a scope guard.

Supported hosts: **OpenCode first** (1.x >= 1.18.29 and 2.x), Claude Code
second. Both read the same skills, agents and scope logic.

## Flow

Start an engagement with `/cybersecurity <target> [--scope scope.yaml]` (or
`opencode run --agent mythos "<target> --scope <file>"`). The `mythos`
orchestrator follows the phase skills in order and delegates the heavy phases:

`engagement-setup` → planner → `recon` (mythos-recon) → `web-scan`
(mythos-scanner, mythos-browser for SPA/DOM) → `exploit` (mythos-exploiter,
only if `allow_exploit`) → `report` (mythos-reporter).

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
  widen it on your own; default `in_scope` to the target host only.
- The scope guard (`hooks/scope-guard.py`, wired as a Claude Code PreToolUse
  hook and as the OpenCode plugin `.opencode/plugin/scope-guard.ts`) warns on
  out-of-scope hosts in bash/webfetch calls. It is warn-only by design
  (`MYTHOS_SCOPE_ENFORCE=block` turns it into a block). A warning means: do
  not run that command.
- Honor `rules.rate_limit_rps` and `rules.max_requests`.
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

## Self-test

`scripts/selftest.sh` checks the toolbox flow and the scope guard against the
ground-truth lab app; `scripts/selftest.sh --host opencode` runs the same
checks through `opencode run --agent mythos`.
