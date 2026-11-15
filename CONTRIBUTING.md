# Contributing

Issues and pull requests are welcome. Mythos is research code for authorized
security testing, so a few rules are not negotiable.

## Where a change goes

There is one source for each kind of change, and no generated copies to keep in
step.

| Change | Where |
|---|---|
| Methodology: how a phase is worked, what a scan covers, when a phase is done | `skills/<name>/SKILL.md` |
| Confirmation playbook for a bug class | `knowledge/` |
| A deterministic tool: probe, verify, coverage, findings, cvefeed, sourcemap, traffic, watch, lessons | `scripts/` |
| The agent itself: loop, tools, prompts, TUI, providers, scope parsing | `cli/src/` |
| Guard rules: scope boundary, pacing, the destructive denylist | `hooks/scope-guard.py`, `hooks/budget-guard.py` |
| The Kali image and the tools in it | `toolbox/` |
| The lab targets the checks run against | `lab/` |

Project instructions live in `AGENTS.md`. Nothing in the repository is
generated from anything else, so there is no build step to run after an edit.
The old `scripts/build-hosts.py` and the `.opencode/` sources it read are both
removed, and so are the `agents/` and `commands/` copies it wrote.

## Two rules about tests

**A new or changed deterministic tool needs a `--selftest`.** Every script in
`scripts/` that an engagement depends on carries its own check, runnable with
no network and no model: `python3 scripts/findings --selftest`. If you add a
script, add the flag. If you change what one of them outputs, add the case that
would have failed before your change. `scripts/probe`, `scripts/models` and
`scripts/lessons-record` have no `--selftest` yet, because the first two only
act against a live target or render `models.json` and the third only runs on a
finished engagement. Adding one to any of them is a welcome pull request.

**A new guard rule needs a selftest case.** The guards decide what the agent is
allowed to send, and a rule that silently stops matching looks exactly like a
clean run. Both have a `_selftest()` built from one assertion per rule,
`eq(...)` in `hooks/scope-guard.py` and `want(...)` in
`hooks/budget-guard.py`. A new pattern gets the line that asserts its verdict,
and it also gets the negative case: the command that resembles it and must
still be allowed. The DELETE rule has both, because it first refused a POST on
an unrelated line of the same script.

## Running the checks

The offline check takes about ten seconds and is what CI runs:

```bash
scripts/selftest.sh
```

It runs every script's `--selftest`, the CLI typecheck and `cli/dist/selftest.js`,
then the two guards end to end against a temporary scope file. It stops at the
first failure. It never installs or builds anything, so in a fresh clone it
prints a skip line for the two CLI checks instead of reaching for npm.

With Docker it also starts the toolbox and reaches a lab target on the host's
loopback:

```bash
docker compose -f lab/docker-compose.yml up -d vulnapp
scripts/selftest.sh --with-docker
```

For the CLI on its own:

```bash
cd cli
npm ci                 # package-lock.json is committed
npm run check          # tsc --noEmit
npm run build          # tsc to dist/
node dist/selftest.js
```

`cli/node_modules/` and `cli/dist/` are git-ignored. Node 20 or newer, Python
3.11 or newer, and Docker for the toolbox.

`mythos doctor` checks the machine rather than the code: Node, Python, Docker,
the toolbox, a model credential, whether the profile has an independent
validator, the scripts, and whether Chromium starts.

If your change touches a skill, a script, a guard or the CLI, say in the pull
request which of these checks you ran.

**Keep the diff small.** One change per pull request. No reformatting of code
you did not otherwise touch.

## What belongs here

New bug-class playbooks under `knowledge/`, new skills, better tool
invocations, and measurements that someone else can reproduce from the
repository.

## What does not

Anything that only helps against targets you are not allowed to test. Mythos is
built for bug-bounty programs in scope, systems you own and lab targets, and
that boundary is the point of the project rather than a disclaimer on top of
it. Concretely: no denial-of-service or brute-force tooling, no detection
evasion, no data exfiltration beyond the minimal proof a finding needs, and
nothing that widens the scope guard's boundary on its own.

## Engagement data

Everything under `engagements/` is git-ignored. Check twice that no scope file,
tool log, screenshot or finding from a real target ends up in a commit. The
same goes for the lab: commit the seeded vulnerability, not the output of a run
against someone else's host.

## Commit messages

The repository uses [Conventional Commits](https://www.conventionalcommits.org/):
a type, an optional scope in parentheses, a colon, then the subject. The types
in use are `feat`, `fix`, `docs` and `chore`, and the scopes name the directory
that changed, for example `scripts`, `hooks` and `docs`.

The subject is lowercase, has no full stop, and says what the change does rather
than what it touches. Several of them add the reason after a comma, which is
worth copying when the reason is not obvious from the diff:

```
fix(hooks): pin the scope in a file, because an export cannot reach a hook
feat(scripts): close a mapped path on a request, not on a mention
docs: record that the recorder leaks a process per engagement
```

Match the surrounding style in whatever file you edit, even if you would write
it differently.

## No AI attribution

Commits, pull request titles and bodies, issues and code comments carry no
`Co-Authored-By` line for a model, no "generated with" footer and no session
link. The author is the person who opened the pull request. This holds however
the change was written.
