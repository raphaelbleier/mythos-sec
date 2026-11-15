# Contributing

Issues and pull requests are welcome. Mythos is research code for authorized
security testing, so a few rules are not negotiable.

## Opening a pull request

`main` is protected: it takes no direct pushes, and a pull request merges once
the `check` and `zizmor` jobs pass.

```bash
gh repo fork raphaelbleier/mythos-sec --clone
cd mythos-sec
git switch -c fix/scope-guard-port-list
# edit
bash scripts/selftest.sh
git commit -am 'fix(hooks): read a port list as a list without PyYAML'
git push -u origin HEAD
gh pr create
```

Branch names are not enforced. `fix/`, `feat/` or `docs/` plus a few words is
enough. One change per pull request; a diff that fixes a bug and reformats a
file next to it takes twice as long to review and is usually sent back.

`scripts/selftest.sh` must pass before you push. It is the same set of checks
`.github/workflows/check.yml` runs, so a failure locally is a failure in CI
roughly ten seconds earlier. The pull request template asks which checks you
ran; answer it honestly, including when you could not run the Docker ones.

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

**A new skill needs frontmatter and a registry entry.** `skills/<name>/SKILL.md`
opens with YAML frontmatter whose `name` is exactly the directory name and whose
`description` is a non-empty string. CI parses every one of them and fails the
run on a skill that does not load, which has happened for a single unquoted
colon in a description. The skill also needs an entry in `skills/registry.yaml`,
with the trigger that selects it and the `why` line a human reads when auditing
a plan. `scripts/triage` decides membership from `surface.json` and that file
alone, so a skill with no entry is never selected and a wrong trigger spends a
phase on a surface that is not there. Put the trigger on a signal the recon
output actually carries.

## Adding a lab target

A capability is only accepted once something in `lab/` seeds the vulnerability
it looks for. New targets are welcome and `lab/README.md` describes each one in
the same shape: what it is deliberately vulnerable to, the routes, and the
commands that reproduce the finding.

Three rules:

- **Bind loopback only.** Every published port in `lab/docker-compose.yml` goes
  through `"${MYTHOS_LAB_BIND:-127.0.0.1}:<host>:<container>"`. These are
  intentionally broken applications; a target that defaults to `0.0.0.0` is an
  open vulnerable host on whatever network the contributor is on.
- **Fake credentials carry the canary.** Every secret, token, key and password a
  target discloses is the single string `MYTHOS_LAB_CANARY`. A run can then grep
  for exactly one token to tell a real leak from the lab's, and nothing that
  looks like a plausible credential ends up in the repository.
- **Prefer the standard library.** Most of the targets are one `app.py` with no
  dependencies, so they also run on the host directly and the selftests do not
  need Docker. An upstream image is fine when the vulnerability is the point of
  that image, and then it is pinned by digest and left alone, see the comment in
  `.github/dependabot.yml`.

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

`cli/node_modules/` and `cli/dist/` are git-ignored. Node 22 or newer, Python
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

Two kinds of pull request are rejected on sight, whatever else they do well:

- One that weakens, bypasses or narrows the scope guard. That includes a code
  path that reaches the network without calling `hooks/scope-guard.py --check`
  through `cli/src/agent/guards.ts`, a loosened pattern, a default that turns
  enforcement down, and a command shape built to be invisible to the guard's
  parsing. If you found such a path by accident, that is a vulnerability in
  Mythos, and `SECURITY.md` says where it goes.
- One that adds a capability for destruction, brute force or denial of service.
  `hooks/budget-guard.py` refuses those and no scope rule turns that off. A
  change that removes a refusal, or that adds a tool whose purpose is to delete
  data, guess credentials at volume or exhaust a target, does not get merged.

This is not a style preference to be argued around. It is the premise the whole
project rests on.

## Engagement data

Everything under `engagements/` is git-ignored. Check twice that no scope file,
tool log, screenshot or finding from a real target ends up in a commit. The
same goes for the lab: commit the seeded vulnerability, not the output of a run
against someone else's host.

No pull request may contain a real target hostname, an engagement artifact or a
credential. Not in code, not in a test fixture, not in a comment, not in a
commit message, and not in the pull request body. The hosts in this repository
are `127.0.0.1`, the lab's service names, and names under `.invalid`, `.test`
or `.example`, which exist for exactly this. The repository has secret scanning
with push protection on, so a pushed key will be blocked rather than quietly
accepted, but that is a backstop and not the check. A diff that carries one of
these gets closed rather than amended, because the commit stays in the fork's
history either way.

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

The type decides the version, which is the other reason it has to be right.
`fix` is a patch, `feat` is a minor, and a `!` after the type or a
`BREAKING CHANGE:` footer is a major. The release notes are built from these
subjects, so a subject written loosely shows up in the next release as an
unsorted line.

## Releases

A release is one command, run on `main` with a clean tree:

```bash
# cli/package.json already carries the new version, committed and merged
git tag -a v0.3.0 -m 'v0.3.0'
git push origin v0.3.0
```

The tag triggers two workflows. `release` refuses the tag if it disagrees with
`cli/package.json`, runs the typecheck, the build and `scripts/selftest.sh`,
packs the CLI with its sha256, and opens the GitHub release with notes grouped
by Conventional Commit type. `toolbox` builds the `linux/amd64` and
`linux/arm64` images, merges the manifest list, signs it keylessly with cosign
and prints the digest for `toolbox/IMAGE_DIGEST` in the run summary.

Bump the version in `cli/package.json` in a normal pull request first. Tagging
a version the package does not claim fails the release before anything is
published.

## No AI attribution

Commits, pull request titles and bodies, issues and code comments carry no
`Co-Authored-By` line for a model, no "generated with" footer and no session
link. The author is the person who opened the pull request. This holds however
the change was written.
