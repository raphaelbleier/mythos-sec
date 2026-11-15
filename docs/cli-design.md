# The command line

Why `mythos` behaves the way it does at the terminal. Decisions, each with the rule
it came from, and — more usefully — the handful of places where this tool
deliberately does not do what the guidelines say, with the reason.

Sources: [clig.dev](https://clig.dev), the GNU coding standards' user-interface
chapter (`--help`, `--version`, long options paired with short ones, `--`),
POSIX's utility argument syntax, [no-color.org](https://no-color.org) with the
`CLICOLOR`/`CLICOLOR_FORCE` and `FORCE_COLOR` conventions around it, and Ink's
own notes on non-interactive output.

The code that implements all of it: `cli/src/index.ts` (flags, commands, errors,
exit codes), `cli/src/plain.ts` (the line logger), `cli/src/tui/theme.ts` (the
colour and glyph decisions), `cli/src/tui/app.tsx` (the full-screen view).
`cli/src/selftest.ts` has a check for each rule below that can be checked
headlessly.

---

## 1. Streams

| Stream | What is on it |
|---|---|
| stdout | the answer: the ledger, the provider list, the doctor table, the JSON document, the live view |
| stderr | the narration: errors, warnings, the banner, progress when `--json` is on |

clig.dev, "the basics": *send output to stdout, send messaging to stderr*. The
split matters here because every structured command has a `--json` form, and
`mythos ... --json > run.json` has to produce a file that a parser can read with
nothing else in it. So `--json` moves **all** human text to stderr — banner,
per-event lines, phase table — and writes exactly one JSON document to stdout.
The selftest asserts that `providers --json` parses and contains no prose and no
escape sequences, because this is the kind of thing that breaks silently.

A failure says nothing on stdout at all. A script that does
`mythos verdicts --json | jq` and gets an empty stdout plus a non-zero exit knows
what happened; one that gets half a sentence does not.

## 2. Exit codes

| Code | Meaning |
|---|---|
| 0 | the work finished and came out clean |
| 1 | it ran and did not: a phase `incomplete` or `failed`, a doctor check that failed, an engagement with no ledger |
| 2 | usage or configuration: a bad flag, a missing credential, a confirmation that could not be asked — **nothing ran** |
| 130 | interrupted (128 + SIGINT) |

0 and 1 are what the repository already meant by them and were not
reinterpreted: the driver's `ok` (every phase `done` or `pending`) still decides
between them, so a wrapper that treats 1 as "did not finish cleanly" keeps
working. 2 is the GNU/POSIX habit for an invocation that never started, and
keeping it apart from 1 is the entire point: **a CI step may retry a 1 and must
never retry a 2.** They are in `EXIT` in `cli/src/index.ts` so there is one place
to read them, and in `mythos --help`.

Findings do not change the exit code. A clean run that found eleven criticals
exits 0, because the question the shell asked was whether the engagement
completed, and `mythos verdicts --json` answers the other one.

## 3. Flags and arguments

- **Every short flag has a long twin** (GNU: *define long-named options
  equivalent to the single-letter options*). The table is `COMMON` + `RUN_FLAGS`
  in `index.ts`, which is also what generates the help, so the two cannot drift.
- **Standard names** (clig.dev: *use standard names for flags, if there is a
  standard*): `-h/--help`, `-V/--version`, `-q/--quiet`, `-v/--verbose`,
  `--json`, `--no-input`, `--no-color`, `-y/--yes`. `-v` is verbose and `-V` is
  version, never both, which clig.dev calls out by name.
- **`--` ends the options** (POSIX), so a target or a path may begin with a dash.
- `--flag=value` and `--flag value` are the same. An option's value may itself
  begin with a dash, which is why a value-taking flag always consumes the next
  argument instead of guessing from its shape — a missing value is an error
  (`--budget needs a value`), not a silent `true`.
- Short flags cluster, and **only the last in a cluster may take a value**
  (POSIX). `-nq` works; `-tn <url>` is an error that says why.
- **An unknown flag is an error**, never a silent no-op. A typo in `--skip` is
  exactly the kind of mistake that runs a phase the operator thought they had
  turned off. A flag that belongs to another command says so by name:
  `--headed is a flag of 'mythos run', not of 'mythos doctor'`.
- **`--quiet` and `--verbose` compose** rather than conflict: one step down, one
  step up, so `-qv` is simply the default. Level 0 still prints every finding,
  every refusal and the run's verdict — what a later reader must act on — and
  drops only the step-by-step.
- **`--json` is refused where there is no document** (`mythos demo --json`)
  rather than accepted and ignored.
- `--no-color` is both a flag and the only thing that outranks `FORCE_COLOR`
  apart from `NO_COLOR`.

## 4. Help

- `--help` and `-h` work **wherever they appear**, as do `--version` and `-V`
  (clig.dev: *help should be shown regardless of whether other arguments and
  flags are set*).
- **Every subcommand has its own page**: synopsis, a paragraph of what it
  actually does, its flags, **the environment variables it reads**, and
  examples. `mythos run --help` and `mythos help run` are the same page.
- **Concise by default.** `mythos` with no arguments prints six lines and exit 0:
  a description, two examples and `mythos --help`. clig.dev asks for exactly
  this; the full page is four screens and scrolling it away does not answer
  "what is this".
- **Examples lead** (clig.dev: *lead with examples*) and each command's examples
  are real commands, including the piped and `--json` forms.
- `mythos help` and `mythos help <command>` exist because clig.dev notes that
  git-like tools should answer `help` as a subcommand, not only as a flag.
- `--version` follows GNU: the first line is `mythos 0.1.0` — easy to parse, the
  version after the last space — then licence and the node/platform a bug report
  needs.
- The help is **plain text with no escape sequences**, so `mythos --help | less`
  and `mythos --help > help.txt` are readable.

## 5. Errors

Every failure a user can cause goes through one function, and says three things
in this order:

```
mythos: no scope file, and example.com is not a loopback target
  while generating the authorization boundary for a remote host
  next: mythos -t https://example.com --yes  if you are authorized to test example.com
    or: mythos -t https://example.com -s <scope.yaml>  to pass a boundary you wrote
```

What happened, what mythos was doing when it happened, and the one command that
fixes it. The next action is **last** because clig.dev says to *consider where the
user will look first — put the most important information last*, and it is the
only line that is a command, so it is the only line that can be pasted.

An error that is *not* the user's fault keeps its stack and says so
(`internal error — … This is a bug in mythos 0.1.0`), which is clig.dev's rule
for the unexpected: *provide debug and traceback information* and where to report
it. Everything else is rewritten for a human. `mythos doctor` prints a `fix:`
line under each failed check, which is the same idea applied to preconditions.

## 6. Colour, glyphs and non-terminals

`colourEnabled()` in `cli/src/tui/theme.ts` decides, highest precedence first:

1. `--no-color`, and `MYTHOS_THEME=mono` — a flag beats the environment
   (clig.dev's precedence ladder; no-color.org also allows a program's own
   configuration to override it).
2. `NO_COLOR` set to anything non-empty. no-color.org is explicit that the value
   does not matter and that an empty string is not "set".
3. `FORCE_COLOR` / `CLICOLOR_FORCE` — colour even into a pipe. `FORCE_COLOR=0`
   and `false` mean the opposite, which is how Node and chalk read them.
4. `TERM=dumb`, `CLICOLOR=0`.
5. Otherwise: **is this stream a terminal?** Checked per stream, not once per
   process, because with `--json` the narration goes to stderr and may be a
   terminal while stdout is a file.

Before this, the banner wrote 24-bit escapes into any pipe that was not
`NO_COLOR`; `mythos … -n > run.log` put `^[[38;2;109;148;196m` in the first line
of the log. Fixed, and the selftest fails if it comes back.

Glyphs degrade separately from colour. `MYTHOS_GLYPHS=ascii` forces the ASCII
set, and otherwise the locale decides, because a terminal without UTF-8 renders
a status column of `✔ ✖ ⛔` as a column of boxes. The ellipsis and the em dash are
part of that set now, so a truncated line in a latin-1 terminal ends in `...`.

The full-screen view needs a terminal to redraw, so it is used only when stdout
is a TTY, `--no-tui` was not passed and `--json` was not passed; otherwise the
line logger takes over **unasked**. clig.dev: *if stdout is not an interactive
terminal, don't display any animations*.

## 7. Progress, and what survives the screen

Every line the line logger prints carries a local-time stamp and names its
phase, so the log reads the same an hour later in a CI transcript as it does
live. The view's feed does not have that luxury — it is a redrawn region — so
the rule is that **nothing the operator needs later exists only on screen**:

- the bus appends every event to `run-events.jsonl` in the engagement directory,
  whichever renderer is attached;
- when the view comes down, the phase table, the engagement directory, the
  report path and the events path are printed to the scrollback — previously the
  phase table was printed only in `-n` mode;
- `mythos verdicts` re-reads the ledger from disk at any time.

## 8. Interactivity

There is one prompt in the whole tool, and it is new. clig.dev's rule for a
severe action is a typed confirmation or a confirmation flag; its rule for
automation is that *a prompt is never required*. Both apply to the same moment:

**Generating a scope file for a host that is not loopback.** With `--scope`, a
human wrote the authorization boundary. With a loopback target, it is a lab. The
remaining case — `mythos -t https://something` with no scope file — is the only
point where nothing human has yet said that this target may be tested, and a
mistyped `-t` would otherwise start an unattended engagement against a stranger.
So:

- `--yes` answers it in advance;
- `--no-input`, or a stdin that is not a terminal, makes it an **error that names
  `--yes`** rather than a prompt (clig.dev: *if `--no-input` is passed, fail with
  instructions for passing the needed flags*);
- on a terminal it asks for the hostname to be typed, which is clig.dev's
  "severe" tier;
- a loopback target never sees any of it, so the lab workflow is unchanged.

`mythos login openrouter` is the other thing that needs a human: it opens a
browser and waits for a callback. It now refuses to start when stdin is not a
terminal or `--no-input` was passed, and names `--api-key` and the provider's
environment variable instead.

Nothing during a run asks anything, which is the repository's own promise and is
not a guideline question.

## 9. Configuration precedence

clig.dev's ladder is flags, then environment, then project config, then user
config, then system config. Mythos uses four rungs of it and the code already
read in that order:

```
--profile  >  MYTHOS_PROFILE  >  models.json default_profile  >  built-in default
--base-url >  MYTHOS_BASE_URL >  the provider's own baseURL
```

`models.json` in the repository root is the project config: version-controlled,
command-specific, shared by everyone working on that checkout, which is what
clig.dev says a project-level config file should be.

**There is deliberately no user-level config file.** A per-user default for
`--target`, `--skip` or `--rps` would mean a run whose scope depends on a file
nobody reads during review, and the flags that matter here are the ones that
decide what gets attacked. Credentials are the exception and live under
`$XDG_STATE_HOME/mythos` (clig.dev: *follow the XDG spec*), overridable with
`MYTHOS_HOME`.

Secrets: `--api-key` exists because providers hand out keys and people paste
them, but clig.dev is right that a flag leaks into the process list and the shell
history, so `mythos login --help` says so and points at the environment
variable, and the provider's `envKeys` are read before any stored credential.

## 10. Deliberately not adopted

- **`noun verb` subcommands.** clig.dev prefers `mythos engagement run` over
  `mythos run`. The commands here are one level deep and single words
  (`doctor`, `providers`, `verdicts`), which the rule is not really aimed at, and
  renaming them would break the README, `AGENTS.md`, the docs and every wrapper
  anyone has written. Kept. The rule does bind anything added later: a second
  level must be `noun verb`.
- **A pager.** clig.dev suggests paging long output. `mythos verdicts` on a large
  engagement is long, but the thing an operator does with it is pipe it, and a
  pager that engages on a TTY and not on a pipe is one more difference between
  what they saw and what they saved. `| less` is theirs to add.
- **Prompting for missing arguments.** clig.dev suggests prompting for a missing
  flag. Not for `--target`: the target is the one argument where a helpful guess
  is a request sent to someone who did not consent. A missing target is an error
  that names the flag.
- **Treating a bare first argument as the target.** `mythos example.com` is an
  error, not a run, because clig.dev warns against a catch-all first argument
  and because `mythos stage` silently probing `http://stage` is worse than any
  error message. The error does suggest `mythos -t example.com`.
- **`--plain`.** clig.dev offers it where human output breaks machine output.
  `-n` already is that mode and `--json` covers the rest; a third output format
  would be a third thing to keep consistent.
- **Analytics, update checks, a crash reporter.** None, and none planned. This
  tool runs with the operator's credentials against someone else's systems.
- **`-v` for version.** `-v` is verbose. `-V` is version. clig.dev calls the
  overload out and the repo already used `-v` for verbose.

## 11. The view

Built for 80 columns and degrading from there, which is the floor clig.dev's
"increase information density" advice is worth having at all:

- no artificial minimum width any more — pretending a 50-column terminal was 64
  wide wrapped every row and cost two lines each;
- below 72 columns the budget bars and the `MYTHOS ·` prefix go, and the findings
  and guard rows collapse to one flat line each, because flex children in a
  50-column row get shrunk a word at a time (`1 scop, 0 budge, 1 refuse`);
- the gate — what each phase must produce to count as done, from the table in
  `AGENTS.md` — is shown for the running phase at 100 columns and up;
- the phase rail lists **all six** phases. It listed four, so `triage` and
  `validate` — the phase that decides what gets tested and the phase that decides
  what counts as confirmed — had no row and no bar;
- the endpoint counts follow the ledger: a candidate that `validate` later
  confirms is counted once, not twice;
- `?` toggles a line explaining the keys;
- a second `q` or ctrl-c exits now. Ink holds stdin in raw mode, so ctrl-c never
  becomes a SIGINT and the driver's "signal again to exit now" path was
  unreachable from the view — an operator whose model call was hanging had no way
  out of their own terminal;
- the cursor is restored on the way out whatever the reason, including the hard
  second-signal exit. A terminal left without a cursor is the one piece of
  lasting damage a CLI can do to the shell that ran it.

The palette and the wordmark in `theme.ts` and `banner.ts` are unchanged.
