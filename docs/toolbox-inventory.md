# Toolbox inventory — what ships, what is reachable, what is wired

Written 2026-11-15. Every statement here was checked against `toolbox/` and
against a locally built image (`docker build -t mythos-toolbox:before -f
toolbox/Dockerfile .`, then `command -v` for each name inside it), not against
the repo's own research notes. `docs/research/notes-2026-11-14/` contains
claims about this image that are wrong; so did `toolbox/tools.txt`,
`toolbox/Dockerfile` and three skills, and the corrections are below.

Reproduce the presence list:

```
docker build -t mythos-toolbox:check -f toolbox/Dockerfile .
docker run --rm --entrypoint bash mythos-toolbox:check -lc \
  'for t in <names>; do command -v "$t" >/dev/null && echo "PRESENT $t" || echo "ABSENT $t"; done'
```

`scripts/mythos tools` does the same for the running container.

## Inclusion criteria

A tool earns a place on the allowlist only if all four hold.

1. **It answers a question Mythos cannot already answer.** Not "it is popular",
   not "Kali ships it". A second content-discovery fuzzer answers ffuf's
   question again.
2. **Its output becomes candidates with an oracle.** A row has to say what
   would settle it. A wall of text that a model then summarises is worse than
   no tool, because the summary reads like a finding.
3. **It is non-destructive**, and non-destructive without needing a flag to be
   remembered.
4. **It can be capped, paced and scope-checked.** Every destination goes
   through `hooks/scope-guard.py` before the tool starts, and the request rate
   comes from `rules.rate_limit_rps`.

Excluded outright, whatever else they score:

- **Denial of service** — slowloris, slowhttptest, any flooder, and
  `graphql-cop`'s five DoS tests (which is why `scripts/apiproto` reimplements
  its eight information checks instead of shelling out).
- **Credential brute force against a live target** — hydra, patator, medusa,
  crowbar, and `jwt_tool -C -d <wordlist>`.
- **Mass scanning of address ranges** — masscan, `nmap` over a range, amass in
  active mode.
- **Detection evasion** — anything whose purpose is to look like something
  else.
- **Exploitation frameworks that fire payloads at a host** — metasploit,
  routersploit.

`hooks/scope-guard.py` refuses data destruction, brute force and denial of
service **in every mode**, and no `scope.yaml` rule overrides that. A tool that
cannot be used without one of those does not belong on the allowlist, and
`scripts/tools` makes that structural: no subcommand takes passthrough argv, so
those invocations cannot be expressed through it at all.

## List 1 — in the image, never invoked by any skill, script or prompt

Checked by grepping `skills/`, `scripts/`, `cli/src/prompts.ts` and
`cli/src/agent/tools.ts` for a command line, not for the word.

| tool | why it is there | verdict |
|---|---|---|
| `nmap` | apt core | **not invoked.** Named only in `skills/traffic` and `scripts/traffic` as a tool whose traffic the recording proxy cannot see. A web engagement does not need it; port state comes from `httpx`. Leave present, do not wire. |
| `nikto` | apt core | **not invoked**, and `skills/web-scan`'s own description promises it. Overlaps nuclei's templated scan almost entirely and its output is a wall of text with no oracle per line. Criterion 1 and 2 both fail. |
| `gobuster`, `wfuzz`, `dirb`, `dirsearch`, `feroxbuster` | apt | **not invoked.** Five more answers to ffuf's question. Criterion 1 fails for all five. `ffuf` is the one that is wired (`scripts/tools fuzz`). |
| `dotdotpwn` | apt optional | **not invoked.** Path traversal by brute force over a payload grid; `skills/web-scan` tests traversal with a handful of aimed requests, which is the same answer at 1/1000 the traffic. |
| `xsser` | apt optional | **not invoked.** `dalfox` is wired and better. |
| `sslscan`, `testssl` | apt optional | **not invoked.** A cipher-suite table is not a candidate list, and nuclei's `ssl` templates plus `scripts/takeover`'s certificate read cover what a web report cites. Criterion 2 fails. |
| `wpscan` | apt optional | **not invoked.** Without an API token it is version detection, which `whatweb` and `scripts/sbom` already do; with a token the vuln data is the token's, not the tool's. |
| `amass` | apt optional | **not invoked.** `subfinder` is wired (`scripts/tools hosts`), and amass's active mode is mass scanning. |
| `masscan` | apt optional | **not invoked and must not be.** Mass scanning of address ranges is excluded. |
| `hydra`, `john`, `hashcat` | apt optional | **not invoked and must not be.** Brute force, which the guard refuses in every mode. ~240 MB of image for nothing (`/usr/share/john` 81 MB, `/usr/share/hashcat` 33 MB, `/usr/share/pocl` 127 MB). First thing to drop. |
| `nbtscan`, `enum4linux` | apt optional | **not invoked.** SMB/NetBIOS enumeration in a web-app toolbox. |
| `msfconsole` | **unintended** — see the defects below | **not invoked and must not be.** Excluded outright. |
| `gf` | go, pinned | **not invoked.** Listed in the `toolbox` skill's belt and in `scripts/mythos`'s version check, called nowhere. It is a grep pattern bank with no patterns installed, so it would print nothing anyway. |
| `graphw00f` | git, pinned | invoked by `scripts/apiproto` — **not** in this list, listed here only because `skills/` never names it directly. |

Present and genuinely invoked: `nuclei`, `httpx`, `katana`, `subfinder`,
`ffuf`, `dalfox`, `sqlmap`, `commix`, `whatweb`, `wafw00f`, `arjun`,
`interactsh-client`, `gau`, `qsreplace`, `grpcurl`, `wcvs`, `jwt_tool`,
`smuggler.py`, `phpggc`, `ysoserial`, `graphw00f`, `graphql-cop`, `chromium`
(through Playwright, `CHROME_BIN`), `curl`, `jq`, `dig`.

## List 2 — invoked by the repo, not in the image (each one a bug)

| named by | tool | state |
|---|---|---|
| `skills/recon/SKILL.md` step 3 | `anew` | **was a live defect.** `gau ... \| anew engagements/<dir>/recon/urls.txt` with `\|\| true` on the end: `anew` is not in the image, so the pipeline failed, the `\|\| true` swallowed it, and the passive URL harvest silently wrote nothing. Fixed in place with `>>` plus `sort -u -o f f`. |
| `skills/toolbox/SKILL.md` tool belt | `waybackurls`, `gospider`, `anew` | **was a defect.** The catalogue a skill reads before picking a tool listed three that do not exist, and the last line offered `gau`↔`waybackurls` as an equivalence where only one side ships. Fixed: the belt now lists what the built image has, plus an explicit "not in the image" line. |
| `scripts/apiproto --schema` help, and three comments | InQL, Clairvoyance | **documented gap, not fixed.** The flag takes an introspection response "saved from InQL or Clairvoyance" and the image has neither, so an operator cannot produce the input the flag wants from inside Mythos. Evaluated and rejected below; `apiproto` already walks the suggestion channel itself. |
| five skills + `cli/src/agent/tools.ts` | `jwt_tool` | **present but broken.** It is in the image and crashed on every invocation. See the section below. |
| `skills/deep-server` step on deserialization | `ysoserial` | **present but broken.** The one chain the skill names (`URLDNS`) died with `InaccessibleObjectException` on this image's JDK. See below. |
| `skills/deep-server` tool table | `wcvs`, `smuggler.py`, `ysoserial`, `phpggc` | **was a defect of the opposite kind:** the table's "in the toolbox image?" column said **no** for all four and told the agent to `go install` and `git clone` them at run time, inside a container with a read-only repo mount. All four have shipped for releases. Fixed. |
| `skills/web-scan/SKILL.md` description | `nikto` | triage advertises nikto and the playbook body never runs it. Not fixed by adding nikto (it fails criteria 1 and 2) — recorded here as a description that overpromises. |
| `toolbox/requirements.in` comment | `paramspider` | correctly recorded as dropped; still named in no skill. No bug. |

## `jwt_tool` was broken in the image — the largest of these

Five skills (`auth-session`, `web-scan`, `exploit`, `cve-deep-dive`,
`toolbox`), `cli/src/agent/tools.ts` and `scripts/mythos`'s version check all
name `jwt_tool`. In the image as built on 2026-11-15 it **could not run at
all**:

```
$ scripts/mythos jwt_tool eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.
No config file yet created.
Running config setup.
configparser.InvalidWriteError: Cannot write key # To disable the proxy option
set this value to: False (no quotes). ... ; contains delimiter :
```

jwt_tool stores its inline *comments* as configparser keys
(`allow_no_value=True`), and those comment strings contain `:`. Python 3.14's
`configparser.write()` now refuses a key containing a delimiter, so
`createConfig()` raised on the first invocation — which is every fresh
container, because the config lives in `~/.jwt_tool`. Worse, the partial file
it left behind was missing its `[argvals]` section, so the *second* call died
with `KeyError('argvals')`. The tool was unusable in both directions.

Fixed in `toolbox/Dockerfile`: the parser is built with `=` as its only
delimiter (`sed`, one line, at the pinned commit), and the config is then
generated at build time with a real token, because `createConfig()` ends in
`exit(1)` and a `--help` run never reaches it (argparse exits first). The step
asserts the file exists and that a second decode prints `alg`, so a future base
image cannot reintroduce this silently. `proxy` is also rewritten from
`127.0.0.1:8080` to `False`, so jwt_tool stops pointing at a proxy that is not
there and falls back to the `HTTP(S)_PROXY` variables `scripts/mythos` injects
— which is where Mythos wants its traffic recorded.

## `ysoserial` could not generate a payload either

`skills/deep-server` tells the agent to confirm deserialization with
`ysoserial URLDNS` — a DNS lookup, no code execution, the one chain that is
safe to send. In the image as built:

```
$ scripts/mythos ysoserial URLDNS 'http://x.oast.fun/'
Error while generating or serializing payload
java.lang.reflect.InaccessibleObjectException: Unable to make field private int
java.net.URL.hashCode accessible: module java.base does not "opens java.net"
to unnamed module
```

ysoserial builds its chains by reflecting into `java.base` internals, which the
module system has closed since JDK 16. The wrapper was `java -jar
ysoserial-all.jar`, with none of the `--add-opens` ysoserial's own README
requires, so on this image's JRE most chains — URLDNS included — produced
nothing. Fixed: the opens list is an `ENV` and the wrapper passes it, and the
build now asserts `ysoserial URLDNS` emits bytes, so a JRE bump cannot
reintroduce it quietly.

## Two tools that ran and silently did nothing

Both were found by running them, not by reading them, and neither would ever
have shown up as an error.

1. **`crlfuzz -u <URL>` ignored `-u` through `scripts/mythos`.** crlfuzz's
   usage is `[buffers] | crlfuzz [options]`: when stdin is a pipe it reads its
   URL list from stdin instead. Every exec through `scripts/mythos` is
   `docker exec -i`, so stdin is always a pipe — crlfuzz read an empty list,
   sent nothing, and exited 0 with no output against an endpoint that is
   plainly vulnerable. `scripts/tools crlf` redirects `< /dev/null`. Anything
   else wired through `scripts/mythos` that takes its target on the command
   line *and* accepts a stdin list has the same trap.
2. **`jwt_tool -M pb` needs `-cv` and `-rh`, or it does nothing.** Without
   `-rh` it reports "No substitution occurred" and scans zero of its thirty
   checks. With `-rh` but no canary, its prescan cannot tell an authenticated
   response from an anonymous one, stops, and asks a yes/no question **on
   stdin** — in a non-interactive exec that is `EOFError` mid-scan.
   `scripts/tools jwt --target` therefore requires `--canary` and says why.

## Three more defects found in `toolbox/` itself

1. **`INSTALL_METASPLOIT` is a no-op.** `commix` is in the best-effort apt list
   and `commix` *Depends on* `metasploit-framework`, so metasploit 6.5.7
   (654 MB in `/usr/share/metasploit-framework` alone) is installed in **every**
   image and `msfconsole` is on `PATH` by default. The Dockerfile header said
   "Metasploit is opt-in (large)". Verified with
   `apt-cache rdepends --installed metasploit-framework`. Comment corrected; the
   dependency is left alone because `commix` *is* invoked (`skills/exploit`,
   `skills/cve-deep-dive`), so removing metasploit means removing commix.
2. **`testssl.sh` does install.** The Dockerfile said "(testssl.sh is today)"
   as the example of a name missing from the Kali snapshot, and `tools.txt`
   repeated it. It installs, and ships the binary as `testssl`, not
   `testssl.sh` — so a `command -v testssl.sh` check reports it missing and a
   `command -v testssl` check does not. Both comments corrected.
3. **`wafw00f` is pip, not apt.** `tools.txt` listed it among the apt packages.
   It comes from `requirements.in`. Corrected.

## What was wired, and why

One normalizing wrapper, `scripts/tools`, with a subcommand per tool. It checks
every destination against `scope.yaml` before the tool starts, derives the
tool's own rate flag from `rules.rate_limit_rps`, caps whatever is cappable,
runs the tool through `scripts/mythos` (so the exec is audited and the
recording proxy sees the wire bytes), parses the output into rows with a
verdict and an oracle, and writes the exact command plus the tool's raw output
into the engagement directory. No verdict it writes is ever `confirmed`.

| subcommand | tool | the question nothing else answered | cap and pacing |
|---|---|---|---|
| `fuzz` | ffuf (already present) | — it was already accepted in recon, but **uncapped**: the recon playbook used `raft-medium-directories` (30k entries) with `-t 40` and no `-rate` at all | `-n` entries (default 300) by cutting the wordlist, `-rate` and `-t` from `rules.rate_limit_rps`, `-maxtime` |
| `params` | arjun (already present) | which unlinked parameters the app reacts to | `-n` names (default 300), arjun's `--rate-limit` from scope, `-t` capped at 10 |
| `crlf` | **crlfuzz v1.4.1 (new)** | CRLF / response-header injection. dalfox does XSS, nuclei has templates for known CRLF CVEs; neither fuzzes the class, and `skills/web-scan` tested it one param at a time by hand | concurrency from scope. crlfuzz has **no** requests-per-second flag — stated in `--help` rather than pretended away |
| `jwt` | jwt_tool (already present) | reachable, but only as raw `scripts/mythos jwt_tool`: unpaced, and one `-C -d` away from brute force | offline by default (no request at all); `--target` is scope-gated and `-rt` = rps × 60 (jwt_tool's rate is per *minute*). Cracking is unreachable: no passthrough argv |
| `secrets` | **gitleaks v8.30.1 (new)** | provider-format secrets in a tree already fetched. `scripts/sourcemap` has **one** regex (`name = "value"`); gitleaks has ~170 provider rules plus entropy, and `--history` reads what the working tree no longer shows | nothing to pace: it reads files and sends nothing |
| `gadget` | ysoserial + phpggc (already present) | which gadget chains this image can build, offline. `skills/deep-server` said both were **not** in the image and told the agent to install them at run time — and ysoserial could not generate a chain at all (see above) | nothing to pace. A `File delete` chain and a destructive `--cmd` exit 3 |
| `hosts` | subfinder (already present) | the hard rule: a discovered name is **not** in scope by discovery. `skills/recon` ran subfinder and piped the result straight into httpx | every name comes back `in_scope: false` unless `scope.yaml` already lists it; no flag widens scope; nothing here sends traffic to a discovered name |

### Rejected, with the reason

- **clairvoyance** — its one capability is walking a GraphQL "Did you mean"
  suggestion channel with a wordlist, and `scripts/apiproto` already implements
  that natively (`field_suggestions`, `SUGGEST_WORDS`); the gap is a bigger
  wordlist, not a missing tool. It also requires the PyPI `asyncio` 3.4.3
  backport, which installs a top-level `asyncio` module that shadows the
  stdlib's in the toolbox's Python. Criterion 1 fails, and the dependency is a
  footgun.
- **InQL** — the same question as clairvoyance; its value is the Burp GUI.
- **kiterunner** — the tool is small, the value is in the kitebuilder route
  wordlists, which are gigabytes. `scripts/tools fuzz -w` with a seclists API
  wordlist answers most of it at no image cost.
- **trufflehog** — overlaps gitleaks, and the one thing it adds is live
  credential verification against the provider, which contacts hosts
  `scope.yaml` never authorized and which `skills/source-review` forbids
  (`rules.allow_secret_verification` stays false). Rejecting it is the policy,
  not a size argument.
- **semgrep** — re-checked, still out. It dominated the image size, and
  `skills/source-review` reads the tree with `scripts/sourcemap` rather than a
  SAST engine, so nothing would call it.
- **retire.js** — `scripts/sbom` already inventories served JavaScript
  libraries with a confidence per marker and hands them to `scripts/cvefeed`
  for KEV/EPSS/NVD/GHSA/OSV ranking. retire.js answers the same question with
  less evidence.
- **testssl.sh / sslyze** — testssl.sh is *already in the image* and still not
  worth wiring: criterion 2. A cipher table is not a candidate list.
- **nikto** — criteria 1 and 2.
- **wpscan, droopescan, CMSeeK** — version detection Mythos already does.
- **XSStrike** — dalfox.
- **h2csmuggler** — a real gap (h2c upgrade smuggling, distinct from
  `smuggler.py`), but it is a Python script needing a new pip dependency
  (`h2`), and the pip belt is `--require-hashes` compiled. Not worth the chain
  for one narrow class; revisit if an engagement needs it.
- **gopherus** — its interface is an interactive menu, with no documented
  non-interactive flags, so there is nothing to wrap without patching it. Not
  verified against the tool itself (it is not in the image); if that is wrong
  it is worth a second look, because the question it answers — an SSRF payload
  for gopher/redis/fastcgi — is one `scripts/ssrfprobe` does not.
- **dnsx, tlsx, naabu** — resolution and certificate reads the stdlib and
  `scripts/takeover` already do; naabu is port scanning.
- **hydra, patator, medusa, slowloris, slowhttptest, routersploit,
  metasploit** — excluded by the rules above, not by judgement.

## One more policy defect, in a skill rather than the image

`skills/web-scan/SKILL.md` step 5 told the agent, by path:

```
weak secret: jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
```

That is credential brute force with a named wordlist, in a skill that triage
selects for **every** target (`always: true`). `hooks/scope-guard.py` refuses
brute force in every mode and no `scope.yaml` rule overrides it, so the
instruction asked for something the framework is built to stop. Removed, with
the reason written in its place, and `scripts/tools jwt` cannot express it
either — no subcommand takes passthrough argv.

It was the only one: nothing else under `skills/` or in `cli/src/prompts.ts`
names rockyou, `-C -d`, hydra or hashcat.

## Image size

| | size |
|---|---|
| before (`mythos-toolbox:before`, unchanged `toolbox/`) | **10.9 GB** |
| after (crlfuzz + gitleaks) | **11.0 GB** as docker reports it; the real delta is two static Go binaries, ~34 MB. The jwt_tool and ysoserial fixes add a `sed`, a config directory and an `ENV`: a few KB. |

The additions are noise. What is not noise, if the image has to shrink:

| drop | saves | cost |
|---|---|---|
| `john`, `hashcat` and `pocl` (the OpenCL runtime hashcat pulls) | ~240 MB | nothing. Brute force is refused in every mode; nothing invokes them. |
| `commix`, which drops `metasploit-framework` with it | ~654 MB + ruby | `skills/exploit` and `skills/cve-deep-dive` invoke commix. Worth proposing: sqlmap plus the aimed command-injection payloads in `skills/web-scan` cover most of it. |
| `mingw-w64` (pulled in by something in the extras) | ~85 MB | nothing in a web toolbox. |
| `seclists` down to the `Discovery/Web-Content` and `Fuzzing` subtrees | ~1.5 GB of 1.9 GB | the wrapper's default wordlist and most of what skills name live under those two. |

That is ~2.5 GB available before touching anything the framework calls.

## Fixtures and the selftest

`tests/fixtures/tools/` holds the bytes each tool actually printed; the command
that produced each file, and the two flags that are load-bearing, are in
`tests/fixtures/tools/PROVENANCE.md`.

`scripts/tools selftest` asserts the parsers against those fixtures, plus the
scope reader, the pacing and the refusals, plus two live asserts that need no
container (an unauthorized destination exits 3 before any tool starts; the
offline JWT decode runs with nothing installed).

`scripts/tools selftest --live` additionally runs **every** wired tool through
the wrapper against a loopback server the selftest starts itself — no lab
container, no network. It needs the toolbox image, which is why it is behind a
flag and why CI runs the offline half.

Each assert was verified to fail when its parser is broken. Breaking
`SENSITIVE`, arjun's key lookup, the crlfuzz variant collapse, the gitleaks
redaction, the phpggc destructive-type flag, the ysoserial table regex, the
jwt canary pairing or the `hosts` scope check each produced at least one
`FAIL` line. The jwt one is the interesting case: changing
`if attack and r["canary"]` to `if attack` makes a line reading
`Exploit: Blank password accepted in signature ... Response Code: 401` into a
candidate, and the assert catches exactly that.
