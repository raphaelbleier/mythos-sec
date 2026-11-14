#!/usr/bin/env python3
"""Mythos budget guard — PreToolUse hook.

Two of the rules the scope file prints were enforced by nothing at all: an
engagement could exceed `rate_limit_rps`, and it could brute-force or destroy
data while the prompt said not to. A prompt rule did not prevent the DVGA
incident, where a run deleted another user's paste and overwrote a second
one's title. This is the code-level version.

There is deliberately no request cap and no exploitation gate. Mythos is a
pentesting suite for bug bounty of every kind: exploitation is the work, not
an exception to it, and a volume ceiling only ever stops the run before the
finding. What a program forbids is surfaced as a warning and left to the
operator's judgement.

What it does, per tool call:

  rate limit     A batch tool (nuclei, ffuf, sqlmap, ...) must carry its own
                 pacing flag, at or under `rules.rate_limit_rps`. The hook
                 cannot pace a tool's internal loop from outside, so it checks
                 that the tool was told to pace itself and says which flag to
                 add. Single-shot calls (curl, WebFetch) are paced here, by
                 sleeping on a token bucket kept in the engagement directory.

  exploitation   Allowed by default, because that is the job. An explicit
                 `rules.allow_exploit: false` means the program forbids
                 proof-of-concept exploitation, so the hook says so once and
                 lets the call through. Honoring it is the operator's call,
                 not the hook's.

  non-destructive
                 Data destruction, brute force and denial of service are
                 refused outright, in every mode. This is not a scope question
                 and it is not negotiable by a flag: the framework's single
                 safety promise is that it does not break the target.
                 MYTHOS_DESTRUCTIVE=warn downgrades it for a lab run.

Modes: MYTHOS_BUDGET_ENFORCE picks `block` (default), `warn` or `off` for the
rate check. The destructive denylist has its own switch, MYTHOS_DESTRUCTIVE,
and also defaults to blocking. Unlike the scope guard, blocking here is the
default, because exceeding a program's rate limit or destroying data is not
something you want to learn about after the request went out.

  python3 hooks/budget-guard.py --check '<command>'

prints the decision as JSON and always exits 0, for the OpenCode plugin.
`--selftest` runs the asserts and needs no network.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

# Tools that send many requests from one invocation, with the flag that paces
# them and an honest over-estimate of what one default invocation costs. The
# estimate only has to be the right order of magnitude: it protects a budget,
# it is not a measurement.
BATCH_TOOLS = {
    "nuclei":       {"flags": ["-rate-limit", "-rl"], "estimate": 2000},
    "ffuf":         {"flags": ["-rate"], "estimate": 5000},
    "feroxbuster":  {"flags": ["--rate-limit"], "estimate": 5000},
    "gobuster":     {"flags": ["--delay"], "estimate": 5000},
    "dirb":         {"flags": ["-z"], "estimate": 5000},
    "dirsearch":    {"flags": ["--max-rate"], "estimate": 5000},
    "sqlmap":       {"flags": ["--delay", "--time-sec"], "estimate": 1500},
    "dalfox":       {"flags": ["--delay"], "estimate": 1000},
    "arjun":        {"flags": ["-d", "--delay"], "estimate": 500},
    "wfuzz":        {"flags": ["-s"], "estimate": 5000},
    "wpscan":       {"flags": ["--throttle"], "estimate": 1000},
    "nikto":        {"flags": ["-Pause"], "estimate": 2000},
    "httpx":        {"flags": ["-rate-limit", "-rl"], "estimate": 200},
    "katana":       {"flags": ["-rate-limit", "-rl"], "estimate": 500},
    "subfinder":    {"flags": ["-rate-limit", "-rl"], "estimate": 100},
    "amass":        {"flags": ["-max-dns-queries"], "estimate": 500},
    "nmap":         {"flags": ["--max-rate", "-T"], "estimate": 1000},
    "masscan":      {"flags": ["--rate"], "estimate": 5000},
    "wcvs":         {"flags": ["--delay"], "estimate": 500},
    "smuggler":     {"flags": [], "estimate": 100},
    "graphw00f":    {"flags": [], "estimate": 50},
    "wafw00f":      {"flags": [], "estimate": 50},
}
SINGLE_SHOT = {"curl", "wget", "http", "https", "httpie"}

# Destroying data, locking accounts and knocking a service over. Refused in
# every mode: no engagement rule makes these acceptable.
DESTRUCTIVE = [
    (re.compile(r"\bsqlmap\b.*--(dump\b|dump-all|os-shell|os-pwn|os-cmd|"
                r"sql-shell|file-write|priv-esc)"),
     "sqlmap data extraction or shell: dumps the database or executes commands"),
    (re.compile(r"\b(hydra|medusa|patator|ncrack|crowbar|thc-hydra)\b"),
     "credential brute force: locks accounts and is forbidden by the rules"),
    (re.compile(r"\bwpscan\b.*(--passwords|--usernames\s+\S+\s+--passwords)"),
     "wpscan password brute force"),
    (re.compile(r"\b(slowhttptest|slowloris|hping3|t50|torshammer|goldeneye)\b"),
     "denial of service tool"),
    (re.compile(r"\b(ab|siege|wrk|vegeta|bombardier|k6)\b\s+.*-(n|c|t)\s*\d"),
     "load generator: a denial-of-service test in all but name"),
    (re.compile(r"\bnuclei\b.*-(tags|t)\s+\S*\bdos\b"),
     "nuclei denial-of-service templates"),
    (re.compile(r"\bnmap\b.*--script[= ]\S*\b(dos|brute|exploit)\b"),
     "nmap intrusive script category (dos, brute or exploit)"),
    (re.compile(r"\bcurl\b(?=(?:[^|;]*\s)?)[^|;]*\s-X\s*['\"]?DELETE\b", re.I),
     "HTTP DELETE: destroys target data. Prove the access-control flaw with a "
     "read, or create your own object and delete that one"),
    (re.compile(r"\bcurl\b[^|;]*\s-X\s*['\"]?(TRACE|CONNECT)\b", re.I),
     "HTTP TRACE/CONNECT via curl: use a dedicated differential probe instead"),
    (re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
     "fork bomb"),
    # Mass destruction expressed as an operation name rather than a command
    # shape. The denylist above reads the shell: it caught `curl -X DELETE` and
    # sqlmap --dump and missed `{deleteAllPastes}` in a GraphQL body, which a
    # real run then executed against a live target and emptied its table. These
    # names have no scoped, self-owned-object reading: there is no version of
    # deleteAll or dropDatabase that touches only what the tester created.
    (re.compile(r"\b(deleteAll\w*|removeAll\w*|purgeAll\w*|destroyAll\w*|"
                r"truncate(?:Table|All)?\w*|dropDatabase|dropCollection|dropTable|"
                r"resetDatabase|reset_?db|wipe(?:All|Database|Data)?\w*|"
                r"deleteEverything|clearAll\w*|flushAll|factoryReset)\b", re.I),
     "an operation that destroys every record, not one you created. Prove the "
     "authorization flaw on an object you made yourself, and report the "
     "mass-destruction endpoint as reachable without exercising it"),
    (re.compile(r"\b(DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|"
                r"DELETE\s+FROM\s+\w+\s*(?:;|$))", re.I),
     "unbounded SQL deletion"),
]

# Destructive-looking operations that DO have a legitimate scoped use: deleting
# the object you just created is how an access-control finding gets proven
# without touching anyone else's data. These warn rather than refuse, because
# refusing them would block the non-destructive proof the rules ask for.
DESTRUCTIVE_SCOPED = re.compile(
    r"\b(delete\w+|remove\w+|destroy\w+|revoke\w+|deactivate\w+|"
    r"cancel\w+|refund\w+|transfer\w+)\s*\(", re.I)

# Exploitation, as distinct from active scanning. Gated on rules.allow_exploit.
EXPLOIT_TOOLS = re.compile(
    r"\b(msfconsole|msfvenom|metasploit|ysoserial|phpggc|marshalsec|"
    r"commix|tplmap|xsser|beef|responder|evil-winrm|impacket-\w+)\b")
# sqlmap below --dump is still exploitation once it goes past detection.
EXPLOIT_FLAGS = re.compile(r"\bsqlmap\b.*--(technique|risk\s*[=\s]*[23]|level\s*[=\s]*[45])")

URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"<>|;`)]+")
MAX_SLEEP = 30.0
# `scripts/traffic exec -- curl ...`: the form that sends through the engagement's recording proxy.
TRAFFIC_EXEC = re.compile(r"scripts/traffic\s+(?:--dir\s+\S+\s+)?exec\b")


def _segments(command: str) -> list[str]:
    """One shell command per entry, so a rule names the line it matched.

    Splits on newlines and on the operators that separate commands, keeping it
    deliberately crude: this is for attributing a match to a line, not for
    parsing shell. A quoted semicolon inside a payload will split a segment,
    which costs nothing because both halves are still checked.
    """
    parts = re.split(r"\n|;|&&|\|\||\|", command)
    return [p for p in (x.strip() for x in parts) if p]


def _scope_file() -> Path | None:
    path = os.environ.get("MYTHOS_SCOPE")
    if path:
        p = Path(path)
        return p if p.exists() else None
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    candidates = list(root.glob("engagements/*/scope.yaml"))
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def load_rules():
    """The engagement's rules, or None when there is no active scope."""
    scope_file = _scope_file()
    if not scope_file:
        return None
    text = scope_file.read_text(encoding="utf-8", errors="replace")
    rules = {}
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text) or {}
        rules = data.get("rules") or {}
        if not isinstance(rules, dict):
            rules = {}
    except Exception:
        # minimal fallback: scalar keys under rules:, without yaml
        in_rules = False
        for line in text.splitlines():
            if re.match(r"^rules\s*:", line):
                in_rules = True
                continue
            if in_rules:
                if line.strip() and not line.startswith((" ", "\t")):
                    break
                m = re.match(r"\s+([a-z_]+)\s*:\s*([^#]+)", line)
                if m:
                    rules[m.group(1)] = m.group(2).strip().strip("'\"")
    return scope_file, rules


def _num(rules, key, default=None):
    value = rules.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool(rules, key):
    """True / False / None, where None means the scope file does not say."""
    value = rules.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().lower() in {"true", "yes", "1"}:
            return True
        if value.strip().lower() in {"false", "no", "0"}:
            return False
    return None


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, comments=False, posix=True)
    except ValueError:
        return command.split()


def classify(command: str) -> tuple[str | None, int]:
    """(batch tool name or None, estimated request count) for this command."""
    try:
        tokens = shlex.split(command, comments=False, posix=True)
    except ValueError:
        tokens = command.split()
    for tok in tokens:
        name = Path(tok).name
        if name in BATCH_TOOLS:
            return name, int(BATCH_TOOLS[name]["estimate"])
    urls = len(URL_RE.findall(command))
    for tok in tokens:
        if Path(tok).name in SINGLE_SHOT:
            return None, max(1, urls)
    return None, urls  # 0 means this call sends nothing we can see


def _paced(command: str, tool: str, limit: float) -> tuple[bool, str]:
    """Does a batch invocation carry a pacing flag at or under the limit?"""
    flags = BATCH_TOOLS[tool]["flags"]
    if not flags:
        return True, ""
    for flag in flags:
        m = re.search(re.escape(flag) + r"[= ]+(\d+(?:\.\d+)?)", command)
        if m:
            # -T (nmap timing) and --delay (seconds between requests) are not
            # requests per second; a present flag is accepted as deliberate
            # pacing, and only a rate-shaped flag is compared to the limit.
            if flag in {"-rate-limit", "-rl", "-rate", "--rate",
                        "--rate-limit", "--max-rate"}:
                if float(m.group(1)) > limit:
                    return False, (f"{tool} is set to {m.group(1)} req/s but the "
                                   f"scope allows {limit:g}")
            return True, ""
    return False, (f"{tool} has no pacing flag, so it will run at its own default "
                   f"rate and ignore the scope's {limit:g} req/s. Add "
                   f"{' or '.join(flags)}")


def _state_path(scope_file: Path) -> Path:
    return scope_file.parent / ".budget"


def _read_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _write_state(path: Path, state: dict) -> None:
    try:
        path.write_text(json.dumps(state))
    except OSError:
        pass  # a read-only workspace must not break the call


def check(command: str, charge: bool = False) -> dict:
    """The decision for one tool call.

    `charge` consumes the rate bucket's tokens. The --check interface does not,
    so a caller can ask twice without double-charging the pacing.
    """
    out = {"action": "allow", "message": None, "sleep": 0.0, "scope": None}
    command = str(command)

    # The destructive denylist does not need a scope file: it is absolute.
    #
    # Matching is per segment, not over the whole string. An agent sends a
    # multi-line script, and judging the blob meant one destructive line
    # refused the whole thing while the message named a rule that had nothing
    # to do with the line the agent was looking at. A live run hit exactly
    # that: a POST to /register was refused with "HTTP DELETE destroys target
    # data" because a later line in the same script held a DELETE. The call is
    # still refused as a whole, since a hook cannot run half a script, but the
    # message now quotes the segment responsible so the agent can resend
    # without it instead of guessing.
    for segment in _segments(command):
        for pattern, why in DESTRUCTIVE:
            if pattern.search(segment):
                mode = os.environ.get("MYTHOS_DESTRUCTIVE", "block")
                shown = segment.strip()
                shown = shown if len(shown) <= 160 else shown[:157] + "..."
                out["message"] = (
                    "⛔ MYTHOS BUDGET GUARD: refused as destructive.\n"
                    f"    {why}.\n"
                    f"    The part that triggered this:\n      {shown}\n"
                    "    The whole call is refused, because a hook cannot run "
                    "half a script. Resend without that part.\n"
                    "    Mythos tests non-destructively: no data destruction, no "
                    "brute force, no denial of service. Find a read-only or "
                    "self-owned-object proof, or report the class as unconfirmed.")
                out["action"] = "warn" if mode == "warn" else "block"
                return out

    loaded = load_rules()
    if not loaded:
        return out
    scope_file, rules = loaded

    if DESTRUCTIVE_SCOPED.search(command):
        out["message"] = (
            "⚠️  MYTHOS BUDGET GUARD: this call names an operation that changes or "
            "removes something.\n"
            "    That is allowed on an object you created yourself, which is how "
            "an access-control finding gets proven without touching another "
            "user's data. It is not allowed on anyone else's. If the object is "
            "not yours, stop and report the endpoint as reachable instead.")
        out["action"] = "warn"
    out["scope"] = str(scope_file)
    mode = os.environ.get("MYTHOS_BUDGET_ENFORCE", "block")

    # Exploitation is the point of the tool, so this never refuses. An
    # explicit `false` is a program rule worth repeating back once.
    if _bool(rules, "allow_exploit") is False and (
            EXPLOIT_TOOLS.search(command) or EXPLOIT_FLAGS.search(command)):
        out.update(action="warn", message=(
            "⚠️  MYTHOS BUDGET GUARD: this command is exploitation and this "
            "engagement sets `rules.allow_exploit: false`.\n"
            f"    Active scope: {scope_file}\n"
            "    The program asked you not to. If that is still the right call, "
            "say so in the report."))

    tool, estimate = classify(command)
    limit = _num(rules, "rate_limit_rps")

    # When this engagement records its traffic (scripts/traffic start), a bare host curl or wget
    # would send a request that no record shows. Refuse it and name the form that is recorded.
    if (scope_file.parent / "traffic" / "proxy.json").exists() and not TRAFFIC_EXEC.search(command) \
            and any(Path(t).name in SINGLE_SHOT for t in _tokens(command)):
        out.update(action="warn" if mode != "block" else "block", message=(
            "⛔ MYTHOS BUDGET GUARD: unrecorded request.\n"
            "    This engagement records its traffic, and a bare curl/wget would not appear in it.\n"
            "    Run it as: scripts/traffic exec -- curl ...\n"
            f"    Active scope: {scope_file}"))
        if out["action"] == "block":
            return out

    if tool and limit:
        ok, why = _paced(command, tool, limit)
        if not ok:
            out.update(action="warn" if mode != "block" else "block", message=(
                "⛔ MYTHOS BUDGET GUARD: unpaced batch tool.\n"
                f"    {why}.\n"
                f"    Active scope: {scope_file} (rate_limit_rps: {limit:g})"))
            if out["action"] == "block":
                return out

    state = _read_state(_state_path(scope_file))

    # Pace single-shot calls here. A batch tool paces itself (checked above);
    # sleeping before it would only delay its first request.
    if limit and limit > 0 and estimate and not tool:
        now = time.monotonic()
        tokens = float(state.get("tokens", limit))
        last = float(state.get("last", now))
        tokens = min(limit, tokens + (now - last) * limit)
        if tokens < estimate:
            out["sleep"] = min(MAX_SLEEP, (estimate - tokens) / limit)
            tokens = 0.0
        else:
            tokens -= estimate
        state["tokens"], state["last"] = tokens, now + out["sleep"]

    if charge and state:
        _write_state(_state_path(scope_file), state)
    return out


def _selftest() -> int:
    import tempfile
    failures = []

    def want(got, expect, label):
        if got != expect:
            failures.append(f"{label}: got {got!r}, want {expect!r}")

    want(classify("curl https://a.test/x")[1], 1, "one url")
    want(classify("curl https://a.test/x https://a.test/y")[1], 2, "two urls")
    want(classify("nuclei -u https://a.test")[0], "nuclei", "batch tool seen")
    want(classify("ls -la")[1], 0, "no requests")
    want(_paced("nuclei -u x -rate-limit 3", "nuclei", 5.0)[0], True, "paced")
    want(_paced("nuclei -u x -rate-limit 50", "nuclei", 5.0)[0], False, "over limit")
    want(_paced("nuclei -u x", "nuclei", 5.0)[0], False, "unpaced")

    with tempfile.TemporaryDirectory() as td:
        scope = Path(td) / "scope.yaml"
        scope.write_text("target: a.test\nin_scope:\n  - a.test\n"
                         "rules:\n  rate_limit_rps: 5\n  allow_exploit: false\n")
        os.environ["MYTHOS_SCOPE"] = str(scope)
        os.environ.pop("MYTHOS_DESTRUCTIVE", None)
        os.environ.pop("MYTHOS_BUDGET_ENFORCE", None)

        want(check("curl https://a.test/")["action"], "allow", "plain curl")
        want(check("sqlmap -u https://a.test/ --dump")["action"], "block",
             "sqlmap dump blocked")
        want(check("hydra -l admin -P list.txt a.test http-post-form")["action"],
             "block", "brute force blocked")
        want(check("curl -X DELETE https://a.test/paste/7")["action"], "block",
             "DELETE blocked")
        # A multi-line script is attributed to the line that matched, which a
        # live run needed: a POST was refused under the DELETE rule because a
        # later line in the same script held one.
        multi = check("curl -sS -X POST https://a.test/register -d x\n"
                      "curl -sS -X DELETE https://a.test/users/2\n"
                      "echo done")
        want(multi["action"], "block", "multi-line script with a DELETE blocked")
        want("DELETE https://a.test/users/2" in multi["message"], True,
             "the offending line is quoted")
        want("register" in multi["message"], False,
             "the innocent line is not blamed")
        # The hole a live run walked through: mass destruction as an operation
        # name in a request body, invisible to a shell-shaped denylist.
        want(check("""curl -X POST https://a.test/graphql -d '{"query":"{deleteAllPastes}"}'""")["action"],
             "block", "deleteAllPastes blocked")
        want(check("curl -s https://a.test/api --data 'q=DROP TABLE users'")["action"],
             "block", "DROP TABLE blocked")
        want(check("curl -X POST https://a.test/g -d 'mutation{dropDatabase}'")["action"],
             "block", "dropDatabase blocked")
        # Deleting what you created yourself is the non-destructive proof, so it
        # warns and runs.
        want(check("""curl -X POST https://a.test/graphql -d '{"query":"mutation{deletePaste(id:9001)}"}'""")["action"],
             "warn", "scoped delete warns, does not block")
        # exploitation is never blocked: an explicit false only warns
        want(check("msfconsole -q -x exploit")["action"], "warn",
             "allow_exploit false warns, does not block")
        want(check("nuclei -u https://a.test")["action"], "block",
             "unpaced nuclei blocked")
        want(check("nuclei -u https://a.test -rate-limit 4")["action"], "allow",
             "paced nuclei allowed")

        # no scope key at all: exploitation just runs
        loose = Path(td) / "loose.yaml"
        loose.write_text("in_scope:\n  - a.test\nrules:\n  rate_limit_rps: 5\n")
        os.environ["MYTHOS_SCOPE"] = str(loose)
        want(check("ysoserial CommonsCollections1 x")["action"], "allow",
             "exploitation allowed by default")

        # warn mode downgrades the rate and budget checks but not destruction
        os.environ["MYTHOS_BUDGET_ENFORCE"] = "warn"
        want(check("nuclei -u https://a.test")["action"], "warn", "warn mode")
        want(check("hydra -l a -P b a.test ssh")["action"], "block",
             "destruction still blocks in warn mode")
        os.environ["MYTHOS_DESTRUCTIVE"] = "warn"
        want(check("hydra -l a -P b a.test ssh")["action"], "warn",
             "explicit destructive warn")
        for key in ("MYTHOS_SCOPE", "MYTHOS_BUDGET_ENFORCE", "MYTHOS_DESTRUCTIVE"):
            os.environ.pop(key, None)

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"budget-guard selftest: {len(failures)} failure(s)")
    return 1 if failures else 0


def main() -> int:
    if sys.argv[1:2] == ["--selftest"]:
        return _selftest()
    if sys.argv[1:2] == ["--check"]:
        # --charge consumes the rate bucket, for a caller that acts on the
        # decision immediately (the OpenCode plugin). Without it the check is
        # read-only, so a caller may ask twice without double-charging.
        argv = sys.argv[2:]
        charge = False
        if argv[:1] == ["--charge"]:
            charge, argv = True, argv[1:]
        print(json.dumps(check(" ".join(argv), charge=charge)))
        return 0
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command") or tool_input.get("url") or ""
    if not command:
        return 0

    decision = check(str(command), charge=True)
    if decision["sleep"]:
        time.sleep(decision["sleep"])
    msg = decision["message"]
    if not msg:
        return 0
    if decision["action"] == "block":
        print(msg, file=sys.stderr)
        return 2
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "additionalContext": msg}}))
    print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
