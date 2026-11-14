#!/usr/bin/env python3
"""Mythos scope guard — PreToolUse hook (warn-only by default).

Reads the Claude Code hook event on stdin. For Bash/tool calls it extracts the
hosts and URLs the command targets and checks them against the active
engagement scope. If a target is out of scope it prints a prominent warning
but does NOT block (the default is warn-only). MYTHOS_SCOPE_ENFORCE picks the
mode: "warn" (default, warn and continue), "ask" (the host asks the user to
confirm the call) or "block" (refuse the call outright).

In "warn" mode the command has already run by the time the warning is read.
This hook is a tripwire, not a barrier: it tells you a slip happened. Only
"ask" and "block" can prevent the call. There is no other scope control in the
system — the agent host's model is the agent, and nothing sits between it and
the network.

Finding the active scope, in order:
  1. $MYTHOS_SCOPE                       (explicit path; set it)
  2. the newest engagements/*/scope.yaml under the project
  3. no scope -> stay silent (nothing to check against)

Option 2 is a fallback, not a feature: a stale engagement directory left in the
working tree would become the authorization boundary. `engagement-setup` pins
$MYTHOS_SCOPE for exactly this reason.

It is also the single scope-check implementation for every agent host. The
OpenCode plugin (.opencode/plugin/scope-guard.ts) calls

  python3 hooks/scope-guard.py --check '<command or url>'

which prints {"offenders": [...], "scope": path|null, "in_scope": [...],
"message": str|null} and always exits 0; the caller decides warn vs block.

`--selftest` runs the extraction and matching asserts and needs no network.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import re
import shlex
import sys
from pathlib import Path

# Container plumbing, never a real target: these are how the toolbox reaches
# the host, not hosts the engagement could authorize.
PLUMBING = {"mythos-toolbox", "host.docker.internal"}
# Loopback is exempt only when the scope itself is a loopback target (lab mode).
# On a customer engagement a request to the operator's own machine is exactly
# the kind of slip worth seeing.
LOOPBACK = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "::"}

URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'\"<>|;`)]+")
# bare host/IP after a flag commonly used by pentest tools
FLAG_VALUE = {"-u", "-h", "-d", "-t", "--url", "--host", "--target", "--domain",
              "--hostname", "--server", "-H"}
# flags whose value is a file holding targets, one per line (nuclei -l,
# sqlmap -r, nmap -iL, ffuf -w on a host list, httpx -l)
FILE_FLAGS = {"-l", "-L", "--list", "-iL", "-r", "--request", "--targets",
              "--target-file", "-T"}
HOSTLIKE = re.compile(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?"
                      r"(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+\.?$", re.I)
HEADER_HOST = re.compile(r"^\s*host\s*:\s*(\S+)\s*$", re.I)
# A token shaped like a hostname but ending in one of these is a filename.
NOT_TLD = {
    "txt", "json", "yaml", "yml", "md", "py", "sh", "log", "csv", "html", "htm",
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "xml", "jar", "zip", "tar", "gz",
    "bz2", "xz", "png", "jpg", "jpeg", "gif", "svg", "pdf", "conf", "cfg",
    "env", "lock", "toml", "ini", "sql", "db", "sqlite", "so", "dll", "out",
    "bak", "tmp", "war", "php", "asp", "jsp", "aspx", "map", "css", "scss",
    "jsonl", "ndjson", "pem", "key", "crt", "cer", "p12", "pcap", "har",
    "nmap", "gnmap", "xlsx", "docx", "pptx", "bin", "exe", "iso", "img",
    "patch", "diff", "lst", "dic", "wordlist", "resolvers",
}
MAX_LIST_BYTES = 256 * 1024
MAX_LIST_LINES = 5000


def load_scope():
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    path = os.environ.get("MYTHOS_SCOPE")
    scope_file = Path(path) if path else (_pinned_scope() or _newest_scope())
    if not scope_file or not scope_file.exists():
        return None
    text = scope_file.read_text(encoding="utf-8", errors="replace")
    if yaml:
        try:
            data = yaml.safe_load(text) or {}
            rules = data.get("rules") or {}
            if not isinstance(rules, dict):
                rules = {}
            return (scope_file, data.get("in_scope") or [],
                    data.get("out_of_scope") or [], _ports(rules.get("ports")
                                                           or data.get("ports")))
        except Exception:
            pass
    # minimal fallback parse without yaml
    return (scope_file, _crude_list(text, "in_scope"),
            _crude_list(text, "out_of_scope"), _ports(_crude_list(text, "ports")))


def _ports(raw):
    """The authorized port set, or None when the scope names none."""
    if raw is None:
        return None
    if isinstance(raw, (int, str)):
        raw = [raw]
    out = set()
    for item in raw:
        for part in re.split(r"[,\s]+", str(item)):
            part = part.strip()
            if not part:
                continue
            if "-" in part[1:]:
                lo, _, hi = part.partition("-")
                try:
                    out.update(range(int(lo), int(hi) + 1))
                except ValueError:
                    continue
            elif part.isdigit():
                out.add(int(part))
    return out or None


PIN_FILE = ".mythos-scope"


def _pinned_scope():
    """The scope the engagement pinned, from a file the agent can actually write.

    `engagement-setup` and the orchestrator both say to `export MYTHOS_SCOPE`.
    That reaches `scripts/probe` and `scripts/verify`, which are children of
    that shell, and it never reaches these hooks: a PreToolUse hook runs as its
    own process in the host's environment, not in the agent's shell, so an
    export inside a Bash call is invisible here. A measured run pinned the scope
    exactly as instructed and the guards still fell back to the newest
    `engagements/*/scope.yaml` by modification time, which is the very fallback
    the pin exists to avoid.

    So the pin is a file. The agent writes the scope's path into
    `.mythos-scope` at the project root, every guard reads it, and the env var
    still wins when it is set by a harness or a wrapper that can set it.
    """
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    f = root / PIN_FILE
    try:
        raw = f.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not raw:
        return None
    p = Path(raw if Path(raw).is_absolute() else root / raw)
    return p if p.exists() else None

def _newest_scope():
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    candidates = list(root.glob("engagements/*/scope.yaml"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _crude_list(text: str, key: str):
    out, grab = [], False
    for line in text.splitlines():
        if line.strip().startswith(key + ":"):
            inline = line.split(":", 1)[1].strip()
            if inline and not inline.startswith("#"):
                out.append(inline.strip("'\""))
                continue
            grab = True
            continue
        if grab:
            m = re.match(r"\s*-\s*['\"]?([^'\"#]+)['\"]?\s*$", line)
            if m:
                out.append(m.group(1).strip())
            elif line.strip() and not line.startswith((" ", "\t", "-")):
                break
    return out


def norm_host(raw: str) -> str | None:
    """Canonical form of anything that could name a host.

    Handles the forms an agent actually emits: bracketed IPv6, a trailing dot,
    an integer or hex IPv4 (http://3232235777/ is 192.168.1.1), and mixed case.
    Returns None for something that cannot be a host.
    """
    if not raw:
        return None
    h = raw.strip().strip("[]").rstrip(".").lower()
    if not h:
        return None
    # integer / hex / octal IPv4
    packed = None
    try:
        if re.fullmatch(r"0x[0-9a-f]+", h):
            packed = int(h, 16)
        elif h.isdigit() and 0x1000000 <= int(h) <= 0xFFFFFFFF:
            packed = int(h)
    except ValueError:
        packed = None
    if packed is not None and 0 <= packed <= 0xFFFFFFFF:
        return str(ipaddress.IPv4Address(packed))
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    if HOSTLIKE.match(h):
        return h
    # a single-label name (the toolbox container), but never a bare number:
    # "8080" is a port, not a host
    if re.fullmatch(r"[a-z0-9][a-z0-9\-]*", h) and not h.isdigit():
        return h
    return None


def _looks_like_file(token: str) -> bool:
    tail = token.rsplit(".", 1)
    return len(tail) == 2 and tail[1].lower() in NOT_TLD


def _from_text(text: str, follow_files: bool = True) -> set[tuple[str, int | None]]:
    """Every (host, port) a command or target list refers to."""
    found: set[tuple[str, int | None]] = set()

    for m in URL_RE.finditer(text):
        try:
            from urllib.parse import urlsplit
            parts = urlsplit(m.group(0))
            # urlsplit puts userinfo before the host, so
            # http://app.example.com@evil.test/ correctly yields evil.test
            host = norm_host(parts.hostname or "")
            port = None
            try:
                port = parts.port
            except ValueError:
                port = None
            if host:
                found.add((host, port))
        except Exception:
            continue

    try:
        tokens = shlex.split(text, comments=False, posix=True)
    except ValueError:
        tokens = text.split()

    prev = ""
    for tok in tokens:
        # --resolve host:port:addr pins a name to an address: both are targets
        if prev in {"--resolve", "--connect-to"} or tok.startswith("--resolve="):
            value = tok.split("=", 1)[1] if "=" in tok and tok.startswith("--") else tok
            bits = value.split(":")
            for bit in (bits[0:1] + bits[2:]):
                host = norm_host(bit)
                if host:
                    found.add((host, None))
            prev = tok
            continue
        # a Host: header reaches a different vhost on the same connection
        hm = HEADER_HOST.match(tok)
        if hm:
            host = norm_host(hm.group(1).split(":")[0])
            if host:
                found.add((host, None))
            prev = tok
            continue
        if prev in FLAG_VALUE or (tok.startswith("--") and "=" in tok
                                  and tok.split("=", 1)[0] in FLAG_VALUE):
            value = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
            bare = value.split("://")[-1].split("/")[0].split("@")[-1]
            host = norm_host(bare.rsplit(":", 1)[0] if bare.count(":") == 1
                             and bare.rsplit(":", 1)[1].isdigit() else bare)
            if host:
                found.add((host, None))
            prev = tok
            continue
        # a file of targets is a list of targets
        if follow_files and prev in FILE_FLAGS and not tok.startswith("-"):
            found |= _from_file(tok)
            prev = tok
            continue
        # a bare positional host: `nmap evil.test`, `curl evil.test`
        if not tok.startswith("-") and "://" not in tok and "/" not in tok:
            if not _looks_like_file(tok):
                host = norm_host(tok.split("@")[-1])
                if host and (HOSTLIKE.match(host) or _is_ip(host)):
                    found.add((host, None))
        prev = tok
    return found


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _from_file(path: str) -> set[tuple[str, int | None]]:
    """Targets listed in a file, as nuclei -l / nmap -iL / sqlmap -r take them."""
    try:
        p = Path(path)
        if not p.is_file() or p.stat().st_size > MAX_LIST_BYTES:
            return set()
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return set()
    found: set[tuple[str, int | None]] = set()
    for line in lines[:MAX_LIST_LINES]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # a saved request (sqlmap -r) carries the host in a Host: header
        hm = HEADER_HOST.match(line)
        if hm:
            host = norm_host(hm.group(1).split(":")[0])
            if host:
                found.add((host, None))
            continue
        found |= _from_text(line, follow_files=False)
    return found


def extract_hosts(command: str) -> set[str]:
    """Backwards-compatible host-only view (used by the self-test and the plugin)."""
    return {h for h, _ in _from_text(str(command))}


def _match(host: str, pattern: str) -> bool:
    host = (norm_host(host) or host.lower().strip())
    pattern = pattern.lower().strip()
    # a scope entry may carry a scheme or a port: http://app.example.com:8443
    pattern = pattern.split("://")[-1].split("/")[0]
    if pattern.count(":") == 1 and pattern.rsplit(":", 1)[1].isdigit():
        pattern = pattern.rsplit(":", 1)[0]
    pattern = pattern.strip("[]").rstrip(".")
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    return fnmatch.fnmatch(host, pattern) or host == pattern


def in_scope(host: str, in_list, out_list) -> bool:
    if any(_match(host, p) for p in out_list):
        return False
    return any(_match(host, p) for p in in_list)


def _lab_mode(in_list) -> bool:
    """True when the engagement itself targets loopback, i.e. the bundled lab."""
    for entry in in_list:
        host = norm_host(str(entry).split("://")[-1].split("/")[0].split(":")[0])
        if host in LOOPBACK or host in PLUMBING:
            return True
        try:
            if ipaddress.ip_address(host or "").is_loopback:
                return True
        except ValueError:
            continue
    return False


def check(command: str) -> dict:
    """Shared core: which hosts in `command` are out of the active scope."""
    result = {"offenders": [], "scope": None, "in_scope": [], "message": None}
    loaded = load_scope()
    if not loaded:
        return result  # no active engagement scope; nothing to check
    scope_file, in_list, out_list, ports = loaded
    result.update(scope=str(scope_file), in_scope=list(in_list))
    pairs = _from_text(str(command))
    lab = _lab_mode(in_list)
    exempt = set(PLUMBING) | (LOOPBACK if lab else set())
    pairs = {(h, p) for h, p in pairs if h not in exempt}

    if not in_list:
        # An empty in_scope authorizes nothing. Reading it as "allow all" is
        # how a half-written scope file becomes a blank cheque.
        offenders = sorted({h for h, _ in pairs})
        if offenders:
            result["offenders"] = offenders
            result["message"] = (
                "⚠️  MYTHOS SCOPE GUARD: the active scope file lists no "
                f"in_scope entries, so nothing is authorized, but this command "
                f"targets: {', '.join(offenders)}\n"
                f"    Active scope: {scope_file}\n"
                "    Fill in in_scope before testing anything.")
        return result

    offenders = sorted({h for h, _ in pairs if not in_scope(h, in_list, out_list)})
    bad_ports = sorted({f"{h}:{p}" for h, p in pairs
                        if p is not None and ports and p not in ports
                        and h not in offenders
                        and in_scope(h, in_list, out_list)})
    if offenders or bad_ports:
        result["offenders"] = offenders + bad_ports
        lines = ["⚠️  MYTHOS SCOPE GUARD: this command targets host(s) that are "
                 f"OUT OF SCOPE: {', '.join(offenders + bad_ports)}"]
        if bad_ports and ports:
            lines.append(f"    Authorized ports: {', '.join(map(str, sorted(ports)))}")
        lines += [f"    Active scope: {scope_file}",
                  f"    In-scope: {', '.join(in_list)}",
                  "    Only test what the engagement authorizes."]
        result["message"] = "\n".join(lines)
    return result


def _selftest() -> int:
    import tempfile
    failures = []

    def eq(got, want, label):
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    # normalization
    eq(norm_host("3232235777"), "192.168.1.1", "decimal IPv4")
    eq(norm_host("0xC0A80101"), "192.168.1.1", "hex IPv4")
    eq(norm_host("[2001:db8::1]"), "2001:db8::1", "bracketed IPv6")
    eq(norm_host("Example.COM."), "example.com", "case and trailing dot")
    eq(norm_host("8080"), None, "a port is not a host")

    # extraction
    cases = {
        "curl http://app.example.com@evil.test/": {"evil.test"},
        "curl evil.test": {"evil.test"},
        "nmap -sV evil.test": {"evil.test"},
        "dig evil.test": {"evil.test"},
        "curl http://[2001:db8::1]/": {"2001:db8::1"},
        "curl http://3232235777/": {"192.168.1.1"},
        "curl --resolve a.test:80:1.2.3.4 http://a.test/": {"a.test", "1.2.3.4"},
        "curl -H 'Host: internal.evil.test' http://app.example.com/":
            {"internal.evil.test", "app.example.com"},
        "cat targets.txt": set(),
        "ls -la": set(),
        "python3 scripts/probe --json": set(),
    }
    for cmd, want in cases.items():
        eq(extract_hosts(cmd), want, f"extract {cmd!r}")

    with tempfile.TemporaryDirectory() as td:
        listing = Path(td) / "targets.txt"
        listing.write_text("https://a.evil.test/\n# comment\nb.evil.test\n")
        eq(extract_hosts(f"nuclei -l {listing}"), {"a.evil.test", "b.evil.test"},
           "nuclei -l file")
        req = Path(td) / "req.txt"
        req.write_text("GET / HTTP/1.1\nHost: c.evil.test\n\n")
        eq(extract_hosts(f"sqlmap -r {req}"), {"c.evil.test"}, "sqlmap -r file")

        scope = Path(td) / "scope.yaml"
        scope.write_text("target: app.example.com\n"
                         "in_scope:\n  - app.example.com\n  - '*.app.example.com'\n"
                         "out_of_scope:\n  - admin.app.example.com\n"
                         "rules:\n  ports: [80, 443]\n")
        os.environ["MYTHOS_SCOPE"] = str(scope)
        for cmd, want in [
            ("curl https://app.example.com/", []),
            ("curl https://api.app.example.com/", []),
            ("curl https://admin.app.example.com/", ["admin.app.example.com"]),
            ("curl http://app.example.com@evil.test/", ["evil.test"]),
            ("curl evil.test", ["evil.test"]),
            ("curl http://3232235777/", ["192.168.1.1"]),
            ("curl https://app.example.com:8443/", ["app.example.com:8443"]),
            ("curl http://127.0.0.1:8080/", ["127.0.0.1"]),
        ]:
            eq(check(cmd)["offenders"], want, f"check {cmd!r}")

        # lab mode: loopback is exempt when the scope itself is loopback
        lab = Path(td) / "lab.yaml"
        lab.write_text("in_scope:\n  - 127.0.0.1\n")
        os.environ["MYTHOS_SCOPE"] = str(lab)
        eq(check("curl http://127.0.0.1:5001/")["offenders"], [], "lab loopback")
        eq(check("curl https://evil.test/")["offenders"], ["evil.test"],
           "lab still guards elsewhere")

        # The pin file is what a hook can actually read: an export inside the
        # agent's shell never reaches this process.
        pinned = Path(td) / "pinned.yaml"
        pinned.write_text("in_scope:\n  - pinned.test\n")
        newest = Path(td) / "engagements" / "later"
        newest.mkdir(parents=True, exist_ok=True)
        (newest / "scope.yaml").write_text("in_scope:\n  - newest.test\n")
        os.environ.pop("MYTHOS_SCOPE", None)
        os.environ["CLAUDE_PROJECT_DIR"] = td
        (Path(td) / PIN_FILE).write_text(str(pinned))
        eq(check("curl https://newest.test/")["offenders"], ["newest.test"],
           "the pin wins over the newest scope by mtime")
        (Path(td) / PIN_FILE).unlink()
        os.environ.pop("CLAUDE_PROJECT_DIR", None)

        # an empty in_scope authorizes nothing
        empty = Path(td) / "empty.yaml"
        empty.write_text("in_scope: []\n")
        os.environ["MYTHOS_SCOPE"] = str(empty)
        eq(check("curl https://anything.test/")["offenders"], ["anything.test"],
           "empty in_scope")
        os.environ.pop("MYTHOS_SCOPE", None)

    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    print(f"scope-guard selftest: {len(failures)} failure(s)")
    return 1 if failures else 0


def main() -> int:
    if sys.argv[1:2] == ["--selftest"]:
        return _selftest()
    if sys.argv[1:2] == ["--check"]:
        print(json.dumps(check(" ".join(sys.argv[2:]))))
        return 0
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command") or tool_input.get("url") or ""
    if not command:
        return 0

    msg = check(str(command))["message"]
    if not msg:
        return 0

    mode = os.environ.get("MYTHOS_SCOPE_ENFORCE", "warn")
    if mode == "block":
        # exit code 2 blocks the tool call and feeds stderr back to Claude
        print(msg, file=sys.stderr)
        return 2
    if mode == "ask":
        # hand the decision to the user: the host shows the reason and prompts
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": msg,
            }
        }))
        return 0
    # warn-only: surface the warning without blocking
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": msg,
        }
    }))
    print(msg, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
