"""Orchestration of ready-made open-source security tools.

The engine prefers mature tools over its own code. Each wrapper detects the
tool on PATH, runs it with a timeout and scope-limited arguments, parses its
output and normalizes the results into Finding objects (or plain data for
recon tools). When a tool is absent the wrapper returns empty, and the
orchestrator falls back to the native checks.

Tools wrapped: subfinder, httpx (ProjectDiscovery), katana, nuclei, ffuf,
dalfox, sqlmap, nikto, whatweb, nmap. These run on PATH; inside the Mythos
toolbox container they are all preinstalled.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .findings import Finding, Evidence, Severity

# simple in-process result cache (tool, args) -> (timestamp, output)
_CACHE: dict[str, tuple[float, str]] = {}
_CACHE_TTL = 3600.0  # seconds

# nuclei / dalfox severity -> our Severity
_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO,
    "unknown": Severity.INFO,
}


def have(tool: str) -> bool:
    # MYTHOS_NO_EXTERNAL forces the pure-Python path even inside the toolbox.
    # MYTHOS_SKIP_TOOLS=nuclei,amass disables only named tools (e.g. drop the
    # memory-heavy nuclei on constrained hosts while keeping katana/arjun/dalfox).
    import os
    if os.environ.get("MYTHOS_NO_EXTERNAL"):
        return False
    skip = {t.strip() for t in os.environ.get("MYTHOS_SKIP_TOOLS", "").split(",") if t.strip()}
    if tool in skip:
        return False
    return shutil.which(tool) is not None


def available_tools() -> dict[str, bool]:
    return {t: have(t) for t in (
        "subfinder", "httpx", "katana", "nuclei", "ffuf",
        "dalfox", "sqlmap", "nikto", "whatweb", "nmap")}


def _run(cmd: list[str], timeout: int = 900, input_text: str | None = None,
         retries: int = 1, cache: bool = False) -> str:
    """Run a tool with a timeout, optional retry/backoff and result caching.

    Mirrors HexStrike's error-recovery idea: transient failures (timeout, empty
    output) are retried with backoff; recon results can be cached by (cmd,input)
    so repeated phases don't re-scan.
    """
    key = ""
    if cache:
        key = hashlib.sha1((" ".join(cmd) + "|" + (input_text or "")).encode()).hexdigest()
        hit = _CACHE.get(key)
        if hit and (time.time() - hit[0]) < _CACHE_TTL:
            return hit[1]

    out = ""
    for attempt in range(max(1, retries) + 1):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, input=input_text)
            out = proc.stdout or ""
            if out.strip() or proc.returncode == 0:
                break
        except subprocess.TimeoutExpired:
            out = ""
        except (FileNotFoundError, OSError):
            return ""  # tool genuinely absent; no point retrying
        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))  # backoff

    if cache and key:
        _CACHE[key] = (time.time(), out)
    return out


# ---- recon -------------------------------------------------------------
def subfinder(domain: str, timeout: int = 300) -> list[str]:
    if not have("subfinder"):
        return []
    out = _run(["subfinder", "-silent", "-d", domain], timeout=timeout, cache=True)
    return sorted({l.strip() for l in out.splitlines() if l.strip()})


def httpx_probe(hosts: list[str], timeout: int = 300) -> list[dict]:
    """Probe hosts for liveness/tech. Returns ProjectDiscovery httpx JSON rows."""
    if not have("httpx") or not hosts:
        return []
    out = _run(["httpx", "-silent", "-json", "-title", "-tech-detect",
                "-status-code", "-no-color"],
               timeout=timeout, input_text="\n".join(hosts), cache=True)
    rows = []
    for line in out.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def arjun(url: str, timeout: int = 180) -> list[str]:
    """Discover hidden query/body parameters on an endpoint. Returns param names."""
    if not have("arjun"):
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    _run(["arjun", "-u", url, "-oJ", out_path, "-q"], timeout=timeout)
    names: set[str] = set()
    try:
        data = json.loads(Path(out_path).read_text()) if Path(out_path).exists() else {}
    except (json.JSONDecodeError, OSError):
        data = {}
    # arjun JSON: { "<url>": {"params": [...], ...} } or {"<url>": [...]}
    for v in (data.values() if isinstance(data, dict) else []):
        if isinstance(v, dict):
            names.update(v.get("params") or [])
        elif isinstance(v, list):
            names.update(v)
    Path(out_path).unlink(missing_ok=True)
    return sorted(n for n in names if isinstance(n, str))


def katana(url: str, timeout: int = 300, depth: int = 3) -> list[str]:
    if not have("katana"):
        return []
    out = _run(["katana", "-silent", "-u", url, "-d", str(depth),
                "-jc", "-no-color"], timeout=timeout, cache=True)
    return sorted({l.strip() for l in out.splitlines() if l.strip().startswith("http")})


# ---- vulnerability scanners -------------------------------------------
def nuclei(url: str, timeout: int = 1800, severity: str = "low,medium,high,critical",
           extra: list[str] | None = None) -> list[Finding]:
    if not have("nuclei"):
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".jsonl", delete=False) as tf:
        out_path = tf.name
    # bounded concurrency + rate limit keep nuclei's memory/footprint in check.
    # MYTHOS_NUCLEI_TAGS / MYTHOS_NUCLEI_CONC let memory-constrained hosts scope
    # the template set (loading all ~9k templates is the memory cost).
    import os
    conc = os.environ.get("MYTHOS_NUCLEI_CONC", "15")
    cmd = ["nuclei", "-u", url, "-jsonl", "-o", out_path, "-silent",
           "-severity", severity, "-no-color", "-c", conc, "-rl", "150",
           "-timeout", "8", "-retries", "1"]
    tags = os.environ.get("MYTHOS_NUCLEI_TAGS")
    if tags:
        cmd += ["-tags", tags]
    if extra:
        cmd += extra
    _run(cmd, timeout=timeout)
    findings: list[Finding] = []
    for line in Path(out_path).read_text(errors="replace").splitlines() if Path(out_path).exists() else []:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = ev.get("info", {})
        sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        findings.append(Finding(
            title=info.get("name", ev.get("template-id", "nuclei finding")),
            severity=sev, kind=ev.get("template-id", "nuclei"),
            url=ev.get("matched-at") or ev.get("host") or url,
            description=info.get("description", "") or "Reported by nuclei template.",
            impact=(info.get("impact") or "").strip(),
            remediation=(info.get("remediation") or "").strip(),
            references=info.get("reference") or [],
            evidence=Evidence(
                request=ev.get("request", ""),
                response=(ev.get("response", "") or "")[:1500],
                matched=str(ev.get("extracted-results") or ev.get("matcher-name") or ""),
                note=f"nuclei template {ev.get('template-id','')}"),
            source="nuclei", confidence="firm"))
    Path(out_path).unlink(missing_ok=True)
    return findings


def dalfox(url: str, timeout: int = 900) -> list[Finding]:
    """Dalfox XSS scanner (v3 CLI). Emits JSONL: first line meta, rest findings."""
    if not have("dalfox") or "?" not in url:
        return []
    out = _run(["dalfox", "url", "--url", url, "--format", "jsonl",
                "--silence", "--no-color"], timeout=timeout)
    return parse_dalfox_jsonl(out, url)


def parse_dalfox_jsonl(out: str, url: str = "") -> list[Finding]:
    """Parse dalfox v3 JSONL (first line meta, rest findings) into Findings."""
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or '"meta"' in line[:12]:
            continue
        try:
            poc = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "meta" in poc or not (poc.get("payload") or poc.get("param")):
            continue
        sev = _SEV.get(str(poc.get("severity", "high")).lower(), Severity.HIGH)
        findings.append(Finding(
            title="Cross-Site Scripting (XSS) — dalfox",
            severity=sev, kind="reflected-xss",
            url=poc.get("data", url), param=poc.get("param", ""),
            payload=poc.get("payload", ""),
            description="Dalfox confirmed an XSS injection point: "
                        + (poc.get("evidence") or poc.get("message_str") or ""),
            impact="Arbitrary JavaScript execution in a victim's browser.",
            remediation="Context-aware output encoding and a strict CSP.",
            references=[poc["cwe"]] if poc.get("cwe") else [],
            evidence=Evidence(request=poc.get("data", ""),
                              matched=poc.get("payload", ""),
                              note=poc.get("inject_type", "")),
            source="dalfox",
            confidence="certain" if poc.get("type") == "V" else "firm"))
    return findings


def sqlmap(url: str, timeout: int = 1200, data: str | None = None) -> list[Finding]:
    if not have("sqlmap"):
        return []
    with tempfile.TemporaryDirectory() as out_dir:
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--output-dir", out_dir, "--disable-coloring"]
        if data:
            cmd += ["--data", data]
        out = _run(cmd, timeout=timeout)
    if "is vulnerable" in out or "sqlmap identified the following injection point" in out.lower():
        return [Finding(
            title="SQL Injection — sqlmap confirmed",
            severity=Severity.CRITICAL, kind="sqli", url=url,
            description="sqlmap confirmed an injectable parameter.",
            impact="Database compromise: data theft, authentication bypass, possible RCE.",
            remediation="Parameterized queries / prepared statements.",
            evidence=Evidence(request=url, response=_tail(out, 1500),
                              matched="sqlmap: is vulnerable"),
            source="sqlmap", confidence="certain")]
    return []


def nikto(url: str, timeout: int = 900) -> list[Finding]:
    if not have("nikto"):
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    _run(["nikto", "-h", url, "-Format", "json", "-output", out_path,
          "-maxtime", str(timeout - 30), "-nointeractive"], timeout=timeout)
    findings: list[Finding] = []
    try:
        data = json.loads(Path(out_path).read_text()) if Path(out_path).exists() else []
    except (json.JSONDecodeError, OSError):
        data = []
    # nikto -Format json emits either a list of host objects or a single dict;
    # each host carries a "vulnerabilities" list.
    hosts = data if isinstance(data, list) else [data]
    vulns = []
    for host in hosts:
        if isinstance(host, dict):
            vulns.extend(host.get("vulnerabilities") or [])
    for v in vulns:
        if not isinstance(v, dict):
            continue
        findings.append(Finding(
            title=f"Nikto: {str(v.get('msg', 'web server issue'))[:80]}",
            severity=Severity.LOW, kind="nikto-" + str(v.get("id", "")),
            url=v.get("url", url), description=str(v.get("msg", "")),
            impact="Server-side misconfiguration or known issue reported by nikto.",
            remediation="Review the reported item against hardening guidance.",
            evidence=Evidence(matched=str(v.get("id", "")), note=str(v.get("msg", ""))),
            source="nikto", confidence="tentative"))
    Path(out_path).unlink(missing_ok=True)
    return findings


def ffuf(base_url: str, wordlist: str, timeout: int = 600,
         match_codes: str = "200,201,301,302,401,403") -> list[dict]:
    if not have("ffuf") or not Path(wordlist).exists():
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    fuzz = base_url.rstrip("/") + "/FUZZ"
    _run(["ffuf", "-u", fuzz, "-w", wordlist, "-mc", match_codes,
          "-of", "json", "-o", out_path, "-s"], timeout=timeout)
    hits: list[dict] = []
    try:
        data = json.loads(Path(out_path).read_text()) if Path(out_path).exists() else {}
    except (json.JSONDecodeError, OSError):
        data = {}
    for r in (data.get("results") or []):
        hits.append({"url": r.get("url"), "status": r.get("status"),
                     "length": r.get("length")})
    Path(out_path).unlink(missing_ok=True)
    return hits


def nmap(host: str, timeout: int = 600, top_ports: int = 1000) -> dict:
    if not have("nmap"):
        return {}
    out = _run(["nmap", "-Pn", "-sV", "--top-ports", str(top_ports),
                "-oG", "-", host], timeout=timeout)
    ports = []
    for line in out.splitlines():
        if "Ports:" in line:
            seg = line.split("Ports:", 1)[1]
            for item in seg.split(","):
                parts = item.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    ports.append({"port": int(parts[0]), "service": parts[4]})
    return {"host": host, "open_ports": ports}


def _tail(s: str, n: int) -> str:
    return s[-n:] if len(s) > n else s
