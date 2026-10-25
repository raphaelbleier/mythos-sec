"""Content discovery.

Probes a curated list of common paths (admin panels, backups, config files,
VCS metadata, API docs) relative to the target root. Uses the built-in list by
default; a larger external wordlist can be supplied. Findings for exposed
sensitive files are raised here; everything found feeds the crawl surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient, ScopeViolation, BudgetExceeded

# Pragmatic high-signal list. Kept small so the pure-Python path stays fast;
# the agents switch to ffuf + SecLists in the toolbox for breadth.
COMMON_PATHS: list[str] = [
    "admin/", "administrator/", "login", "dashboard", "config.php",
    "configuration.php", "wp-admin/", "wp-login.php", "phpinfo.php",
    "server-status", "actuator", "actuator/health", "actuator/env",
    ".git/HEAD", ".git/config", ".svn/entries", ".env", ".env.bak",
    "backup/", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "config.json", "config.yml", "settings.py", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    "api/", "api/v1/", "swagger-ui.html", "swagger.json", "openapi.json",
    "v2/api-docs", "graphql", "console", "debug", "test.php", "info.php",
    ".htaccess", ".DS_Store", "id_rsa", "credentials", "secrets.json",
]

SENSITIVE = {
    ".git/HEAD": ("Exposed Git repository metadata", "high"),
    ".git/config": ("Exposed Git repository metadata", "high"),
    ".svn/entries": ("Exposed Subversion metadata", "high"),
    ".env": ("Exposed environment file (.env)", "high"),
    ".env.bak": ("Exposed environment file backup", "high"),
    "db.sql": ("Exposed database dump", "high"),
    "dump.sql": ("Exposed database dump", "high"),
    "backup.zip": ("Exposed backup archive", "high"),
    "backup.tar.gz": ("Exposed backup archive", "high"),
    "id_rsa": ("Exposed private SSH key", "critical"),
    "secrets.json": ("Exposed secrets file", "high"),
    "credentials": ("Exposed credentials file", "high"),
    "actuator/env": ("Spring Boot Actuator env endpoint exposed", "high"),
    "phpinfo.php": ("phpinfo() information disclosure", "medium"),
    "info.php": ("phpinfo() information disclosure", "medium"),
    "server-status": ("Apache server-status exposed", "medium"),
    ".DS_Store": ("Exposed .DS_Store directory listing", "low"),
    "web.config": ("Exposed IIS web.config", "medium"),
}


@dataclass
class DiscoveryResult:
    base: str
    hits: list[dict] = field(default_factory=list)  # {path,url,status,length}

    def to_dict(self) -> dict:
        return {"base": self.base, "hits": self.hits}


def _baseline_404(client: HttpClient, base: str) -> int:
    """Length of a known-missing path, to detect soft-404 pages."""
    probe = urljoin(base, "mythos-nonexistent-%s" % "x7q9z2")
    try:
        resp = client.get(probe)
    except Exception:
        return -1
    return len(resp.text or "") if resp is not None else -1


def discover(client: HttpClient, target: str, *, wordlist: list[str] | None = None):
    """Returns (DiscoveryResult, [Finding]) for exposed sensitive paths."""
    from ..findings import Finding, Evidence, Severity

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}/"
    result = DiscoveryResult(base=base)
    findings = []
    soft404_len = _baseline_404(client, base)
    paths = wordlist or COMMON_PATHS

    for path in paths:
        url = urljoin(base, path)
        try:
            resp = client.get(url, allow_redirects=False)
        except (ScopeViolation, BudgetExceeded):
            continue
        if resp is None:
            continue
        status = resp.status_code
        length = len(resp.text or "")
        if status in (404, 400):
            continue
        if status == 200 and soft404_len >= 0 and abs(length - soft404_len) < 16:
            continue  # soft-404
        if status in (200, 201, 301, 302, 401, 403, 500):
            result.hits.append({"path": path, "url": url, "status": status, "length": length})
        if status in (200, 301, 302) and path in SENSITIVE:
            title, sev = SENSITIVE[path]
            findings.append(Finding(
                title=title, severity=Severity(sev), kind="sensitive-exposure",
                url=url,
                description=f"The path {path!r} is reachable and returned HTTP {status}.",
                impact="Sensitive files or metadata exposed to unauthenticated users "
                       "can leak source code, credentials or internal configuration.",
                remediation="Remove the file from the web root or restrict access. "
                            "Ensure VCS metadata and backups are never deployed.",
                evidence=Evidence(
                    request=f"GET {url}",
                    response=f"HTTP {status}, {length} bytes",
                    matched=path),
                confidence="firm"))
    return result, findings
