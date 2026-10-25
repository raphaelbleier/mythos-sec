# Benchmark — the skill-driven Mythos flow

Validation of the current architecture (Claude Code as the agent, driving the
Kali toolbox via phase skills). No Python engine, no external API key.

## 1. Regression self-test (`scripts/selftest.sh`)

Repeatable, automated. Starts the ground-truth lab app and drives the toolbox
exactly as the skills do, asserting each class is found with real tool output
and that a safe endpoint is not flagged (false-positive control), plus the
scope-guard hook behaviour.

```
$ scripts/selftest.sh
  PASS  fingerprint (Flask detected)
  PASS  reflected XSS /search?q=
  PASS  SQLi error leak /user?id=
  PASS  open redirect /go?next=
  PASS  path traversal /download?file=
  PASS  CORS reflects Origin /api/data
  PASS  sensitive exposure /.env
  PASS  no false-positive XSS on /
  PASS  scope-guard warns out-of-scope
  PASS  scope-guard silent in-scope
== result: 10 passed, 0 failed ==
```

## 2. Live engagement — OWASP Juice Shop v17.1.1

A real modern web app (Angular SPA + REST API), not the ground-truth app. Full
flow: recon (whatweb/httpx + katana JS-aware crawl, 56 URLs) → targeted scan →
exploit. Every confirmed finding below has real tool evidence; see
`engagements/juiceshop-<date>/report.md` for the full report.

| Finding                                                                                                        | Severity | Status                                                     |
| -------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------------------------------- |
| SQLi (UNION) in `/rest/products/search?q=` → full Users dump (emails + MD5 hashes; admin cracks to `admin123`) | Critical | Confirmed                                                  |
| Sensitive file disclosure via `/ftp/` directory listing (incl. a KeePass `.kdbx`)                              | High     | Confirmed                                                  |
| Poison-null-byte extension-filter bypass (`.bak` 403 directly, 200 via `%2500.md`)                             | High     | Confirmed                                                  |
| Open redirect in `/redirect?to=` (allowlist-substring bypass)                                                  | Medium   | Confirmed                                                  |
| Info disclosure: `/rest/admin/application-configuration`                                                       | Low      | Confirmed                                                  |
| DOM XSS in client-side search (`<iframe src="javascript:…">`)                                                  | High     | **Confirmed** (browser agent — JS executed, `alert` fired) |

**6 classes confirmed on a real app**, 5 unauthenticated with tool output and
the DOM XSS confirmed in a real browser. The SQLi, the null-byte bypass and the
open-redirect each required the agent to _reason past a first failed payload_
(wrong quote closure, wrong allowlist org, wrong extension) — exactly what the
skill-driven model is for.

## Notes / honest limits

- DOM XSS was confirmed by the `mythos-browser` agent: headless Chromium +
  Playwright in the toolbox navigated the search payload and captured the
  `alert('MYTHOSXSS')` dialog firing (JS execution, not just reflection).
- A tag-scoped `nuclei` exposures pass added nothing on this SPA in the time
  box; the manual, stack-aware checks found the real issues. nuclei stays in the
  flow for CVE/misconfig breadth on server-rendered stacks.
- Host is RAM-limited (WSL ~3.7 GB): tools run one at a time; heavy parallel
  scans are avoided by design.
