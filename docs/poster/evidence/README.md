# Example engagement reports

Six reports and two raw tool outputs from manual engagements through the
toolbox flow, kept as examples of what the framework produces. They are
**evidence that the flow works on real targets, not measurements**: single runs,
no control arm, no repeats, no blinding, and none of them was produced under the
controlled protocol in [`bench/METHODOLOGY.md`](../../../bench/METHODOLOGY.md).

Nothing in this directory should be read as a success rate. The controlled
figures, and what the audit of 13 November 2026 leaves of them, are in the
repository README and in `../poster.md`.

| File | Target | What it shows |
|---|---|---|
| `juiceshop-report.md` | OWASP Juice Shop | UNION SQLi, `/ftp` disclosure, poison-null-byte bypass, open redirect, DOM XSS confirmed in a browser |
| `crapi-report.md` | OWASP crAPI | the full engagement report |
| `crapi-bola-confirmed.md` | OWASP crAPI | one BOLA finding worked through to a confirmed proof |
| `vampi-report.md` | VAmPI | includes a BOLA that was tested and disproven rather than claimed |
| `dvwa-authenticated-report.md` | DVWA | authenticated flow with session handling |
| `exploiter-validation.md` | several | the exploiter sub-agent's proof standard applied case by case |
| `agent-ginjuice-trace.json` | Gin & Juice Shop | a raw agent trace |
| `juiceshop-nuclei-full.jsonl` | OWASP Juice Shop | raw nuclei output from one run |

The reports contain findings against deliberately vulnerable practice
applications only.
