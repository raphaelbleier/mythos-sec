# Fixture provenance

Every file in this directory is the bytes a real tool printed, recorded on
2026-11-15 from the image built by `docker build -f toolbox/Dockerfile .`
(crlfuzz v1.4.1, gitleaks v8.30.1, ffuf v2.3.0, arjun from
`toolbox/requirements.txt`, jwt_tool at the pinned commit, phpggc at the pinned
commit, ysoserial-all.jar v0.0.6, subfinder v2.17.0). Nothing here was written
by hand, which is the point: `scripts/tools selftest` asserts its parsers
against these, so a parser that stops understanding its tool fails the build.

The HTTP targets are the loopback fixture server `scripts/tools` starts itself
(`_fixture_server`, an ephemeral port on 127.0.0.1) — never a lab container and
never a remote host. Each run gets a different port, so the ports in the
commands below differ from the ports inside the files.

`subfinder.txt` is the one exception: subfinder cannot be pointed at a loopback
server, so it was run once against `example.com`, IANA's reserved
documentation domain. It queries passive third-party datasets about the name
and sends nothing to any host, which is exactly the property
`scripts/tools hosts` relies on.

Regenerate everything with the recorder in this repo's scratch notes, or by
hand with the commands below through
`MYTHOS_NET=host MYTHOS_IMAGE=<image> scripts/mythos sh '<command>'`.

| file | command |
|---|---|
| `ffuf.json` | `ffuf -u http://127.0.0.1:33891/FUZZ -w /repo/engagements/.fixgen-paths.txt -mc 200,204,301,302,307,401,403,405 -fs 0 -ac -s -t 2 -rate 20 -of json -o /tmp/f.json >/dev/null 2>&1; cat /tmp/f.json` |
| `arjun.json` | `rm -f /tmp/a.json; arjun -u http://127.0.0.1:33891/reflect -w /repo/engagements/.fixgen-params.txt -oJ /tmp/a.json -t 2 --rate-limit 20 -T 15 -q >/dev/null 2>&1; cat /tmp/a.json` |
| `crlfuzz.txt` | `crlfuzz -u 'http://127.0.0.1:33891/go?url=x' -c 2 -s < /dev/null 2>&1` |
| `gitleaks.json` | `rm -f /tmp/g.json; gitleaks dir /repo/engagements/.fixgen-tree --no-banner --report-format json --report-path /tmp/g.json --exit-code 0 >/dev/null 2>&1; cat /tmp/g.json` |
| `phpggc-l.txt` | `phpggc -l 2>&1 | head -60` |
| `ysoserial.txt` | `ysoserial 2>&1 | head -40` |
| `jwt_tool-pb.txt` | `jwt_tool -t http://127.0.0.1:33891/jwt -rh 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.' -cv 'Welcome, admin' -rt 1200 -M pb eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. < /dev/null 2>&1` |
| `subfinder.txt` | `subfinder -d example.com -silent -timeout 10 -max-time 2 < /dev/null 2>/dev/null \| head -40` |

Two details in those commands are load-bearing and were each found by a tool
silently doing nothing:

- **`< /dev/null`** for crlfuzz and jwt_tool. Every exec through
  `scripts/mythos` is `docker exec -i`, so stdin is always a pipe. crlfuzz's
  usage is `[buffers] | crlfuzz [options]`: with a pipe on stdin it reads its
  URL list from stdin and **ignores `-u`**, so `crlfuzz -u <URL>` reported no
  hits against a plainly vulnerable endpoint.
- **`-cv 'Welcome, admin'`** for jwt_tool. Without a canary its prescan cannot
  tell an authenticated response from an anonymous one, stops and asks on
  stdin, and the non-interactive exec dies with `EOFError`. And without
  `-rh`, jwt_tool has nowhere to substitute the token and prints
  "No substitution occurred" instead of scanning. `scripts/tools jwt` requires
  `--canary` with `--target` for that reason.

The planted strings in the gitleaks tree are fabricated and in two documented
provider formats. AWS's own `AKIA…EXAMPLE` is deliberately not used:
gitleaks allowlists it, so a fixture built on it would assert nothing.

## One redaction in `gitleaks.json`

The Slack bot token in the recorded report is fabricated — all zeros in the two
numeric fields — but it has the documented shape, and GitHub's push protection
blocked a push of this repository over it. So the `Match` and `Secret` fields of
that one row carry `xoxb-REDACTED-see-PROVENANCE.md` instead of the value
gitleaks saw. Nothing asserted against this fixture reads the secret's
characters: the checks are that the rule id is carried through, that a hit is a
candidate, that every row names its file and line, and that the secret is never
echoed in full. The string that produced the row is still in the selftest's own
tree writer, assembled from pieces for the same reason.
