---
name: traffic
description: Read, summarize and replay the HTTP an engagement actually sends. Use to answer what was sent, how fast, to which hosts and what came before the target broke, to prove a finding by replaying its stored request byte for byte, and before the report to write run.json and a HAR for the operator.
---

# Traffic: what was actually sent

`engagements/audit.jsonl` holds the argv of each toolbox exec. It holds no
request. `scripts/traffic` records the requests themselves, per engagement,
so an operator can review them in Burp, Caido or a browser's devtools and so a
stored proof of concept can be checked by sending it again.

Triage never selects this skill; any phase reads it on demand when a question
about what was actually sent comes up. It drives `traffic`. Its entry in
`skills/registry.yaml` carries no triggers for that reason.

## The driver starts it

`scripts/traffic start` runs before the first phase and `scripts/traffic stop`
after the last one, both from the driver. There is nothing to start, and
nothing to wrap: the recorder is already in front of you.

Which paths it actually captures:

| path | how | recorded |
|---|---|---|
| the `shell` and `request` tools | `scripts/mythos` passes `scripts/traffic env --container --json` into every exec, so a plain `curl` is recorded | yes for tools that honor `HTTP_PROXY` |
| the `script` tool's `probe` and `verify` | they read the proxy from the pinned engagement, no prefix needed | yes, they use urllib |
| the `browser` tool's Chromium | needs `--proxy-server` and a CA flag; plain Chromium refuses the CA and shows up as a `tls_client_rejected` gap | http only, https not verified |
| nmap, raw sockets, `smuggler.py`, `h2spacex`, anything that ignores the proxy variables | cannot | no |
| a command an operator runs on the host themselves | `scripts/traffic exec -- curl -s https://target/` | yes |

Measured against the toolbox image, with the proxy variables set: curl, wget,
python requests and urllib, httpx, ffuf, katana, sqlmap, whatweb, wafw00f,
arjun, gobuster, feroxbuster, dirsearch, wfuzz and commix are recorded. nikto
and dalfox ignore the variables (dalfox records with its own `--proxy`, nikto
has its own proxy option, untested here). nuclei was not in the image used for the measurement and is
untested. A tool you have not seen in this list is untested: check `summary`'s
capture line after its first run.

If `scripts/traffic start` ran and the proxy is later down, `scripts/traffic
env` and `exec` refuse rather than send an unrecorded request.

Do not export the proxy variables into the shell that runs `mythos` itself: the
CLI's own calls to the model provider would be recorded too, API key included.

## Read it

```bash
scripts/traffic summary            # requests, hosts, rate against the limit, out of scope, 5xx, what came before the first failure
scripts/traffic summary --json
scripts/traffic list --status 5    # ids; --host, --grep, --limit
scripts/traffic show 41            # one request and response, credentials redacted
```

The out-of-scope count comes from `hooks/scope-guard.py --check`, the same code
the tools call before each request, so it agrees with the warnings you saw. A
request that already went out is in the record whether or not the guard
warned.

`summary` ends with a capture line. Read it before you rely on the record:

- `INCOMPLETE` lists every gap: a client that refused the CA, an upstream
  certificate that did not verify, framing the proxy would not guess about, a
  CONNECT it could only tunnel, a body cut at `--max-body`.
- `no request recorded while these toolbox tools ran` means a tool ran for
  seconds and the proxy saw nothing. It ignores `HTTP_PROXY`. Its traffic is
  not in the record. Say so in the report, or give the tool its own proxy flag
  (`-proxy`, `--proxy`, `-useproxy`).

## Prove with it

A finding is `validated` only with a proof that holds again. Replay is the check:

```bash
scripts/traffic replay 41                                  # same bytes, same host, diff the response
scripts/traffic replay 41 --ignore-body 'csrf=[0-9a-f]+'   # blank what changes every time
```

It exits 0 when the response is identical (status, headers, body), 1 when it
differs, 2 when it could not send. It refuses a host the scope guard flags, and
the replay is itself recorded as `replay of 41`. A replay whose body differs only
in a nonce you named with `--ignore-body` is still identical; one that differs
anywhere else is not the same proof. Put the record id in the finding's
`proof:` field next to the script path.

## Report

```bash
scripts/traffic run                # engagements/<dir>/run.json
scripts/traffic export             # traffic/traffic.har, redacted, for Burp or Caido
```

`run.json` is the engagement's own account of itself: request count, duration,
hosts and per-host counts, rate against the limit, scope violations on the wire,
toolbox tool runs, phases, and whether the record is complete. State its
`capture` section in the report's scope-and-method paragraph. Cite request ids
in evidence and paste `scripts/traffic show <id>` output, not `--raw`.

## Credentials

`traffic/log.jsonl` is raw on purpose: a replay that cannot send the real
`Cookie` proves nothing. It is 0600, inside the git-ignored engagement
directory. Everything the tool prints or exports is redacted with the patterns
in `scripts/findings`. `--raw` turns that off for your own screen; never paste
it into a report, a ticket or a chat, and delete the engagement's `traffic/`
when the retention period for the engagement ends.
