# The web view

```bash
mythos web
```

It prints a URL on `127.0.0.1` with a token in it. Open that URL and you get a
read-only view of every engagement under `engagements/`: what was found, what
was decided, what was sent, and what the scope file said was allowed.

The terminal view is still the primary interface, and this does not replace it.
A run is driven from `mythos -t <url>`, paused and hinted there, and nothing on
this page can do any of that. What the page is for is the other half of the
work: reading a finished engagement, handing one to someone who is not going to
read a terminal, and answering "what did this thing actually touch" without
grepping a JSONL file.

---

## What it shows

**Engagements.** Every directory under `engagements/` that has a `scope.yaml`,
with its target, its date, the phase it reached, findings counted by severity,
endpoint verdicts counted by state, and wall clock. An engagement still running
is marked live.

**The run.** The six phases with the gate each one closes on, the budget it was
given and how much of it went, the workers that are running right now with the
tool each is on, and the event feed. This works on a run in progress and on one
that finished last week, through the same code path, because
`run-events.jsonl` is the event bus: `Bus.record()` appends every event to it
as the driver emits it, so tailing that file and subscribing to the emitter
give the same events in the same order. A live run streams over
`text/event-stream`; a finished one is read once and left alone.

**A finding.** The write-up, the severity with both CVSS vectors and both
computed scores, the evidence bundle's manifest with a digest per file, the
screenshots, and the validator's reasoning out of the ledger.

The centre of that page is the pair: the request that proved the flaw beside
the request that did not, their bytes side by side on a shared grid so the
response bodies begin on the same line, with a strip underneath naming what
differs: status, response size, time, path. A finding is believable or not
depending on whether that difference is the attacker's input and nothing else,
and putting the two anywhere but side by side makes the reader hold both in
their head to see it. When a finding cites no control, or cites one that is not
in the traffic store, the page says so in that space rather than quietly
showing one pane.

**The verdict ledger.** Every mapped endpoint with its state, filterable by
state and by text. A mapped endpoint with no row at all is shown as `open`, in
dashed red, because the gap between "tested" and "covered" is the thing this
project built the ledger to make visible, and an omission that is invisible
reads as coverage.

**Traffic.** Every record the proxy and the raw transport wrote, searchable by
method, path, status, host and agent, and optionally through the recorded bytes
themselves. A record opens to the bytes sent and the bytes received, with the
byte shape, which is length, digest, how many CRLF, how many bare LF and how
many bare CR. That line is what a desync proof turns on, and `scripts/traffic`
prints it in the same words. A `kind: "raw"` record is labelled raw and its method, path
and status are not shown, because those fields are a parser's opinion sitting
next to bytes whose whole value is that nobody parsed them.

**Scope.** What `scope.yaml` authorizes, the rate limit in force against the
average and peak the recorder measured, every host that received a request with
whether it was in scope, and every guard event in the run with the destination
the guard named. A guard event that only warned says so, and says that the
request had already left by the time the warning existed, because that is how
scope enforcement is configured by default.

**The report.** `report.md` rendered, with a download, and an evidence bundle
per finding as a `.tar.gz`.

---

## The security model

This page renders bytes a hostile server chose, and it sits on top of a
directory holding credentials, session cookies and proofs of exploitation. The
posture below is not a set of preferences, and `cli/src/web/selftest.ts` fails
if any of it stops being true.

**Loopback only.** The server binds `127.0.0.1`. A non-loopback address is
refused unless `--allow-remote` is passed, and the refusal says what the flag
does: it puts engagement data on the network. The port is random and printed;
`--port` pins it.

**A per-run bearer token.** Minted at startup, printed in the URL, and checked
on every request: the API, the stylesheet, the script, the icon and every
download. There is no cookie and therefore nothing sent ambiently. The token is
compared in constant time. It is the only credential, so the URL is exactly as
sensitive as the engagement directory: anyone who has it has every engagement
on the machine.

**No CORS, ever.** `Access-Control-Allow-Origin` is never set, on any response.
A page on another origin cannot read an engagement whatever it knows.

**A Host check.** A request whose `Host` header is not the address the server
bound to gets a 421. A page on the internet can make a name resolve to
`127.0.0.1` and then it is same-origin as far as the browser is concerned; what
it cannot do is send a `Host` header this server answers to.

**Read-only, structurally.** `GET` and `HEAD` reach a handler. Everything else
gets a 405 before any routing happens. There is no endpoint that starts, stops
or modifies an engagement, sends a request at a target, or writes `scope.yaml`,
and there is none behind a flag or a confirmation either. `--allow-actions`
exists so that the help text and the server agree on what it would mean; no
action is implemented, and the server says so when the flag is passed.

**Nothing renders as markup.** Response bodies, finding write-ups, guard
messages and file names are served as data and drawn into text nodes. The page
contains no `innerHTML`, no `insertAdjacentHTML`, no `document.write`, no
`eval` and no `new Function`; every element comes from `createElement` and a
text node. JSON leaves the server with `<`, `>`, `&`, U+2028 and U+2029 escaped
even though it is already typed `application/json` with `nosniff`. An evidence
file downloads as `application/octet-stream` with
`Content-Disposition: attachment`, so a captured HTML page is never handed to
the browser as a document; only a real image renders inline, and anything else
asked for inline gets a 415.

**A strict policy, served everywhere.** Every response, including the 401,
carries `default-src 'none'` widened only to `'self'` for script, style, font,
image and connect, with `data:` added for the inline mark. There is no
`unsafe-inline`, so the page could not run an inline script even if one got in,
and there is no CDN, no web font and no outbound request of any kind. Every
response also carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cross-Origin-Resource-Policy: same-origin` and `Cache-Control: no-store`.

The policy is strict enough to have caught its own author: an early version of
the phase rail set a bar width with a `style` attribute, the browser refused
it, and the fix was to set the width through the CSSOM rather than to widen the
policy.

**No path leaves the engagement.** Every file the server opens is resolved
first and then checked to be inside the engagement directory, and the
engagement directory is resolved and checked to be inside the engagements root.
`..`, an absolute path and a name that climbs out all fail the check before
anything is opened.

**Redaction is not undone.** A finding's body comes from `findings.json`, which
is what `scripts/findings` already redacted. An evidence bundle is packed from
the files `scripts/evidence` wrote, byte for byte, with its redaction intact.
The traffic store is a different matter and is shown raw, because it is raw on
purpose: a replay that cannot send the real cookie proves nothing. The traffic
browser is the one place on this page where a live credential is on screen.

---

## What it deliberately cannot do

- **Drive a run.** No start, no stop, no pause, no abort, no hint. The bus
  carries control events in the other direction and this server never emits
  one. Use the terminal.
- **Send anything at a target.** There is no replay button, no "try this
  again", no proxy. `scripts/traffic replay` does that, from a shell, where the
  guards are in the path.
- **Edit scope, or anything else.** Nothing here writes to an engagement
  directory. `scope.yaml` is the authorization boundary and widening it is a
  human action taken in an editor, outside a run.
- **Serve to more than one person.** There is one token, no accounts, no roles
  and no audit of who looked at what. It is a local tool for the operator.
- **Render a captured page.** You can read a response's bytes and download
  them. You cannot ask this UI to show you what the page looked like, because
  that means executing a target's markup in a context that can reach the
  engagements.
- **Show `inconclusive`.** The brief for this page listed it as a verdict
  state; `cli/src/verdicts.ts` has five states and that is not one of them. The
  UI accepts it if a row ever carries it, and shows nothing for it until then.
  The honest sixth bucket is `open`, which is not a state in the file at all. It
  is the absence of a row, and the ledger view synthesises it.
- **Tell you a phase ran when the events do not say so.** A phase with no
  `phase:start` in `run-events.jsonl` is drawn as pending, even when other
  artifacts suggest it ran. Guessing would make the rail prettier and less
  true.

---

## Running it

```bash
mythos web                      # loopback, random port, token printed
mythos web --port 8787          # pin the port
mythos web --engagements /path  # read a different directory
```

No dependency was added for any of it. The server is `node:http` and four other
node built-ins; the page is one HTML file, one stylesheet, one ES module and
one SVG, served from disk with no bundler, no framework and no build step at
runtime. `npm run build` compiles the server and copies those four files.

It reads and writes nothing outside the engagements root, starts no process,
and makes no outbound connection. The checks for all of that are in
`cli/src/web/selftest.ts` and run in about a second with no network, no docker
and no model.
