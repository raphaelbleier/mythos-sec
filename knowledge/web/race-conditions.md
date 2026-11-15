# Race Conditions (limit overrun, TOCTOU)

**Class:** business logic  **Updated:** 2026-11-15

## What it is
A check and the state change it guards are not atomic, so requests that arrive
together all pass the check: a coupon redeemed twice, a balance spent twice, a
rate limit or invite quota exceeded. Most common on redeem, transfer, vote,
signup-bonus and "one per user" endpoints.

## How Mythos detects it
- `scripts/race` (`limit`, `single-packet`, `toctou`): a sequential control
  wave against a parallel wave on a fresh one-shot resource, N <= 20, 6
  repeats, the authoritative state read back as the owner after each wave, and
  a hit rate with intervals. HTTP/2 single-packet is hand-rolled in the script
  (stdlib sockets, no h2 library); the HTTP/1.1 last-byte-sync fallback runs
  when ALPN `h2` is not negotiated and the output names which mode ran.
- nuclei `race: true` + `race_count: N` for simple cases (whether it uses
  single-packet is undocumented).

## The statistics rule: one success is not a finding

A race is stochastic. The same burst against the same endpoint overruns on some
attempts and not others, so the number a report may print is a **rate with an
interval**, never a fraction and never an anecdote.

- The Bernoulli trial is a **whole repeat** — one fresh object, one control
  wave, one parallel wave — not one request in the burst. Twenty requests
  arriving together are one trial, not twenty.
- Report Wilson for the body of the range and Clopper-Pearson for the edges,
  which is where a race measurement lives (0/k and k/k). `scripts/race` prints
  both, in the same shape `scripts/aiplatform` uses for injection trials.
- `candidate` requires the parallel arm's 95% **lower** bound to clear the
  control arm's 95% **upper** bound. With six repeats, 6/6 against 0/6 gives
  61% against 46% and clears. 3/3 against 0/3 gives 44% against 71% and does
  not: it is `inconclusive`, which is why `--repeats` defaults to 6 and why two
  repeats is not a measurement. This is the same arithmetic that makes 0/6 mean
  "below 46%" rather than "zero".
- The **sequential control must come out clean**, in every repeat. A control
  that overruns says the action was never once-only, or the setup did not
  produce a fresh object; either way the concurrency explains nothing and the
  verdict is `inconclusive` regardless of how good the parallel arm looks.
- The **oracle is the authoritative state read back as the owner**, before and
  after each wave, and the delta must exceed one unit. A racing response body
  is not evidence in either direction: an endpoint can answer 200 N times and
  have written once, and it can answer 409 and have credited the balance
  anyway. `scripts/race` keeps the response-derived count as
  `apparent_successes`, explicitly labelled a diagnostic.
- Say which **sync mode** produced the number. A `no-signal` under
  `h1-last-byte-sync` is a far weaker statement than one under
  `h2-single-packet`, and the two are not interchangeable in a report.

## How to confirm (non-destructive)
Only on a resource the agent created, or one the owner endpoint lists as the
agent's. Proof = every sequential wave allows exactly one, the parallel waves
overrun in enough repeats to clear the control's interval, and the
authoritative state moved by more than one unit each time. Never race a
destructive action unless this run created the object. The recorded bytes are
the proof: the validate phase replays them (`scripts/traffic replay <id>`), and
the exploit worker writes `candidate`, never `confirmed`.

## The single-packet attack, mechanically

Kettle, "Smashing the state machine" (BH USA 2023): last-byte sync still sends
N TCP segments that traverse the network independently, so jitter staggers
arrival by more than the window is wide. The single-packet attack removes the
network from the experiment by finishing every request inside **one segment**.

Over HTTP/2 that is possible because a request is a sequence of frames and the
client decides when each one leaves:

1. Connection preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, then an empty
   `SETTINGS` frame, then a `WINDOW_UPDATE` large enough that N bodies and N
   replies do not stall on flow control.
2. Read the server's `SETTINGS`, ACK it (`SETTINGS` with flag `0x1`), and read
   `MAX_CONCURRENT_STREAMS` (setting `0x3`) out of it. Below N, the attack
   cannot be set up and the honest move is to fall back and say so.
3. One `HEADERS` frame per stream (ids 1, 3, 5, …) with `END_HEADERS` and
   **not** `END_STREAM`: the request is deliberately unfinished. HPACK needs no
   dynamic table for this — literal header field without indexing, new name
   (`0x00`, length-prefixed name, length-prefixed value, no Huffman) is legal,
   stateless and auditable. Pseudo-headers `:method :path :scheme :authority`
   come first.
4. For a request with a body, a `DATA` frame carrying all but the last byte,
   also without `END_STREAM`.
5. Pause (~100 ms) so the server parks every stream.
6. **One `send()`** of every final frame: an empty `DATA` with `END_STREAM`, or
   the last byte of the body with `END_STREAM`. Nine bytes of frame header plus
   at most one byte of payload each, so twenty of them are ~200 bytes and fit
   inside one 1500-byte segment with room to spare. Reported 4–10x more
   effective than last-byte sync, ~20–30 requests per packet.

Reading the replies back is deliberately shallow: a response `:status` is
decoded only when the server encoded it as an indexed HPACK static entry
(`0x88`..`0x8e` for 200, 204, 206, 304, 400, 404, 500). A literal status may be
Huffman-coded, and a Huffman decoder is 257 table entries that buy nothing
here, because the `DATA` frames arrive as plaintext and the read-back is the
oracle. `scripts/race` reports `status: null` for such a stream rather than
guessing.

Over HTTP/1.1 there is no equivalent: the fallback opens N connections, sends
all but the last byte of each, and releases the last bytes from a thread
barrier. It works, it is weaker, and the mode belongs in the finding.

## Remediation
Make check-and-update atomic: DB transaction with row lock or a conditional
update (`UPDATE ... WHERE used = false`), unique constraints, idempotency keys.

## Lab
`lab/racelab` (host ports 5035 plaintext, 5036 HTTP/2 over TLS) has a
single-use coupon with a non-atomic check, a confirm-then-use TOCTOU pair and a
balance endpoint for read-back. `RACE_WINDOW_MS=0` closes the window, which is
the control for the measurement itself: a tool that still reports an overrun
against it is reporting noise.

## Sources
- PortSwigger Research, "Smashing the state machine" (2023-08)
- RFC 9113 (HTTP/2) §4.1, §6; RFC 7541 (HPACK) §5.1, §6.2.2
- nxenon/h2spacex README (2026-10)
- ProjectDiscovery nuclei docs, HTTP race conditions (2026-10)
