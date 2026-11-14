/**
 * Bytes on a socket, with their own recorder.
 *
 * Modern request smuggling is no longer a timing game. Kettle's "HTTP/1.1 must
 * die" (6 August 2025) moved detection to a baseline request compared against a
 * trigger request, and the interesting variants — 0.CL, CL.0, Expect-based,
 * H2.TE — are decided by framing the client chooses deliberately. None of that
 * survives a library that writes the headers for you.
 *
 * It cannot go through the recording proxy either, and that is architectural
 * rather than a detail: `scripts/traffic` is an HTTP/1.1 stdlib forward proxy
 * that parses each message's framing, so a 0.CL probe deadlocks it and HTTP/2
 * cannot cross it at all. A tool that simply bypasses the proxy would leave no
 * record of the most dangerous requests in the engagement, so this one tees its
 * own: the same `traffic/log.jsonl`, one line per connection, the bytes exactly
 * as they crossed the wire.
 *
 * Reader side: `scripts/traffic` reads these lines. `list` marks them RAW with
 * no method and no status, `show` prints the bytes verbatim plus a count of
 * CRLF against bare LF and bare CR (the thing a desync proof turns on), and
 * `replay` resends `req` byte for byte without parsing its framing. `export`
 * puts them under `log._mythos.raw` rather than among the HAR entries, because
 * a parsed entry rebuilt from ambiguous framing would describe a request that
 * was never sent.
 *
 * It ignores the `m`, `p` and `s` fields written below and derives its own hint
 * from the first line instead. That is the right call and they are kept only
 * because a method and a path make the record readable next to the proxy's: a
 * parser's opinion has no business sitting beside bytes whose whole value is
 * that nobody parsed them.
 *
 * Every call opens a fresh connection and closes it. A connection is never
 * reused across calls: a desync probe leaves the socket poisoned by design, and
 * the next request on it would be answered with whatever the previous one
 * queued — which, on a shared front end, can be a real user's request.
 */
import { appendFileSync, mkdirSync } from "node:fs";
import { connect as netConnect, isIP, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { resolve } from "node:path";

/** One write, and how long to wait before sending it. */
export interface RawWrite {
  bytes: string;
  delay_ms?: number;
}

export interface RawCall {
  host: string;
  port: number;
  tls?: boolean;
  writes: RawWrite[];
  /** Sent first, on a connection of its own: the control a desync probe is read against. */
  baseline?: RawWrite[];
  half_close?: boolean;
  read_timeout_ms?: number;
  why: string;
  /** The engagement directory, where the tee record goes. */
  dir: string;
}

interface Reply {
  sent: number[];
  received: number;
  bytes: Buffer;
  dur: number;
  error?: string;
  cut: boolean;
}

/** Enough of a response to judge it; a raw probe is read by its first lines. */
const SHOW = 4000;
/** Bodies beyond this are not what a desync probe is looking at. */
const CAP = 1 << 20;

/**
 * The escapes a caller needs to write a request line by hand. Anything else a
 * backslash precedes is kept as it was typed, so a payload containing a literal
 * backslash does not need doubling.
 */
export function unescapeBytes(s: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\" || i === s.length - 1) {
      out.push(...Buffer.from(s[i]!, "utf8"));
      continue;
    }
    const c = s[++i]!;
    if (c === "r") out.push(13);
    else if (c === "n") out.push(10);
    else if (c === "t") out.push(9);
    else if (c === "0") out.push(0);
    else if (c === "\\") out.push(92);
    else if (c === "x" && /^[0-9a-fA-F]{2}/.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(...Buffer.from(`\\${c}`, "utf8"));
  }
  return Buffer.from(out);
}

/** The method and path of the first request in the bytes, for the record's index line. */
export function requestLine(b: Buffer): { m: string; p: string } {
  const first = b.subarray(0, 8192).toString("latin1").split("\r\n")[0] ?? "";
  const bits = first.split(" ");
  return { m: bits[0] ?? "", p: bits.length > 1 ? bits[1]! : "" };
}

/** The first status code in a response, or null when nothing parsed as one. */
export function statusOf(b: Buffer): number | null {
  const m = /HTTP\/[\d.]+ (\d{3})/.exec(b.subarray(0, 8192).toString("latin1"));
  return m ? Number(m[1]) : null;
}

/** The line appended to traffic/log.jsonl, shaped like the proxy's own records. */
export function rawRecord(
  call: Pick<RawCall, "host" | "port" | "tls" | "half_close" | "why">,
  writes: RawWrite[],
  reply: Reply,
  role: string,
  now = Date.now(),
): Record<string, unknown> {
  const sent = Buffer.concat(writes.map((w) => unescapeBytes(w.bytes)));
  const { m, p } = requestLine(sent);
  return {
    kind: "raw",
    t: Math.round(now - reply.dur * 1000) / 1000,
    dur: Math.round(reply.dur * 1000) / 1000,
    ttfb: null,
    client: "mythos-raw",
    scheme: call.tls ? "https" : "http",
    host: call.host,
    port: call.port,
    ip: null,
    m,
    p,
    s: statusOf(reply.bytes),
    ua: "",
    req: sent.toString("base64"),
    res: reply.bytes.toString("base64"),
    req_cut: false,
    res_cut: reply.cut,
    role,
    writes: writes.map((w) => ({ bytes: unescapeBytes(w.bytes).length, delay_ms: w.delay_ms ?? 0 })),
    half_close: Boolean(call.half_close),
    why: call.why,
    error: reply.error ?? null,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** One connection: dial, write in order, read until it goes quiet, hang up. */
function once(call: RawCall, writes: RawWrite[]): Promise<Reply> {
  return new Promise((done) => {
    const t0 = Date.now();
    const chunks: Buffer[] = [];
    const sent: number[] = [];
    let received = 0;
    let cut = false;
    let error: string | undefined;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const socket: Socket = call.tls
      ? tlsConnect({
          host: call.host,
          port: call.port,
          // The target's certificate is not the subject of the test, and a lab
          // target's is usually self-signed.
          rejectUnauthorized: false,
          ...(isIP(call.host) ? {} : { servername: call.host }),
        })
      : netConnect({ host: call.host, port: call.port });

    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.destroy();
      done({
        sent,
        received,
        bytes: Buffer.concat(chunks),
        dur: (Date.now() - t0) / 1000,
        error,
        cut,
      });
    };

    socket.on("data", (d: Buffer) => {
      received += d.length;
      if (received <= CAP) chunks.push(d);
      else cut = true;
    });
    socket.on("close", finish);
    socket.on("end", finish);
    socket.on("error", (e: Error) => {
      error = e.message;
      finish();
    });

    socket.on(call.tls ? "secureConnect" : "connect", () => {
      void (async () => {
        try {
          for (const w of writes) {
            if (w.delay_ms) await sleep(Math.min(w.delay_ms, 30_000));
            if (settled) return;
            const buf = unescapeBytes(w.bytes);
            socket.write(buf);
            sent.push(buf.length);
          }
          // A half close is what tells a server "that is the whole request" when
          // the framing says nothing, and it is the CL.0 probe's whole point.
          if (call.half_close) socket.end();
        } catch (e) {
          error = (e as Error).message;
          finish();
          return;
        }
        timer = setTimeout(finish, call.read_timeout_ms ?? 10_000);
      })();
    });
  });
}

/**
 * Run the call: the baseline connection first when one is given, then the
 * probe, each on its own socket, each appended to the engagement's log.
 */
export async function sendRaw(call: RawCall): Promise<string> {
  const legs: Array<[string, RawWrite[]]> = [];
  if (call.baseline?.length) legs.push(["baseline", call.baseline]);
  legs.push(["probe", call.writes]);

  const out: string[] = [];
  for (const [role, writes] of legs) {
    const reply = await once(call, writes);
    record(call.dir, rawRecord(call, writes, reply, role));
    const status = statusOf(reply.bytes);
    out.push(
      `${role}: ${writes.length} write(s), ${reply.sent.join(" + ") || 0} bytes sent, ` +
        `${reply.received} bytes received in ${reply.dur.toFixed(2)}s` +
        `${status ? `, first status ${status}` : ""}${reply.cut ? ", response truncated" : ""}` +
        `${reply.error ? `, socket error: ${reply.error}` : ""}\n` +
        // latin1 so the bytes survive the trip: a desync response is read by its
        // status lines and header framing, not as text.
        (reply.bytes.length
          ? reply.bytes.subarray(0, SHOW).toString("latin1") +
            (reply.received > SHOW ? `\n…[${reply.received - SHOW} bytes not shown]…` : "")
          : "(nothing came back)"),
    );
  }
  return out.join("\n\n");
}

/** Append one line, 0600, the way scripts/traffic's own `append` does. */
function record(dir: string, rec: Record<string, unknown>): void {
  try {
    const path = resolve(dir, "traffic", "log.jsonl");
    mkdirSync(resolve(path, ".."), { recursive: true, mode: 0o700 });
    appendFileSync(path, `${JSON.stringify(rec)}\n`, { mode: 0o600 });
  } catch {
    // An unrecordable probe is still a probe that was sent; losing the line is
    // worse than silence only if it is hidden, and the summary says what ran.
  }
}
