/**
 * `mythos web` — the read-only overview of an engagement.
 *
 * The terminal view stays the primary interface. This is the same truth for
 * someone who does not want to read a terminal, and for the moment after a run
 * when the question is "what did this thing touch" rather than "what is it
 * doing now".
 *
 * It renders bytes a hostile server chose, and it sits on top of a directory
 * holding credentials, session cookies and proofs of exploitation. So the
 * posture is not a preference:
 *
 *   loopback only       127.0.0.1 unless `--host` is passed on purpose, which
 *                       the help text says puts engagement data on the network
 *   bearer token        minted per run, in the printed URL, checked on every
 *                       request including the stylesheet. No cookie, no CORS
 *                       header, ever
 *   read only           nothing here starts, stops or edits an engagement,
 *                       sends a request at a target, or touches scope.yaml.
 *                       There is no write path to add a flag to
 *   inert rendering     response bodies are served as text/plain and drawn into
 *                       text nodes. A stored-XSS payload captured from a target
 *                       is a string here, and `selftest.ts` proves it
 *   nothing leaves      no telemetry, no CDN, no outbound request. A strict CSP
 *                       with no `unsafe-inline` is served on every response
 *
 * Everything the page needs is served from `assets/`, which is why the UI works
 * with no build step: `tsc` compiles this file, and the assets are copied.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ENGAGEMENTS } from "../paths.js";
import {
  PathError,
  bundleOf,
  citedIds,
  engagementDir,
  fileIn,
  findingRecords,
  ledger,
  listEngagements,
  readEvents,
  reportOf,
  scopePanel,
  summary,
  trafficIndex,
  trafficRecord,
  verdictRows,
  walk,
} from "./data.js";
import { tarGz } from "./bundle.js";

export interface WebOptions {
  /** The engagements root. Only directories under it are ever opened. */
  root?: string;
  host?: string;
  port?: number;
  /** Required before a non-loopback bind is accepted. */
  allowRemote?: boolean;
  /** Reserved for a future non-scope-affecting action. Nothing reads it yet. */
  allowActions?: boolean;
}

export interface WebServer {
  url: string;
  host: string;
  port: number;
  token: string;
  root: string;
  close(): Promise<void>;
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost", "[::1]"]);

export const isLoopback = (host: string) => LOOPBACK.has(host.replace(/^\[|\]$/g, ""));

/**
 * The one strict policy, widened by hand where the page actually needs it.
 *
 * `default-src 'none'` means a payload that reaches the DOM has nothing to
 * reach for: no inline script, no remote script, no form target, no frame.
 * `img-src` carries `data:` for the inline mark only; every screenshot comes
 * from this origin.
 */
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join("; ");

function headers(res: ServerResponse, type: string, extra: Record<string, string> = {}) {
  res.setHeader("Content-Type", type);
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cache-Control", "no-store");
  // Access-Control-Allow-Origin is never set. A page on another origin must not
  // be able to read an engagement, token or no token.
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
}

/** JSON with the characters that could ever matter in an HTML context escaped. */
export function safeJson(value: unknown): string {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

export function tokenOk(expected: string, given: string | null): boolean {
  if (!given) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(given);
  // timingSafeEqual throws on a length mismatch, so the length is compared
  // first and the comparison still runs on equal-length input only.
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The token from the query string or an Authorization header, never a cookie. */
export function tokenOf(url: URL, req: IncomingMessage): string | null {
  const q = url.searchParams.get("t");
  if (q) return q;
  const auth = req.headers.authorization ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m?.[1] ?? null;
}

/**
 * Reject a request whose Host header is not the address we bound to.
 *
 * This is the DNS-rebinding stop. A page on the internet can make a name point
 * at 127.0.0.1 and then it is same-origin as far as the browser is concerned;
 * what it cannot do is send a Host header this server accepts.
 */
export function hostOk(bind: string, hostHeader: string | undefined, port: number): boolean {
  if (!hostHeader) return false;
  const name = hostHeader.replace(/:\d+$/, "").replace(/^\[|\]$/g, "").toLowerCase();
  void port;
  if (isLoopback(name)) return true;
  return name === bind.replace(/^\[|\]$/g, "").toLowerCase();
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
};

const IMAGE_TYPES = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

export function assetDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/web/assets after a build; src/web/assets when run straight from
  // source with tsx, which is how the selftest and `npm run dev` reach it.
  for (const c of [join(here, "assets"), join(here, "..", "..", "src", "web", "assets")]) {
    if (existsSync(join(c, "index.html"))) return c;
  }
  return join(here, "assets");
}

export async function serve(opts: WebOptions = {}): Promise<WebServer> {
  const root = opts.root ?? ENGAGEMENTS;
  const host = opts.host ?? "127.0.0.1";
  if (!isLoopback(host) && !opts.allowRemote) {
    throw new Error(
      `refusing to bind ${host}: that puts engagement data — credentials, session ` +
        `cookies and proofs of exploitation — on the network. Pass --allow-remote if ` +
        `that is what you want.`,
    );
  }
  const token = randomBytes(32).toString("base64url");
  const assets = assetDir();

  const server = createServer((req, res) => {
    void handle(req, res, { root, token, assets, host }).catch((e: Error) => {
      if (!res.headersSent) {
        headers(res, "application/json");
        res.statusCode = e instanceof PathError ? 400 : 500;
      }
      res.end(safeJson({ error: e.message }));
    });
  });

  const port = await new Promise<number>((ok, fail) => {
    server.once("error", fail);
    server.listen(opts.port ?? 0, host, () => {
      const a = server.address();
      ok(typeof a === "object" && a ? a.port : 0);
    });
  });

  const shown = host.includes(":") ? `[${host}]` : host;
  return {
    url: `http://${shown}:${port}/?t=${token}`,
    host,
    port,
    token,
    root,
    close: () => new Promise<void>((ok) => server.close(() => ok())),
  };
}

interface Ctx {
  root: string;
  token: string;
  assets: string;
  host: string;
}

async function handle(req: IncomingMessage, res: ServerResponse, ctx: Ctx) {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method !== "GET" && req.method !== "HEAD") {
    // Read-only means read-only: there is no handler to reach.
    headers(res, "application/json", { Allow: "GET, HEAD" });
    res.statusCode = 405;
    res.end(safeJson({ error: "this server is read-only" }));
    return;
  }
  if (!hostOk(ctx.host, req.headers.host, 0)) {
    headers(res, "text/plain; charset=utf-8");
    res.statusCode = 421;
    res.end("wrong host\n");
    return;
  }
  if (!tokenOk(ctx.token, tokenOf(url, req))) {
    headers(res, "text/plain; charset=utf-8");
    res.statusCode = 401;
    res.end("mythos web: this URL needs the token the command printed\n");
    return;
  }

  const path = url.pathname;
  if (path === "/" || path === "/index.html") return shell(res, ctx);
  if (path.startsWith("/api/")) return api(req, res, url, ctx);
  if (/^\/[a-z0-9._-]+$/i.test(path)) return asset(res, ctx, path.slice(1));

  headers(res, "text/plain; charset=utf-8");
  res.statusCode = 404;
  res.end("not found\n");
}

/** The shell, with the token woven into the two asset URLs the browser fetches. */
function shell(res: ServerResponse, ctx: Ctx) {
  const html = readFileSync(join(ctx.assets, "index.html"), "utf8").replaceAll("__TOKEN__", ctx.token);
  headers(res, TYPES[".html"]!);
  res.end(html);
}

function asset(res: ServerResponse, ctx: Ctx, name: string) {
  const file = fileIn(ctx.assets, name);
  if (!existsSync(file)) {
    headers(res, "text/plain; charset=utf-8");
    res.statusCode = 404;
    res.end("not found\n");
    return;
  }
  headers(res, TYPES[extname(file).toLowerCase()] ?? "application/octet-stream");
  res.end(readFileSync(file));
}

const json = (res: ServerResponse, value: unknown, status = 200) => {
  headers(res, "application/json; charset=utf-8");
  res.statusCode = status;
  res.end(safeJson(value));
};

async function api(req: IncomingMessage, res: ServerResponse, url: URL, ctx: Ctx) {
  const parts = url.pathname.split("/").filter(Boolean).slice(1);

  if (parts[0] === "engagements") return json(res, { root: ctx.root, engagements: listEngagements(ctx.root) });
  if (parts[0] !== "e" || !parts[1]) return json(res, { error: "no such endpoint" }, 404);

  const dir = engagementDir(ctx.root, decodeURIComponent(parts[1]));
  if (!existsSync(join(dir, "scope.yaml"))) return json(res, { error: "no such engagement" }, 404);
  const what = parts[2] ?? "summary";

  switch (what) {
    case "summary":
      return json(res, summary(dir));
    case "events": {
      const from = Number(url.searchParams.get("from") ?? 0) || 0;
      return json(res, readEvents(dir, from));
    }
    case "stream":
      return stream(req, res, dir, Number(url.searchParams.get("from") ?? 0) || 0);
    case "findings":
      return json(res, { findings: findingRecords(dir).map(({ body, ...rest }) => ({ ...rest, bytes: body.length })) });
    case "finding": {
      const id = decodeURIComponent(parts[3] ?? "");
      const found = findingRecords(dir).find((f) => f.id === id);
      if (!found) return json(res, { error: "no such finding" }, 404);
      const cited = citedIds(`${found.body} ${found.proof ?? ""} ${found.negativeControl ?? ""}`);
      const proofIds = citedIds(found.proof ?? "");
      const controlIds = citedIds(found.negativeControl ?? "");
      return json(res, {
        finding: found,
        bundle: bundleOf(dir, id),
        proof: proofIds.map((n) => trafficRecord(dir, n)).filter(Boolean),
        control: controlIds.map((n) => trafficRecord(dir, n)).filter(Boolean),
        cited: cited.map((n) => trafficRecord(dir, n)?.row).filter(Boolean),
      });
    }
    case "verdicts":
      return json(res, { rows: ledger(dir), surface: verdictRows(dir).surface.length });
    case "traffic": {
      if (parts[3]) {
        const rec = trafficRecord(dir, Number(parts[3]));
        return rec ? json(res, rec) : json(res, { error: "no such record" }, 404);
      }
      return json(res, trafficIndex(dir, {
        q: url.searchParams.get("q") ?? "",
        kind: url.searchParams.get("kind") ?? "all",
        deep: url.searchParams.get("deep") === "1",
        offset: Number(url.searchParams.get("offset") ?? 0) || 0,
        limit: Number(url.searchParams.get("limit") ?? 200) || 200,
      }));
    }
    case "scope":
      return json(res, scopePanel(dir));
    case "report":
      return json(res, reportOf(dir));
    case "image":
      return file(res, dir, url.searchParams.get("path") ?? "", "inline");
    case "download":
      return file(res, dir, url.searchParams.get("path") ?? "", "attachment");
    case "bundle":
      return bundle(res, dir, decodeURIComponent(parts[3] ?? ""));
    default:
      return json(res, { error: "no such endpoint" }, 404);
  }
}

/**
 * One file out of the engagement directory.
 *
 * `fileIn` is the whole check and it runs before anything is opened: a `path`
 * of `../../etc/passwd` resolves outside the base and throws. Images keep their
 * real type so the browser can draw them; everything else leaves as an opaque
 * attachment, because a captured HTML page with a payload in it must never be
 * handed to the browser as a document.
 */
function file(res: ServerResponse, dir: string, rel: string, how: "inline" | "attachment") {
  if (!rel) return json(res, { error: "no path" }, 400);
  const abs = fileIn(dir, rel);
  if (!existsSync(abs) || !statSync(abs).isFile()) return json(res, { error: "no such file" }, 404);
  const ext = extname(abs).toLowerCase();
  const name = rel.split("/").at(-1) ?? "file";
  if (how === "inline") {
    if (!IMAGE_TYPES.has(ext)) return json(res, { error: "only images render inline" }, 415);
    headers(res, TYPES[ext]!, { "Content-Disposition": `inline; filename="${safeName(name)}"` });
  } else {
    headers(res, "application/octet-stream", {
      "Content-Disposition": `attachment; filename="${safeName(name)}"`,
    });
  }
  res.end(readFileSync(abs));
}

const safeName = (n: string) => n.replace(/[^A-Za-z0-9._-]/g, "_");

function bundle(res: ServerResponse, dir: string, id: string) {
  const base = fileIn(dir, join("evidence", id));
  if (!existsSync(base) || !statSync(base).isDirectory()) {
    return json(res, { error: "no evidence bundle for this finding" }, 404);
  }
  const files = walk(base).map((rel) => ({ rel, abs: fileIn(base, rel) }));
  if (!files.length) return json(res, { error: "the bundle is empty" }, 404);
  headers(res, "application/gzip", {
    "Content-Disposition": `attachment; filename="evidence-${safeName(id)}.tar.gz"`,
  });
  res.end(tarGz(files, `evidence-${safeName(id)}`));
}

/**
 * The live view.
 *
 * `run-events.jsonl` is the bus: `Bus.record()` appends every event to it as it
 * is emitted, so tailing the file and subscribing to the emitter deliver the
 * same stream in the same order. That is why this server needs no hook into a
 * running process — and why it works the same on a run that finished last week.
 */
function stream(req: IncomingMessage, res: ServerResponse, dir: string, from: number) {
  headers(res, "text/event-stream; charset=utf-8", { Connection: "keep-alive" });
  res.flushHeaders?.();
  let cursor = from;
  let closed = false;

  const tick = () => {
    if (closed) return;
    const { events, total } = readEvents(dir, cursor);
    if (events.length) {
      cursor = total;
      res.write(`data: ${safeJson({ from: cursor, events })}\n\n`);
    } else {
      res.write(": idle\n\n");
    }
  };
  const timer = setInterval(tick, 900);
  tick();

  const stop = () => {
    closed = true;
    clearInterval(timer);
  };
  req.on("close", stop);
  res.on("close", stop);
}
