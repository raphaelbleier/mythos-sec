/**
 * Reading an engagement directory, and nothing else.
 *
 * Every function here opens files the run already wrote. None of them writes,
 * none of them spawns a process, and none of them reaches the network — that is
 * the whole security posture of `mythos web` expressed as a module boundary,
 * so a reviewer can check the claim by reading the imports.
 *
 * The shapes are not re-invented: `scope.yaml` goes through the CLI's own
 * `readScope`, the surface map through `surfaceFromMap`, and `traffic/log.jsonl`
 * is read by the format `scripts/traffic` documents in its own file. A second
 * parser here would drift from the one the report is checked against, and the
 * one that drifts is always the one that matters.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { readScope, type Scope } from "../scope.js";
import { surfaceFromMap, endpointKey } from "../verdicts.js";

export interface VerdictRow {
  endpoint: string;
  state: string;
  note: string;
  by: string;
  at: string;
}

export interface EngagementSummary {
  dir: string;
  target: string;
  started: string | null;
  ended: string | null;
  running: boolean;
  durationS: number | null;
  phase: string | null;
  phaseState: string | null;
  phases: Array<{ name: string; state: string; wall: number | null; reason: string | null }>;
  severities: Record<string, number>;
  findingsTotal: number;
  verdicts: Record<string, number>;
  surfaceTotal: number;
  open: number;
  rateLimitRps: number;
  requests: number | null;
  hasReport: boolean;
}

// ------------------------------------------------------------------ paths

/**
 * An engagement directory, resolved and proven to be inside the root.
 *
 * Every path the HTTP layer ever opens comes through here or through
 * `fileIn`. `resolve` collapses `..` before the check, so a name like
 * `../../etc` fails the prefix test rather than escaping it, and a symlinked
 * directory is rejected because the real path is compared, not the joined one.
 */
export function engagementDir(root: string, name: string): string {
  const base = realRoot(root);
  const dir = resolve(base, name);
  if (dir !== base && !dir.startsWith(base + sep)) {
    throw new PathError(`outside the engagements root: ${name}`);
  }
  if (dir === base) throw new PathError("not an engagement directory");
  return dir;
}

/** A file inside one engagement, by the same rule. */
export function fileIn(dir: string, rel: string): string {
  const base = resolve(dir);
  const file = resolve(base, rel);
  if (!file.startsWith(base + sep)) throw new PathError(`outside the engagement: ${rel}`);
  return file;
}

export class PathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathError";
  }
}

const realRoot = (root: string) => resolve(root);

// ------------------------------------------------------------------ reading

const readJson = <T>(file: string, fallback: T): T => {
  try {
    return JSON.parse(readFileSync(file, "utf8")) as T;
  } catch {
    return fallback;
  }
};

const readText = (file: string): string | null => {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return null;
  }
};

export interface RunEvent {
  ts?: string;
  t: string;
  [k: string]: unknown;
}

/** The run's event stream. This file *is* the bus: `Bus.record()` appends every
 *  event to it verbatim, so tailing it and subscribing are the same thing. */
export function readEvents(dir: string, from = 0): { events: RunEvent[]; total: number } {
  const text = readText(join(dir, "run-events.jsonl"));
  if (text === null) return { events: [], total: 0 };
  const lines = text.split("\n").filter((l) => l.trim());
  const out: RunEvent[] = [];
  for (const line of lines.slice(from)) {
    try {
      out.push(JSON.parse(line) as RunEvent);
    } catch {
      /* a half-written last line during a live run is read again next poll */
    }
  }
  return { events: out, total: lines.length };
}

export function listEngagements(root: string): EngagementSummary[] {
  let names: string[];
  try {
    names = readdirSync(realRoot(root));
  } catch {
    return [];
  }
  const out: EngagementSummary[] = [];
  for (const name of names) {
    let dir: string;
    try {
      dir = engagementDir(root, name);
    } catch {
      continue;
    }
    if (!existsSync(join(dir, "scope.yaml"))) continue;
    try {
      out.push(summary(dir));
    } catch {
      /* a directory we cannot read is not a reason to show none of them */
    }
  }
  return out.sort((a, b) => (a.started ?? a.dir) < (b.started ?? b.dir) ? 1 : -1);
}

interface RunJson {
  window?: { start?: string; end?: string; running?: boolean; duration_s?: number };
  requests?: { total?: number };
  rate?: { limit_rps?: number };
  phases?: Array<{ name?: string; start?: string; end?: string; requests?: number }>;
  scope?: { out_of_scope_requests?: number; tool_invocations_flagged?: unknown[] };
  hosts?: Record<string, { requests?: number; in_scope?: boolean }>;
}

const PHASE_ORDER = ["recon", "triage", "scan", "exploit", "validate", "report"];

export function summary(dir: string): EngagementSummary {
  const scope = scopeOf(dir);
  const run = readJson<RunJson>(join(dir, "run.json"), {});
  const { events } = readEvents(dir);
  const ledger = verdictRows(dir);
  const surface = surfaceOf(dir);

  const phases = phaseStates(events, run);
  const last = [...phases].reverse().find((p) => p.state !== "pending") ?? null;
  const ended = events.find((e) => e.t === "run:end");
  const started = events.find((e) => e.t === "run:start");

  const findings = findingRecords(dir);
  const severities: Record<string, number> = {};
  for (const f of findings) severities[f.severity] = (severities[f.severity] ?? 0) + 1;

  const verdicts: Record<string, number> = {};
  for (const r of ledger.rows) verdicts[r.state] = (verdicts[r.state] ?? 0) + 1;

  const startedAt = run.window?.start ?? (typeof started?.ts === "string" ? started.ts : null);
  const endedAt = run.window?.end ?? (typeof ended?.ts === "string" ? ended.ts : null);
  const duration =
    run.window?.duration_s ??
    (typeof ended?.wall === "number" ? ended.wall : null) ??
    (startedAt && endedAt ? (Date.parse(endedAt) - Date.parse(startedAt)) / 1000 : null);

  return {
    dir: basename(dir),
    target: scope?.target ?? "unknown",
    started: startedAt,
    ended: endedAt,
    // A run with a start and no end is live. run.json is written by the
    // recorder when it stops, so its own flag wins when it is there.
    running: run.window?.running ?? (Boolean(started) && !ended),
    durationS: duration,
    phase: last?.name ?? null,
    phaseState: last?.state ?? null,
    phases,
    severities,
    findingsTotal: findings.length,
    verdicts,
    surfaceTotal: surface.length,
    open: ledger.open.length,
    rateLimitRps: scope?.rules.rate_limit_rps ?? 0,
    requests: run.requests?.total ?? null,
    hasReport: existsSync(join(dir, "report.md")),
  };
}

const basename = (d: string) => d.split(sep).filter(Boolean).at(-1) ?? d;

export function scopeOf(dir: string): Scope | null {
  const file = join(dir, "scope.yaml");
  if (!existsSync(file)) return null;
  try {
    return readScope(file);
  } catch {
    return null;
  }
}

/**
 * One row per phase, merging what the event stream says with what `run.json`
 * recorded. The stream is authoritative while a run is live; run.json is what
 * is left once the process is gone.
 */
function phaseStates(events: RunEvent[], run: RunJson) {
  const rows = PHASE_ORDER.map((name) => ({
    name,
    state: "pending",
    wall: null as number | null,
    reason: null as string | null,
    budget: null as number | null,
    startedAt: null as string | null,
    attempt: 0,
    of: 0,
  }));
  const by = new Map(rows.map((r) => [r.name, r]));
  for (const e of events) {
    if (e.t === "phase:start") {
      const r = by.get(String(e.phase));
      if (r) {
        r.state = "running";
        r.budget = typeof e.budget === "number" ? e.budget : null;
        r.startedAt = typeof e.ts === "string" ? e.ts : null;
        r.attempt = typeof e.attempt === "number" ? e.attempt : 0;
        r.of = typeof e.of === "number" ? e.of : 0;
      }
    }
    if (e.t === "phase:end") {
      const r = by.get(String(e.phase));
      if (r) {
        r.state = String(e.state);
        r.wall = typeof e.wall === "number" ? e.wall : null;
        r.reason = typeof e.reason === "string" ? e.reason : null;
      }
    }
  }
  // Without an event stream (an engagement driven by hand, or one whose log was
  // pruned) the traffic recorder's own phase markers still say what ran.
  if (!events.length) {
    for (const p of run.phases ?? []) {
      const r = by.get(String(p.name));
      if (r) {
        r.state = p.end ? "done" : "running";
        r.startedAt = p.start ?? null;
        r.wall = p.start && p.end ? Math.round((Date.parse(p.end) - Date.parse(p.start)) / 1000) : null;
      }
    }
  }
  return rows;
}

// ----------------------------------------------------------------- verdicts

export function verdictRows(dir: string): { rows: VerdictRow[]; open: string[]; surface: string[] } {
  const rows = readJson<VerdictRow[]>(join(dir, "verdicts.json"), []).map((r) => ({
    endpoint: String(r.endpoint ?? ""),
    state: String(r.state ?? "tested"),
    note: String(r.note ?? ""),
    by: String(r.by ?? ""),
    at: String(r.at ?? ""),
  }));
  const surface = surfaceOf(dir);
  const seen = new Set(rows.map((r) => endpointKey(r.endpoint)));
  const open = surface.filter((e) => !seen.has(endpointKey(e)));
  return { rows, open, surface };
}

function surfaceOf(dir: string): string[] {
  const f = join(dir, "surface.json");
  return existsSync(f) ? surfaceFromMap(f) : [];
}

/** The ledger with the gap folded in: a mapped endpoint nobody judged is a row
 *  in state `open`, because an omission that is invisible reads as coverage. */
export function ledger(dir: string): VerdictRow[] {
  const { rows, open } = verdictRows(dir);
  return [
    ...rows,
    ...open.map((endpoint) => ({
      endpoint,
      state: "open",
      note: "mapped by recon, never given a verdict",
      by: "",
      at: "",
    })),
  ];
}

// ----------------------------------------------------------------- findings

export interface FindingRecord {
  id: string;
  title: string;
  severity: string;
  state: string;
  cls: string;
  asset: string;
  route: string;
  param: string;
  cwe: number | null;
  cvss: { vector: string | null; score: number | null };
  cvss4: { vector: string | null; score: number | null; severity: string | null };
  proof: string | null;
  negativeControl: string | null;
  fingerprint: string | null;
  problems: string[];
  body: string;
}

interface FindingsJson {
  findings?: Array<Record<string, unknown>>;
  counts?: Record<string, number>;
  problems?: string[];
}

/**
 * The findings, from `findings.json` where the run produced one and from the
 * markdown files where it did not. A run that stopped before the report phase
 * still has findings on disk, and showing nothing for it would be a lie about
 * the work that was done.
 */
export function findingRecords(dir: string): FindingRecord[] {
  const data = readJson<FindingsJson>(join(dir, "findings.json"), {});
  const fromJson = (data.findings ?? []).map((f) => fromFindingJson(dir, f));
  if (fromJson.length) return fromJson;

  const fdir = join(dir, "findings");
  if (!existsSync(fdir)) return [];
  const out: FindingRecord[] = [];
  for (const name of readdirSync(fdir)) {
    if (!name.endsWith(".md")) continue;
    const text = readText(join(fdir, name)) ?? "";
    const field = (k: string) => new RegExp(`^${k}\\s*:\\s*(.+)$`, "mi").exec(text)?.[1]?.trim() ?? "";
    const vector = field("cvss") || field("cvss_vector");
    out.push({
      id: name.replace(/\.md$/, ""),
      title: field("title") || /^#\s*(.+)$/m.exec(text)?.[1]?.trim() || name,
      severity: (field("severity") || "unrated").toLowerCase(),
      state: field("state") || "unreported",
      cls: field("class"),
      asset: field("asset"),
      route: field("route"),
      param: field("param"),
      cwe: Number(field("cwe")) || null,
      cvss: { vector: vector || null, score: Number(field("cvss_score")) || null },
      cvss4: { vector: field("cvss4") || null, score: null, severity: null },
      proof: field("proof") || null,
      negativeControl: field("negative_control") || null,
      fingerprint: null,
      problems: [],
      body: text,
    });
  }
  return out.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
}

function fromFindingJson(dir: string, f: Record<string, unknown>): FindingRecord {
  const s = (k: string) => (typeof f[k] === "string" ? (f[k] as string) : "");
  const n = (k: string) => (typeof f[k] === "number" ? (f[k] as number) : null);
  const id = s("id");
  const file = s("file") || `${id}.md`;
  // `evidence` in findings.json is the redacted body scripts/findings produced.
  // Preferring it keeps this UI from undoing a redaction the pipeline applied.
  const body = s("evidence") || readText(join(dir, "findings", file)) || "";
  return {
    id,
    title: s("title") || id,
    severity: (s("severity") || "unrated").toLowerCase(),
    state: s("state") || "unreported",
    cls: s("class"),
    asset: s("asset"),
    route: s("route"),
    param: s("param"),
    cwe: n("cwe"),
    cvss: { vector: s("cvss_vector") || null, score: n("cvss_score") },
    cvss4: {
      vector: s("cvss4_vector") || null,
      score: n("cvss4_score"),
      severity: s("cvss4_severity") || null,
    },
    proof: s("proof") || null,
    negativeControl: s("negative_control") || null,
    fingerprint: s("fingerprint") || null,
    problems: Array.isArray(f.problems) ? (f.problems as string[]).map(String) : [],
    body,
  };
}

const SEVERITIES = ["critical", "high", "medium", "low", "info", "unrated"];
const sevRank = (s: string) => {
  const i = SEVERITIES.indexOf(s.toLowerCase());
  return i < 0 ? SEVERITIES.length : i;
};

/** Traffic record ids a finding cites, in the `traffic/422-424, 430` forms
 *  `scripts/evidence` reads. Same three forms, because all three appear. */
export function citedIds(text: string): number[] {
  const out = new Set<number>();
  for (const m of text.matchAll(/\btraffic[/#](\d+(?:\s*-\s*\d+)?(?:\s*,\s*\d+(?:\s*-\s*\d+)?)*)/g)) {
    for (const part of (m[1] ?? "").split(",")) {
      const range = part.trim().split("-").map((x) => Number(x.trim()));
      const a = range[0];
      const b = range.length > 1 ? range[1] : a;
      if (a === undefined || b === undefined || !Number.isFinite(a) || !Number.isFinite(b)) continue;
      if (b < a || b - a > 64) continue;
      for (let i = a; i <= b; i++) out.add(i);
    }
  }
  return [...out].sort((x, y) => x - y);
}

export interface Bundle {
  id: string;
  present: boolean;
  redacted: boolean | null;
  reproducible: boolean | null;
  generated: string | null;
  problems: string[];
  files: Array<{ path: string; sha256: string; bytes: number }>;
  screenshots: string[];
  oracle: unknown;
}

/** The evidence bundle `scripts/evidence build` wrote for one finding. */
export function bundleOf(dir: string, id: string): Bundle {
  const base = fileIn(dir, join("evidence", id));
  const manifest = readJson<Record<string, unknown>>(join(base, "manifest.json"), {});
  const files = Object.entries((manifest.files as Record<string, string>) ?? {}).map(([path, sha256]) => {
    let bytes = 0;
    try {
      bytes = statSync(join(base, path)).size;
    } catch {
      /* a file in the manifest that is gone shows as zero rather than failing */
    }
    return { path, sha256: String(sha256), bytes };
  });
  return {
    id,
    present: existsSync(join(base, "manifest.json")),
    redacted: typeof manifest.redacted === "boolean" ? manifest.redacted : null,
    reproducible: typeof manifest.reproducible === "boolean" ? manifest.reproducible : null,
    generated: typeof manifest.generated === "string" ? manifest.generated : null,
    problems: Array.isArray(manifest.problems) ? (manifest.problems as string[]).map(String) : [],
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
    screenshots: Array.isArray(manifest.screenshots)
      ? (manifest.screenshots as string[]).map(String)
      : [],
    oracle: manifest.oracle ?? null,
  };
}

// ------------------------------------------------------------------ traffic

export interface TrafficRow {
  id: number;
  kind: string;
  t: number;
  method: string;
  path: string;
  status: number | null;
  host: string;
  port: number | null;
  scheme: string;
  dur: number | null;
  ua: string;
  client: string;
  label: string;
  cut: boolean;
  reqBytes: number;
  resBytes: number;
}

interface RawRecord {
  kind?: string;
  t?: number;
  dur?: number;
  m?: string;
  p?: string;
  s?: number;
  host?: string;
  port?: number;
  scheme?: string;
  ua?: string;
  client?: string;
  req?: string;
  res?: string;
  req_cut?: boolean;
  res_cut?: boolean;
  [k: string]: unknown;
}

const cache = new Map<string, { key: string; rows: TrafficRow[]; records: RawRecord[] }>();

function trafficLog(dir: string): { rows: TrafficRow[]; records: RawRecord[] } {
  const file = join(dir, "traffic", "log.jsonl");
  let key = "none";
  try {
    const st = statSync(file);
    key = `${st.size}:${st.mtimeMs}`;
  } catch {
    return { rows: [], records: [] };
  }
  const hit = cache.get(dir);
  if (hit && hit.key === key) return hit;

  const rows: TrafficRow[] = [];
  const records: RawRecord[] = [];
  const text = readText(file) ?? "";
  let id = 0;
  for (const line of text.split("\n")) {
    id += 1;
    if (!line.trim()) continue;
    let r: RawRecord;
    try {
      r = JSON.parse(line) as RawRecord;
    } catch {
      // `scripts/traffic` turns an unreadable line into a gap rather than
      // dropping it silently; so does this, for the same reason.
      r = { kind: "gap", t: 0, note: `line ${id} unreadable` };
    }
    records[id] = r;
    rows.push(rowOf(id, r));
  }
  const entry = { key, rows, records };
  cache.set(dir, entry);
  return entry;
}

function rowOf(id: number, r: RawRecord): TrafficRow {
  const raw = r.kind === "raw";
  const hint = raw ? firstLine(r.req) : "";
  return {
    id,
    kind: String(r.kind ?? "gap"),
    t: typeof r.t === "number" ? r.t : 0,
    // Method and path on a raw record are a parser's opinion sitting next to
    // bytes whose whole value is that nobody parsed them, so they are not read.
    method: raw ? "" : String(r.m ?? ""),
    path: raw ? hint : String(r.p ?? ""),
    status: raw ? null : typeof r.s === "number" ? r.s : null,
    host: String(r.host ?? ""),
    port: typeof r.port === "number" ? r.port : null,
    scheme: String(r.scheme ?? ""),
    dur: typeof r.dur === "number" ? r.dur : null,
    ua: String(r.ua ?? ""),
    client: String(r.client ?? (raw ? "raw" : "")),
    label: raw ? rawLabel(r) : "",
    cut: Boolean(r.req_cut || r.res_cut),
    reqBytes: b64len(r.req),
    resBytes: b64len(r.res),
  };
}

const rawLabel = (r: RawRecord) =>
  String(r.label ?? r.why ?? r.tool ?? r.role ?? "raw bytes");

const firstLine = (b64?: string) =>
  b64 ? decode(b64).subarray(0, 200).toString("latin1").split("\n", 1)[0]?.trimEnd() ?? "" : "";

const decode = (b64: string) => Buffer.from(b64, "base64");
const b64len = (b64?: string) => (b64 ? Math.floor((b64.length * 3) / 4) : 0);

export interface TrafficQuery {
  q?: string;
  kind?: string;
  deep?: boolean;
  offset?: number;
  limit?: number;
}

export function trafficIndex(dir: string, query: TrafficQuery) {
  const { rows, records } = trafficLog(dir);
  const q = (query.q ?? "").trim().toLowerCase();
  let hits = rows;
  if (query.kind && query.kind !== "all") hits = hits.filter((r) => r.kind === query.kind);
  if (q) {
    hits = hits.filter((r) => {
      const meta = `${r.method} ${r.path} ${r.status ?? ""} ${r.host} ${r.ua} ${r.client} ${r.label}`;
      if (meta.toLowerCase().includes(q)) return true;
      if (!query.deep) return false;
      const rec = records[r.id];
      if (!rec) return false;
      return bytesOf(rec, "req").toLowerCase().includes(q) || bytesOf(rec, "res").toLowerCase().includes(q);
    });
  }
  const offset = Math.max(0, query.offset ?? 0);
  const limit = Math.min(500, Math.max(1, query.limit ?? 200));
  return { total: rows.length, matched: hits.length, offset, rows: hits.slice(offset, offset + limit) };
}

const bytesOf = (rec: RawRecord, key: "req" | "res") =>
  typeof rec[key] === "string" ? decode(rec[key] as string).toString("latin1") : "";

export interface TrafficDetail {
  row: TrafficRow;
  meta: Record<string, unknown>;
  request: Message;
  response: Message;
}

export interface Message {
  /** Latin-1 text of exactly the recorded bytes. Rendered as text, never markup. */
  text: string;
  bytes: number;
  shape: string;
  cut: boolean;
  /** True when the bytes are not printable text, so the view offers the hex pane. */
  binary: boolean;
  hex: string;
}

export function trafficRecord(dir: string, id: number): TrafficDetail | null {
  const { rows, records } = trafficLog(dir);
  const rec = records[id];
  const row = rows.find((r) => r.id === id);
  if (!rec || !row) return null;
  const meta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rec)) if (k !== "req" && k !== "res") meta[k] = v;
  return {
    row,
    meta,
    request: message(rec, "req"),
    response: message(rec, "res"),
  };
}

function message(rec: RawRecord, key: "req" | "res"): Message {
  const raw = typeof rec[key] === "string" ? decode(rec[key] as string) : Buffer.alloc(0);
  const capped = raw.subarray(0, 512 * 1024);
  return {
    text: capped.toString("latin1"),
    bytes: raw.length,
    shape: byteShape(raw),
    cut: Boolean(rec[`${key}_cut`]),
    binary: isBinary(capped),
    hex: hexdump(capped.subarray(0, 4096)),
  };
}

/** The same sentence `scripts/traffic` prints: what a desync proof turns on. */
export function byteShape(b: Buffer): string {
  const count = (needle: string) => {
    let n = 0;
    let i = b.indexOf(needle, 0, "latin1");
    while (i >= 0) {
      n += 1;
      i = b.indexOf(needle, i + needle.length, "latin1");
    }
    return n;
  };
  const crlf = count("\r\n");
  const lf = count("\n") - crlf;
  const cr = count("\r") - crlf;
  const sha = createHash("sha256").update(b).digest("hex").slice(0, 16);
  return `${b.length} bytes, sha256 ${sha}, ${crlf} CRLF, ${lf} bare LF, ${cr} bare CR`;
}

function isBinary(b: Buffer): boolean {
  const head = b.subarray(0, 4096);
  let odd = 0;
  for (const byte of head) {
    if (byte === 9 || byte === 10 || byte === 13) continue;
    if (byte < 32 || byte === 127) odd += 1;
  }
  return head.length > 0 && odd / head.length > 0.08;
}

function hexdump(b: Buffer): string {
  const lines: string[] = [];
  for (let i = 0; i < b.length; i += 16) {
    const slice = b.subarray(i, i + 16);
    const hex = [...slice].map((x) => x.toString(16).padStart(2, "0")).join(" ").padEnd(47);
    const ascii = [...slice].map((x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
  }
  return lines.join("\n");
}

// -------------------------------------------------------------------- scope

export interface GuardRefusal {
  at: string | null;
  kind: string;
  action: string;
  /** The hosts the guard named, pulled out of its own message. */
  destinations: string[];
  message: string;
}

export interface ScopePanel {
  scope: Scope | null;
  scopeText: string | null;
  refusals: GuardRefusal[];
  flagged: Array<{ cmd: string; offenders: string[] }>;
  hosts: Array<{ host: string; requests: number; inScope: boolean }>;
  rate: { limitRps: number; avgRps: number | null; peakRps: number | null; secondsOver: number | null };
  outOfScopeRequests: number | null;
  totalRequests: number | null;
}

const OUT_OF_SCOPE = /OUT OF SCOPE:\s*(.+)/;
const TARGETS = /targets:\s*(.+)/;

export function scopePanel(dir: string): ScopePanel {
  const run = readJson<RunJson & { rate?: Record<string, number> }>(join(dir, "run.json"), {});
  const { events } = readEvents(dir);
  const refusals: GuardRefusal[] = [];
  for (const e of events) {
    if (e.t !== "guard") continue;
    const message = String(e.message ?? "");
    const line = OUT_OF_SCOPE.exec(message) ?? TARGETS.exec(message);
    refusals.push({
      at: typeof e.ts === "string" ? e.ts : null,
      kind: String(e.kind ?? "scope"),
      action: String(e.action ?? "warn"),
      destinations: line
        ? (line[1] ?? "").split(",").map((s) => s.trim()).filter(Boolean)
        : [],
      message,
    });
  }
  const hosts = Object.entries(run.hosts ?? {}).map(([host, h]) => ({
    host,
    requests: h.requests ?? 0,
    inScope: h.in_scope !== false,
  }));
  const flagged = (run.scope?.tool_invocations_flagged ?? []).map((x) => {
    const o = x as { cmd?: string; offenders?: string[] };
    return { cmd: String(o.cmd ?? ""), offenders: (o.offenders ?? []).map(String) };
  });
  const scope = scopeOf(dir);
  return {
    scope,
    scopeText: readText(join(dir, "scope.yaml")),
    refusals,
    flagged,
    hosts,
    rate: {
      limitRps: run.rate?.limit_rps ?? scope?.rules.rate_limit_rps ?? 0,
      avgRps: run.rate?.avg_rps ?? null,
      peakRps: run.rate?.peak_rps ?? null,
      secondsOver: run.rate?.seconds_over_limit ?? null,
    },
    outOfScopeRequests: run.scope?.out_of_scope_requests ?? null,
    totalRequests: run.requests?.total ?? null,
  };
}

// ------------------------------------------------------------------- report

export function reportOf(dir: string): { text: string | null; bytes: number } {
  const text = readText(join(dir, "report.md"));
  return { text, bytes: text ? Buffer.byteLength(text) : 0 };
}

/** Every regular file under one directory, relative, for a bundle download. */
export function walk(base: string, rel = ""): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(join(base, rel));
  } catch {
    return out;
  }
  for (const name of entries) {
    const r = rel ? join(rel, name) : name;
    const full = fileIn(base, r);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(base, r));
    else if (st.isFile()) out.push(r);
  }
  return out;
}
