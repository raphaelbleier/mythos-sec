/**
 * The ledger that decides when the exploit phase is finished.
 *
 * This exists because of a measurement in this project's own history: on a
 * target with 76 documented vulnerabilities, both the scaffolded and the bare
 * agent stopped after a quarter of their budget, having found about a third,
 * and whole surfaces — merchant, bill payment, cards, GraphQL — never received
 * a single request. The agent believed it was done. A coverage gate that merely
 * nudged did not change that.
 *
 * So "done" stops being the model's opinion. Every endpoint the surface map
 * found needs an explicit verdict:
 *
 *   candidate  the exploit worker believes it found something
 *   confirmed  a validator reproduced it independently, with the evidence pair
 *   rejected   a validator could not reproduce it
 *   tested     tested against the classes the surface suggests, nothing proven
 *   skipped    deliberately not tested, with a reason a reader can check
 *
 * The split between `candidate` and `confirmed` is deliberate and it is the one
 * thing here that is not about coverage. An agent that confirms its own finding
 * is measuring its own hope: Berkeley's RECEIPT work put a naive "the JavaScript
 * executed" verifier in front of an agent and got 111 claimed cross-site
 * scripting findings, of which ten were real. So the worker that finds a flaw
 * may only write a candidate, and a separate validator with a fresh context has
 * to reproduce it from the recorded request before it becomes a finding.
 *
 * An endpoint with no verdict is not a decision, it is an omission, and the
 * driver keeps assigning work until none are left or the budget ends. The
 * difference matters in a report: "tested, not vulnerable" and "never looked
 * at" are not the same sentence, and only one of them is honest about a gap.
 */
import { execFile } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { REPO, script } from "./paths.js";

const run = promisify(execFile);

export type VerdictState = "candidate" | "confirmed" | "rejected" | "tested" | "skipped";

export const VERDICT_STATES: VerdictState[] = [
  "candidate",
  "confirmed",
  "rejected",
  "tested",
  "skipped",
];

/** A candidate is an open question, not an outcome: validate still owes it one. */
export const isResolved = (s: VerdictState) => s !== "candidate";

export interface VerdictRow {
  endpoint: string;
  state: VerdictState;
  note: string;
  by: string;
  at: string;
}

/**
 * The key two endpoint strings are compared on.
 *
 * A worker is asked to repeat the endpoint exactly as it was assigned and
 * mostly does, but "http://host/login", "/login" and "/login/" are the same
 * endpoint and a worker that writes any of them has done the work. Matching on
 * the raw string would leave the endpoint open, and the phase would spend all
 * six rounds reassigning something that was already decided.
 */
export function endpointKey(e: string): string {
  let k = e.trim();
  const m = /^[a-z]+:\/\/[^/]+(\/.*)?$/i.exec(k);
  if (m) k = m[1] ?? "/";
  k = k.replace(/\s+/g, " ");
  if (k.length > 1) k = k.replace(/\/+$/, "");
  return k.toLowerCase();
}

export class Ledger {
  private rows = new Map<string, VerdictRow>();
  private file: string;

  constructor(private dir: string) {
    this.file = join(dir, "verdicts.json");
    if (existsSync(this.file)) {
      try {
        const data = JSON.parse(readFileSync(this.file, "utf8")) as VerdictRow[];
        for (const r of data) this.rows.set(endpointKey(r.endpoint), r);
      } catch {
        /* a corrupt ledger is rebuilt rather than inherited */
      }
    }
  }

  record(endpoint: string, state: VerdictState, note: string, by: string) {
    this.rows.set(endpointKey(endpoint), {
      endpoint,
      state,
      note,
      by,
      at: new Date().toISOString(),
    });
    this.flush();
  }

  private flush() {
    writeFileSync(this.file, JSON.stringify([...this.rows.values()], null, 1) + "\n");
  }

  get all(): VerdictRow[] {
    return [...this.rows.values()];
  }

  has(endpoint: string) {
    return this.rows.has(endpointKey(endpoint));
  }

  get(endpoint: string): VerdictRow | undefined {
    return this.rows.get(endpointKey(endpoint));
  }

  /**
   * The mapped surface, from the probe's map via `scripts/coverage`. Reusing
   * that script keeps one definition of "the surface": a second parser here
   * would drift from the one the report is checked against.
   */
  async surface(): Promise<string[]> {
    const f = join(this.dir, "surface.json");
    if (!existsSync(f)) return [];
    try {
      const { stdout } = await run("python3", [script("coverage"), this.dir, "--list", "10000"], {
        cwd: REPO,
        maxBuffer: 16 << 20,
      }).catch((e: { stdout?: string }) => ({ stdout: e.stdout ?? "" }));
      const open = stdout
        .split("\n")
        .filter((l) => l.startsWith("OPEN "))
        .map((l) => l.slice(5).trim());
      // `coverage` reports what the report does not mention yet; the ledger
      // needs the whole surface, so the already-covered ones come from the map.
      const mapped = surfaceFromMap(f);
      return [...new Set([...mapped, ...open])];
    } catch {
      return surfaceFromMap(f);
    }
  }

  /** Endpoints with no verdict yet, which is the work the driver still owes. */
  async open(): Promise<string[]> {
    return (await this.surface()).filter((e) => !this.rows.has(endpointKey(e)));
  }

  /**
   * The candidates the validate phase still owes an answer. Keyed by the file
   * the worker wrote, because that file holds the evidence the validator has to
   * reproduce, and the endpoint alone does not say which claim is at stake.
   */
  unresolved(): VerdictRow[] {
    return [...this.rows.values()].filter((r) => !isResolved(r.state));
  }

  summary(): Record<VerdictState, number> {
    const s: Record<VerdictState, number> = {
      candidate: 0,
      confirmed: 0,
      rejected: 0,
      tested: 0,
      skipped: 0,
    };
    for (const r of this.rows.values()) s[r.state] += 1;
    return s;
  }
}

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/** The same reading of surface.json that scripts/coverage does, for the total. */
export function surfaceFromMap(file: string): string[] {
  let m: Record<string, unknown>;
  try {
    m = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  } catch {
    return [];
  }
  const origin = String(m.origin ?? m.target ?? "");
  const items: string[] = [];
  const strip = (u: string) => (origin && u.startsWith(origin) ? u.slice(origin.length) : u);

  for (const page of (m.pages ?? []) as Array<Record<string, unknown>>) {
    items.push(strip(String(page.url ?? page.path ?? "")));
    for (const form of (page.forms ?? []) as Array<Record<string, unknown>>) {
      items.push(String(form.action ?? ""));
    }
  }
  for (const r of (m.reachable_paths ?? []) as Array<unknown>) {
    items.push(typeof r === "object" && r ? String((r as { path?: string }).path ?? "") : String(r));
  }
  for (const e of (m.api_endpoints ?? []) as Array<unknown>) {
    const s = String(e).trim();
    if (!s) continue;
    const head = s.split(/\s+/)[0] ?? "";
    items.push(METHODS.includes(head) ? (s.split(/\s+/).at(-1) ?? s) : s);
  }
  for (const p of (m.parameters ?? []) as Array<Record<string, unknown>>) {
    if (p.name) items.push(`param:${String(p.name)}`);
  }
  const out: string[] = [];
  for (const raw of items) {
    const i = raw.trim();
    if (i && i !== "/" && !out.includes(i)) out.push(i);
  }
  return out;
}
