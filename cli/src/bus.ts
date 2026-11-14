/**
 * One event stream for the whole run.
 *
 * The driver and the agents never print. They emit, and exactly one renderer
 * consumes: the full-screen view, or the line logger with -n. That split is why
 * a run can be watched or piped into a file without two code paths that drift,
 * and it is what makes the operator's interventions possible — the same bus
 * carries hints in the other direction.
 */
import { EventEmitter } from "node:events";
import { appendFileSync } from "node:fs";

export type PhaseState = "pending" | "running" | "done" | "incomplete" | "failed";

export interface Verdict {
  endpoint: string;
  state: "confirmed" | "tested" | "skipped";
  note: string;
}

export type Event =
  | { t: "run:start"; target: string; dir: string; model: string; budget: number }
  | { t: "run:end"; ok: boolean; wall: number; summary: string }
  | { t: "phase:start"; phase: string; attempt: number; of: number; model: string; budget: number }
  | { t: "phase:end"; phase: string; state: PhaseState; wall: number; reason?: string }
  | { t: "agent:start"; id: string; phase: string; label: string; model: string }
  | { t: "agent:end"; id: string; steps: number; tokens: number; error?: string }
  | { t: "agent:text"; id: string; text: string }
  | { t: "tool:call"; id: string; tool: string; summary: string }
  | { t: "tool:result"; id: string; tool: string; ok: boolean; summary: string }
  | { t: "guard"; kind: "scope" | "budget" | "destructive"; action: "warn" | "block"; message: string }
  | { t: "finding"; id: string; title: string; severity: string }
  | { t: "verdict"; verdict: Verdict }
  | { t: "note"; level: "info" | "warn" | "error"; text: string };

export type Control =
  | { t: "pause" }
  | { t: "resume" }
  | { t: "abort" }
  | { t: "hint"; text: string };

export class Bus extends EventEmitter {
  private jsonl?: string;
  private paused = false;
  private aborted = false;
  private hints: string[] = [];

  /** Append every event to a file too, so a finished run can be replayed or diffed. */
  record(file: string) {
    this.jsonl = file;
    return this;
  }

  emitEvent(e: Event) {
    const line = { ts: new Date().toISOString(), ...e };
    if (this.jsonl) {
      try {
        appendFileSync(this.jsonl, JSON.stringify(line) + "\n");
      } catch {
        /* a full disk must not kill the engagement */
      }
    }
    this.emit("event", line);
  }

  note(level: "info" | "warn" | "error", text: string) {
    this.emitEvent({ t: "note", level, text });
  }

  control(c: Control) {
    if (c.t === "pause") this.paused = true;
    if (c.t === "resume") this.paused = false;
    if (c.t === "abort") this.aborted = true;
    if (c.t === "hint") this.hints.push(c.text);
    this.emit("control", c);
  }

  get isAborted() {
    return this.aborted;
  }

  /**
   * Called between agent steps. Pausing blocks here; aborting throws. The run
   * never blocks waiting for input on its own — only an explicit pause does
   * that, which is the difference between "watchable" and "needs babysitting".
   */
  async checkpoint(): Promise<void> {
    if (this.aborted) throw new AbortedError();
    while (this.paused && !this.aborted) await new Promise((r) => setTimeout(r, 120));
    if (this.aborted) throw new AbortedError();
  }

  /** Hints the operator typed since the last call, to fold into the next prompt. */
  takeHints(): string[] {
    const h = this.hints;
    this.hints = [];
    return h;
  }
}

export class AbortedError extends Error {
  constructor() {
    super("aborted by the operator");
    this.name = "AbortedError";
  }
}
