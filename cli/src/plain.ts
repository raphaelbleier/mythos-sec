/**
 * The quiet renderer: one line per event, no cursor tricks.
 *
 * This is what a cron job, a CI step and `tee run.log` get. It is the same bus
 * the full-screen view reads, so a run never behaves differently because nobody
 * was watching it.
 *
 * Three verbosity levels, because clig.dev asks for both `-q` and `-v` and says
 * they should compose: 0 drops everything a later reader would not act on, 1 is
 * the default narration, 2 adds the tool results and the agents' prose. Each
 * line carries its own timestamp and phase, so the log still makes sense when it
 * is read a week later, scrolled back, or grepped out of a CI transcript.
 */
import type { Bus, Event } from "./bus.js";
import { glyphs } from "./tui/theme.js";

export type Level = 0 | 1 | 2;

// Local time, not UTC. A log line an hour off the operator's clock cannot be
// lined up against anything else they are looking at while the run goes.
const stamp = () =>
  new Date().toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

export interface PlainOptions {
  level?: Level;
  /**
   * Where the narration goes. stdout normally; stderr when `--json` is on, so
   * the one JSON document on stdout stays the only thing a pipe reads.
   */
  stream?: { write: (s: string) => unknown };
}

export function attachPlain(bus: Bus, opts: PlainOptions = {}) {
  const level = opts.level ?? 1;
  const out = opts.stream ?? process.stdout;
  bus.on("event", (e: Event) => {
    const line = renderLine(e, level);
    if (line) out.write(`${stamp()} ${line}\n`);
  });
}

/**
 * One event as one line, or null if this level does not carry it.
 *
 * Level 0 keeps what an unattended run must still report: the run's own
 * boundaries, anything the guard refused, every finding and verdict, and
 * warnings. It drops the step-by-step narration, not the outcome — a quiet run
 * whose log cannot say what it found would be worse than no log.
 */
export function renderLine(e: Event, level: Level): string | null {
  const g = glyphs();
  switch (e.t) {
    case "run:start":
      return `target ${e.target}\n${stamp()} engagement ${e.dir}\n${stamp()} model ${e.model}, budget ${e.budget}s`;
    case "run:end":
      return `done in ${e.wall}s ${g.dash} ${e.summary}`;
    case "phase:start":
      return level < 1
        ? null
        : `phase ${e.phase} start${e.of > 1 ? ` (attempt ${e.attempt}/${e.of})` : ""} [${e.model}, ${e.budget}s]`;
    case "phase:end":
      return `phase ${e.phase} ${e.state}${e.reason ? `: ${e.reason}` : ""} (${e.wall}s)`;
    case "agent:start":
      return level < 1 ? null : `  agent ${e.label} [${e.model}]`;
    case "agent:end":
      return level < 1
        ? null
        : `  agent ${e.id} ended, ${e.steps} steps, ${e.tokens} tokens${e.error ? ` ${g.dash} ${e.error}` : ""}`;
    case "tool:call":
      return level < 1 ? null : `    ${e.tool}: ${flat(e.summary, 160)}`;
    case "tool:result":
      return level > 1 ? `      ${g.arrow} ${flat(e.summary, 120)}` : null;
    case "guard":
      return `  ${e.action === "block" ? "REFUSED" : "WARN"} (${e.kind}) ${flat(e.message, 400)}`;
    case "finding":
      return `  FINDING [${e.severity}] ${e.title}`;
    case "verdict":
      return `  verdict ${e.verdict.state}: ${e.verdict.endpoint}`;
    case "agent:text":
      return level > 1 ? `    ${flat(e.text, 300)}` : null;
    case "note":
      return e.level === "info" && level < 1 ? null : `${e.level === "info" ? "" : e.level.toUpperCase() + " "}${e.text}`;
    default:
      return null;
  }
}

const flat = (s: string, max: number) => {
  const e = glyphs().ellipsis;
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, Math.max(1, max - e.length)) + e : t;
};
