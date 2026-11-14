/**
 * The quiet renderer: one line per event, no cursor tricks.
 *
 * This is what a cron job, a CI step and `tee run.log` get. It is the same bus
 * the full-screen view reads, so a run never behaves differently because nobody
 * was watching it.
 */
import type { Bus, Event } from "./bus.js";

// Local time, not UTC. A log line an hour off the operator's clock cannot be
// lined up against anything else they are looking at while the run goes.
const stamp = () =>
  new Date().toLocaleTimeString("en-GB", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

export function attachPlain(bus: Bus, opts: { verbose: boolean } = { verbose: false }) {
  bus.on("event", (e: Event) => {
    const line = render(e, opts.verbose);
    if (line) process.stdout.write(`${stamp()} ${line}\n`);
  });
}

function render(e: Event, verbose: boolean): string | null {
  switch (e.t) {
    case "run:start":
      return `target ${e.target}\n${stamp()} engagement ${e.dir}\n${stamp()} model ${e.model}, budget ${e.budget}s`;
    case "run:end":
      return `done in ${e.wall}s — ${e.summary}`;
    case "phase:start":
      return `phase ${e.phase} start${e.of > 1 ? ` (attempt ${e.attempt}/${e.of})` : ""} [${e.model}, ${e.budget}s]`;
    case "phase:end":
      return `phase ${e.phase} ${e.state}${e.reason ? `: ${e.reason}` : ""} (${e.wall}s)`;
    case "agent:start":
      return `  agent ${e.label} [${e.model}]`;
    case "agent:end":
      return `  agent ${e.id} ended, ${e.steps} steps, ${e.tokens} tokens${e.error ? ` — ${e.error}` : ""}`;
    case "tool:call":
      return `    ${e.tool}: ${flat(e.summary, 160)}`;
    case "tool:result":
      return verbose ? `      → ${flat(e.summary, 120)}` : null;
    case "guard":
      return `  ${e.action === "block" ? "REFUSED" : "WARN"} (${e.kind}) ${flat(e.message, 400)}`;
    case "finding":
      return `  FINDING [${e.severity}] ${e.title}`;
    case "verdict":
      return `  verdict ${e.verdict.state}: ${e.verdict.endpoint}`;
    case "agent:text":
      return verbose ? `    ${flat(e.text, 300)}` : null;
    case "note":
      return `${e.level === "info" ? "" : e.level.toUpperCase() + " "}${e.text}`;
    default:
      return null;
  }
}

const flat = (s: string, max: number) => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
};
