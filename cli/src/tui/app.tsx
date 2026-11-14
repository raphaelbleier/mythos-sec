/**
 * The full-screen view.
 *
 * It renders the bus and nothing else: the driver has no idea it exists, which
 * is why the same run works piped into a log file. Three panes — phases,
 * workers, and a feed — plus a key bar.
 *
 * The one piece of real interaction is the hint line. An operator watching a run
 * often knows something the agent does not ("the admin panel is on 8443"), and
 * before this there was nowhere to put it short of killing the run. Typing a
 * hint never blocks the agents; it is folded into the next phase's prompt as
 * advice.
 */
import React, { useEffect, useReducer, useState } from "react";
import { Box, Text, useApp, useInput } from "ink";
import type { Bus, Event, PhaseState } from "../bus.js";

interface Line {
  kind: "tool" | "note" | "guard" | "finding" | "verdict" | "text";
  text: string;
  tone: "normal" | "dim" | "warn" | "bad" | "good";
}

interface Worker {
  id: string;
  label: string;
  model: string;
  tool?: string;
  steps: number;
  done: boolean;
  error?: string;
}

interface State {
  target: string;
  dir: string;
  budget: number;
  phases: Array<{ name: string; state: PhaseState; attempt: number; of: number; wall?: number; reason?: string }>;
  workers: Worker[];
  feed: Line[];
  findings: number;
  verdicts: { confirmed: number; tested: number; skipped: number };
  guards: { scope: number; budget: number; destructive: number };
  ended?: { ok: boolean; summary: string; wall: number };
}

const PHASE_ORDER = ["recon", "scan", "exploit", "report"];

const empty: State = {
  target: "",
  dir: "",
  budget: 0,
  phases: PHASE_ORDER.map((name) => ({ name, state: "pending" as PhaseState, attempt: 0, of: 0 })),
  workers: [],
  feed: [],
  findings: 0,
  verdicts: { confirmed: 0, tested: 0, skipped: 0 },
  guards: { scope: 0, budget: 0, destructive: 0 },
};

const FEED_MAX = 300;

function push(s: State, line: Line): State {
  const feed = [...s.feed, line];
  if (feed.length > FEED_MAX) feed.splice(0, feed.length - FEED_MAX);
  return { ...s, feed };
}

function reduce(s: State, e: Event & { ts?: string }): State {
  switch (e.t) {
    case "run:start":
      return { ...s, target: e.target, dir: e.dir, budget: e.budget };
    case "run:end":
      return push({ ...s, ended: { ok: e.ok, summary: e.summary, wall: e.wall } }, {
        kind: "note",
        tone: e.ok ? "good" : "warn",
        text: `run finished in ${e.wall}s — ${e.summary}`,
      });
    case "phase:start":
      return push(
        {
          ...s,
          phases: s.phases.map((p) =>
            p.name === e.phase ? { ...p, state: "running", attempt: e.attempt, of: e.of } : p,
          ),
        },
        { kind: "note", tone: "normal", text: `▶ ${e.phase}${e.of > 1 ? ` (attempt ${e.attempt}/${e.of})` : ""}` },
      );
    case "phase:end":
      return push(
        {
          ...s,
          phases: s.phases.map((p) =>
            p.name === e.phase ? { ...p, state: e.state, wall: e.wall, reason: e.reason } : p,
          ),
        },
        {
          kind: "note",
          tone: e.state === "done" ? "good" : "warn",
          text: `■ ${e.phase} ${e.state}${e.reason ? `: ${e.reason}` : ""} (${e.wall}s)`,
        },
      );
    case "agent:start":
      return {
        ...s,
        workers: [
          ...s.workers.filter((w) => w.id !== e.id),
          { id: e.id, label: e.label, model: e.model, steps: 0, done: false },
        ],
      };
    case "agent:end":
      return {
        ...s,
        workers: s.workers.map((w) =>
          w.id === e.id ? { ...w, done: true, steps: e.steps, error: e.error } : w,
        ),
      };
    case "agent:text":
      return push(s, { kind: "text", tone: "dim", text: oneLine(e.text, 200) });
    case "tool:call":
      return push(
        { ...s, workers: s.workers.map((w) => (w.id === e.id ? { ...w, tool: e.tool, steps: w.steps + 1 } : w)) },
        { kind: "tool", tone: "normal", text: `${e.tool}: ${oneLine(e.summary, 150)}` },
      );
    case "tool:result":
      return push(s, {
        kind: "tool",
        tone: e.ok ? "dim" : "warn",
        text: `  ${e.tool} → ${oneLine(e.summary, 120)}`,
      });
    case "guard":
      return push(
        { ...s, guards: { ...s.guards, [e.kind]: s.guards[e.kind] + 1 } },
        {
          kind: "guard",
          tone: e.action === "block" ? "bad" : "warn",
          text: `${e.action === "block" ? "REFUSED" : "WARN"} (${e.kind}) ${oneLine(e.message, 220)}`,
        },
      );
    case "finding":
      return push({ ...s, findings: s.findings + 1 }, {
        kind: "finding",
        tone: "good",
        text: `finding: [${e.severity}] ${e.title}`,
      });
    case "verdict":
      return push(
        { ...s, verdicts: { ...s.verdicts, [e.verdict.state]: s.verdicts[e.verdict.state] + 1 } },
        { kind: "verdict", tone: "dim", text: `${e.verdict.state}: ${e.verdict.endpoint}` },
      );
    case "note":
      return push(s, {
        kind: "note",
        tone: e.level === "error" ? "bad" : e.level === "warn" ? "warn" : "normal",
        text: e.text,
      });
    default:
      return s;
  }
}

const oneLine = (s: string, max: number) => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
};

const color = (tone: Line["tone"]) =>
  tone === "bad" ? "red" : tone === "warn" ? "yellow" : tone === "good" ? "green" : undefined;

const MARK: Record<PhaseState, string> = {
  pending: "·",
  running: "◆",
  done: "✓",
  incomplete: "~",
  failed: "✗",
};

const PHASE_COLOR: Record<PhaseState, string | undefined> = {
  pending: "gray",
  running: "cyan",
  done: "green",
  incomplete: "yellow",
  failed: "red",
};

export function App({ bus }: { bus: Bus }) {
  const [state, dispatch] = useReducer(reduce, empty);
  const [paused, setPaused] = useState(false);
  const [typing, setTyping] = useState(false);
  const [hint, setHint] = useState("");
  const [elapsed, setElapsed] = useState(0);
  const { exit } = useApp();

  useEffect(() => {
    const onEvent = (e: Event) => dispatch(e);
    bus.on("event", onEvent);
    return () => void bus.off("event", onEvent);
  }, [bus]);

  useEffect(() => {
    const t = setInterval(() => setElapsed((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (state.ended) {
      const t = setTimeout(() => exit(), 1500);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [state.ended, exit]);

  useInput((input, key) => {
    if (typing) {
      if (key.return) {
        if (hint.trim()) {
          bus.control({ t: "hint", text: hint.trim() });
          // Say when it lands. An agent in the middle of a tool call has no seam
          // to take a message, so the hint reaches the next worker or the next
          // phase, and an operator who is not told that waits for nothing.
          bus.note("info", `hint queued, reaches the next phase or worker: ${hint.trim()}`);
        }
        setHint("");
        setTyping(false);
        return;
      }
      if (key.escape) {
        setHint("");
        setTyping(false);
        return;
      }
      if (key.backspace || key.delete) {
        setHint((h) => h.slice(0, -1));
        return;
      }
      if (input) setHint((h) => h + input);
      return;
    }
    if (input === "p") {
      bus.control({ t: paused ? "resume" : "pause" });
      setPaused(!paused);
    }
    if (input === "h") setTyping(true);
    if (input === "q" || (key.ctrl && input === "c")) {
      bus.control({ t: "abort" });
    }
  });

  const live = state.workers.filter((w) => !w.done);
  const mmss = (n: number) => `${Math.floor(n / 60)}:${String(n % 60).padStart(2, "0")}`;

  return (
    <Box flexDirection="column" paddingX={1}>
      <Box justifyContent="space-between">
        <Text>
          <Text bold color="magenta">
            MYTHOS
          </Text>
          <Text> {state.target || "…"}</Text>
        </Text>
        <Text dimColor>
          {mmss(elapsed)}
          {state.budget ? ` / ${mmss(state.budget)}` : ""}
          {paused ? "  ⏸ PAUSED" : ""}
        </Text>
      </Box>

      <Box marginTop={1}>
        {state.phases.map((p) => (
          <Box key={p.name} marginRight={2}>
            <Text color={PHASE_COLOR[p.state]}>
              {MARK[p.state]} {p.name}
              {p.of > 1 && p.state === "running" ? ` ${p.attempt}/${p.of}` : ""}
              {p.wall !== undefined ? ` ${p.wall}s` : ""}
            </Text>
          </Box>
        ))}
      </Box>

      <Box marginTop={1} flexDirection="column">
        <Text dimColor>
          findings {state.findings} · endpoints {state.verdicts.confirmed}c/{state.verdicts.tested}t/
          {state.verdicts.skipped}s · guards {state.guards.scope} scope, {state.guards.budget} budget,{" "}
          {state.guards.destructive} refused
        </Text>
      </Box>

      {live.length > 0 && (
        <Box marginTop={1} flexDirection="column">
          {live.map((w) => (
            <Text key={w.id}>
              <Text color="cyan">◆ </Text>
              <Text>{w.label.padEnd(16)}</Text>
              <Text dimColor>
                {String(w.steps).padStart(3)} steps {w.tool ? `· ${w.tool}` : ""} · {w.model}
              </Text>
            </Text>
          ))}
        </Box>
      )}

      <Box marginTop={1} flexDirection="column">
        {state.feed.slice(-14).map((l, i) => (
          <Text key={i} color={color(l.tone)} dimColor={l.tone === "dim"} wrap="truncate-end">
            {l.text}
          </Text>
        ))}
      </Box>

      <Box marginTop={1}>
        {typing ? (
          <Text>
            <Text color="magenta">hint› </Text>
            <Text>{hint}</Text>
            <Text dimColor>▌ (enter to send, esc to cancel)</Text>
          </Text>
        ) : (
          <Text dimColor>
            {state.ended
              ? `finished — ${state.ended.summary}`
              : "p pause/resume · h hint · q abort"}
          </Text>
        )}
      </Box>
    </Box>
  );
}
