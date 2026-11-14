/**
 * The full-screen view.
 *
 * It renders the bus and nothing else: the driver has no idea it exists, which
 * is why the same run works piped into a log file. The layout is sized against
 * the real terminal so nothing scrolls out from under the operator: a header
 * with the clock, a phase rail with a bar per phase, the live workers, and the
 * feed taking whatever is left.
 *
 * The one piece of real interaction is the hint line. An operator watching a
 * run often knows something the agent does not ("the admin panel is on 8443"),
 * and before this there was nowhere to put it short of killing the run. Typing
 * a hint never blocks the agents; it is folded into the next prompt as advice.
 */
import React, { useEffect, useReducer, useState } from "react";
import { Box, Text, useApp, useInput, useStdout } from "ink";
import type { Bus, Event, PhaseState } from "../bus.js";
import { bar, c, clock, glyphs, theme, type Theme } from "./theme.js";
import { TAGLINE, wordmarkRows } from "./banner.js";

interface Line {
  at: string;
  kind: "tool" | "note" | "guard" | "finding" | "verdict" | "text" | "phase";
  tag: string;
  text: string;
  tone: "normal" | "dim" | "warn" | "bad" | "good" | "accent";
}

interface Worker {
  id: string;
  label: string;
  model: string;
  tool?: string;
  steps: number;
  tokens: number;
  done: boolean;
  error?: string;
}

interface Phase {
  name: string;
  state: PhaseState;
  attempt: number;
  of: number;
  budget: number;
  startedAt?: number;
  wall?: number;
  reason?: string;
}

interface State {
  target: string;
  dir: string;
  budget: number;
  model: string;
  phases: Phase[];
  workers: Worker[];
  feed: Line[];
  findings: Array<{ title: string; severity: string }>;
  verdicts: { candidate: number; confirmed: number; rejected: number; tested: number; skipped: number };
  open: number;
  guards: { scope: number; budget: number; destructive: number };
  tokens: number;
  ended?: { ok: boolean; summary: string; wall: number };
}

const PHASE_ORDER = ["recon", "scan", "exploit", "report"];
const FEED_MAX = 400;

const empty: State = {
  target: "",
  dir: "",
  budget: 0,
  model: "",
  phases: PHASE_ORDER.map((name) => ({ name, state: "pending", attempt: 0, of: 0, budget: 0 })),
  workers: [],
  feed: [],
  findings: [],
  verdicts: { candidate: 0, confirmed: 0, rejected: 0, tested: 0, skipped: 0 },
  open: 0,
  guards: { scope: 0, budget: 0, destructive: 0 },
  tokens: 0,
};

const stamp = () =>
  new Date().toLocaleTimeString("en-GB", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

function push(s: State, line: Omit<Line, "at">): State {
  const feed = [...s.feed, { ...line, at: stamp() }];
  if (feed.length > FEED_MAX) feed.splice(0, feed.length - FEED_MAX);
  return { ...s, feed };
}

const flat = (s: string, max: number) => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, Math.max(1, max - 1)) + "…" : t;
};

function reduce(s: State, e: Event): State {
  switch (e.t) {
    case "run:start":
      return { ...s, target: e.target, dir: e.dir, budget: e.budget, model: e.model };
    case "run:end":
      return push({ ...s, ended: { ok: e.ok, summary: e.summary, wall: e.wall } }, {
        kind: "note",
        tag: "run",
        tone: e.ok ? "good" : "warn",
        text: `finished in ${clock(e.wall)} — ${e.summary}`,
      });
    case "phase:start":
      return push(
        {
          ...s,
          phases: s.phases.map((p) =>
            p.name === e.phase
              ? { ...p, state: "running", attempt: e.attempt, of: e.of, budget: e.budget, startedAt: Date.now() }
              : p,
          ),
        },
        {
          kind: "phase",
          tag: e.phase,
          tone: "accent",
          text: `started${e.of > 1 ? `, attempt ${e.attempt} of ${e.of}` : ""} · ${clock(e.budget)} budget · ${e.model}`,
        },
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
          kind: "phase",
          tag: e.phase,
          tone: e.state === "done" ? "good" : "warn",
          text: `${e.state}${e.reason ? `: ${e.reason}` : ""} after ${clock(e.wall)}`,
        },
      );
    case "agent:start":
      return {
        ...s,
        workers: [
          ...s.workers.filter((w) => w.id !== e.id),
          { id: e.id, label: e.label, model: e.model, steps: 0, tokens: 0, done: false },
        ],
      };
    case "agent:end":
      return {
        ...s,
        tokens: s.tokens + e.tokens,
        workers: s.workers.map((w) =>
          w.id === e.id ? { ...w, done: true, steps: e.steps, tokens: e.tokens, error: e.error } : w,
        ),
      };
    case "agent:text":
      return push(s, { kind: "text", tag: "says", tone: "dim", text: e.text });
    case "tool:call":
      return push(
        { ...s, workers: s.workers.map((w) => (w.id === e.id ? { ...w, tool: e.tool, steps: w.steps + 1 } : w)) },
        { kind: "tool", tag: e.tool, tone: "normal", text: e.summary },
      );
    case "tool:result":
      // A successful result is already implied by the next call; only a failure
      // is worth a line, or the feed becomes two lines per step and scrolls the
      // interesting ones away.
      return e.ok ? s : push(s, { kind: "tool", tag: e.tool, tone: "warn", text: `failed: ${e.summary}` });
    case "guard":
      return push(
        { ...s, guards: { ...s.guards, [e.kind]: s.guards[e.kind] + 1 } },
        {
          kind: "guard",
          tag: e.action === "block" ? "refused" : e.kind,
          tone: e.action === "block" ? "bad" : "warn",
          text: e.message.split("\n").map((l) => l.trim()).filter(Boolean).slice(0, 2).join("  "),
        },
      );
    case "finding":
      return push({ ...s, findings: [...s.findings, { title: e.title, severity: e.severity }] }, {
        kind: "finding",
        tag: e.severity,
        tone: "good",
        text: e.title,
      });
    case "verdict":
      return push({ ...s, verdicts: { ...s.verdicts, [e.verdict.state]: s.verdicts[e.verdict.state] + 1 } }, {
        kind: "verdict",
        tag: e.verdict.state,
        tone:
          e.verdict.state === "confirmed"
            ? "good"
            : e.verdict.state === "candidate"
              ? "warn"
              : e.verdict.state === "rejected"
                ? "bad"
                : "dim",
        text: e.verdict.endpoint,
      });
    case "note": {
      const open = /(\d+) open across/.exec(e.text);
      return push(open ? { ...s, open: Number(open[1]) } : s, {
        kind: "note",
        tag: e.level === "info" ? "mythos" : e.level,
        tone: e.level === "error" ? "bad" : e.level === "warn" ? "warn" : "normal",
        text: e.text,
      });
    }
    default:
      return s;
  }
}

function Panel({ title, t, children }: { title: string; t: Theme; children: React.ReactNode }) {
  return (
    <Box flexDirection="column">
      <Box>
        <Text color={c(t, t.frame)}>── </Text>
        <Text color={c(t, t.muted)}>{title}</Text>
      </Box>
      <Box flexDirection="column" paddingLeft={1}>
        {children}
      </Box>
    </Box>
  );
}

export function App({ bus }: { bus: Bus }) {
  const [state, dispatch] = useReducer(reduce, empty);
  const [paused, setPaused] = useState(false);
  const [typing, setTyping] = useState(false);
  const [hint, setHint] = useState("");
  const [tick, setTick] = useState(0);
  const [startedAt] = useState(() => Date.now());
  const { exit } = useApp();
  const { stdout } = useStdout();
  const t = theme();
  const g = glyphs();

  const cols = Math.max(64, Math.min(stdout?.columns ?? 100, 170));
  const rows = stdout?.rows ?? 30;
  const wordmark = rows >= 36 && cols >= 80;

  useEffect(() => {
    const onEvent = (e: Event) => dispatch(e);
    bus.on("event", onEvent);
    return () => void bus.off("event", onEvent);
  }, [bus]);

  useEffect(() => {
    const i = setInterval(() => setTick((n) => n + 1), 120);
    return () => clearInterval(i);
  }, []);

  useEffect(() => {
    if (!state.ended) return undefined;
    const to = setTimeout(() => exit(), 1200);
    return () => clearTimeout(to);
  }, [state.ended, exit]);

  useInput((input, key) => {
    if (typing) {
      if (key.return) {
        if (hint.trim()) {
          bus.control({ t: "hint", text: hint.trim() });
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
    if (input === "q" || (key.ctrl && input === "c")) bus.control({ t: "abort" });
  });

  void tick;
  const elapsed = Math.floor((Date.now() - startedAt) / 1000);
  const spin = g.spinner[Math.floor(tick / 3) % g.spinner.length] ?? "";
  const live = state.workers.filter((w) => !w.done);
  const tone = (x: Line["tone"]) =>
    x === "bad"
      ? t.refused
      : x === "warn"
        ? t.warn
        : x === "good"
          ? t.confirmed
          : x === "accent"
            ? t.accent
            : t.ink;

  const mark: Record<PhaseState, string> = {
    pending: g.pending,
    running: spin,
    done: g.done,
    incomplete: g.incomplete,
    failed: g.failed,
  };
  const phaseColour: Record<PhaseState, string> = {
    pending: t.idle,
    running: t.running,
    done: t.done,
    incomplete: t.warn,
    failed: t.refused,
  };

  const feedRows = Math.max(5, rows - 17 - (wordmark ? 7 : 0) - (live.length ? live.length + 2 : 0));
  const sev = state.findings.reduce<Record<string, number>>(
    (a, f) => ({ ...a, [f.severity]: (a[f.severity] ?? 0) + 1 }),
    {},
  );
  const sevText = Object.entries(sev).map(([k, n]) => `${n} ${k}`).join(", ") || "none yet";
  const v = state.verdicts;
  // A candidate is not decided: the validate phase still owes it an answer,
  // and counting it as progress would show a run as further along than it is.
  const decided = v.confirmed + v.rejected + v.tested + v.skipped;
  const total = decided + state.open;
  const barWidth = Math.max(10, Math.min(30, cols - 56));

  return (
    <Box flexDirection="column" paddingX={1} width={cols}>
      {wordmark && (
        <Box flexDirection="column" marginBottom={1}>
          {wordmarkRows().map((r, i) => (
            <Text key={i} color={c(t, t.accent)}>
              {r}
            </Text>
          ))}
          <Text color={c(t, t.muted)}>{TAGLINE}</Text>
        </Box>
      )}
      <Box justifyContent="space-between" width={cols - 2}>
        <Box>
          {/* The name twice is noise when the wordmark is already above. */}
          {!wordmark && (
            <>
              <Text color={c(t, t.accent)} bold>
                MYTHOS
              </Text>
              <Text color={c(t, t.frame)}> {g.bullet} </Text>
            </>
          )}
          <Text color={c(t, t.muted)}>target </Text>
          <Text color={c(t, t.ink)}>{state.target || "…"}</Text>
          {state.model ? <Text color={c(t, t.muted)}>{`   ${state.model}`}</Text> : null}
        </Box>
        <Text color={c(t, t.muted)}>
          {paused ? "PAUSED  " : ""}
          {clock(elapsed)}
          {state.budget ? ` / ${clock(state.budget)}` : ""}
        </Text>
      </Box>
      <Text color={c(t, t.frame)}>{"─".repeat(cols - 2)}</Text>

      <Box flexDirection="column" marginTop={1}>
        {state.phases.map((p) => {
          const ran = p.state === "done" || p.state === "incomplete" || p.state === "failed";
          const ratio = ran
            ? 1
            : p.state === "running" && p.budget && p.startedAt
              ? Math.min(1, (Date.now() - p.startedAt) / 1000 / p.budget)
              : 0;
          const right =
            p.wall !== undefined
              ? clock(p.wall)
              : p.state === "running"
                ? `${clock(Math.floor((Date.now() - (p.startedAt ?? Date.now())) / 1000))} / ${clock(p.budget)}`
                : "";
          return (
            <Box key={p.name}>
              <Text color={c(t, phaseColour[p.state])}>
                {mark[p.state]} {p.name.padEnd(8)}
              </Text>
              <Text color={c(t, p.state === "pending" ? t.idle : phaseColour[p.state])}>
                {bar(ratio, barWidth, g)[0]}
              </Text>
              <Text color={c(t, t.idle)}>{bar(ratio, barWidth, g)[1]}</Text>
              <Text color={c(t, t.muted)}>
                {"  "}
                {right.padEnd(13)}
                {p.attempt > 1 ? `try ${p.attempt}/${p.of}  ` : ""}
                {p.reason ? flat(p.reason, Math.max(10, cols - barWidth - 40)) : ""}
              </Text>
            </Box>
          );
        })}
      </Box>

      <Box marginTop={1} flexDirection="column">
        <Box>
          <Text color={c(t, t.muted)}>findings  </Text>
          <Text color={c(t, state.findings.length ? t.confirmed : t.idle)}>{sevText}</Text>
          <Text color={c(t, t.muted)}>{"    endpoints  "}</Text>
          <Text color={c(t, t.confirmed)}>{v.confirmed}{g.confirmed}</Text>
          <Text color={c(t, t.muted)}>{" "}</Text>
          <Text color={c(t, t.ink)}>{v.tested}{g.tested}</Text>
          <Text color={c(t, t.muted)}>{" "}</Text>
          <Text color={c(t, t.idle)}>{v.skipped}{g.skipped}</Text>
          {v.rejected ? (
            <>
              <Text color={c(t, t.muted)}>{" "}</Text>
              <Text color={c(t, t.refused)}>{v.rejected}{g.refused}</Text>
            </>
          ) : null}
          {v.candidate ? (
            <>
              <Text color={c(t, t.muted)}>{" "}</Text>
              <Text color={c(t, t.warn)}>{v.candidate}{g.warn}</Text>
            </>
          ) : null}
          <Text color={c(t, t.muted)}>{total ? ` of ${total}` : ""}</Text>
        </Box>
        <Box>
          <Text color={c(t, t.muted)}>guards    </Text>
          <Text color={c(t, state.guards.scope ? t.warn : t.idle)}>{state.guards.scope} scope</Text>
          <Text color={c(t, t.muted)}>, </Text>
          <Text color={c(t, state.guards.budget ? t.warn : t.idle)}>{state.guards.budget} budget</Text>
          <Text color={c(t, t.muted)}>, </Text>
          <Text color={c(t, state.guards.destructive ? t.refused : t.idle)}>
            {state.guards.destructive} refused
          </Text>
          {state.tokens > 0 && (
            <Text color={c(t, t.muted)}>{`    ${(state.tokens / 1000).toFixed(0)}k tokens`}</Text>
          )}
        </Box>
      </Box>

      {live.length > 0 && (
        <Box marginTop={1}>
          <Panel title={`working  ${live.length}`} t={t}>
            {live.map((w) => (
              <Box key={w.id}>
                <Text color={c(t, t.running)}>{spin} </Text>
                <Text color={c(t, t.ink)}>{w.label.padEnd(15)}</Text>
                <Text color={c(t, t.muted)}>
                  {String(w.steps).padStart(3)} steps  {(w.tool ?? "").padEnd(9)}  {w.model}
                </Text>
              </Box>
            ))}
          </Panel>
        </Box>
      )}

      <Box marginTop={1}>
        <Panel title="feed" t={t}>
          {state.feed.slice(-feedRows).map((l, i) => (
            <Box key={i}>
              <Text color={c(t, t.idle)}>{l.at} </Text>
              <Text color={c(t, l.kind === "guard" || l.kind === "finding" ? tone(l.tone) : t.muted)}>
                {l.tag.slice(0, 9).padEnd(10)}
              </Text>
              <Text color={c(t, tone(l.tone))} dimColor={!t.mono && l.tone === "dim"} wrap="truncate-end">
                {flat(l.text, Math.max(20, cols - 25))}
              </Text>
            </Box>
          ))}
        </Panel>
      </Box>

      <Box marginTop={1} width={cols - 2}>
        {typing ? (
          <Text>
            <Text color={c(t, t.accent)}>hint {g.arrow} </Text>
            <Text color={c(t, t.ink)}>{hint}</Text>
            <Text color={c(t, t.idle)}>▌ enter sends, esc cancels</Text>
          </Text>
        ) : state.ended ? (
          <Text color={c(t, state.ended.ok ? t.confirmed : t.warn)}>
            {state.ended.ok ? g.done : g.incomplete} {flat(state.ended.summary, cols - 6)}
          </Text>
        ) : (
          <Text color={c(t, t.idle)}>
            <Text color={c(t, t.muted)}>p</Text> {paused ? "resume" : "pause"}
            {"   "}
            <Text color={c(t, t.muted)}>h</Text> hint
            {"   "}
            <Text color={c(t, t.muted)}>q</Text> abort
            {state.dir ? `   ${state.dir.split("/").slice(-2).join("/")}` : ""}
          </Text>
        )}
      </Box>
    </Box>
  );
}
