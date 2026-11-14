/**
 * The colours and glyphs the view is built from.
 *
 * They come from the project's own mark: a hydra coiled around a labyrinth in
 * deep navy and steel blue on cream. A terminal cannot show the mark, so the
 * palette is what carries it, and nothing here invents a colour that is not in
 * the logo. One accent, one ink, and the semantic colours a security tool
 * actually needs: something confirmed, something refused, something skipped.
 *
 * Terminals vary more than browsers do. `MYTHOS_THEME=mono` and the `NO_COLOR`
 * convention drop every colour, which matters for a run piped into a file or
 * read on a terminal that renders dim text as invisible.
 */
export interface Theme {
  /** The hydra's steel blue: anything the eye should land on first. */
  accent: string;
  /** The darker navy, for structure that should recede. */
  frame: string;
  /** Body text. */
  ink: string;
  /** Secondary text: timestamps, models, counts. */
  muted: string;
  confirmed: string;
  refused: string;
  warn: string;
  running: string;
  done: string;
  idle: string;
  mono: boolean;
}

const BRAND: Theme = {
  accent: "#6d94c4",
  frame: "#3b5578",
  ink: "#e8e4d8",
  muted: "#8795a8",
  confirmed: "#8fbf7f",
  refused: "#d6786e",
  warn: "#d9a65c",
  running: "#6d94c4",
  done: "#8fbf7f",
  idle: "#5a6675",
  mono: false,
};

const MONO: Theme = {
  accent: "",
  frame: "",
  ink: "",
  muted: "",
  confirmed: "",
  refused: "",
  warn: "",
  running: "",
  done: "",
  idle: "",
  mono: true,
};

export function theme(): Theme {
  const want = (process.env.MYTHOS_THEME ?? "").toLowerCase();
  if (want === "mono" || process.env.NO_COLOR !== undefined) return MONO;
  return BRAND;
}

/** A colour prop that disappears in mono, so one component serves both. */
export const c = (t: Theme, colour: string) => (t.mono ? undefined : colour);

/**
 * Glyphs. The ASCII set is not a lesser fallback: a terminal without a Nerd
 * Font renders the others as boxes, and a status column of boxes is worse than
 * one of letters.
 */
export interface Glyphs {
  done: string;
  running: string;
  pending: string;
  incomplete: string;
  failed: string;
  confirmed: string;
  tested: string;
  skipped: string;
  refused: string;
  warn: string;
  bullet: string;
  arrow: string;
  barFull: string;
  barEmpty: string;
  spinner: string[];
}

const UNICODE: Glyphs = {
  done: "✔",
  running: "▸",
  pending: "·",
  incomplete: "~",
  failed: "✖",
  confirmed: "●",
  tested: "○",
  skipped: "–",
  refused: "⛔",
  warn: "▲",
  bullet: "·",
  arrow: "→",
  barFull: "━",
  barEmpty: "┈",
  spinner: ["◐", "◓", "◑", "◒"],
};

const ASCII: Glyphs = {
  done: "+",
  running: ">",
  pending: ".",
  incomplete: "~",
  failed: "x",
  confirmed: "*",
  tested: "o",
  skipped: "-",
  refused: "!",
  warn: "!",
  bullet: ".",
  arrow: "->",
  barFull: "=",
  barEmpty: "-",
  spinner: ["|", "/", "-", "\\"],
};

export function glyphs(): Glyphs {
  if ((process.env.MYTHOS_GLYPHS ?? "").toLowerCase() === "ascii") return ASCII;
  const lang = `${process.env.LC_ALL ?? ""}${process.env.LC_CTYPE ?? ""}${process.env.LANG ?? ""}`;
  return /utf-?8/i.test(lang) || process.platform === "darwin" ? UNICODE : ASCII;
}

/**
 * A horizontal bar as two pieces, so the filled and unfilled parts can be
 * coloured apart. One string in one colour reads as a full bar whatever the
 * glyph, which made an exploit phase two seconds in look finished.
 */
export function bar(ratio: number, width: number, g: Glyphs): [string, string] {
  const n = Math.max(0, Math.min(width, Math.round(ratio * width)));
  return [g.barFull.repeat(n), g.barEmpty.repeat(width - n)];
}

/** m:ss, or h:mm:ss once a run passes an hour. */
export function clock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h
    ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    : `${m}:${String(sec).padStart(2, "0")}`;
}
