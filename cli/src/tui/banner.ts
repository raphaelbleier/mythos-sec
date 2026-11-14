/**
 * The wordmark.
 *
 * The letters are the logo's own, in the hydra's steel blue, with the tagline
 * the logo uses. The full-screen view draws it as part of the frame when the
 * window is tall enough, rather than printing it above: a banner printed first
 * and then repainted over is a banner cut in half, and the terminal's
 * scrollback is not ours to rely on. The quiet mode gets the one-line form.
 */
import { c, theme, type Theme } from "./theme.js";

/**
 * Five rows of full blocks and spaces, nothing else. Half-block glyphs made a
 * prettier letterform on paper and an unreadable one in most terminal fonts:
 * "MYTHOS" came out as "MT INV3".
 */
const LETTERS: Record<string, string[]> = {
  M: ["\u2588   \u2588", "\u2588\u2588 \u2588\u2588", "\u2588 \u2588 \u2588", "\u2588   \u2588", "\u2588   \u2588"],
  Y: ["\u2588   \u2588", " \u2588 \u2588 ", "  \u2588  ", "  \u2588  ", "  \u2588  "],
  T: ["\u2588\u2588\u2588\u2588\u2588", "  \u2588  ", "  \u2588  ", "  \u2588  ", "  \u2588  "],
  H: ["\u2588   \u2588", "\u2588   \u2588", "\u2588\u2588\u2588\u2588\u2588", "\u2588   \u2588", "\u2588   \u2588"],
  O: [" \u2588\u2588\u2588 ", "\u2588   \u2588", "\u2588   \u2588", "\u2588   \u2588", " \u2588\u2588\u2588 "],
  S: [" \u2588\u2588\u2588\u2588", "\u2588    ", " \u2588\u2588\u2588 ", "    \u2588", "\u2588\u2588\u2588\u2588 "],
};

const ESC = (hex: string) => {
  const n = parseInt(hex.slice(1), 16);
  return `\x1b[38;2;${(n >> 16) & 255};${(n >> 8) & 255};${n & 255}m`;
};
const RESET = "\x1b[0m";

/** The five rows of the wordmark, without colour, for the view to render. */
export function wordmarkRows(): string[] {
  return [0, 1, 2, 3, 4].map((r) =>
    "MYTHOS"
      .split("")
      .map((ch) => LETTERS[ch]?.[r] ?? "     ")
      .join(" "),
  );
}

export const TAGLINE = "web red-team framework";

/** The wordmark as five rows, plus a tagline. Plain text when colour is off. */
export function banner(t: Theme = theme()): string {
  const word = "MYTHOS";
  const rows = [0, 1, 2, 3, 4].map((r) =>
    word
      .split("")
      .map((ch) => LETTERS[ch]?.[r] ?? "     ")
      .join(" "),
  );
  const tag = "web red-team framework";
  const pad = "  ";

  if (t.mono) {
    return [...rows.map((r) => pad + r), pad + tag, ""].join("\n");
  }
  const a = ESC(t.accent);
  const m = ESC(t.muted);
  return (
    [
      ...rows.map((r) => `${pad}${a}${r}${RESET}`),
      `${pad}${m}${tag}${RESET}`,
      "",
    ].join("\n")
  );
}

/** One line for the quiet mode, where three rows of block letters are noise. */
export function bannerLine(version: string, t: Theme = theme()): string {
  if (t.mono) return `mythos ${version} — web red-team framework, authorized testing only`;
  return (
    `${ESC(t.accent)}mythos${RESET} ${ESC(t.muted)}${version} — web red-team framework, ` +
    `authorized testing only${RESET}`
  );
}

export const colour = (t: Theme, hex: string, s: string) =>
  c(t, hex) ? `${ESC(hex)}${s}${RESET}` : s;
