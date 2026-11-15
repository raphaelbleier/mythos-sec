/**
 * The engagement directory and its scope file.
 *
 * `scope.yaml` is the authorization boundary. The agent never writes it: the
 * operator passes one with --scope, or the CLI generates the narrowest possible
 * file from the target URL (that one host, that one port) and nothing else.
 * Widening it is a human action, taken in an editor, outside a run.
 *
 * The reader here is a deliberately small YAML subset (scalars, inline and
 * block lists, quoted strings, comments) so the package needs no YAML
 * dependency and cannot be surprised by an anchor or a merge key in a file the
 * Python guards read differently. Anything it cannot parse is reported, not
 * guessed at.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { ENGAGEMENTS, ensureDir } from "./paths.js";

export interface ScopeRules {
  rate_limit_rps: number;
  allow_active: boolean;
  allow_exploit: boolean;
  max_requests?: number;
}

export interface Scope {
  file: string;
  dir: string;
  target: string;
  in_scope: string[];
  out_of_scope: string[];
  ports: number[];
  rules: ScopeRules;
  notes: string;
}

const unquote = (s: string) => s.replace(/^['"]|['"]$/g, "");

function parseScalar(raw: string): string | number | boolean {
  const v = unquote(raw.trim());
  if (v === "true") return true;
  if (v === "false") return false;
  if (v !== "" && !Number.isNaN(Number(v))) return Number(v);
  return v;
}

/** Minimal YAML: top-level keys, one nesting level, inline `[a, b]` or `- item` lists. */
export function parseYaml(text: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let key: string | null = null;
  let list: unknown[] | null = null;
  let map: Record<string, unknown> | null = null;

  // A key with nothing after the colon is either a block list or a nested map,
  // and which one it is only becomes clear on the next indented line. So both
  // containers are kept and the one that filled wins at flush time; flushing a
  // still-empty list over a filled map is how `rules:` lost its contents.
  const flush = () => {
    if (key) {
      if (list && list.length) out[key] = list;
      else if (map && Object.keys(map).length) out[key] = map;
      else if (list) out[key] = list;
    }
    list = null;
    map = null;
    key = null;
  };

  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\s+#.*$/, "").replace(/^#.*$/, "");
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const t = line.trim();

    if (t.startsWith("- ")) {
      if (indent > 0 && list) list.push(parseScalar(t.slice(2)));
      continue;
    }
    const m = /^([A-Za-z_][\w-]*):\s*(.*)$/.exec(t);
    if (!m) continue;
    const [, k, rest] = m as unknown as [string, string, string];

    if (indent > 0) {
      if (map) map[k] = parseScalar(rest);
      continue;
    }
    flush();
    if (rest === "") {
      list = [];
      map = {};
      key = k;
      continue;
    }
    if (rest.startsWith("[")) {
      out[k] = rest
        .replace(/^\[|\]$/g, "")
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean)
        .map(parseScalar);
      continue;
    }
    out[k] = parseScalar(rest);
  }
  flush();
  return out;
}

export function readScope(file: string): Scope {
  const text = readFileSync(file, "utf8");
  const y = parseYaml(text);
  const rules = (y.rules ?? {}) as Record<string, unknown>;
  const asList = (v: unknown): string[] =>
    Array.isArray(v) ? v.map(String).filter((s) => s && s !== "[]") : [];
  const target = String(y.target ?? "");
  if (!target) throw new Error(`${file}: no 'target' key — a scope file must name the target`);
  return {
    file: resolve(file),
    dir: resolve(file, ".."),
    target,
    in_scope: asList(y.in_scope),
    out_of_scope: asList(y.out_of_scope),
    ports: (Array.isArray(y.ports) ? y.ports : []).map(Number).filter((n) => !Number.isNaN(n)),
    rules: {
      rate_limit_rps: Number(rules.rate_limit_rps ?? 5),
      allow_active: rules.allow_active !== false,
      allow_exploit: rules.allow_exploit !== false,
      max_requests: rules.max_requests === undefined ? undefined : Number(rules.max_requests),
    },
    notes: String(y.notes ?? ""),
  };
}

const stamp = () => new Date().toISOString().slice(0, 10).replace(/-/g, "");

/** `engagements/<host>[-<port>]-<date>/` — the same shape the Python scripts expect. */
export function engagementDir(target: string): string {
  const u = new URL(target);
  const port = u.port ? `-${u.port}` : "";
  return join(ENGAGEMENTS, `${u.hostname}${port}-${stamp()}`);
}

export interface NewScopeOptions {
  target: string;
  rps?: number;
  notes?: string;
  dir?: string;
}

/**
 * The narrowest scope file the target allows: that host, that port, nothing
 * else. Generated only when the operator passed no file of their own.
 */
export function writeScope(opts: NewScopeOptions): Scope {
  const u = new URL(opts.target);
  const dir = ensureDir(opts.dir ?? engagementDir(opts.target));
  const file = join(dir, "scope.yaml");
  const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
  const body = [
    `# generated by mythos for ${opts.target} on ${new Date().toISOString()}`,
    "# This file is the authorization boundary. Widen it by hand, never during a run,",
    "# and only for a target you are allowed to test.",
    `target: ${u.origin}`,
    "in_scope:",
    `  - ${u.hostname}`,
    "out_of_scope: []",
    `ports: [${port}]`,
    "rules:",
    `  rate_limit_rps: ${opts.rps ?? 5}`,
    "  allow_active: true",
    "  allow_exploit: true",
    "identities: []",
    `notes: ${JSON.stringify(opts.notes ?? `Authorized assessment of ${u.origin}.`)}`,
    "",
  ].join("\n");
  writeFileSync(file, body);
  return readScope(file);
}

/** Resolve the engagement for this run: an explicit file, or a fresh directory. */
export function resolveScope(target: string | undefined, scopeFile: string | undefined, rps?: number): Scope {
  if (scopeFile) {
    if (!existsSync(scopeFile)) throw new Error(`scope file not found: ${scopeFile}`);
    const s = readScope(scopeFile);
    if (target && new URL(target).origin !== new URL(s.target).origin) {
      throw new Error(
        `--target ${target} is not the target in ${basename(scopeFile)} (${s.target}). ` +
          `Edit the scope file if that target is authorized; the CLI will not widen it.`,
      );
    }
    return s;
  }
  if (!target) throw new Error("need --target <url> or --scope <file>");
  return writeScope({ target, rps });
}
