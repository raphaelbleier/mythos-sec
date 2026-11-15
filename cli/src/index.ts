#!/usr/bin/env node
/**
 * mythos — the command line.
 *
 *   mythos -t http://127.0.0.1:5001            run an engagement, full screen
 *   mythos -t <url> --scope engagements/x/scope.yaml
 *   mythos -t <url> -n                          quiet, one line per event
 *   mythos login openrouter                     OAuth, or --api-key for the rest
 *   mythos providers                            what can be reached, and how
 *   mythos doctor                               what is missing before a run
 *
 * There is one human gate in the whole tool and it is the scope file. After that
 * the engagement runs recon, triage, scan, exploit, validate and report
 * unattended, and nothing will ask the operator anything.
 *
 * The conventions this file follows, and the few it deliberately does not, are
 * written down in docs/cli-design.md with the rule each one came from. The two
 * that shape the code most: every stream has one job (stdout carries the
 * machine's answer, stderr carries the human's narration, and `--json` makes
 * that split absolute), and every failure a user can cause names the next
 * command rather than a stack.
 */
import { existsSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Bus } from "./bus.js";
import { Driver } from "./driver.js";
import { plan } from "./model.js";
import { attachPlain, type Level } from "./plain.js";
import { ENGAGEMENTS, ensureDir, script } from "./paths.js";
import * as auth from "./providers/auth.js";
import { login as openrouterLogin } from "./providers/openrouter.js";
import { PROVIDERS, byId } from "./providers/registry.js";
import { resolveScope } from "./scope.js";
import { TAGLINE, bannerLine } from "./tui/banner.js";
import { glyphs, theme } from "./tui/theme.js";

interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
}

/**
 * What the shell learns from a run.
 *
 * 0 and 1 are what the repository already meant by them and are not up for
 * reinterpretation: a wrapper script that treats 1 as "the engagement did not
 * finish cleanly" keeps working. 2 is the POSIX/GNU habit for a command that
 * was never able to start, and keeping it separate from 1 is the whole point —
 * a CI step can retry a 1 and must never retry a 2. 130 is 128+SIGINT.
 */
export const EXIT = {
  ok: 0,
  /** The work ran and did not come out clean: a phase incomplete, a check failed. */
  unclean: 1,
  /** Usage or configuration: a bad flag, a missing credential, nothing ran. */
  usage: 2,
  interrupted: 130,
} as const;

const PKG = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      version?: string;
      license?: string;
    };
  } catch {
    // An install that lost its package.json still has to run; only --version suffers.
    return {};
  }
})();
const VERSION = PKG.version ?? "0.0.0";

/**
 * Every failure a user can cause goes through here.
 *
 * Three things, in the order clig.dev asks for them ("consider where the user
 * will look first — put the most important information last"): what went wrong,
 * what mythos was doing when it did, and the one command that fixes it. The
 * next action is last because that is the line the eye lands on, and it is the
 * only line that is a command.
 */
function fail(what: string, doing: string, next: string | string[]): number {
  const steps = Array.isArray(next) ? next : [next];
  process.stderr.write(
    `mythos: ${what}\n  while ${doing}\n` +
      steps.map((s, i) => `  ${i === 0 ? "next:" : "  or:"} ${s}\n`).join(""),
  );
  return EXIT.usage;
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

interface FlagSpec {
  long: string;
  short?: string;
  /** The value's name in help. Absent means the flag is a boolean. */
  arg?: string;
  help: string;
}

/**
 * The flags every command takes, with the standard names clig.dev lists so that
 * nobody has to look them up: `-h/--help`, `-V/--version` (never `-v`, which is
 * verbose), `-q/--quiet`, `-v/--verbose`, `--json`, `--no-input`.
 */
const COMMON: FlagSpec[] = [
  { long: "help", short: "h", help: "this help" },
  { long: "version", short: "V", help: "print the version and exit" },
  { long: "json", help: "one JSON document on stdout, all human text on stderr" },
  { long: "quiet", short: "q", help: "only what a later reader must act on" },
  { long: "verbose", short: "v", help: "tool results and the agents' prose too" },
  { long: "no-color", help: "never colour the output (so does NO_COLOR=1)" },
  { long: "no-input", help: "never prompt; fail instead and name the flag" },
  { long: "yes", short: "y", help: "answer the one confirmation in advance" },
];

const RUN_FLAGS: FlagSpec[] = [
  { long: "target", short: "t", arg: "url", help: "the target. A scope file is generated for this host and port alone if you pass none." },
  { long: "scope", short: "s", arg: "file", help: "an existing scope.yaml. This is the authorization boundary and nothing in the run widens it." },
  { long: "budget", short: "b", arg: "seconds", help: "whole-run wall clock. Default 3600." },
  { long: "model", short: "m", arg: "spec", help: "pin every tier, e.g. openrouter/z-ai/glm-5.3" },
  { long: "profile", arg: "name", help: "a profile from models.json instead" },
  { long: "workers", short: "w", arg: "n", help: "parallel exploit workers. Default 3." },
  { long: "retries", arg: "n", help: "attempts per phase before it is recorded incomplete. Default 2." },
  { long: "skip", arg: "list", help: "phases to skip, comma separated: recon, triage, scan, exploit, validate, report" },
  { long: "rps", arg: "n", help: "rate limit for a generated scope file. Default 5." },
  { long: "base-url", arg: "url", help: "OpenAI-compatible endpoint, for --model custom/<name>" },
  { long: "headed", help: "show the browser instead of running it headless" },
  { long: "no-tui", short: "n", help: "no full-screen view, one line per event" },
];

interface Command {
  name: string;
  summary: string;
  synopsis: string[];
  flags: FlagSpec[];
  detail?: string;
  examples: string[];
  /** The environment this command reads, as NAME + what it does. */
  env: Array<[string, string]>;
  /** Whether `--json` produces a document. */
  json: boolean;
}

const GLOBAL_ENV: Array<[string, string]> = [
  ["NO_COLOR", "set to anything non-empty: never colour (no-color.org)"],
  ["FORCE_COLOR", "colour even into a pipe; 0 or false means never"],
  ["MYTHOS_THEME", "mono drops every colour, as --no-color does"],
  ["MYTHOS_GLYPHS", "ascii forces the ASCII glyph set; otherwise the locale decides"],
  ["MYTHOS_HOME", "where credentials live. Default $XDG_STATE_HOME/mythos"],
  ["MYTHOS_REPO", "the repository whose skills and scripts to drive"],
];

const COMMANDS: Command[] = [
  {
    name: "run",
    summary: "run an engagement against a target",
    synopsis: ["mythos -t <url> [options]", "mythos run -t <url> [options]", "mythos -s <scope.yaml> [options]"],
    flags: RUN_FLAGS,
    detail:
      "The scope file is the authorization boundary. Pass one with --scope and nothing in\n" +
      "the run widens it; pass only --target and mythos writes the narrowest file it can —\n" +
      "that one host, that one port — into a fresh engagement directory. Generating one for\n" +
      "a host that is not loopback needs --yes, or a typed confirmation on a terminal.\n\n" +
      "After that nothing asks the operator anything. Phases: recon, triage, scan, exploit,\n" +
      "validate, report. Every event is also appended to run-events.jsonl in the engagement\n" +
      "directory, so a run watched on screen is never the only record of itself.",
    examples: [
      "mythos -t http://127.0.0.1:5001",
      "mythos -t https://target.example.com -s engagements/acme/scope.yaml",
      "mythos -t https://target.example.com -n -q | tee run.log",
      "mythos -t https://target.example.com --json > run.json",
      "mythos -t <url> --skip exploit,validate -b 900",
    ],
    env: [
      ["MYTHOS_PROFILE", "the models.json profile, when --profile is not given"],
      ["MYTHOS_BASE_URL", "the OpenAI-compatible endpoint, when --base-url is not given"],
      ["MYTHOS_NET", "host, or a docker network the toolbox should join"],
      ["MYTHOS_IMAGE", "the toolbox image, instead of the pinned digest"],
      ["MYTHOS_SCOPE_ENFORCE", "warn (default) or block for the scope guard"],
      ["MYTHOS_BUDGET_ENFORCE", "warn (default) or block for the request budget"],
      ["MYTHOS_CHROMIUM", "a Chromium binary, instead of Playwright's"],
      ["OPENROUTER_API_KEY", "and the other providers' keys; 'mythos providers' lists them"],
    ],
    json: true,
  },
  {
    name: "login",
    summary: "store a credential for a model provider",
    synopsis: ["mythos login <provider> [--api-key <key>]"],
    flags: [{ long: "api-key", arg: "key", help: "a key you already have, instead of the OAuth flow" }],
    detail:
      "OpenRouter has an OAuth flow: mythos opens a browser and waits for the callback,\n" +
      "which needs a human, so it refuses to start when stdin is not a terminal or\n" +
      "--no-input was passed. Everything else takes --api-key, or its environment\n" +
      "variable, which 'mythos providers' names per provider.\n\n" +
      "A key passed on the command line is visible in the process list and the shell\n" +
      "history of every user on the machine. Prefer the environment variable, or pipe\n" +
      "the key in: mythos login anthropic --api-key \"$(cat key.txt)\" is no better.",
    examples: ["mythos login openrouter", "mythos login anthropic --api-key sk-ant-..."],
    env: [["MYTHOS_HOME", "where the credential is written"]],
    json: true,
  },
  {
    name: "logout",
    summary: "forget a stored credential",
    synopsis: ["mythos logout <provider>"],
    flags: [],
    examples: ["mythos logout openrouter"],
    env: [["MYTHOS_HOME", "where the credential is read from"]],
    json: true,
  },
  {
    name: "providers",
    summary: "list providers and what is configured",
    synopsis: ["mythos providers"],
    flags: [],
    examples: ["mythos providers", "mythos providers --json | jq '.[] | select(.usable).id'"],
    env: [["MYTHOS_HOME", "where stored credentials are read from"]],
    json: true,
  },
  {
    name: "doctor",
    summary: "check the machine before a run",
    synopsis: ["mythos doctor"],
    flags: [],
    detail:
      "Each precondition a run needs, as pass or fail with the command that fixes it.\n" +
      "Exits 0 when everything passes and 1 when anything does not, so it can gate a\n" +
      "wrapper script. The toolbox check pulls and starts the signed Kali image on the\n" +
      "first run, which takes a few minutes.",
    examples: ["mythos doctor", "mythos doctor --json | jq '.checks[] | select(.ok == false)'"],
    env: [
      ["MYTHOS_IMAGE", "the toolbox image to probe"],
      ["MYTHOS_NET", "host, or a docker network the toolbox should join"],
    ],
    json: true,
  },
  {
    name: "verdicts",
    summary: "the endpoint ledger of an engagement",
    synopsis: ["mythos verdicts [dir]"],
    flags: [],
    detail:
      "Every endpoint the run reached and what it decided. Without a directory, the most\n" +
      "recently touched engagement. A candidate is not an answer: the validate phase still\n" +
      "owes it a confirmed or a rejected.",
    examples: ["mythos verdicts", "mythos verdicts engagements/acme-20261115", "mythos verdicts --json | jq .summary"],
    env: [],
    json: true,
  },
  {
    name: "web",
    summary: "a local, read-only view of every engagement",
    synopsis: ["mythos web [--port <n>]"],
    flags: [
      { long: "port", arg: "n", help: "pin the port instead of taking a random one" },
      { long: "engagements", arg: "dir", help: "read a directory other than engagements/" },
      {
        long: "allow-remote",
        help:
          "bind a non-loopback address. This puts engagement data — credentials, session " +
          "cookies and proofs of exploitation — on the network. Loopback otherwise.",
      },
      {
        long: "allow-actions",
        help: "reserved. No action is implemented; the server is read-only with this flag set.",
      },
    ],
    detail:
      "The URL it prints carries a per-run bearer token, and that token is the only\n" +
      "credential: anyone with the URL has every engagement on this machine. The view is\n" +
      "read-only — no endpoint starts a run, sends a request or edits a scope file — and\n" +
      "every byte a target chose is rendered as text, never as markup.",
    examples: ["mythos web", "mythos web --port 7777", "mythos web --engagements /mnt/data/engagements"],
    env: [],
    json: false,
  },
  {
    name: "demo",
    summary: "replay a scripted run through the view",
    synopsis: ["mythos demo [--every <ms>]"],
    flags: [{ long: "every", arg: "ms", help: "milliseconds between replayed events. Default 160." }],
    detail: "No network, no model, no docker: a fixed script of events, to check the view after a change.",
    examples: ["mythos demo", "mythos demo --every 20", "mythos demo -n | head"],
    env: [],
    json: false,
  },
  {
    name: "help",
    summary: "help for mythos or for one command",
    synopsis: ["mythos help [command]"],
    flags: [],
    examples: ["mythos help", "mythos help run"],
    env: [],
    json: false,
  },
];

const byName = (n: string) => COMMANDS.find((c) => c.name === n);
const SPECS = [...COMMON, ...COMMANDS.flatMap((c) => c.flags)];
const TAKES_VALUE = new Set(SPECS.filter((s) => s.arg).map((s) => s.long));
const ALIAS: Record<string, string> = Object.fromEntries(
  SPECS.filter((s) => s.short).map((s) => [s.short!, s.long]),
);

class UsageError extends Error {}

/**
 * The argument parser.
 *
 * No dependency: the grammar is POSIX's, which is small enough to read here and
 * one less package in a tool that runs with the operator's credentials. What it
 * follows, from the POSIX utility conventions and the GNU standards: every short
 * flag has a long twin, `--` ends the options so a target or a path may begin
 * with a dash, `--flag=value` and `--flag value` are the same, short flags
 * cluster and only the last in a cluster may take a value, and an option's value
 * may itself begin with a dash. Unknown flags are an error, never a silent
 * no-op, because a typo in --skip is the kind of thing that runs a phase the
 * operator thought they had turned off.
 */
export function parse(argv: string[]): Args {
  const out: Args = { _: [], flags: {} };
  const take = (key: string, i: number): number => {
    if (i + 1 >= argv.length) throw new UsageError(`--${key} needs a value`);
    out.flags[key] = argv[i + 1]!;
    return i + 1;
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split("=", 2);
      const key = k!;
      if (!SPECS.some((s) => s.long === key)) throw new UsageError(`unknown flag: --${key}`);
      if (inline !== undefined) out.flags[key] = inline;
      else if (TAKES_VALUE.has(key)) i = take(key, i);
      else out.flags[key] = true;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      const chars = [...a.slice(1)];
      for (let j = 0; j < chars.length; j++) {
        const ch = chars[j]!;
        const key = ALIAS[ch];
        if (!key) throw new UsageError(`unknown flag: -${ch}`);
        if (TAKES_VALUE.has(key)) {
          if (j < chars.length - 1) throw new UsageError(`-${ch} takes a value, so it must end the group -${a.slice(1)}`);
          i = take(key, i);
        } else {
          out.flags[key] = true;
        }
      }
      continue;
    }
    out._.push(a);
  }
  return out;
}

/**
 * The common flags this command actually honours.
 *
 * clig.dev wants consistency across subcommands, not a help page that offers a
 * flag the command then rejects: --json only where there is a document, and
 * --yes/--no-input only where something could ask.
 */
function commonFor(cmd: Command): FlagSpec[] {
  const asks = cmd.name === "run" || cmd.name === "login";
  return COMMON.filter(
    (s) => (s.long !== "json" || cmd.json) && (!["yes", "no-input"].includes(s.long) || asks),
  );
}

/** The flags this command accepts, so a typo lands on the command that has it. */
function checkFlags(cmd: Command, args: Args): void {
  const allowed = new Set([...commonFor(cmd), ...cmd.flags].map((s) => s.long));
  for (const k of Object.keys(args.flags)) {
    if (allowed.has(k)) continue;
    if (k === "json") {
      throw new UsageError(`'mythos ${cmd.name}' has no structured output, so --json would print nothing`);
    }
    if (k === "yes" || k === "no-input") {
      throw new UsageError(`--${k} answers a confirmation, and 'mythos ${cmd.name}' never asks for one`);
    }
    const owner = COMMANDS.find((c) => c.flags.some((s) => s.long === k));
    throw new UsageError(
      owner
        ? `--${k} is a flag of 'mythos ${owner.name}', not of 'mythos ${cmd.name}'`
        : `unknown flag: --${k}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

const AUTHORIZED =
  "Mythos tests only what its scope file authorizes: bug-bounty programs in scope,\n" +
  "systems you own, or lab targets. It is non-destructive by design and the guard\n" +
  "refuses data destruction, brute force and denial of service outright.";

function flagLines(flags: FlagSpec[]): string {
  const left = (s: FlagSpec) =>
    `${s.short ? `-${s.short}, ` : "    "}--${s.long}${s.arg ? ` <${s.arg}>` : ""}`;
  const width = Math.max(...flags.map((s) => left(s).length));
  return flags
    .map((s) => {
      const pad = " ".repeat(width - left(s).length);
      // Wrapped at the column the text starts in, so a long description does not
      // land under the next flag's name when the terminal is 80 wide.
      const indent = " ".repeat(width + 4);
      const words = s.help.split(" ");
      const lines: string[] = [];
      let line = "";
      for (const w of words) {
        if (line && (line + " " + w).length > 72 - width) {
          lines.push(line);
          line = w;
        } else line = line ? `${line} ${w}` : w;
      }
      lines.push(line);
      return `  ${left(s)}${pad}  ${lines.join(`\n${indent}`)}`;
    })
    .join("\n");
}

/** The whole help: what clig.dev calls "extensive help text when asked". */
function fullHelp(): string {
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  return [
    `mythos ${VERSION} ${glyphs().dash} ${TAGLINE}, for authorized testing only`,
    "",
    "USAGE",
    "  mythos -t <url> [options]            run an engagement",
    "  mythos <command> [options]",
    "",
    "COMMANDS",
    ...COMMANDS.filter((c) => c.name !== "run").map((c) => `  ${c.name.padEnd(width)}  ${c.summary}`),
    "",
    "RUN OPTIONS",
    flagLines(RUN_FLAGS),
    "",
    "COMMON OPTIONS",
    flagLines(COMMON),
    "",
    "KEYS (full-screen view)",
    "  p pause/resume    h send a hint to the agents    q abort    ctrl-c abort",
    "",
    "ENVIRONMENT",
    ...GLOBAL_ENV.map(([k, v]) => `  ${k.padEnd(14)}  ${v}`),
    "  (per command: mythos help <command>)",
    "",
    "EXIT CODES",
    "  0  the work finished and came out clean",
    "  1  it ran and did not: a phase incomplete or failed, a check that failed",
    "  2  usage or configuration: nothing ran",
    "  130  interrupted",
    "",
    "EXAMPLES",
    ...(byName("run")?.examples ?? []).map((e) => `  ${e}`),
    "",
    "'mythos help <command>' for one command. 'mythos doctor' before the first run.",
    "",
    AUTHORIZED,
  ].join("\n");
}

/** Help for one command, with its own examples and the environment it reads. */
function commandHelp(c: Command): string {
  const flags = [...c.flags, ...commonFor(c)];
  return [
    `mythos ${c.name} ${glyphs().dash} ${c.summary}`,
    "",
    "USAGE",
    ...c.synopsis.map((s) => `  ${s}`),
    ...(c.detail ? ["", c.detail] : []),
    "",
    "OPTIONS",
    flagLines(flags),
    ...(c.env.length ? ["", "ENVIRONMENT", ...c.env.map(([k, v]) => `  ${k.padEnd(22)}  ${v}`)] : []),
    "",
    "EXAMPLES",
    ...c.examples.map((e) => `  ${e}`),
    "",
  ].join("\n");
}

/**
 * The short form, for an invocation that said nothing.
 *
 * clig.dev: "display concise help text by default" — a description, an example
 * or two, and where the rest is. The full text is four screens and scrolling it
 * away is not an answer to "what is this".
 */
function conciseHelp(): string {
  return [
    `mythos ${VERSION} ${glyphs().dash} ${TAGLINE}, for authorized testing only`,
    "",
    "  mythos -t http://127.0.0.1:5001        run an engagement",
    "  mythos doctor                          check the machine first",
    "  mythos --help                          every command and flag",
    "",
    AUTHORIZED,
  ].join("\n");
}

function versionText(): string {
  // GNU: the first line is meant to be easy to parse, and the version number
  // proper starts after the last space.
  return [
    `mythos ${VERSION}`,
    `${PKG.license ?? "MIT"} licence. For authorized testing only.`,
    `node ${process.version} on ${process.platform}-${process.arch}`,
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const jsonOut = (doc: unknown) => process.stdout.write(JSON.stringify(doc, null, 2) + "\n");

/** stdout belongs to the document when --json is on, so narration moves over. */
const humanStream = (args: Args) => (args.flags.json === true ? process.stderr : process.stdout);

function level(args: Args): Level {
  // clig.dev asks for both and says they compose: one step down for --quiet,
  // one step up for --verbose, so -qv is simply the default again.
  const n = 1 + (args.flags.verbose === true ? 1 : 0) - (args.flags.quiet === true ? 1 : 0);
  return Math.max(0, Math.min(2, n)) as Level;
}

async function main(argv: string[]): Promise<number> {
  let args: Args;
  try {
    args = parse(argv);
  } catch (e) {
    return fail((e as Error).message, "reading the command line", "mythos --help");
  }

  // --version and --help answer wherever they appear, which is what clig.dev
  // means by "show full help when -h and --help are passed ... regardless of
  // whether other arguments and flags are set".
  if (args.flags.version === true) {
    process.stdout.write(versionText());
    return EXIT.ok;
  }

  const first = args._[0];
  const cmd = first && byName(first) ? byName(first)! : byName("run")!;
  const named = Boolean(first && byName(first));

  if (first && !named && !first.startsWith("-") && !args.flags.target && !args.flags.scope) {
    // Not treated as a target: clig.dev warns against a catch-all subcommand,
    // and `mythos stage` silently probing http://stage would be worse than an error.
    return fail(
      `unknown command: ${first}`,
      "choosing what to run",
      [`mythos --help  (the commands are: ${COMMANDS.map((c) => c.name).join(", ")})`, `mythos -t ${first}  if you meant a target`],
    );
  }

  if (cmd.name === "help" || args.flags.help === true) {
    // `mythos help run` and `mythos run --help` are the same page; a bare
    // --help is the whole thing, which is what clig.dev means by extensive.
    const topic = cmd.name === "help" ? args._[1] : named ? cmd.name : undefined;
    const target = topic ? byName(topic) : undefined;
    if (topic && !target) {
      return fail(`no such command: ${topic}`, "looking up help", "mythos --help");
    }
    process.stdout.write(target ? commandHelp(target) : fullHelp() + "\n");
    return EXIT.ok;
  }

  if (!named && !args.flags.target && !args.flags.scope && args._.length === 0) {
    process.stdout.write(conciseHelp() + "\n");
    return EXIT.ok;
  }

  try {
    checkFlags(cmd, args);
  } catch (e) {
    return fail((e as Error).message, `reading 'mythos ${cmd.name}'`, `mythos help ${cmd.name}`);
  }

  switch (cmd.name) {
    case "login":
      return cmdLogin(args);
    case "logout":
      return cmdLogout(args);
    case "providers":
      return cmdProviders(args);
    case "doctor":
      return cmdDoctor(args);
    case "verdicts":
      return cmdVerdicts(args);
    case "web":
      return cmdWeb(args);
    case "demo":
      return cmdDemo(args);
    default:
      return cmdRun(args);
  }
}

async function cmdLogin(args: Args): Promise<number> {
  const id = args._[1];
  if (!id) {
    return fail(
      "no provider named",
      "storing a credential",
      ["mythos providers  (then: mythos login <provider>)"],
    );
  }
  const p = byId(id);
  if (!p) {
    return fail(`unknown provider: ${id}`, "storing a credential", "mythos providers");
  }
  const key = typeof args.flags["api-key"] === "string" ? args.flags["api-key"] : undefined;
  const say = humanStream(args);

  if (key) {
    auth.store(p.id, { key, via: "paste" });
    if (args.flags.json === true) jsonOut({ provider: p.id, via: "paste", hint: auth.hint(key) });
    else say.write(`stored a key for ${p.label} (${auth.hint(key)})\n`);
    return EXIT.ok;
  }
  if (p.oauth === "openrouter") {
    // The browser round trip is the one interactive thing in the tool, so it
    // obeys clig.dev's rule for interactivity: only on a terminal, and when
    // there is none, fail naming the flag that would have answered it.
    if (args.flags["no-input"] === true || !process.stdin.isTTY) {
      return fail(
        "the OAuth flow needs a browser and a terminal",
        `signing in to ${p.label} without an interactive stdin`,
        [`mythos login ${p.id} --api-key <key>`, `export ${p.envKeys[0] ?? "the provider's key variable"}=<key>`],
      );
    }
    const r = await openrouterLogin({ print: (s) => void say.write(s + "\n") });
    auth.store(p.id, { key: r.key, via: "oauth" });
    if (args.flags.json === true) jsonOut({ provider: p.id, via: "oauth", hint: auth.hint(r.key) });
    else say.write(`signed in to ${p.label} (${auth.hint(r.key)})\n`);
    return EXIT.ok;
  }
  return fail(
    `${p.label} has no OAuth flow here`,
    "storing a credential",
    [`mythos login ${p.id} --api-key <key>  (get one at ${p.docs})`, `export ${p.envKeys[0] ?? "the provider's key variable"}=<key>`],
  );
}

function cmdLogout(args: Args): number {
  const id = args._[1];
  if (!id) return fail("no provider named", "forgetting a credential", "mythos providers");
  const forgotten = auth.forget(id);
  if (args.flags.json === true) jsonOut({ provider: id, forgotten });
  else humanStream(args).write(forgotten ? `forgot ${id}\n` : `nothing stored for ${id}\n`);
  return EXIT.ok;
}

function cmdProviders(args: Args): number {
  const have = new Set(auth.available());
  const saved = new Map(auth.stored().map((s) => [s.provider, s]));
  const rows = PROVIDERS.map((p) => {
    const s = saved.get(p.id);
    const envHit = p.envKeys.find((k) => process.env[k]);
    return {
      id: p.id,
      label: p.label,
      usable: have.has(p.id),
      credential: s
        ? { kind: "stored" as const, via: s.via, hint: s.hint }
        : envHit
          ? { kind: "env" as const, variable: envHit }
          : p.local
            ? { kind: "local" as const }
            : { kind: "none" as const },
      env_keys: p.envKeys,
      examples: p.examples,
      next: s || envHit || p.local ? null : p.oauth ? `mythos login ${p.id}` : `mythos login ${p.id} --api-key <key>`,
    };
  });

  if (args.flags.json === true) {
    jsonOut(rows);
    return EXIT.ok;
  }

  const g = glyphs();
  const how = (r: (typeof rows)[number]) =>
    r.credential.kind === "stored"
      ? `stored (${r.credential.via}, ${r.credential.hint})`
      : r.credential.kind === "env"
        ? `$${r.credential.variable}`
        : r.credential.kind === "local"
          ? "local server"
          : (r.next ?? "no credential");
  const body = rows
    .map((r) => `${r.usable ? g.done : " "} ${r.id.padEnd(12)} ${r.label.padEnd(34)} ${how(r)}`)
    .join("\n");

  if (level(args) < 1) {
    process.stdout.write(rows.filter((r) => r.usable).map((r) => r.id).join("\n") + "\n");
    return EXIT.ok;
  }
  process.stdout.write(
    `Providers (${g.done} = usable now)\n\n${body}\n\n` +
      `Subscription logins: OpenRouter's OAuth is implemented, because OpenRouter\n` +
      `publishes that flow for third-party clients and it mints a real key. Consumer\n` +
      `plans for ChatGPT, Claude and Copilot are not, and will not be: those flows\n` +
      `require borrowing another client's OAuth credentials, the providers either\n` +
      `forbid it or merely tolerate it, and the account that gets suspended is yours.\n` +
      `One OpenRouter login reaches most of the models above.\n\n` +
      `Pin a model as provider/model, e.g. --model openrouter/z-ai/glm-5.3.\n`,
  );
  return EXIT.ok;
}

interface Check {
  name: string;
  ok: boolean;
  detail: string;
  /** The command that fixes it. Printed only when the check failed. */
  fix?: string;
}

async function cmdDoctor(args: Args): Promise<number> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  const checks: Check[] = [];
  const first = (s: string) => s.trim().split("\n")[0] ?? "";

  const probe = async (name: string, file: string, argv: string[], fix: string, timeout = 20_000) => {
    try {
      const { stdout, stderr } = await run(file, argv, { timeout, maxBuffer: 8 << 20 });
      checks.push({ name, ok: true, detail: first(stdout || stderr) });
    } catch (e) {
      checks.push({ name, ok: false, detail: first((e as Error).message), fix });
    }
  };

  checks.push({ name: "node", ok: true, detail: process.version });
  await probe("python3", "python3", ["--version"], "install Python 3: the scripts/ helpers are stdlib-only Python");
  // `docker --version` answers from the client alone, which passes on a machine
  // where the daemon is down and the toolbox therefore cannot start.
  await probe("docker", "docker", ["version", "--format", "{{.Server.Version}}"], "start the docker daemon: systemctl start docker");
  // One exec, not `mythos tools`: probing fifteen binaries inside the container
  // takes minutes, and what doctor needs to know is only whether the toolbox
  // runs a command at all. `mythos tools` is the command for the rest.
  await probe(
    "toolbox",
    "python3",
    [script("mythos"), "sh", "command -v curl sqlmap ffuf | tr '\\n' ' '"],
    "scripts/mythos up  (or MYTHOS_BUILD=1 scripts/mythos up to build it locally)",
    240_000,
  );

  const creds = auth.available();
  checks.push({
    name: "model credential",
    ok: creds.length > 0,
    detail: creds.length ? creds.join(", ") : "none stored and none in the environment",
    fix: "mythos login openrouter  (one key reaches most models; 'mythos providers' lists the rest)",
  });

  try {
    const p = plan({});
    checks.push({
      name: "independent validator",
      ok: !p.singleModelValidation,
      detail: p.singleModelValidation
        ? `profile ${p.profile} has one model for both tiers; findings will say the check was not independent`
        : `${p.tiers.validator} reviews ${p.tiers.strong}`,
      fix: "pick a profile whose validator tier differs, in models.json, or pass --profile",
    });
  } catch (e) {
    checks.push({
      name: "independent validator",
      ok: false,
      detail: first((e as Error).message),
      fix: "mythos login <provider>, or --profile <name> from models.json",
    });
  }

  for (const s of ["probe", "verify", "coverage", "findings", "cvefeed", "traffic"]) {
    const f = script(s);
    checks.push({
      name: `scripts/${s}`,
      ok: existsSync(f),
      detail: existsSync(f) ? "" : `missing at ${f}`,
      fix: "the repository checkout is incomplete: re-clone it, or set MYTHOS_REPO to a complete one",
    });
  }

  // An engagement directory that cannot be written turns into a failed run three
  // phases in, long after the model budget has been spent.
  try {
    const probeFile = join(ensureDir(ENGAGEMENTS), `.doctor-${process.pid}`);
    writeFileSync(probeFile, "");
    unlinkSync(probeFile);
    checks.push({ name: "engagement dir", ok: true, detail: ENGAGEMENTS });
  } catch (e) {
    checks.push({
      name: "engagement dir",
      ok: false,
      detail: first((e as Error).message),
      fix: `make ${ENGAGEMENTS} writable, or point MYTHOS_REPO at a checkout you own`,
    });
  }

  try {
    const { chromium } = await import("playwright-core");
    const b = await chromium.launch({ headless: true, args: ["--no-sandbox"] }).catch(async () =>
      chromium.launch({ headless: true, channel: "chrome", args: ["--no-sandbox"] }),
    );
    checks.push({ name: "browser", ok: true, detail: "chromium starts" });
    await b.close();
  } catch (e) {
    checks.push({
      name: "browser",
      ok: false,
      detail: first((e as Error).message),
      fix: "npx playwright install chromium",
    });
  }

  const bad = checks.filter((c) => !c.ok);
  if (args.flags.json === true) {
    jsonOut({ ok: bad.length === 0, checks });
    return bad.length ? EXIT.unclean : EXIT.ok;
  }

  const g = glyphs();
  const shown = level(args) < 1 ? bad : checks;
  let out = "";
  for (const c of shown) {
    out += `${c.ok ? g.done : g.failed} ${c.name.padEnd(22)} ${c.detail}\n`;
    if (!c.ok && c.fix) out += `${" ".repeat(2)}  fix: ${c.fix}\n`;
  }
  out += bad.length
    ? `\n${bad.length} problem${bad.length > 1 ? "s" : ""} to fix before a run: ${bad.map((c) => c.name).join(", ")}\n`
    : "\nReady. Next: mythos -t <url>\n";
  process.stdout.write(out);
  return bad.length ? EXIT.unclean : EXIT.ok;
}

function cmdVerdicts(args: Args): number {
  const dir = args._[1] ?? newestEngagement();
  if (!dir) {
    return fail(
      `no engagement directory under ${ENGAGEMENTS}`,
      "looking for the newest engagement",
      ["mythos -t <url>  to run one", "mythos verdicts <dir>  if the engagement is elsewhere"],
    );
  }
  const f = join(dir, "verdicts.json");
  if (!existsSync(f)) {
    process.stderr.write(
      `mythos: no verdict ledger in ${dir}\n  while reading the engagement\n` +
        `  next: the run never reached the exploit phase — see ${join(dir, "run-events.jsonl")}\n`,
    );
    return EXIT.unclean;
  }
  let rows: Array<{ endpoint: string; state: string; note: string }>;
  try {
    rows = JSON.parse(readFileSync(f, "utf8")) as typeof rows;
  } catch (e) {
    return fail(
      `${f} is not valid JSON: ${(e as Error).message}`,
      "reading the verdict ledger",
      "the file was truncated, probably by a killed run — delete it and retest the engagement",
    );
  }
  const by = rows.reduce<Record<string, number>>((a, r) => ({ ...a, [r.state]: (a[r.state] ?? 0) + 1 }), {});

  if (args.flags.json === true) {
    jsonOut({ dir, count: rows.length, summary: by, endpoints: rows });
    return EXIT.ok;
  }

  const g = glyphs();
  const mark: Record<string, string> = {
    candidate: g.warn,
    confirmed: g.confirmed,
    rejected: g.refused,
    tested: g.tested,
    skipped: g.skipped,
  };
  const quiet = level(args) < 1;
  for (const r of rows) {
    if (quiet && r.state !== "confirmed" && r.state !== "candidate") continue;
    process.stdout.write(
      `${mark[r.state] ?? "?"} ${r.state.padEnd(10)} ${r.endpoint}\n` + (quiet ? "" : `    ${r.note}\n`),
    );
  }
  process.stdout.write(
    `\n${rows.length} endpoints: ${Object.entries(by).map(([k, v]) => `${v} ${k}`).join(", ")}\n`,
  );
  return EXIT.ok;
}

function newestEngagement(): string | undefined {
  if (!existsSync(ENGAGEMENTS)) return undefined;
  const dirs = readdirSync(ENGAGEMENTS)
    .map((d) => join(ENGAGEMENTS, d))
    .filter((d) => existsSync(join(d, "scope.yaml")));
  return dirs.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
}

/** Replay a scripted run through the real view, to check it after a change. */
/** The read-only web view. Everything it does lives under src/web/. */
async function cmdWeb(args: Args): Promise<number> {
  const { runWeb } = await import("./web/command.js");
  return runWeb(args.flags, VERSION);
}

async function cmdDemo(args: Args): Promise<number> {
  const bus = new Bus();
  const { playDemo } = await import("./tui/demo.js");
  if (args.flags["no-tui"] === true || !process.stdout.isTTY) {
    attachPlain(bus, { level: level(args) });
    await playDemo(bus, 1);
    return EXIT.ok;
  }
  const app = await startTui(bus);
  await playDemo(bus, num(args.flags.every) ?? 160);
  await app.waitUntilExit();
  return EXIT.ok;
}

/**
 * Mount the full-screen view.
 *
 * The cursor is Ink's to hide and Ink's to restore, and it does restore it on a
 * clean unmount — but a second signal exits the process from under it, and a
 * terminal left without a cursor is the one piece of damage a CLI can do to the
 * shell it was run from. So the show-cursor sequence is written on the way out
 * whatever the reason, which is harmless to repeat.
 */
async function startTui(bus: Bus) {
  const { render } = await import("ink");
  const React = await import("react");
  const { App } = await import("./tui/app.js");
  const app = render(React.createElement(App, { bus }), { exitOnCtrlC: false });
  process.on("exit", () => {
    if (process.stdout.isTTY) process.stdout.write("\x1b[?25h");
  });
  return app;
}

/**
 * The one confirmation in the tool.
 *
 * Generating a scope file for a host that is not loopback is the only moment
 * where nothing human has yet said that this target may be tested: a mistyped
 * `-t` would otherwise start an unattended engagement against a stranger.
 * clig.dev's rule for a severe action is a typed value or a confirmation flag,
 * and its rule for automation is that a prompt is never required — so --yes
 * answers it in advance, --no-input and a non-terminal stdin turn it into an
 * error that names --yes, and a lab target on 127.0.0.1 never sees it at all.
 */
async function confirmRemoteTarget(target: string, args: Args): Promise<boolean> {
  // stderr, not the stream the run narrates to: with -n and stdout redirected,
  // a question written to stdout lands in the log file and the operator waits
  // at a terminal that is showing them nothing.
  const say = process.stderr;
  const host = new URL(target).hostname.replace(/^\[|\]$/g, "");
  const loopback = host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127\./.test(host);
  if (loopback || args.flags.yes === true) return true;
  if (args.flags["no-input"] === true || !process.stdin.isTTY || !say.isTTY) {
    fail(
      `no scope file, and ${host} is not a loopback target`,
      "generating the authorization boundary for a remote host",
      [`mythos -t ${target} --yes  if you are authorized to test ${host}`, `mythos -t ${target} -s <scope.yaml>  to pass a boundary you wrote`],
    );
    return false;
  }
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: say });
  try {
    say.write(
      `mythos is about to write a scope file authorizing itself to test ${host}.\n` +
        `Only continue for a bug-bounty program in scope, a system you own, or a lab.\n`,
    );
    const typed = await rl.question(`Type the hostname to confirm (or --yes next time): `);
    if (typed.trim() === host) return true;
    say.write(`that is not ${host} — nothing was written\n`);
    return false;
  } finally {
    rl.close();
  }
}

async function cmdRun(args: Args): Promise<number> {
  const target = typeof args.flags.target === "string" ? args.flags.target : args._[1];
  const scopeFile = typeof args.flags.scope === "string" ? args.flags.scope : undefined;
  const json = args.flags.json === true;
  const say = humanStream(args);

  if (!target && !scopeFile) {
    return fail(
      "no target",
      "deciding what to test",
      ["mythos -t <url>", "mythos -s <scope.yaml>  to reuse an engagement's boundary"],
    );
  }

  const profile = typeof args.flags.profile === "string" ? args.flags.profile : undefined;
  const model = typeof args.flags.model === "string" ? args.flags.model : undefined;
  const baseURL = typeof args.flags["base-url"] === "string" ? args.flags["base-url"] : undefined;
  if (baseURL) process.env.MYTHOS_BASE_URL = baseURL;

  // The model plan and the credential are checked before anything is written,
  // so a typo in --profile does not leave an empty engagement directory behind
  // and does not fail three phases into a run.
  let resolved;
  try {
    resolved = plan({ profile, model });
    const { bind } = await import("./model.js");
    bind(resolved.tiers.strong);
    bind(resolved.tiers.validator);
  } catch (e) {
    // auth.ts ends its message with "Run:" and then the command on the next
    // line; split across what/next, that dangling colon reads like a truncation.
    const lines = (e as Error).message.split("\n");
    return fail(
      (lines[0] ?? "no usable model").replace(/\s*Run:\s*$/, ""),
      "choosing the models for the run",
      [
        ...lines.slice(1).map((l) => l.trim()).filter(Boolean),
        "mythos doctor  to see every precondition at once",
      ],
    );
  }

  if (!scopeFile && target && !(await confirmRemoteTarget(target, args))) return EXIT.usage;

  let scope;
  try {
    scope = resolveScope(target, scopeFile, num(args.flags.rps));
  } catch (e) {
    return fail(
      (e as Error).message,
      "resolving the scope file, which is the authorization boundary",
      scopeFile ? `mythos verdicts ${scopeFile.replace(/scope\.yaml$/, "")}` : "mythos -t <url> -s <scope.yaml>",
    );
  }

  ensureDir(scope.dir);
  const bus = new Bus().record(join(scope.dir, "run-events.jsonl"));

  const driverOpts = {
    scope,
    bus,
    budget: num(args.flags.budget) ?? 3600,
    retries: num(args.flags.retries) ?? 2,
    workers: num(args.flags.workers) ?? 3,
    profile,
    model,
    skipPhases:
      typeof args.flags.skip === "string" ? args.flags.skip.split(",").map((s) => s.trim()) : [],
    headlessBrowser: args.flags.headed !== true,
  };

  // The view redraws stdout in place, so it needs a terminal to redraw and it
  // must not be the thing writing when stdout is carrying a JSON document.
  const wantTui = args.flags["no-tui"] !== true && !json && process.stdout.isTTY;
  let waitForTui: Promise<unknown> = Promise.resolve();

  if (wantTui) {
    const app = await startTui(bus);
    waitForTui = app.waitUntilExit();
  } else {
    say.write(bannerLine(`v${VERSION}`, theme(say)) + "\n");
    attachPlain(bus, { level: level(args), stream: say });
    say.write(`mythos — engagement ${scope.dir}\n`);
  }

  // The first signal asks the driver to unwind, which lets the proxy stop and
  // the ledger flush. A model call in flight can take half a minute, so a
  // second signal is taken as "I meant now".
  let signalled = false;
  const onSignal = () => {
    if (signalled) process.exit(EXIT.interrupted);
    signalled = true;
    bus.note("warn", "stopping after the current step — signal again to exit now");
    bus.control({ t: "abort" });
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  const driver = new Driver(driverOpts);
  let code: number = EXIT.ok;
  let result: { ok: boolean; reports: Array<{ phase: string; state: string; wall: number; reason?: string }>; summary: string } | undefined;
  try {
    result = await driver.execute();
    code = result.ok ? EXIT.ok : EXIT.unclean;
  } catch (e) {
    bus.note("error", (e as Error).message);
    code = EXIT.unclean;
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
  await waitForTui;

  const report = join(scope.dir, "report.md");
  if (json) {
    jsonOut({
      ok: result?.ok ?? false,
      exit: code,
      target: scope.target,
      scope: scope.file,
      engagement: scope.dir,
      report: existsSync(report) ? report : null,
      events: join(scope.dir, "run-events.jsonl"),
      summary: result?.summary ?? "the run did not finish",
      phases: result?.reports ?? [],
    });
    return code;
  }

  // The phase table and the paths are printed after the view comes down as well
  // as in quiet mode: everything else the view showed is in run-events.jsonl,
  // but a verdict the operator has to retype from memory is lost work.
  if (result) {
    say.write(`\n${result.summary}\n`);
    for (const p of result.reports) {
      say.write(`  ${p.phase.padEnd(8)} ${p.state.padEnd(11)} ${p.wall}s${p.reason ? ` — ${p.reason}` : ""}\n`);
    }
  }
  say.write(`\nengagement: ${scope.dir}\nreport: ${report}\nevents: ${join(scope.dir, "run-events.jsonl")}\n`);
  return code;
}

const num = (v: string | boolean | undefined): number | undefined =>
  typeof v === "string" && v !== "" && !Number.isNaN(Number(v)) ? Number(v) : undefined;

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    // An error that reaches here is a bug, not a mistake the user made, so it
    // keeps its stack: clig.dev asks for the traceback and where to report it.
    process.stderr.write(
      `mythos: internal error — ${(e as Error).stack ?? String(e)}\n` +
        `This is a bug in mythos ${VERSION}. Please report it with the lines above.\n`,
    );
    process.exit(EXIT.unclean);
  },
);
