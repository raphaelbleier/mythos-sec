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
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { Bus } from "./bus.js";
import { Driver } from "./driver.js";
import { plan } from "./model.js";
import { attachPlain } from "./plain.js";
import { ENGAGEMENTS, REPO, ensureDir, script } from "./paths.js";
import * as auth from "./providers/auth.js";
import { login as openrouterLogin } from "./providers/openrouter.js";
import { PROVIDERS, byId } from "./providers/registry.js";
import { resolveScope } from "./scope.js";

interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
}

const VERSION = (() => {
  try {
    const f = join(REPO, "cli", "package.json");
    return "v" + (JSON.parse(readFileSync(f, "utf8")) as { version?: string }).version;
  } catch {
    return "";
  }
})();

function parse(argv: string[]): Args {
  const out: Args = { _: [], flags: {} };
  const alias: Record<string, string> = {
    t: "target",
    s: "scope",
    m: "model",
    n: "no-tui",
    b: "budget",
    w: "workers",
    v: "verbose",
    h: "help",
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
      if (inline !== undefined) {
        out.flags[key] = inline;
      } else if (argv[i + 1] && !argv[i + 1]!.startsWith("-")) {
        out.flags[key] = argv[++i]!;
      } else {
        out.flags[key] = true;
      }
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      for (const ch of a.slice(1)) {
        const key = alias[ch] ?? ch;
        if (["target", "scope", "model", "budget", "workers", "base-url"].includes(key) && argv[i + 1]) {
          out.flags[key] = argv[++i]!;
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

const HELP = `mythos — autonomous web red-team agent, for authorized testing only

USAGE
  mythos -t <url> [options]            run an engagement
  mythos login <provider> [--api-key K]
  mythos logout <provider>
  mythos providers                     list providers and what is configured
  mythos doctor                        check the machine before a run
  mythos verdicts [dir]                the endpoint ledger of an engagement
  mythos demo                          replay a scripted run through the view

OPTIONS
  -t, --target <url>      the target. A scope file is generated for this host
                          and port alone if you pass none.
  -s, --scope <file>      an existing scope.yaml. This is the authorization
                          boundary and nothing in the run widens it.
  -b, --budget <seconds>  whole-run wall clock. Default 3600.
  -m, --model <spec>      pin every tier, e.g. openrouter/z-ai/glm-5.3
      --profile <name>    a profile from models.json instead
  -w, --workers <n>       parallel exploit workers. Default 3.
      --retries <n>       attempts per phase before it is recorded
                          incomplete. Default 2.
      --skip <list>       phases to skip, comma separated: recon, triage,
                          scan, exploit, validate, report
      --rps <n>           rate limit for a generated scope file. Default 5.
      --base-url <url>    OpenAI-compatible endpoint, for --model custom/<name>
      --headed            show the browser instead of running it headless
  -n, --no-tui            no full-screen view, one line per event
  -v, --verbose           with -n, also log tool results and agent prose

KEYS (full-screen view)
  p pause/resume    h send a hint to the agents    q abort

Mythos tests only what its scope file authorizes: bug-bounty programs in scope,
systems you own, or lab targets. It is non-destructive by design and the guard
refuses data destruction, brute force and denial of service outright.`;

async function main(argv: string[]) {
  const args = parse(argv);
  const cmd = args._[0];

  if (args.flags.help || (!cmd && !args.flags.target)) {
    process.stdout.write(HELP + "\n");
    return 0;
  }

  switch (cmd) {
    case "login":
      return cmdLogin(args);
    case "logout":
      return cmdLogout(args);
    case "providers":
      return cmdProviders();
    case "doctor":
      return cmdDoctor();
    case "verdicts":
      return cmdVerdicts(args);
    case "demo":
      return cmdDemo(args);
    case "run":
    case undefined:
      return cmdRun(args);
    default:
      process.stderr.write(`unknown command: ${cmd}\n\n${HELP}\n`);
      return 2;
  }
}

async function cmdLogin(args: Args): Promise<number> {
  const id = args._[1];
  if (!id) {
    process.stderr.write("usage: mythos login <provider> [--api-key KEY]\n");
    return 2;
  }
  const p = byId(id);
  if (!p) {
    process.stderr.write(`unknown provider: ${id}. 'mythos providers' lists them.\n`);
    return 2;
  }
  const key = typeof args.flags["api-key"] === "string" ? args.flags["api-key"] : undefined;

  if (key) {
    auth.store(p.id, { key, via: "paste" });
    process.stdout.write(`stored a key for ${p.label} (${auth.hint(key)})\n`);
    return 0;
  }
  if (p.oauth === "openrouter") {
    const r = await openrouterLogin();
    auth.store(p.id, { key: r.key, via: "oauth" });
    process.stdout.write(`signed in to ${p.label} (${auth.hint(r.key)})\n`);
    return 0;
  }
  process.stderr.write(
    `${p.label} has no OAuth flow here. Get a key at ${p.docs} and run:\n` +
      `  mythos login ${p.id} --api-key <key>\n` +
      `or set ${p.envKeys[0] ?? "the provider's environment variable"}.\n`,
  );
  return 2;
}

function cmdLogout(args: Args): number {
  const id = args._[1];
  if (!id) {
    process.stderr.write("usage: mythos logout <provider>\n");
    return 2;
  }
  process.stdout.write(auth.forget(id) ? `forgot ${id}\n` : `nothing stored for ${id}\n`);
  return 0;
}

function cmdProviders(): number {
  const have = new Set(auth.available());
  const saved = new Map(auth.stored().map((s) => [s.provider, s]));
  const rows = PROVIDERS.map((p) => {
    const s = saved.get(p.id);
    const envHit = p.envKeys.find((k) => process.env[k]);
    const how = s
      ? `stored (${s.via}, ${s.hint})`
      : envHit
        ? `$${envHit}`
        : p.local
          ? "local server"
          : p.oauth
            ? `mythos login ${p.id}`
            : "no credential";
    return `${have.has(p.id) ? "✓" : " "} ${p.id.padEnd(12)} ${p.label.padEnd(34)} ${how}`;
  });
  process.stdout.write(
    `Providers (✓ = usable now)\n\n${rows.join("\n")}\n\n` +
      `Subscription logins: OpenRouter's OAuth is implemented, because OpenRouter\n` +
      `publishes that flow for third-party clients and it mints a real key. Consumer\n` +
      `plans for ChatGPT, Claude and Copilot are not, and will not be: those flows\n` +
      `require borrowing another client's OAuth credentials, the providers either\n` +
      `forbid it or merely tolerate it, and the account that gets suspended is yours.\n` +
      `One OpenRouter login reaches most of the models above.\n\n` +
      `Pin a model as provider/model, e.g. --model openrouter/z-ai/glm-5.3.\n`,
  );
  return 0;
}

async function cmdDoctor(): Promise<number> {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  const line = (ok: boolean | null, what: string, detail = "") =>
    `${ok === null ? "?" : ok ? "✓" : "✗"} ${what.padEnd(26)} ${detail}\n`;
  let out = "";
  let bad = 0;

  const check = async (what: string, file: string, argv: string[], timeout = 20_000) => {
    try {
      const { stdout, stderr } = await run(file, argv, { timeout, maxBuffer: 8 << 20 });
      out += line(true, what, (stdout || stderr).trim().split("\n")[0] ?? "");
    } catch (e) {
      bad += 1;
      out += line(false, what, (e as Error).message.split("\n")[0] ?? "");
    }
  };

  out += line(true, "node", process.version);
  await check("python3", "python3", ["--version"]);
  await check("docker", "docker", ["--version"]);
  // One exec, not `mythos tools`: probing fifteen binaries inside the container
  // takes minutes, and what doctor needs to know is only whether the toolbox
  // runs a command at all. `mythos tools` is the command for the rest.
  await check("toolbox", "python3", [script("mythos"), "sh", "command -v curl sqlmap ffuf | tr '\\n' ' '"], 240_000);

  const creds = auth.available();
  out += line(creds.length > 0, "model credential", creds.length ? creds.join(", ") : "none — run 'mythos login'");
  if (!creds.length) bad += 1;

  const p = plan({});
  out += line(
    !p.singleModelValidation,
    "independent validator",
    p.singleModelValidation
      ? `profile ${p.profile} has one model for both tiers; findings will say the check was not independent`
      : `${p.tiers.validator} reviews ${p.tiers.strong}`,
  );

  for (const s of ["probe", "verify", "coverage", "findings", "cvefeed", "traffic"]) {
    const f = script(s);
    out += line(existsSync(f), `scripts/${s}`, existsSync(f) ? "" : "missing");
    if (!existsSync(f)) bad += 1;
  }

  try {
    const { chromium } = await import("playwright-core");
    const b = await chromium.launch({ headless: true, args: ["--no-sandbox"] }).catch(async () =>
      chromium.launch({ headless: true, channel: "chrome", args: ["--no-sandbox"] }),
    );
    out += line(true, "browser", "chromium starts");
    await b.close();
  } catch (e) {
    out += line(false, "browser", `${(e as Error).message.split("\n")[0]} — npx playwright install chromium`);
  }

  process.stdout.write(out + (bad ? `\n${bad} problem(s) to fix before a run.\n` : "\nReady.\n"));
  return bad ? 1 : 0;
}

function cmdVerdicts(args: Args): number {
  const dir = args._[1] ?? newestEngagement();
  if (!dir) {
    process.stderr.write("no engagement directory found\n");
    return 2;
  }
  const f = join(dir, "verdicts.json");
  if (!existsSync(f)) {
    process.stderr.write(`no verdict ledger in ${dir}\n`);
    return 1;
  }
  const rows = JSON.parse(readFileSync(f, "utf8")) as Array<{
    endpoint: string;
    state: string;
    note: string;
  }>;
  const mark = {
    candidate: "?",
    confirmed: "!",
    rejected: "x",
    tested: "·",
    skipped: "-",
  } as Record<string, string>;
  for (const r of rows) {
    process.stdout.write(`${mark[r.state] ?? "?"} ${r.state.padEnd(10)} ${r.endpoint}\n    ${r.note}\n`);
  }
  const by = rows.reduce<Record<string, number>>((a, r) => ({ ...a, [r.state]: (a[r.state] ?? 0) + 1 }), {});
  process.stdout.write(`\n${rows.length} endpoints: ${Object.entries(by).map(([k, v]) => `${v} ${k}`).join(", ")}\n`);
  return 0;
}

function newestEngagement(): string | undefined {
  if (!existsSync(ENGAGEMENTS)) return undefined;
  const dirs = readdirSync(ENGAGEMENTS)
    .map((d) => join(ENGAGEMENTS, d))
    .filter((d) => existsSync(join(d, "scope.yaml")));
  return dirs.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
}

/** Replay a scripted run through the real view, to check it after a change. */
async function cmdDemo(args: Args): Promise<number> {
  const bus = new Bus();
  const { playDemo } = await import("./tui/demo.js");
  if (args.flags["no-tui"] === true || !process.stdout.isTTY) {
    attachPlain(bus, { verbose: args.flags.verbose === true });
    await playDemo(bus, 1);
    return 0;
  }
  const { render } = await import("ink");
  const React = await import("react");
  const { App } = await import("./tui/app.js");
  const app = render(React.createElement(App, { bus }), { exitOnCtrlC: false });
  await playDemo(bus, num(args.flags.every) ?? 160);
  await app.waitUntilExit();
  return 0;
}

async function cmdRun(args: Args): Promise<number> {
  const target = typeof args.flags.target === "string" ? args.flags.target : args._[1];
  const scopeFile = typeof args.flags.scope === "string" ? args.flags.scope : undefined;

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
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }

  let scope;
  try {
    scope = resolveScope(target, scopeFile, num(args.flags.rps));
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
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

  const wantTui = args.flags["no-tui"] !== true && process.stdout.isTTY;
  let waitForTui: Promise<unknown> = Promise.resolve();

  if (!wantTui) {
    const { bannerLine } = await import("./tui/banner.js");
    process.stdout.write(bannerLine(VERSION) + "\n");
  }

  if (wantTui) {
    const { render } = await import("ink");
    const React = await import("react");
    const { App } = await import("./tui/app.js");
    const app = render(React.createElement(App, { bus }), { exitOnCtrlC: false });
    waitForTui = app.waitUntilExit();
  } else {
    attachPlain(bus, { verbose: args.flags.verbose === true });
    process.stdout.write(`mythos — engagement ${scope.dir}\n`);
  }

  // The first signal asks the driver to unwind, which lets the proxy stop and
  // the ledger flush. A model call in flight can take half a minute, so a
  // second signal is taken as "I meant now".
  let signalled = false;
  const onSignal = () => {
    if (signalled) process.exit(130);
    signalled = true;
    bus.note("warn", "stopping after the current step — signal again to exit now");
    bus.control({ t: "abort" });
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  const driver = new Driver(driverOpts);
  let code = 0;
  try {
    const r = await driver.execute();
    code = r.ok ? 0 : 1;
    if (!wantTui) {
      process.stdout.write(`\n${r.summary}\n`);
      for (const p of r.reports) {
        process.stdout.write(
          `  ${p.phase.padEnd(8)} ${p.state.padEnd(11)} ${p.wall}s${p.reason ? ` — ${p.reason}` : ""}\n`,
        );
      }
      process.stdout.write(`\nreport: ${join(scope.dir, "report.md")}\n`);
    }
  } catch (e) {
    bus.note("error", (e as Error).message);
    code = 1;
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
  await waitForTui;
  if (wantTui) {
    process.stdout.write(`\nengagement: ${scope.dir}\nreport: ${join(scope.dir, "report.md")}\n`);
  }
  return code;
}

const num = (v: string | boolean | undefined): number | undefined =>
  typeof v === "string" && v !== "" && !Number.isNaN(Number(v)) ? Number(v) : undefined;

void REPO;

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`mythos: ${(e as Error).stack ?? String(e)}\n`);
    process.exit(1);
  },
);
