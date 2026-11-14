/**
 * The phase driver: the part that makes the run finish its work.
 *
 * The previous design asked one long-lived agent to walk the phases itself and
 * trusted it to decide when each was done. Measured, that trust was misplaced:
 * runs stopped at a quarter of their budget with two thirds of the target
 * untouched, and a Stop hook that nudged them to continue changed nothing. Worse,
 * the nudge only existed on one host, so the behaviour depended on which host
 * the operator happened to use.
 *
 * So the phase order lives here, in code, and a phase closes on an artifact
 * rather than on an opinion:
 *
 *   recon    surface.json and recon.md exist, and the map is not empty
 *   scan     candidates.md exists
 *   exploit  every endpoint in the surface has a verdict
 *   report   report.md and findings.json exist (the coverage check is the report
 *            agent's own last step, not a gate: it is a text check over the
 *            prose and would fail a correct report that names a gap in words
 *            the check does not match)
 *
 * A phase that does not produce its artifact runs again with what it left
 * behind, up to `retries` times. After that the run carries on and the phase is
 * recorded as incomplete, because a half-finished engagement that says so is
 * worth more than one that hangs at three in the morning.
 */
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { Bus, AbortedError, type PhaseState } from "./bus.js";
import { Browser } from "./agent/browser.js";
import { Guards } from "./agent/guards.js";
import { runAgent, withHints, type AgentResult } from "./agent/loop.js";
import { plan, tierFor, type Plan } from "./model.js";
import { REPO, script } from "./paths.js";
import {
  exploitPrompt,
  reconPrompt,
  needsHostNetwork,
  reportPrompt,
  scanPrompt,
  systemPrompt,
  validatorPrompt,
} from "./prompts.js";
import type { Scope } from "./scope.js";
import { Ledger, surfaceFromMap } from "./verdicts.js";

const run = promisify(execFile);

export interface DriverOptions {
  scope: Scope;
  bus: Bus;
  /** Whole-run budget in seconds. */
  budget: number;
  /** Attempts per phase before it is recorded incomplete. */
  retries: number;
  /** Parallel exploit workers. */
  workers: number;
  profile?: string;
  model?: string;
  skipPhases: string[];
  headlessBrowser: boolean;
}

export interface PhaseReport {
  phase: string;
  state: PhaseState;
  attempts: number;
  wall: number;
  reason?: string;
}

const PHASES = ["recon", "scan", "exploit", "report"] as const;
export type PhaseName = (typeof PHASES)[number];

/**
 * How much of the *remaining* time a phase may take.
 *
 * Shares of the nominal total were the first version and they starve a short
 * run: on a 900 second budget recon got 135 seconds, ran out mid-step and the
 * phase retried from nothing. Taken from what is left instead, an early phase
 * that finishes fast hands its slack to exploitation, which is where it is
 * worth the most, and the floor keeps the last phase able to write a report at
 * all.
 */
const SHARE: Record<PhaseName, number> = { recon: 0.3, scan: 0.35, exploit: 0.7, report: 1 };
const FLOOR_MS = 300_000;

export class Driver {
  private ledger: Ledger;
  private guards: Guards;
  private browser: Browser;
  private plan: Plan;
  private started = Date.now();
  private reports: PhaseReport[] = [];
  private seenFindings = new Set<string>();

  constructor(private opts: DriverOptions) {
    this.ledger = new Ledger(opts.scope.dir);
    this.guards = new Guards({ scopeFile: opts.scope.file, bus: opts.bus });
    this.browser = new Browser({ headless: opts.headlessBrowser });
    this.plan = plan({ profile: opts.profile, model: opts.model });
    // Set before the toolbox starts, and inherited by every child process, so
    // the container and the prompts agree on how the target is addressed.
    if (needsHostNetwork(opts.scope.target)) process.env.MYTHOS_NET = "host";
  }

  private left(): number {
    return this.opts.budget * 1000 - (Date.now() - this.started);
  }

  private modelFor(agent: string): string {
    return this.plan.tiers[tierFor(agent)];
  }

  async execute(): Promise<{ ok: boolean; reports: PhaseReport[]; summary: string }> {
    const { bus, scope } = this.opts;
    mkdirSync(join(scope.dir, "findings"), { recursive: true });
    mkdirSync(join(scope.dir, "verdicts"), { recursive: true });

    bus.emitEvent({
      t: "run:start",
      target: scope.target,
      dir: scope.dir,
      model: this.plan.tiers.strong,
      budget: this.opts.budget,
    });

    await this.prepare();

    try {
      for (const phase of PHASES) {
        if (this.opts.skipPhases.includes(phase)) {
          this.reports.push({ phase, state: "pending", attempts: 0, wall: 0, reason: "skipped by --skip" });
          continue;
        }
        if (this.left() <= 15_000) {
          this.reports.push({ phase, state: "incomplete", attempts: 0, wall: 0, reason: "out of budget" });
          bus.note("warn", `${phase}: no budget left, skipping`);
          continue;
        }
        await this.phase(phase);
      }
    } catch (e) {
      if (!(e instanceof AbortedError)) throw e;
      bus.note("warn", "aborted by the operator");
    } finally {
      await this.browser.close();
      await this.finish();
    }

    const summary = this.summarize();
    const ok = this.reports.every((r) => r.state === "done" || r.state === "pending");
    bus.emitEvent({ t: "run:end", ok, wall: Math.round((Date.now() - this.started) / 1000), summary });
    return { ok, reports: this.reports, summary };
  }

  /** The toolbox and the traffic recorder, before any phase sends a request. */
  private async prepare() {
    const { bus, scope } = this.opts;
    bus.note("info", "starting the Kali toolbox");
    const up = await run("python3", [script("mythos"), "up"], {
      cwd: REPO,
      env: { ...process.env, MYTHOS_SCOPE: scope.file },
      maxBuffer: 8 << 20,
    }).catch((e: Error) => ({ stdout: "", stderr: e.message }));
    if (up.stderr?.trim()) bus.note("info", up.stderr.trim().split("\n").slice(-2).join(" "));

    bus.note("info", "starting the recording proxy");
    await run("python3", [script("traffic"), "start", "--dir", scope.dir], {
      cwd: REPO,
      maxBuffer: 8 << 20,
    }).catch((e: Error) => {
      // An engagement without recording is still a valid engagement; one that
      // silently thinks it is recording is not.
      bus.note("warn", `traffic proxy did not start: ${e.message.split("\n")[0]}. Requests will not be recorded.`);
      return { stdout: "", stderr: "" };
    });
  }

  /** `scripts/traffic phase <name>`, best effort: a missing marker costs nothing. */
  private async mark(name: string) {
    await run("python3", [script("traffic"), "phase", name, "--dir", this.opts.scope.dir], {
      cwd: REPO,
    }).catch(() => ({ stdout: "", stderr: "" }));
  }

  private async finish() {
    const { scope, bus } = this.opts;
    await run("python3", [script("traffic"), "stop", "--dir", scope.dir], { cwd: REPO }).catch(() => {
      bus.note("warn", "the traffic proxy did not stop cleanly");
      return { stdout: "", stderr: "" };
    });
    // One line per finding into ~/.mythos/lessons.jsonl: class, state, playbook
    // and a salted hash of the host, never the host or the evidence. `scripts/
    // lessons` reads it back as a class prior, which the recon phase uses as a
    // tie-breaker. Read its own caveat before trusting it: the denominator is
    // findings reported, not classes attempted.
    await run("python3", [script("lessons-record")], {
      cwd: REPO,
      env: { ...process.env, MYTHOS_SCOPE: scope.file },
    }).catch(() => ({ stdout: "", stderr: "" }));
  }

  private async phase(name: PhaseName) {
    const { bus } = this.opts;
    const t0 = Date.now();
    // Mark the boundary in the traffic record, so `scripts/traffic summary` can
    // say which phase a request belongs to. Without it the recording is one
    // undifferentiated run and "what did we send just before the target broke"
    // has no phase to name.
    await this.mark(name);
    const attempts = this.opts.retries + 1;
    let state: PhaseState = "incomplete";
    let reason: string | undefined;
    let used = 0;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      used = attempt;
      bus.emitEvent({
        t: "phase:start",
        phase: name,
        attempt,
        of: attempts,
        model: this.modelFor(`mythos-${name === "scan" ? "scanner" : name === "report" ? "reporter" : name}`),
      });
      try {
        await this.runPhase(name, attempt);
      } catch (e) {
        if (e instanceof AbortedError) throw e;
        reason = (e as Error).message;
        bus.note("error", `${name}: ${reason}`);
      }
      const gate = await this.gate(name);
      if (gate.ok) {
        state = "done";
        reason = undefined;
        break;
      }
      reason = gate.reason;
      if (attempt < attempts && this.left() > 20_000) {
        bus.note("warn", `${name} did not close: ${gate.reason}. Retrying.`);
      }
      if (this.left() <= 20_000) break;
    }

    const wall = Math.round((Date.now() - t0) / 1000);
    this.reports.push({ phase: name, state, attempts: used, wall, reason });
    bus.emitEvent({ t: "phase:end", phase: name, state, wall, reason });
  }

  private phaseBudget(name: PhaseName): number {
    const left = this.left() - 10_000;
    return Math.max(Math.min(left, FLOOR_MS), Math.floor(left * SHARE[name]));
  }

  private async runPhase(name: PhaseName, attempt: number) {
    const { scope, bus } = this.opts;
    const hints = bus.takeHints();
    const sys = systemPrompt(scope, attempt > 1 ? retryNote(attempt) : "");

    if (name === "exploit") return this.exploitPhase(sys, hints);

    const p =
      name === "recon"
        ? reconPrompt(scope)
        : name === "scan"
          ? scanPrompt(scope)
          : reportPrompt(scope, this.plan.singleModelValidation);

    const agentName =
      name === "recon" ? "mythos-recon" : name === "scan" ? "mythos-scanner" : "mythos-reporter";

    if (name === "report") await this.validate();

    await runAgent(
      {
        id: `${name}-${attempt}`,
        label: name,
        phase: name,
        model: this.modelFor(agentName),
        system: sys,
        prompt: withHints(p.prompt, hints),
        budgetMs: this.phaseBudget(name),
        maxSteps: name === "recon" ? 80 : 140,
      },
      { scope, guards: this.guards, bus, browser: this.browser },
    );
  }

  /**
   * Exploitation fans out: one worker per group of endpoints, several at a time,
   * and the phase keeps assigning rounds until every endpoint has a verdict or
   * the budget runs out. This is the piece the old design could not express,
   * because a single agent deciding it was finished was exactly the failure.
   */
  private async exploitPhase(sys: string, hints: string[]) {
    const { scope, bus } = this.opts;
    const deadline = Date.now() + this.phaseBudget("exploit");
    let round = 0;

    while (Date.now() < deadline - 20_000) {
      const open = await this.ledger.open();
      if (!open.length) break;
      round += 1;
      if (round > 6) {
        bus.note("warn", `exploit: ${open.length} endpoints still open after 6 rounds, moving on`);
        break;
      }

      const groups = chunk(open, this.opts.workers);
      // Workers run in parallel, so a round costs one worker's budget in wall
      // clock. Half the remaining time leaves room for the next round, which is
      // where the endpoints a worker ran out of time on get picked up again.
      const perWorker = Math.max(60_000, Math.floor((deadline - Date.now()) / 2));
      bus.note("info", `exploit round ${round}: ${open.length} open across ${groups.length} workers`);

      // Each worker drives its own Chromium: one page cannot serve three agents
      // navigating at once. They are closed on the way out, including when the
      // worker threw, or a run leaves a browser per worker per round behind.
      const browsers = groups.map(() => new Browser({ headless: this.opts.headlessBrowser }));
      const results = await Promise.allSettled(
        groups.map((group, i) =>
          runAgent(
            {
              id: `exploit-r${round}-w${i + 1}`,
              label: `exploit ${i + 1}/${groups.length}`,
              phase: "exploit",
              model: this.modelFor("mythos-exploiter"),
              system: sys,
              prompt: withHints(exploitPrompt(scope, group, round).prompt, hints),
              budgetMs: Math.min(perWorker, deadline - Date.now() - 10_000),
              maxSteps: 160,
            },
            { scope, guards: this.guards, bus, browser: browsers[i]! },
          ),
        ),
      );
      await Promise.all(browsers.map((b) => b.close()));
      for (const r of results) {
        if (r.status === "rejected" && r.reason instanceof AbortedError) throw r.reason;
      }

      const before = this.ledger.all.length;
      this.collectVerdicts();
      this.announceFindings();
      if (this.ledger.all.length === before) {
        // A round that recorded nothing will not record anything next time
        // either: the endpoints are unreachable, or the model cannot see them.
        bus.note("warn", "exploit: a full round produced no verdict, stopping the fan-out");
        break;
      }
    }
    this.collectVerdicts();
  }

  /**
   * Announce findings that appeared since the last check.
   *
   * The front matter is the same one `scripts/findings` parses, so a finding
   * that shows up here is one that will reach `findings.json`; a file the agent
   * wrote without front matter is reported with what it has, because a silent
   * omission here would hide the finding from the operator watching the run.
   */
  private announceFindings() {
    const dir = join(this.opts.scope.dir, "findings");
    if (!existsSync(dir)) return;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".md") || this.seenFindings.has(f)) continue;
      this.seenFindings.add(f);
      const text = readFileSync(join(dir, f), "utf8");
      const field = (name: string) =>
        new RegExp(`^${name}\\s*:\\s*(.+)$`, "mi").exec(text)?.[1]?.trim();
      const title = field("title") ?? field("class") ?? /^#\s*(.+)$/m.exec(text)?.[1]?.trim() ?? f;
      this.opts.bus.emitEvent({
        t: "finding",
        id: f.replace(/\.md$/, ""),
        title,
        severity: field("severity") ?? field("status") ?? "unrated",
      });
    }
  }

  /** Read `verdicts/*.md` the workers wrote into the ledger. */
  private collectVerdicts() {
    const dir = join(this.opts.scope.dir, "verdicts");
    if (!existsSync(dir)) return;
    for (const f of readdirSync(dir)) {
      if (!f.endsWith(".md")) continue;
      const text = readFileSync(join(dir, f), "utf8");
      const endpoint = /^endpoint:\s*(.+)$/m.exec(text)?.[1]?.trim();
      const stateRaw = /^state:\s*(\w+)/m.exec(text)?.[1]?.trim();
      const note = /^note:\s*([\s\S]*?)(?:\n[a-z_]+:|$)/m.exec(text)?.[1]?.trim() ?? "";
      if (!endpoint || !stateRaw) continue;
      const state =
        stateRaw === "confirmed" || stateRaw === "tested" || stateRaw === "skipped" ? stateRaw : "tested";
      if (!this.ledger.has(endpoint)) {
        this.ledger.record(endpoint, state, note, f);
        this.opts.bus.emitEvent({ t: "verdict", verdict: { endpoint, state, note } });
      }
    }
  }

  /** The independent check, on a different model where the profile has one. */
  private async validate() {
    const { scope, bus } = this.opts;
    const dir = join(scope.dir, "findings");
    if (!existsSync(dir)) return;
    const files = readdirSync(dir).filter((f) => f.endsWith(".md"));
    if (!files.length) return;

    const body = files
      .map((f) => `### ${f}\n\n${readFileSync(join(dir, f), "utf8").slice(0, 8000)}`)
      .join("\n\n");

    if (this.plan.singleModelValidation) {
      bus.note(
        "warn",
        "no second model in this profile: the validation pass is not independent and the report must say so",
      );
    }
    const r = await runAgent(
      {
        id: "validator",
        label: "validator",
        phase: "report",
        model: this.plan.tiers.validator,
        system:
          "You review security findings written by another agent. You have no tools: judge only " +
          "what the evidence in front of you establishes.",
        prompt: validatorPrompt(body),
        budgetMs: Math.min(240_000, Math.max(60_000, this.left() * 0.15)),
        maxSteps: 2,
      },
      { scope, guards: this.guards, bus, browser: this.browser },
    );
    if (r.text.trim()) {
      writeFileSync(
        join(scope.dir, "validation.md"),
        `# Validation pass\n\nModel: ${this.plan.tiers.validator}\n` +
          `Independent: ${this.plan.singleModelValidation ? "no — same model as the author" : "yes"}\n\n${r.text}\n`,
      );
      bus.note("info", "validation.md written");
    }
  }

  /** The artifact gate for a phase. */
  private async gate(name: PhaseName): Promise<{ ok: boolean; reason?: string }> {
    const d = this.opts.scope.dir;
    const has = (f: string) => existsSync(join(d, f));

    if (name === "recon") {
      if (!has("surface.json")) return { ok: false, reason: "no surface.json" };
      const items = surfaceFromMap(join(d, "surface.json"));
      if (items.length === 0) return { ok: false, reason: "surface.json maps nothing" };
      if (!has("recon.md")) return { ok: false, reason: "no recon.md" };
      return { ok: true };
    }
    if (name === "scan") {
      return has("candidates.md") ? { ok: true } : { ok: false, reason: "no candidates.md" };
    }
    if (name === "exploit") {
      this.collectVerdicts();
      this.announceFindings();
      // An empty surface satisfies "every endpoint has a verdict" without a
      // single request being sent, which would report the phase as done after
      // doing nothing. Recon failing is the usual cause, and it has to surface
      // here rather than be laundered into a clean result.
      if ((await this.ledger.surface()).length === 0) {
        return { ok: false, reason: "the surface map is empty, so there was nothing to assign" };
      }
      const open = await this.ledger.open();
      if (open.length) {
        return { ok: false, reason: `${open.length} endpoints without a verdict` };
      }
      return { ok: true };
    }
    this.announceFindings();
    if (!has("report.md")) return { ok: false, reason: "no report.md" };
    if (!has("findings.json")) {
      // The report agent may have written the prose and skipped the build; do it
      // for them rather than spending another attempt on it.
      await run(
        "python3",
        [script("findings"), d, "--sarif", join(d, "findings.sarif")],
        { cwd: REPO, maxBuffer: 32 << 20 },
      ).catch(() => ({ stdout: "", stderr: "" }));
    }
    return has("findings.json") ? { ok: true } : { ok: false, reason: "no findings.json" };
  }

  private summarize(): string {
    const v = this.ledger.summary();
    const findings = existsSync(join(this.opts.scope.dir, "findings"))
      ? readdirSync(join(this.opts.scope.dir, "findings")).filter((f) => f.endsWith(".md")).length
      : 0;
    const phases = this.reports.map((r) => `${r.phase}:${r.state}`).join(" ");
    return (
      `${findings} finding${findings === 1 ? "" : "s"}, ` +
      `${v.confirmed} confirmed / ${v.tested} tested / ${v.skipped} skipped endpoints. ${phases}`
    );
  }
}

function retryNote(attempt: number): string {
  return `This is attempt ${attempt} at this phase. The previous attempt did not leave the file
the phase owes. Read what is already in the engagement directory, keep it, and
produce the missing artifact — do not start over.`;
}

/** Split a list into at most `n` groups, round-robin so each worker gets a mix. */
export function chunk<T>(items: T[], n: number): T[][] {
  const groups: T[][] = Array.from({ length: Math.max(1, Math.min(n, items.length)) }, () => []);
  items.forEach((item, i) => groups[i % groups.length]!.push(item));
  return groups.filter((g) => g.length);
}
