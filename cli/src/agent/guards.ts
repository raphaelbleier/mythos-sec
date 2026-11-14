/**
 * The two guards, called from inside every tool that can reach the target.
 *
 * This is the structural fix for the defect that invalidated the project's own
 * benchmark: the guards used to be host plugin hooks, and a cell that ran with
 * a fresh HOME loaded no plugin, so every measured run had its scope guard,
 * rate limiter and destructive denylist inert without saying so. Here they are
 * not hooks. A tool call reaches the network by going through this module, so
 * there is no configuration in which the guard is absent — the only way to
 * bypass it is to delete the call.
 *
 * The rules themselves stay in `hooks/*.py`, which have selftests and are the
 * files a reader audits. Reimplementing them in TypeScript would mean two
 * denylists drifting apart, and the one that drifts is always the one that
 * matters.
 *
 * Policy, which is the project's standing promise and not a setting:
 *   scope      warn only. The run reports the slip and carries on. Scope is a
 *              judgement about authorization that the operator owns.
 *   rate       warn only, and the pacing sleep is honored.
 *   destructive  refused. Data destruction, brute force and denial of service
 *              are the one hard line, because the DVGA incident showed a prompt
 *              rule does not hold: a run sent {deleteAllPastes} and emptied the
 *              target's table. MYTHOS_DESTRUCTIVE=warn downgrades it, for a
 *              throwaway lab only.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { hook } from "../paths.js";
import type { Bus } from "../bus.js";

const run = promisify(execFile);

export interface ScopeVerdict {
  offenders: string[];
  message?: string;
  scope?: string | null;
}

export interface BudgetVerdict {
  action: "allow" | "warn" | "block";
  message?: string;
  sleep: number;
}

async function check(file: string, command: string, env: NodeJS.ProcessEnv): Promise<unknown> {
  try {
    const { stdout } = await run("python3", [hook(file), "--check", command], {
      env,
      maxBuffer: 4 << 20,
      timeout: 30_000,
    });
    return JSON.parse(stdout || "{}");
  } catch (e) {
    // A guard that cannot run is not an excuse to send the request: the whole
    // point is that there is no path to the target without it.
    throw new Error(
      `guard ${file} failed to run (${(e as Error).message}). ` +
        `python3 must be on PATH; refusing the call rather than sending it unchecked.`,
    );
  }
}

export interface GuardOptions {
  /** The engagement's scope file, pinned for the guards' own resolution. */
  scopeFile: string;
  bus: Bus;
}

export class Guards {
  private env: NodeJS.ProcessEnv;

  constructor(private opts: GuardOptions) {
    this.env = {
      ...process.env,
      MYTHOS_SCOPE: opts.scopeFile,
      // Warn is the default and it is the project's standing choice, but an
      // operator testing a program where one out-of-scope request is
      // unacceptable can set `ask` or `block`, and the documentation tells them
      // to. Hard-coding warn here made that instruction a lie.
      MYTHOS_SCOPE_ENFORCE: process.env.MYTHOS_SCOPE_ENFORCE || "warn",
      MYTHOS_BUDGET_ENFORCE: process.env.MYTHOS_BUDGET_ENFORCE || "warn",
      // The destructive denylist keeps its own switch and its own default
      // (block), so none of the above downgrades it.
    };
  }

  /**
   * Returns the text to prepend to the tool result, or throws when the call is
   * refused. A warning deliberately reaches the agent with the result rather
   * than silently: it has to know a slip happened so it can stop repeating it.
   */
  async vet(command: string): Promise<string> {
    const notes: string[] = [];

    const scope = (await check("scope-guard.py", command, this.env)) as ScopeVerdict;
    if (scope?.offenders?.length && scope.message) {
      // In `ask` or `block` mode an out-of-scope call is refused rather than
      // reported after the fact. Nothing here can ask a human: a run is
      // unattended, so `ask` is treated as `block` and the refusal is what the
      // agent gets, which is the safe reading of "do not send this without me".
      const mode = this.env.MYTHOS_SCOPE_ENFORCE;
      const refuse = mode === "block" || mode === "ask";
      this.opts.bus.emitEvent({
        t: "guard",
        kind: "scope",
        action: refuse ? "block" : "warn",
        message: scope.message,
      });
      if (refuse) throw new GuardRefusal(scope.message);
      notes.push(scope.message);
    }

    const budget = (await check("budget-guard.py", command, this.env)) as BudgetVerdict;
    if (budget?.action === "block") {
      const message = budget.message ?? "refused by the budget guard";
      this.opts.bus.emitEvent({ t: "guard", kind: "destructive", action: "block", message });
      throw new GuardRefusal(message);
    }
    if (budget?.action === "warn" && budget.message) {
      this.opts.bus.emitEvent({ t: "guard", kind: "budget", action: "warn", message: budget.message });
      notes.push(budget.message);
    }
    if (budget?.sleep && budget.sleep > 0) {
      await new Promise((r) => setTimeout(r, Math.min(budget.sleep, 30) * 1000));
    }
    return notes.length ? notes.join("\n\n") + "\n\n" : "";
  }
}

export class GuardRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardRefusal";
  }
}
