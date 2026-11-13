// Mythos enforcement adapter for OpenCode: a thin shim over the two hooks in
// hooks/, so OpenCode and Claude Code enforce exactly the same rules.
//
// The logic lives once, in hooks/scope-guard.py and hooks/budget-guard.py (both
// also Claude Code PreToolUse hooks). This plugin shells out to each one's
// `--check` for every bash / webfetch call, finding the active engagement
// scope.yaml the same way ($MYTHOS_SCOPE, else the newest
// engagements/*/scope.yaml).
//
// The budget guard carries the rules the scope file prints and nothing used to
// enforce: rate_limit_rps, max_requests, allow_exploit, and the
// non-destructive rule. It defaults to blocking, because a rate limit you
// learn about afterwards has already been exceeded.
//
// Warn-only by default: the warning is printed to the bash tool's stderr so
// the model sees it, and to the OpenCode log. MYTHOS_SCOPE_ENFORCE picks the
// mode: "warn" (default), "ask" (refuse and name the reason, since OpenCode
// has no hook-level user prompt) or "block" (refuse outright).
//
// Dual export, no imports from a plugin package: OpenCode 1.x (>= 1.18.29)
// calls `server()`; OpenCode 2.x calls `setup(ctx)` (Plugin.define is the
// identity function, so a plain object is equivalent).
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"

const SCOPE = fileURLToPath(new URL("../../hooks/scope-guard.py", import.meta.url))
const BUDGET = fileURLToPath(new URL("../../hooks/budget-guard.py", import.meta.url))

function py(script: string, args: string[], cwd: string): any | null {
  const run = spawnSync("python3", [script, ...args], { cwd, encoding: "utf8" })
  try {
    return JSON.parse(run.stdout)
  } catch {
    return null // guard unavailable (no python3?): stay out of the way
  }
}

function warn(tool: string, args: any, msg: string): void {
  warn(tool, args, msg)
}

function check(tool: string, args: any, cwd: string): void {
  const target = tool === "bash" ? args?.command : tool === "webfetch" ? args?.url : undefined
  if (!target) return
  // The budget guard runs first: it refuses outright, so there is no point
  // pacing or warning about a call that is about to be rejected.
  const budget = py(BUDGET, ["--check", "--charge", String(target)], cwd)
  if (budget?.message) {
    if (budget.action === "block") throw new Error(budget.message)
    warn(tool, args, budget.message)
  }
  if (budget?.sleep > 0) spawnSync("sleep", [String(budget.sleep)])

  const msg: string | null = py(SCOPE, ["--check", String(target)], cwd)?.message ?? null
  if (!msg) return
  const mode = process.env.MYTHOS_SCOPE_ENFORCE ?? "warn"
  if (mode === "block") throw new Error(msg)
  if (mode === "ask") {
    // OpenCode has no hook-level "ask", so an unattended run must not pass silently:
    // refuse the call and name the scope reason. Interactive users re-run it after
    // widening scope.yaml, or set MYTHOS_SCOPE_ENFORCE=warn.
    throw new Error(msg + "\n(MYTHOS_SCOPE_ENFORCE=ask: refused pending your decision)")
  }
  warn(tool, args, msg)
}

export default {
  id: "mythos.guards",
  // OpenCode 2.x
  async setup(ctx: any) {
    await ctx.tool.hook("execute.before", async (ev: any) => check(ev.tool, ev.input, process.cwd()))
  },
  // OpenCode 1.x
  async server(input: { directory: string }) {
    return {
      "tool.execute.before": async (i: { tool: string }, output: { args: any }) =>
        check(i.tool, output.args, input.directory),
    }
  },
}
