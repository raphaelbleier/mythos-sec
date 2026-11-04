// Mythos scope guard for OpenCode: a thin adapter over hooks/scope-guard.py.
//
// The scope logic lives once, in hooks/scope-guard.py (also the Claude Code
// PreToolUse hook). This plugin shells out to `scope-guard.py --check` for
// every bash / webfetch call, finding the active engagement scope.yaml the
// same way ($MYTHOS_SCOPE, else the newest engagements/*/scope.yaml).
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

const SCRIPT = fileURLToPath(new URL("../../hooks/scope-guard.py", import.meta.url))

function check(tool: string, args: any, cwd: string): void {
  const target = tool === "bash" ? args?.command : tool === "webfetch" ? args?.url : undefined
  if (!target) return
  const run = spawnSync("python3", [SCRIPT, "--check", String(target)], { cwd, encoding: "utf8" })
  let msg: string | null = null
  try {
    msg = JSON.parse(run.stdout).message
  } catch {
    return // guard unavailable (no python3?): stay out of the way, like the Claude hook
  }
  if (!msg) return
  const mode = process.env.MYTHOS_SCOPE_ENFORCE ?? "warn"
  if (mode === "block") throw new Error(msg)
  if (mode === "ask") {
    // OpenCode has no hook-level "ask", so an unattended run must not pass silently:
    // refuse the call and name the scope reason. Interactive users re-run it after
    // widening scope.yaml, or set MYTHOS_SCOPE_ENFORCE=warn.
    throw new Error(msg + "\n(MYTHOS_SCOPE_ENFORCE=ask: refused pending your decision)")
  }
  console.error(msg)
  if (tool === "bash") {
    const quoted = "'" + msg.replace(/'/g, `'\\''`) + "'"
    args.command = `printf '%s\\n' ${quoted} >&2; ${args.command}`
  }
}

export default {
  id: "mythos.scope-guard",
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
