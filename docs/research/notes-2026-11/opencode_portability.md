# OpenCode-first portability of a Claude Code plugin agent framework (state: 2026-11-04)

> **Working notes, not documentation.** This file belongs to the research
> trail behind Mythos. It records what was true when it was written and is not
> kept in sync with the code. For maintained documentation see `README.md`,
> `AGENTS.md` and `docs/architecture.md`.

IMPORTANT VERSION CORRECTION: the brief assumed "OpenCode 1.18.x". The GitHub releases show the 1.x line ended at v1.19.5 (2026-10-28) and OpenCode 2 is released (latest v2.2.5, 2026-10-30; v2.2.0 exists). OpenCode 1.18.x ran roughly 2026-08-24 to 2026-10-06 (v1.18.22 to v1.18.35). So "OpenCode" is now two live generations. Config files, agents, commands and skills are cross-compatible; the PLUGIN API is not. This drives the whole design. Source: [GitHub releases](https://github.com/anomalyco/opencode/releases) (queried via `gh api repos/anomalyco/opencode/releases`). Repo is `anomalyco/opencode` (formerly sst/opencode).

Docs caveat: opencode.ai/docs (fetched) documents V1 (text says "In OpenCode 1 ..."); V2 docs live in the repo at `services/www/src/docs/content/*.mdx` and at v2.opencode.ai. Both are cited below and labelled V1/V2.

---

## 1. OpenCode config: agent, command, instructions, mcp, permission, skills

### Takeaway
Use V1-style config (`opencode.json`, singular `agent`/`command`/`permission`/`plugin`): V2 still reads it unchanged, so one config serves 1.18.x/1.19.x and 2.x. Agents, commands and skills as markdown files in `.opencode/agents|commands|skills/` work on both. V1 agent `tools:` map is deprecated; use `permission`.

### Cited Findings
**Files / precedence (V1 docs)**
- Config names: `opencode.json` or `opencode.jsonc`; schema `https://opencode.ai/config.json`. Global `~/.config/opencode/opencode.json`, project `opencode.json`, custom `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, inline `OPENCODE_CONFIG_CONTENT`. Merge order (later wins): remote .well-known, global, OPENCODE_CONFIG, project, `.opencode` dirs, inline, managed. Configs are merged, not replaced. — [Config (V1)](https://opencode.ai/docs/config/)
- Variable substitution: `{env:VAR}` and `{file:path}` (relative to config file, or absolute/`~`). — [Config](https://opencode.ai/docs/config/)
- `.opencode` subdirs are plural: `agents/ commands/ modes/ plugins/ skills/ tools/ themes/`; singular names also supported. Same layout for `~/.config/opencode` and `OPENCODE_CONFIG_DIR`. — [Config](https://opencode.ai/docs/config/)
- Top-level keys (V1): `model, small_model, provider, server, shell, tools, attachment, agent, default_agent, subagent_depth, command, snapshot, autoupdate, formatter, lsp, permission, compaction, watcher, mcp, plugin, instructions, disabled_providers, enabled_providers, experimental`. No documented `skills` key on that page, but see skills below. — [Config](https://opencode.ai/docs/config/)

**Agents (V1 docs)** — [Agents](https://opencode.ai/docs/agents/)
- Locations: `agent` key in opencode.json; markdown in `.opencode/agents/` (project) or `~/.config/opencode/agents/` (global). Filename = agent name.
- Fields: `description` (required), `mode` (`primary|subagent|all`, default `all`), `model` (`provider/model-id`), `prompt` (`{file:./prompts/x.txt}` in JSON; relative to config file), `temperature`, `top_p`, `steps` (replaces `maxSteps`), `disable`, `permission`, `tools` (DEPRECATED, use permission), `hidden` (subagent only; hides from @ menu, still Task-callable), `color`; unknown keys pass through as provider model options (e.g. `reasoningEffort`).
- Subagent without `model` uses the invoking primary agent's model (this is the equivalent of Claude's `model: inherit`). Primary without `model` uses the global `model`.
- Permission keys: `read edit glob grep list bash task todowrite external_directory webfetch websearch lsp skill question doom_loop`; values `ask|allow|deny`; object form with globs on read/edit/glob/grep/list/bash/task/external_directory/lsp/skill; last matching rule wins, put `"*"` first. `edit` gates write/edit/apply_patch. Keys are wildcard-matched against tool names, so MCP tools work too.
- `permission.task` controls which subagents an agent may call, e.g. `{"*":"deny","orchestrator-*":"allow","code-reviewer":"ask"}`. Deny removes the subagent from the Task tool description; user can still `@`-invoke.
- Built-ins: `build` (primary default), `plan` (primary), `general` and `explore` (subagents), hidden `compaction/title/summary`.
- Markdown example (V1 shape):
```markdown
---
description: Reviews code for quality and best practices
mode: subagent
model: provider/model-id
temperature: 0.1
permission:
  edit: deny
  bash:
    "*": ask
    "git diff": allow
  webfetch: deny
---
Prompt body = the agent's system prompt.
```

**Commands (V1 docs)** — [Commands](https://opencode.ai/docs/commands/)
- Locations: `command` key in config; `.opencode/commands/*.md`, `~/.config/opencode/commands/`. Filename = command name (`test.md` -> `/test`).
- Fields: `template` (required in JSON; markdown body in .md), `description`, `agent`, `subtask` (bool, forces subagent run), `model`.
- Placeholders: `$ARGUMENTS`, `$1 $2 $3`, `` !`shell cmd` `` (output injected, runs from project root), `@path/file` (file contents injected). Custom commands override built-ins of same name.
- Example:
```markdown
---
description: Run tests with coverage
agent: build
model: anthropic/claude-sonnet-5-5
---
Run the full test suite with coverage report and show any failures.
```

**Skills** — see Q2 for discovery. Frontmatter: `name` (required, `^[a-z0-9]+(-[a-z0-9]+)*$`, 1-64 chars, must equal directory name), `description` (required, 1-1024), optional `license`, `compatibility`, `metadata` (string map); unknown fields ignored. Permission: `permission.skill` patterns (`allow|deny|ask`). — [Skills (V1)](https://opencode.ai/docs/skills/)

**Instructions / rules** — `instructions` array in opencode.json accepts file paths, globs (`.cursor/rules/*.md`, `packages/*/AGENTS.md`) and remote URLs (5 s timeout); combined with AGENTS.md. — [Rules (V1)](https://opencode.ai/docs/rules/)

**MCP (V1)** — [MCP servers](https://opencode.ai/docs/mcp-servers/)
- Local: `{"type":"local","command":["npx","-y","pkg"],"cwd":"...","environment":{},"enabled":true,"timeout":30000}`. Remote: `{"type":"remote","url":"...","headers":{},"oauth":{clientId,clientSecret,scope}|false,"enabled":true,"timeout":30000}`.
- Per-agent enabling via `tools` glob map: global `"tools":{"my-mcp*":false}`, agent `"tools":{"my-mcp*":true}` (page itself links the `tools` map as deprecated; `permission` keys are wildcard-matched to MCP tool names per the agents page). MCP tools are prefixed `<server>_`.

**Permissions (V1)** — [Permissions](https://opencode.ai/docs/permissions/)
- `"permission":"allow"` sets everything; defaults mostly `allow`; `doom_loop` and `external_directory` default `ask`; `read` allows but `*.env`, `*.env.*` ask.
- bash patterns: `"git *":"allow"`, `"rm *":"deny"`; trailing ` *` matches command with/without args; last match wins.

**V2 differences (only matters if you adopt native V2 config; V1 syntax keeps working)** — [Migrate from V1 (V2 docs)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/migrate-v1.mdx)
- Statement: "Existing supported server config fields, agent definitions, command definitions, skills, and other files in `.opencode/` should continue to work without changes." V2 normalizes V1 fields in memory without rewriting.
- Native V2 renames: `agent`->`agents` (`prompt`->`system`, `disable`->`disabled`, `permission` -> `permissions` ordered array of `{action,resource,effect}`, `model` + `variant` -> `provider/model#variant`); `command`->`commands` (`subtask`->`subagent`); `permission` actions `bash`->`shell`, `task`->`subagent`; `mcp` -> `mcp.servers`, `enabled`->`disabled`; `plugin`->`plugins`; `skills.paths/urls` -> `skills: [...]`; `provider`->`providers`.
- V2 changed defaults: `external_directory` allowed by default (V1 asked); todos off by default; V2 ignores `lsp`, top-level `subagent_depth` (use `experimental.subagent_depth`), `server`, `logLevel`.
- V2 agent markdown rule: a file using any of `permissions|request|system|disabled` is parsed as V2 (V1 fields like `tools`, `permission`, `temperature` then ignored with warning); other files are parsed as V1. Do not mix in one file.
- V2 agent request params: `temperature`/`top_p`/`options` on agents have no effect in V2; set on a model variant.
- Agent files: V2 still discovers `agent/ agents/ mode/ modes/`; commands `command/ commands/`; skills `skill/ skills/`.

### Inferences
- Portable choice: write agents as markdown with V1 frontmatter (`description, mode, model, permission`), commands as markdown (`description, agent`, `$ARGUMENTS`), config in V1 syntax. Both 1.x and 2.x accept them. Avoid per-agent `temperature` if you need it to take effect on V2.
- Claude `tools: Read, Grep, Bash` has no direct V1/V2 frontmatter equivalent besides `permission` (deny `edit`, deny `bash`, etc.). Needs translation at build time (see layout).

### Gaps
- Exact JSON schema (`config.json`) field list for V2 not enumerated; read from the repo docs only.
- Whether `--auto` and V1 `permission.skill` exist in 1.18.x specifically was not verified per release (V1 docs list `--auto`; check `opencode run --help` on the pinned version).

---

## 2. Skills and Claude Code compatibility (what exactly OpenCode reads)

### Takeaway
OpenCode natively implements SKILL.md (Agent Skills spec) and reads `.claude/skills/` and `.agents/skills/` (project and global). It does NOT read `.claude/agents`, `.claude/commands`, `.claude/settings.json` hooks, or `.claude-plugin/` manifests. CLAUDE.md is read as a fallback in V1 only; V2 reads AGENTS.md only.

### Cited Findings
- Skill discovery V1 (project, walking up to git worktree): `.opencode/skills/<name>/SKILL.md`, `.claude/skills/<name>/SKILL.md`, `.agents/skills/<name>/SKILL.md`; global: `~/.config/opencode/skills/`, `~/.claude/skills/`, `~/.agents/skills/`. — [Skills (V1)](https://opencode.ai/docs/skills/)
- Skill discovery V2: same sources (global `~/.config/opencode/skills`, compat `~/.claude/skills`, `~/.agents/skills`; project `.opencode/skills`, `.claude/skills`, `.agents/skills`); additionally `skills` config array of local dirs or HTTP catalog URLs (relative paths resolve from working directory, not config file); search depth 6 below source root; `skills/review.md` flat markdown also allowed. — [Skills (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/skills.mdx)
- V1 rules: project `CLAUDE.md` used only if no `AGENTS.md`; global `~/.claude/CLAUDE.md` used only if `~/.config/opencode/AGENTS.md` absent; `~/.claude/skills/` read. Disable switches: `OPENCODE_DISABLE_CLAUDE_CODE=1` (all), `OPENCODE_DISABLE_CLAUDE_CODE_PROMPT=1`, `OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=1`. — [Rules (V1)](https://opencode.ai/docs/rules/)
- V2: "OpenCode V2 recognizes `AGENTS.md` only. It does not use `CLAUDE.md` as a fallback." Migration doc says to move CLAUDE.md guidance into AGENTS.md and file a compat issue. — [Instructions (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/instructions.mdx), [Migrate](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/migrate-v1.mdx)
- No `.claude-plugin/plugin.json` / `marketplace.json` support: open feature issues ask for Agent Plugins support ([#40993](https://github.com/anomalyco/opencode/issues/40993) open; [#41561](https://github.com/anomalyco/opencode/issues/41561) closed with duplicate bot comment) and a skill-discovery request for skills installed by Claude Code plugins (#40629 per the bot comment). No evidence it shipped.
- Agent Plugins 1.0 (agent-plugins.org) only standardizes skills + MCP servers (`plugin.json` at root, `skills/<name>/`, `mcp.json`), not agents, commands or hooks; no clients named on the page. — [agent-plugins.org](https://agent-plugins.org)
- An odd V2 provider `claude-agent` runs Claude Code as the model backend; it explicitly does NOT load Claude Code settings, CLAUDE.md, hooks, MCP, skills. Not a compatibility layer. — [Claude Agent (V2 docs)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/claude-agent.mdx)

### Inferences
- `skills/*/SKILL.md` placed in `.claude/skills/` is picked up by both Claude Code and OpenCode with zero duplication, but a Claude Code plugin's `skills/` dir inside the plugin root is not found by OpenCode unless it is a symlink target or listed via `skills` config / copied.
- Write `AGENTS.md` as the canonical instructions file and make `CLAUDE.md` a one-line `@AGENTS.md` import (Claude Code supports `@path` imports; this is general Claude Code knowledge, not re-verified here) to satisfy V2's AGENTS-only rule.
- `knowledge/*.md`: load via `instructions` globs (V1 and V2: `instructions` field is listed as unchanged "no migration needed") or reference from skills (progressive disclosure, preferable for token cost).

### Gaps
- Did not verify whether `.claude/agents/` is ever read (docs don't mention it; assume no).
- Did not verify a nested-skill `name` vs directory mismatch behavior in V2 (V2 docs example uses `name: Git Release`, which would violate the V1 regex; keep lowercase-hyphen names for portability).

---

## 3. OpenCode plugins and a scope guard

### Takeaway
V1 plugin API (`@opencode-ai/plugin`, returns a hooks object) and V2 plugin API (`@opencode/plugin`, `Plugin.define({id, setup(ctx)})`) are different; V1 plugin code does not run on V2. A single package can export both. For a security-critical scope guard, put the real enforcement in the permission config (bash allow/deny patterns, deny webfetch) and treat the plugin as the dynamic, scope-file-aware layer, implemented twice (or shared core + two thin adapters).

### Cited Findings
**V1 API** — [Plugins (V1)](https://opencode.ai/docs/plugins/)
- Locations: `.opencode/plugins/` (project), `~/.config/opencode/plugins/` (global), or npm names in `"plugin": [...]` (installed with Bun at startup, cached in `~/.cache/opencode/node_modules/`). Local plugins needing deps use `.opencode/package.json`. Load order: global config, project config, global plugin dir, project plugin dir; all hooks run in sequence.
- Signature: `export const MyPlugin = async ({ project, client, $, directory, worktree }) => ({ ...hooks })`; type `import type { Plugin } from "@opencode-ai/plugin"`.
- Events/hooks listed: `command.executed, file.edited, file.watcher.updated, installation.updated, lsp.client.diagnostics, lsp.updated, message.part.removed, message.part.updated, message.removed, message.updated, permission.asked, permission.replied, server.connected, session.created/compacted/deleted/diff/error/idle/status/updated, todo.updated, shell.env, tool.execute.before, tool.execute.after, tui.prompt.append, tui.command.execute, tui.toast.show, experimental.session.compacting`.
- Official blocking example: throwing in `tool.execute.before` blocks the call:
```js
export const EnvProtection = async () => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool === "read" && output.args.filePath.includes(".env")) {
      throw new Error("Do not read .env files")
    }
  },
})
```
  (Args are on `output.args`, tool name on `input.tool`.) — [Plugins docs source](https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/plugins.mdx)
- Custom tools: `.opencode/tools/*.ts` using `tool({description,args: tool.schema..., execute})` from `@opencode-ai/plugin`; filename = tool name; can shell out to any language. — [Custom tools](https://opencode.ai/docs/custom-tools/)
- Pitfall: V1 `permission.ask` plugin hook was typed/documented but never invoked since v1.3.0 (issues [#47674](https://github.com/anomalyco/opencode/issues/47674), #47654, #46809, #22311 all closed; #42633 "restore permission ask hook safely" closed). Do not rely on it. Also open issue [#50652](https://github.com/anomalyco/opencode/issues/50652) "External plugin tools bypass configured permissions". Earlier issues about hooks not firing in the desktop app (#38604, closed) and `tool.execute.after` once not firing (#25918, closed).
- A real-world V1 scope guard exists in NeoTheCapt/RedteamAgent: `tool.execute.before` filters `input.tool === "bash"`, extracts hostnames from the command, loads `scope.json` and only WARNS (logs) when out of scope. Note: it reads `input.args?.command`, whereas official docs read `output.args`; verify which carries args on your pinned version. — [engagement-hooks.ts](https://github.com/NeoTheCapt/RedteamAgent/blob/HEAD/agent/.opencode/plugins/engagement-hooks.ts)

**V2 API** — [Plugin server docs (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/build/plugins/server.mdx), [Migrate plugins](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/build/plugins/migrate-v1.mdx)
- `import { Plugin } from "@opencode/plugin"; export default Plugin.define({ id, async setup(ctx) {...} })`. Hook map: `tool.execute.before` -> `ctx.tool.hook("execute.before", ev)`, `tool.execute.after` -> `"execute.after"`, `permission.ask` -> `ctx.permission.hook("evaluate", ev)`, `event` -> `ctx.event.subscribe()`, `shell.env` -> `ctx.shell.hook("create.before")`, `chat.message` -> `ctx.session.hook("prompt")`.
- `execute.before` event: `{ tool, sessionID, agent, messageID, id, input (mutable) }`; throw to block. `execute.after`: adds `status: "completed"|"error"`, `result` or `error`. Permission evaluation event: `{sessionID, agent?, action, resources, effect (mutable), message?}`, so V2 lets a plugin set `effect="deny"` programmatically (V2 permission actions are `shell`, `webfetch`, `subagent`...). — [promise/permission.ts](https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/promise/permission.ts), [promise/tool.ts](https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/promise/tool.ts)
- Local plugin discovery V2: `.opencode/plugins/` (also still `.opencode/plugin/`); configured local `plugins` entries must be directories (a single file path is skipped). Config key renamed `plugin` -> `plugins`; entries may be `{package, options}`.
- V2 doc "Support V1": one default export combining both:
```ts
import { Plugin } from "@opencode/plugin"
export default {
  ...Plugin.define({ id: "example", async setup(ctx) {
    await ctx.tool.hook("execute.before", () => { /* V2 */ })
  }}),
  async server() {            // V1 path
    return { "tool.execute.before": async () => { /* V1 */ } }
  },
}
```
  V1 calls `server()`; V2 ignores it. "The V1 object form is supported in OpenCode 1.18.29. Older V1 releases may expect function exports." — [server.mdx "Support V1"](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/build/plugins/server.mdx). So pin >= 1.18.29 on V1.

**Example scope guard (my synthesis from the above; not run)** — block mode, shared core + both adapters:
```ts
// .opencode/plugins/scope-guard.ts
import { Plugin } from "@opencode/plugin"            // V2; drop for V1-only
import { readFileSync } from "node:fs"

const scope = () => JSON.parse(readFileSync(process.env.MYTHOS_SCOPE ?? "engagement/scope.json", "utf8")) as { hosts: string[] }
const hostsIn = (s: string) => [...s.matchAll(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})/gi)].map(m => m[1].toLowerCase())
const inScope = (h: string, allow: string[]) => allow.some(a => h === a || h.endsWith("." + a))

function check(tool: string, args: any) {                // shared core
  const text = tool === "bash" ? args?.command : tool === "webfetch" ? args?.url : ""
  if (!text) return
  const allow = scope().hosts
  const bad = hostsIn(String(text)).filter(h => !inScope(h, allow))
  if (bad.length) throw new Error(`OUT OF SCOPE: ${bad.join(", ")}`)
}

export default {
  ...Plugin.define({ id: "mythos.scope-guard", async setup(ctx) {
    await ctx.tool.hook("execute.before", (ev) => check(ev.tool, ev.input))
  }}),
  async server() {
    return { "tool.execute.before": async (input: any, output: any) => check(input.tool, output.args) }
  },
}
```
  Field names `args.command` (bash) and `args.url` (webfetch) are from general knowledge of the built-in tools and the RedteamAgent code; the `bash` tool name and `filePath` for read are documented. Verify `webfetch` arg name with `opencode run` + a logging hook. Hostname regex is a heuristic: it will miss IPs encoded as decimal/hex, variables, base64, DNS via `$(...)`.

### Inferences
- Enforcement that must not be bypassable: also set `permission.bash` allowlist/denylist and `webfetch: deny` (or `ask`) in config, and require explicit allow for tools like `nmap *`. Plugin hooks can be bypassed by MCP tools or plugin-registered tools (issue #50652) and by commands that resolve hosts at runtime.
- Because V1 hooks are guaranteed only for built-in tools, route all network tools through bash/webfetch, or wrap MCP network tools in your own plugin tool that calls the guard.
- Claude Code side: the same `check()` logic can sit behind a `hooks/hooks.json` PreToolUse command hook (`scripts/scope-guard.mjs` reading JSON from stdin, exit 2 to block) so both hosts share one core module. Claude hook contract is from general knowledge of Claude Code docs, not re-fetched here.

### Gaps
- Exact V1 `tool.execute.before` TypeScript types (could not fetch `packages/plugin/src/index.ts` for V1; the repo moved to the V2 layout, and the 404 raw URLs were tried). Rely on the official `.env` example for args location.
- Whether tool.execute.before fires for subagent (child session) tool calls: not confirmed in docs; V2 event includes `agent` and `sessionID`, suggesting it fires for all sessions. Test empirically.

---

## 4. Subagents, delegation, model selection

### Takeaway
A primary agent delegates through the built-in Task tool (V1 permission key `task`, V2 `subagent`) to subagents by name; subagents run in child sessions with fresh context. A subagent with no `model` inherits the invoking agent's model (= Claude's `model: inherit`). Models are `provider/model-id`; V2 adds `#variant`.

### Cited Findings
- Subagents can be invoked by the model (Task tool) or by `@name`; `permission.task` globs control which subagents each agent may launch; deny hides them from the tool description. Subagents default to the invoking primary's model. — [Agents (V1)](https://opencode.ai/docs/agents/)
- V2: "Subagents run with fresh context in foreground or background child sessions. The parent agent's `subagent` permissions control which agents it may launch; the child uses its own configured permissions." Built-in `general` cannot launch further subagents; V2 also has an `explore` and a `scout` subagent (per search summary of [v2.opencode.ai/agents](https://v2.opencode.ai/agents)). Nested agent IDs from subdirectories (`.opencode/agents/team/reviewer.md` -> `team/reviewer`). — [Agents (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/agents.mdx)
- Slash command can force a subagent run: `subtask: true` (V1) / `subagent: true` (V2; `subtask` still accepted; delegated commands now run in background and report to parent). — [Commands](https://opencode.ai/docs/commands/), [Migrate](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/migrate-v1.mdx)
- Model IDs: `provider/model-id`, e.g. `anthropic/claude-sonnet-5-5`; models.dev data shows provider `zai` has `glm-5.3-flash`, `glm-5.3`, `glm-5.2`, `glm-5.1`, `glm-4.7`..., provider `zai-coding-plan` has `glm-5.3-flash`, `glm-5.3`, `glm-5.2`, and provider `opencode` (Zen) has `glm-5.3-flash-free`, `deepseek-v4.1-flash-free`, `big-pickle`, `claude-sonnet-5-5`, `kimi-k2.6`... — [models.dev API](https://models.dev/api.json) (queried live), [Zen docs](https://opencode.ai/docs/zen/)
- Zen free models (limited time): `opencode/big-pickle`, `opencode/pulse-alpha-free`, `opencode/glm-5.3-flash-free` (zero-retention), `opencode/deepseek-v4.1-flash-free` (zero-retention), `opencode/beam-free`, `opencode/flint-40b-free`, `opencode/mimo-v2.6-flash-free`, three `nemotron-3*-free` (trial, logged), `opencode/jev-1.13-free` (structured decision model, not chat). Config: `"model": "opencode/glm-5.3-flash-free"`. `OPENCODE_DISABLE_FREE_MODELS=1` hides them. Free models may log data: do not feed engagement data to those without zero-retention. — [Zen](https://opencode.ai/docs/zen/)
- Model list: `opencode models [provider]`, `--refresh`. — [CLI](https://opencode.ai/docs/cli/)
- V2 model syntax: `provider/model#variant` (e.g. `anthropic/claude-sonnet-5-5#high`). — [Agents V2](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/agents.mdx)

### Inferences
- Mapping for Claude `model: inherit` -> omit `model` in OpenCode frontmatter. Other Claude values (`sonnet`, `opus`, `haiku`) have no OpenCode meaning; they must map to explicit `provider/model` ids or be dropped.
- Orchestrator pattern: primary `mythos` agent with `permission.task: {"*":"deny","mythos-*":"allow"}`; hidden helper subagents via `hidden: true`.
- Model-per-role routing (cheap model for recon, strong for exploit) is natural: put `model:` in each subagent file; keep the id out of shared sources by generating it from a small `models.json`.

### Gaps
- Did not verify the Task tool's argument name (`subagent_type`) in the current release; documented behavior is name-based `@`/Task invocation.
- Max subagent depth control: V1 top-level `subagent_depth`; V2 `experimental.subagent_depth` (migration doc). Default values not found.

---

## 5. Distribution

### Takeaway
No marketplace/registry for OpenCode. Distribution is: npm package (or git spec) in the `plugin`/`plugins` array or `opencode plugin add`, copy/clone a `.opencode/` directory, `skills` array pointing at paths or HTTP catalogs, `instructions` globs, and remote `.well-known/opencode` config.

### Cited Findings
- npm names (incl. scoped) in `plugin` array; installed automatically with Bun, cached in `~/.cache/opencode/node_modules/`. — [Plugins V1](https://opencode.ai/docs/plugins/)
- V1 CLI: `opencode plugin <module>` (alias `plug`), `-g/--global`, `-f/--force`. — [CLI](https://opencode.ai/docs/cli/)
- V2 CLI: `opencode plugin add|list|check|update|remove`; `add` accepts npm name@version/tag/range and git specs (`github:acme/opencode-plugin`, `git+ssh://...#main`, `github:acme/plugins#main::path:packages/opencode-plugin`). Entries may be `{package, options}`; `-` prefix disables a plugin id. — [Plugins (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/plugins.mdx)
- A plugin package can only ship plugin code (hooks/tools); agents, commands and skills in an npm package are not auto-registered by the documented mechanism. A V2 plugin can register agents/commands/skills programmatically via `ctx.agent.transform`, `ctx.command.transform`, `ctx.skill.transform` (example in promise README: `agent.update("reviewer", item => {item.mode="subagent"})`). — [Promise plugin README](https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/README.md)
- Skill distribution by URL/path via `skills` array (V2 doc) / `skills.paths`+`skills.urls` (V1 form). — [Skills V2](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/skills.mdx), [Migrate](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/migrate-v1.mdx)
- A "unified marketplace" PR (#40085) is closed, not confirmed merged. Treat as absent.
- Reference install pattern used by a dual-host pentest project: `install.sh <target> <claude|codex|opencode|docker>` copies from a canonical `agent/` dir; generates per-host files; verification script checks generated files are in sync. — [RedteamAgent](https://github.com/NeoTheCapt/RedteamAgent)

### Inferences
- Pragmatic OpenCode install for this project: (a) `git clone` + `./install.sh --target opencode` writing `.opencode/` into the user's engagement dir, or (b) `opencode plugin add github:<org>/mythos-sec` for the guard plugin only, plus an `opencode.json` snippet with `instructions`/`skills`. Option (a) is the only one that delivers agents + commands.
- Claude side stays `/plugin marketplace add` unchanged.

### Gaps
- No evidence of an official OpenCode registry beyond npm (docs show none). Community lists (awesome-opencode) not checked.

---

## 6. Existing security / dual-host projects (structure worth copying)

### Cited Findings
- **NeoTheCapt/RedteamAgent**: red-team agent for Claude Code, OpenCode, Codex; 8 agents, ~31 skills, 79 reference files, Kali docker. Layout: `agent/` is single source of truth; `.opencode/` is canonical for prompts (`prompts/agents/`), `commands/`, `opencode.json`, `plugins/engagement-hooks.ts`; `.claude/settings.json` holds hooks; Claude/Codex agents and commands are GENERATED from the OpenCode sources at install; `skills/` and `references/` shared (OpenCode loads them via the `instructions` array, Claude/Codex read on demand); `operator-core.md` rendered into CLAUDE.md/AGENTS.md; CI-style check script verifies generated files in sync. Scope enforcement: Claude blocks (settings.json hook), OpenCode only warns (plugin), Codex none. Its opencode.json lists every SKILL.md in `instructions` and sets `"plugin": ["./plugins"]`, local MCP (metasploit) with `{env:...}` substitution. — [repo](https://github.com/NeoTheCapt/RedteamAgent), [opencode.json](https://github.com/NeoTheCapt/RedteamAgent/blob/HEAD/agent/.opencode/opencode.json)
- **vichhka-git/opencode-shannon-plugin**: pentest plugin, six phases recon to reporting, AGPL-3.0, can combine with Oh-My-OpenCode orchestration; recommends per-agent models (from search summary, code not reviewed). — [search result](https://gh.hhj520.top/vichhka-git/opencode-shannon-plugin)
- **PentestCode** (tomevault listing of s0ld13rr/pentestcode): hard fork of OpenCode for pentesting; strategist-coordinator primary + web-app subagent; skills in `.opencode/opencode.jsonc` (listing only, unverified). — [listing](https://tomevault.io/tome/s0ld13rr/pentestcode)
- Licensing/authorization note: these are third-party offensive tools; code not audited here; Shannon is AGPL (copying code would be viral; copy structure only).

### Inferences
- Copy RedteamAgent's "one canonical dir + generator + sync check" pattern, but choose the canonical format to be Claude-style markdown (since Mythos is already Claude-plugin shaped) or OpenCode-style; see layout below.
- Their `instructions`-array-of-SKILL.md approach inflates context on every turn (all skills always loaded); use native skills discovery (on-demand `skill` tool) instead.

### Gaps
- Did not read agent/skill contents or licenses of RedteamAgent or PentestCode.

---

## 7. Headless / batch

### Takeaway
`opencode run "<prompt>"` with `--agent`, `--model provider/model`, `--format json` (NDJSON events), `--file`, `--continue/--session`, `--dir`, `--variant`, `--auto`. In non-interactive mode un-answerable permission "ask"s are auto-rejected unless `--auto` (approves everything not explicitly denied). Best practice for benchmarks: pre-allow needed tools in config and keep `deny` rules, rather than relying on `--auto`.

### Cited Findings
- V1 `run` flags: `--command`, `-c/--continue`, `-s/--session`, `--fork`, `-m/--model provider/model`, `--agent`, `-f/--file`, `--format default|json`, `--title`, `--attach <url of opencode serve>`, `-p/--password`, `-u/--username`, `--dir`, `--port`, `--variant`, `--thinking`, `--auto`. — [CLI (V1)](https://opencode.ai/docs/cli/)
- `opencode export [sessionID]` (`--sanitize`) dumps session JSON (V1). V2 form: `opencode session export <id> [--sanitize]`, `opencode session list --format json`, `opencode session import`. V2 `run` additionally has `--standalone` (private in-process server; for CI), `--archived`. — [CLI (V2)](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/cli/commands.mdx)
- Env: `OPENCODE_PERMISSION` (inline JSON permissions), `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `OPENCODE_CONFIG_CONTENT`. V2 server auth `OPENCODE_PASSWORD`. — [CLI V1](https://opencode.ai/docs/cli/), [Migrate](https://github.com/anomalyco/opencode/blob/dev/services/www/src/docs/content/migrate-v1.mdx)
- `--auto` "approves requests that would otherwise ask; explicit deny rules still apply"; works with `opencode run --auto "..."`. — [Permissions V1](https://opencode.ai/docs/permissions/)
- Source: in the non-interactive runner, with no `--auto` a permission request is answered "reject" and prints `permission requested: <action> (<resources>); auto-rejecting`; with V1-compat mode the run is also interrupted, outside V1 compat the model gets feedback and continues; with `--auto` the reply is `once`. — [packages/cli/src/run/noninteractive.ts](https://github.com/anomalyco/opencode/blob/dev/packages/cli/src/run/noninteractive.ts) (V2 code; V1 runtime behavior in 1.18.x not read)
- `opencode serve` + `run --attach http://host:port` avoids per-run cold start; `OPENCODE_SERVER_PASSWORD` for basic auth. — [CLI](https://opencode.ai/docs/cli/)
- `opencode stats --days N --models` gives token/cost breakdown. — [CLI](https://opencode.ai/docs/cli/)

### Inferences
- Benchmark harness sketch: `OPENCODE_CONFIG_DIR=<generated dir> opencode run --agent mythos --model opencode/glm-5.3-flash-free --format json --title "$TARGET" --dir /work/$TARGET "$PROMPT" > run.ndjson; opencode export <id> > session.json`. Get the session id from the first JSON events or from `session list --format json`.
- Run with `--auto` only inside a container/VM with the scope guard and `deny` rules in place, since out-of-scope protection then relies entirely on those.

### Gaps
- Exact NDJSON event schema for `--format json` not fetched.
- Whether `run --auto` exists in 1.18.x not verified per version (appears in V1 docs now; confirm with `opencode run --help`).

---

## 8. Primitive mapping: Claude Code plugin -> OpenCode

| Claude Code | OpenCode V1 (1.18/1.19) | OpenCode V2 (2.x) | Portable? |
|---|---|---|---|
| `.claude-plugin/plugin.json`, `marketplace.json` | none (no plugin-manifest concept) | none; `plugins` array is JS plugins only | No. Keep for Claude; OpenCode installs via script/npm |
| `commands/*.md` (`description`, `argument-hint`, `$ARGUMENTS`) | `.opencode/commands/*.md` (`description`, `agent`, `model`, `subtask`; `$ARGUMENTS`, `$1..`, `` !`cmd` ``, `@file`) | same; `subtask`->`subagent` (old still ok) | Mostly: same body; frontmatter differs (generate or keep minimal `description` only, which both accept) |
| `agents/*.md` (`name`, `description`, `model: inherit`, `tools: A, B`) | `.opencode/agents/*.md` (`description`, `mode: subagent`, `model` omitted = inherit, `permission:` map; name = filename) | same dir; V1 frontmatter auto-translated; native uses `permissions:` array | Needs generator: `tools` -> `permission` deny rules; drop `name`/`model: inherit`; add `mode: subagent` |
| `skills/*/SKILL.md` | `.opencode/skills/`, `.claude/skills/`, `.agents/skills/` native | same + `skills: [paths/urls]` | Yes. Same files. Use lowercase-hyphen `name` equal to dir |
| `hooks/hooks.json` PreToolUse command hook | plugin: `tool.execute.before` (throw to block) | plugin: `ctx.tool.hook("execute.before")` | Logic shareable; wiring not. Two adapters |
| `knowledge/*.md` | `instructions` globs, or read by skills | same | Yes |
| `CLAUDE.md` | `AGENTS.md` (CLAUDE.md fallback only if no AGENTS.md) | `AGENTS.md` only | Make AGENTS.md canonical |
| MCP in `.mcp.json` | `mcp` in opencode.json (`type: local|remote`, `command` array) | `mcp.servers` (V1 syntax still read) | Translate format |
| `permissions` in settings.json | `permission` | `permissions` array (V1 syntax read) | Translate |
| Task tool + `subagent_type` | Task tool (`permission.task`) | `subagent` tool (`permission.subagent`) | Names in prompts: avoid hardcoding tool names; say "delegate to the X agent" |
| Model aliases (`sonnet`, `inherit`) | `provider/model-id`, omit = inherit | `provider/model#variant` | Per-host model map |

---

## 9. Recommended repo layout (shared sources, minimal duplication)

Principle: author in the format both hosts read natively wherever possible (skills, AGENTS.md, knowledge); generate only the three things that differ (agents frontmatter, command frontmatter, hook wiring/config). Avoid symlinks for distributed artifacts (Claude plugin cache copies; Windows), but symlinks are fine inside the repo for dev.

```
mythos-sec/
  AGENTS.md                      # canonical instructions (OpenCode V1+V2 read it)
  CLAUDE.md                      # one line: @AGENTS.md
  src/                           # single source of truth
    agents/*.md                  # neutral frontmatter: description, role, tools: [read,grep,bash,webfetch], model: inherit|<alias>
    commands/*.md                # neutral: description, $ARGUMENTS body
    skills/<name>/SKILL.md       # spec-compliant, lowercase-hyphen names (used as-is by both)
    knowledge/*.md
    guard/core.ts                # check(tool,args) scope logic, pure functions
    models.json                  # alias -> {claude: "sonnet", opencode: "zai/glm-5.3-flash"}
  scripts/build.mjs              # generates targets below; CI step `build --check` fails on drift
  # generated, committed so users can install without building:
  .claude-plugin/{plugin.json,marketplace.json}
  agents/                        # Claude format (name, description, model, tools: comma list)
  commands/                      # Claude format
  skills/                        # copy or symlink of src/skills (Claude plugin root expects ./skills)
  hooks/hooks.json               # PreToolUse -> node ${CLAUDE_PLUGIN_ROOT}/dist/guard-claude.mjs
  .opencode/
    agents/*.md                  # V1 frontmatter (description, mode: subagent, permission:) ; model omitted unless pinned
    commands/*.md
    skills/ -> ../skills         # or rely on .claude/skills discovery
    plugins/scope-guard.ts       # dual-export: V2 setup() + V1 server(), imports guard/core
    opencode.json                # instructions: ["knowledge/*.md"], permission baseline, mcp, default_agent
  install.sh                     # --target opencode|claude copies .opencode/ (+ skills/knowledge) into the project
  bench/run-opencode.sh          # OPENCODE_CONFIG_DIR + opencode run --format json
```

Notes:
- Direction of generation: Claude-format files are what Mythos already has, so alternatively make Claude format canonical and generate `.opencode/agents` (rewrite `tools:` -> `permission`, drop `model: inherit`). Either works; RedteamAgent chose OpenCode-canonical. Pick the one with the richer metadata (neutral `src/` above avoids lock-in).
- `tools:` -> `permission` translation: for every tool not in the allowlist set deny (Read->`read`, Grep->`grep`, Glob->`glob`, Bash->`bash`, Edit/Write->`edit`, WebFetch->`webfetch`, WebSearch->`websearch`, Task->`task`). Always include `permission: { edit: deny }` etc. Keep a mapping table in build.mjs.
- Guard: bundle `guard/core.ts` into `dist/guard-claude.mjs` (stdin JSON -> exit 2 + stderr message) and import it in the OpenCode plugin. Also express hard rules as static `permission.bash` / `webfetch` entries in `.opencode/opencode.json`, because plugin hooks are an additional, not sole, layer.
- Commit generated outputs and add a `build --check` CI gate (RedteamAgent uses a similar sync-check script).
- Version policy: pin tested OpenCode versions in README (e.g. `>=1.18.29 <2` and `2.2.x`); run the benchmark on both. If you need a single plugin file, use the dual-export form; if V1 is not needed, drop `server()`.
- Skills for OpenCode: install into `.opencode/skills/` or `.claude/skills/`; the second works for both hosts if the user installs the Claude plugin too, but do not rely on it (a Claude plugin's internal `skills/` is not in a project's `.claude/skills/`).
- Avoid: Claude-specific tool names in prompt bodies (`Task`, `Bash(...)` permission syntax) and OpenCode `{file:}` references in shared sources.

## Open items to verify empirically on the pinned version
1. `opencode --version`; `opencode run --help` for `--auto`, `--format json`.
2. Log `input`/`output` in `tool.execute.before` for `bash`, `webfetch`, `task` to confirm arg names and that subagent tool calls reach the hook.
3. That a deny thrown from the V1 hook surfaces to the model as a tool error and not as a crashed run.
4. That V1-format agent markdown with `permission:` works on 2.2.x without warnings (docs say it does).
