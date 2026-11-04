"""Mythos arm on the Claude Code host: `claude -p` with the repo loaded as a plugin.

Same skills, knowledge and scope guard as the OpenCode arm, a different agent host. Pair it
with `claude_control` so both arms share one model, prompt, budget and sandbox; the only
difference is the scaffolding. The run's scope.yaml is handed over as $MYTHOS_SCOPE and named
in the prompt, which is the orchestrator's non-interactive gate.

Output is streamed as JSON lines, not one object at the end: the harness watches the
transcript for progress, and a single trailing object would look like a stalled provider.

Permissions are skipped for the run (`--dangerously-skip-permissions`): the cell is the
single human gate, the target is a local throwaway container, and an interactive prompt would
hang an unattended sweep. The scope guard still runs as a PreToolUse hook.
"""
from pathlib import Path
from . import base

REPO = Path(__file__).resolve().parent.parent.parent
ASSETS = ["AGENTS.md", "CLAUDE.md", ".claude-plugin", "agents", "commands", "hooks",
          "knowledge", "scripts", "skills", "toolbox"]


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    for name in ASSETS:
        if not (cwd / name).exists():
            (cwd / name).symlink_to(REPO / name)
    (cwd / "engagements").mkdir(exist_ok=True)
    scope = workdir / "scope.yaml"
    text = (f"/cybersecurity {target_url} --scope {scope}\n\n{base.prompt(target_url)}")
    env = dict(base.claude_env(home), MYTHOS_SCOPE=str(scope))
    argv = ["claude", "-p", text, "--model", model, "--output-format", "stream-json", "--verbose",
            "--dangerously-skip-permissions", "--plugin-dir", str(REPO),
            "--add-dir", str(REPO)]
    return base.run_proc(argv, cwd, env, budget_s, workdir)
