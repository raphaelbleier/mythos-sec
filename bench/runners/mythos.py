"""Mythos arm: `opencode run --agent mythos` in a per-run cwd that symlinks the repo's agent
assets (AGENTS.md, opencode.json, .opencode, skills, knowledge, scripts, ...) and has its own
empty engagements/. Not --pure: the local scope-guard plugin must load. The run's scope.yaml is
passed as `--scope` (the orchestrator's non-interactive gate) and as $MYTHOS_SCOPE.

Shared state, by design of the toolbox: `scripts/mythos` runs every tool in one global
`mythos-toolbox` container with the real repo mounted at /repo, so tool output files land in the
repo's engagements/, not in this cwd. Scoring reads the transcript, which carries tool output."""
from pathlib import Path
from . import base

REPO = Path(__file__).resolve().parent.parent.parent
ASSETS = ["AGENTS.md", "opencode.json", ".opencode", "agents", "commands", "hooks", "knowledge",
          "scripts", "skills", "toolbox"]


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    for name in ASSETS:
        if not (cwd / name).exists():
            (cwd / name).symlink_to(REPO / name)
    (cwd / "engagements").mkdir(exist_ok=True)
    scope = workdir / "scope.yaml"
    text = f"{target_url} --scope {scope}\n\n{base.objective(target_url)}"
    env = dict(base.clean_env(home), MYTHOS_SCOPE=str(scope))
    argv = base.opencode_argv("mythos", model, cwd, text, pure=False)
    return base.run_proc(argv, cwd, env, budget_s, workdir)
