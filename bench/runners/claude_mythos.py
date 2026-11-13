"""Mythos arm on the Claude Code host: `claude -p` with the repo loaded as a plugin.

Same skills, knowledge and scope guard as the OpenCode arm, a different agent host. Pair it
with `claude_control` so both arms share one model, prompt, budget and sandbox; the only
difference is the scaffolding. The run's scope.yaml is handed over as $MYTHOS_SCOPE and named
in the prompt, which is the orchestrator's non-interactive gate.

Output is streamed as JSON lines, not one object at the end: the harness watches the
transcript for progress, and a single trailing object would look like a stalled provider.

Permissions are skipped for the run (`--dangerously-skip-permissions`): the cell is the
single human gate, the target is a local throwaway container, and an interactive prompt would
hang an unattended sweep. The scope guard still runs as a PreToolUse hook. Both arms skip
permissions in the same way, so the grant is symmetric; what it means for the ground truth is
in METHODOLOGY.md.

The plugin is loaded from a staged copy of the agent assets outside the repo, not from the repo
itself. Until 13 November 2026 this arm ran with `--plugin-dir <repo> --add-dir <repo>`, which
put `bench/data/ground_truth/*.json` inside a root it was invited to read while the control arm
got an empty directory, and mounted the same repo into the toolbox at `/repo`. `grants()`
publishes the roots so `run.py` can refuse a cell whose roots reach the key.
"""
import json
from pathlib import Path
from . import base

REPO = Path(__file__).resolve().parent.parent.parent
ASSETS = ["AGENTS.md", "CLAUDE.md", ".claude-plugin", "agents", "commands", "hooks",
          "knowledge", "scripts", "skills", "toolbox"]


def grants(workdir, model=None):
    """The roots this arm is handed and the treatments it carries, for the run record."""
    workdir, stage = Path(workdir), base.stage_assets(ASSETS)
    return {"roots": [str(workdir / "cwd"), str(stage)],
            "treatment": {"scaffolding": True, "plugin": True, "skills": True,
                          "subagents": True, "toolbox": True, "scope_guard": True,
                          "coverage_gate": base.coverage_gate_wired(stage),
                          "skip_permissions": True, "tools": "host default",
                          "assets": sorted(ASSETS)}}


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    stage = base.stage_assets(ASSETS)
    for name in ASSETS:
        if not (cwd / name).exists() and (stage / name).exists():
            (cwd / name).symlink_to(stage / name)
    (cwd / "engagements").mkdir(exist_ok=True)
    scope = workdir / "scope.yaml"
    text = (f"/mythos-sec:cybersecurity {target_url} --scope {scope}\n\n{base.objective(target_url)}")
    env = dict(base.claude_env(home), MYTHOS_SCOPE=str(scope))
    argv = ["claude", "-p", text, "--model", model, "--output-format", "stream-json", "--verbose",
            "--dangerously-skip-permissions", "--plugin-dir", str(stage),
            "--add-dir", str(stage)]
    t = base.run_proc(argv, cwd, env, budget_s, workdir)
    if not plugin_loaded(t):
        raise RuntimeError(f"mythos plugin did not load in {t}: the cell measures a bare model, not the "
                           "scaffolding (check .claude-plugin/plugin.json against `claude --plugin-dir`)")
    return t


def plugin_loaded(transcript):
    """The init event lists the loaded commands. An invalid manifest is rejected silently, so the
    arm would otherwise run as a second control and the comparison would be vacuous."""
    for line in Path(transcript).read_text().splitlines()[:5]:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("subtype") == "init":
            return any(c.endswith(":cybersecurity") for c in ev.get("slash_commands", []))
    return False
