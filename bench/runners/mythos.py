"""Mythos arm: `opencode run --agent mythos` in a per-run cwd that symlinks the repo's agent
assets (AGENTS.md, opencode.json, .opencode, skills, knowledge, scripts, ...) and has its own
empty engagements/. Not --pure: the local scope-guard plugin must load. The run's scope.yaml is
passed as `--scope` (the orchestrator's non-interactive gate) and as $MYTHOS_SCOPE.

Shared state, by design of the toolbox: `scripts/mythos` runs every tool in one global
`mythos-toolbox` container with the real repo mounted at /repo, so tool output files land in the
repo's engagements/, not in this cwd. Scoring reads the transcript, which carries tool output."""
import json
import subprocess
from pathlib import Path
from . import base

REPO = Path(__file__).resolve().parent.parent.parent
# models.json is staged too: scripts/models reads it relative to its own location, so without it
# the staged copy cannot resolve the per-agent model assignment.
ASSETS = ["AGENTS.md", "opencode.json", "models.json", ".opencode", "agents", "commands", "hooks",
          "knowledge", "scripts", "skills", "toolbox"]


def per_agent_config(stage, model):
    """Every agent in the suite pinned to `model`, as an OPENCODE_CONFIG_CONTENT fragment.

    `--model` only moves the orchestrator. `opencode.json` gives each of the six sub-agents its
    own `agent.<id>.model`, so a sweep run with `--model X` would put this arm's sub-agents on
    whatever that file pins while the control arm ran entirely on X. The arms would then differ
    by model as well as by scaffolding. `scripts/models <provider/model>` renders a fragment that
    assigns the one model to every agent, and OPENCODE_CONFIG_CONTENT takes precedence over both
    `opencode.json` and the agent frontmatter.
    """
    if "/" not in model:
        raise RuntimeError(f"mythos arm needs a provider-qualified model id, got {model!r}: "
                           "scripts/models reads an unqualified argument as a profile name, and "
                           "the sub-agents would silently keep opencode.json's models")
    r = subprocess.run(["python3", str(Path(stage) / "scripts" / "models"), model],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"scripts/models {model} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def grants(workdir, model=None):
    """The roots this arm is handed and the treatments it carries, for the run record."""
    workdir, stage = Path(workdir), base.stage_assets(ASSETS)
    g = {"roots": [str(workdir / "cwd"), str(stage)],
         "treatment": {"scaffolding": True, "plugin": True, "skills": True,
                       "subagents": True, "toolbox": True, "scope_guard": True,
                       "coverage_gate": base.coverage_gate_wired(stage),
                       "coverage_gate_effective": base.coverage_gate_effective(stage, "opencode"),
                       "pure": False, "tools": "agent default",
                       "assets": sorted(ASSETS)}}
    if model:
        # Recorded as configured, not as observed: the OpenCode event stream carries no model id,
        # so there is nothing in the transcript to check this against. See METHODOLOGY.md.
        g["per_agent_models"] = json.loads(per_agent_config(stage, model))
        g["per_agent_models_source"] = "configured via OPENCODE_CONFIG_CONTENT"
    return g


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    stage = base.stage_assets(ASSETS)
    for name in ASSETS:
        if not (cwd / name).exists() and (stage / name).exists():
            (cwd / name).symlink_to(stage / name)
    (cwd / "engagements").mkdir(exist_ok=True)
    scope = workdir / "scope.yaml"
    text = f"{target_url} --scope {scope}\n\n{base.objective(target_url)}"
    cfg = per_agent_config(stage, model)
    (workdir / "opencode-config-content.json").write_text(cfg)   # exactly what the arm ran with
    env = dict(base.clean_env(home), MYTHOS_SCOPE=str(scope), OPENCODE_CONFIG_CONTENT=cfg)
    argv = base.opencode_argv("mythos", model, cwd, text, pure=False)
    return base.run_proc(argv, cwd, env, budget_s, workdir)
