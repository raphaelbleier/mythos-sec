"""Control arm: the bare model with a shell. Same model, prompt, budget and sandbox as mythos,
but `opencode run --pure` (no plugins), the built-in `build` agent, an empty cwd, and only the
bash tool (edit/webfetch/websearch/task/skill denied), so it shows what the scaffolding adds."""
import json
from pathlib import Path
from . import base

CONFIG = {"$schema": "https://opencode.ai/config.json",
          "provider": {"zai": {"npm": "@ai-sdk/openai-compatible", "name": "Z.ai (GLM coding endpoint)", "options": {"baseURL": "https://api.z.ai/api/coding/paas/v4", "apiKey": "{env:LLM_API_KEY}"}, "models": {"glm-5.3": {"name": "GLM 5.3"}, "glm-5.3-flash": {"name": "GLM 5.3 Flash"}}}},
          "permission": {"bash": "allow", "read": "allow", "edit": "deny", "webfetch": "deny",
                         "websearch": "deny", "task": "deny", "skill": "deny", "todowrite": "deny"}}


def grants(workdir, model=None):
    """The roots this arm is handed and the treatments it carries, for the run record."""
    perm = CONFIG["permission"]
    return {"roots": [str(Path(workdir) / "cwd")],
            "treatment": {"scaffolding": False, "plugin": False, "skills": False,
                          "subagents": False, "toolbox": False, "scope_guard": False,
                          "coverage_gate": False, "pure": True,
                          "tools": "; ".join(f"{k}={v}" for k, v in sorted(perm.items()))}}


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    (cwd / "opencode.json").write_text(json.dumps(CONFIG, indent=1))
    argv = base.opencode_argv("build", model, cwd, base.objective(target_url), pure=True)
    return base.run_proc(argv, cwd, base.clean_env(home), budget_s, workdir)
