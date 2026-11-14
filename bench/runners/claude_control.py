"""Control arm on the Claude Code host: the bare model with a shell, no Mythos.

Same model, prompt, budget and sandbox as `claude_mythos`, but an empty working directory,
no plugin, no skills, no knowledge base, and only Bash. What it solves is what the model and
a shell do on their own; the difference to the mythos arm is what the scaffolding adds.
"""
from pathlib import Path
from . import base

ALLOWED = ["Bash", "Read", "Glob", "Grep"]
DENIED = ["Task", "WebFetch", "WebSearch", "Edit", "Write"]


def grants(workdir, model=None):
    """The roots this arm is handed and the treatments it carries, for the run record.

    One root, the empty working directory. The tool denials are part of the treatment, not of
    the sandbox: this arm cannot write a file, so on a flagless target its report exists only as
    the final message while the scaffolded arm writes `report.md`. That is a confound, recorded
    here so it can be read off the result instead of inferred.
    """
    return {"roots": [str(Path(workdir) / "cwd")],
            "treatment": {"scaffolding": False, "plugin": False, "skills": False,
                          "subagents": False, "toolbox": False, "scope_guard": False,
                          "coverage_gate": False, "skip_permissions": True,
                          "tools": "allow " + ",".join(ALLOWED) + "; deny " + ",".join(DENIED)}}


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    argv = ["claude", "-p", base.objective(target_url), "--model", model,
            "--output-format", "stream-json", "--verbose",
            "--settings", str(base.cell_settings(cwd)), "--permission-mode", "acceptEdits",
            "--allowed-tools", *ALLOWED,
            "--disallowed-tools", *DENIED]
    return base.run_proc(argv, cwd, base.claude_env(home), budget_s, workdir)
