"""Control arm on the Claude Code host: the bare model with a shell, no Mythos.

Same model, prompt, budget and sandbox as `claude_mythos`, but an empty working directory,
no plugin, no skills, no knowledge base, and only Bash. What it solves is what the model and
a shell do on their own; the difference to the mythos arm is what the scaffolding adds.
"""
from . import base

ALLOWED = ["Bash", "Read", "Glob", "Grep"]


def run(target_url, workdir, model, budget_s):
    workdir, cwd, home = base.dirs(workdir)
    argv = ["claude", "-p", base.prompt(target_url), "--model", model,
            "--output-format", "json", "--dangerously-skip-permissions",
            "--allowed-tools", *ALLOWED,
            "--disallowed-tools", "Task", "WebFetch", "WebSearch", "Edit", "Write"]
    return base.run_proc(argv, cwd, base.claude_env(home), budget_s, workdir)
