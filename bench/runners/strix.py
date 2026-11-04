"""Strix arm: the CLI from the checkout at /mnt/linux-data/mythos-bench/strix, headless.

  uv run --project $STRIX_DIR strix -n -t <url> --instruction <prompt>

LLM config is Strix's own (LiteLLM ids, not opencode ids):
  STRIX_LLM     model, e.g. zai/glm-5.3 or openrouter/z-ai/glm-5.3 (run.py --strix-model sets it)
  LLM_API_KEY   provider key (required for hosted models)
  LLM_API_BASE  OpenAI-compatible base URL (local models or a logging proxy)
Strix keeps the real HOME (~/.strix/cli-config.json) and starts its own sandbox container, which
reaches the target on the docker0 gateway. Its run artifacts (strix_runs/<run>/, including
penetration_test_report.md) are appended to the transcript after the run."""
import os
from pathlib import Path
from . import base

STRIX_DIR = os.environ.get("STRIX_DIR", "/mnt/linux-data/mythos-bench/strix")


def run(target_url, workdir, model, budget_s):
    workdir, cwd, _ = base.dirs(workdir)
    env = dict(os.environ, **({"STRIX_LLM": model} if model else {}))
    if not env.get("STRIX_LLM"):
        raise RuntimeError("strix needs a model: pass --strix-model or set STRIX_LLM (+ LLM_API_KEY)")
    argv = ["uv", "run", "--project", STRIX_DIR, "strix", "-n", "-t", target_url,
            "--instruction", base.prompt(target_url)]
    transcript = base.run_proc(argv, cwd, env, budget_s, workdir)
    with open(transcript, "a") as t:
        for p in sorted((cwd / "strix_runs").rglob("*")):
            if p.is_file() and p.suffix in (".md", ".json", ".jsonl", ".txt", ".log"):
                t.write(f"\n===== {p.relative_to(cwd)} =====\n{p.read_text(errors='replace')}")
    return transcript
