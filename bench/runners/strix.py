"""Strix arm: the CLI from the checkout at $XBEN_ROOT/strix (or $STRIX_DIR), headless.

  uv run --project $STRIX_DIR strix -n -t <url> --instruction <prompt>

LLM config is Strix's own (LiteLLM ids, not opencode ids):
  STRIX_LLM     model, e.g. zai/glm-5.3 or openrouter/z-ai/glm-5.3 (run.py --strix-model sets it)
  LLM_API_KEY   provider key (required for hosted models)
  LLM_API_BASE  OpenAI-compatible base URL (local models or a logging proxy)
Strix keeps the real HOME (~/.strix/cli-config.json) and starts its own sandbox container, which
reaches the target on the docker0 gateway. Its run artifacts (strix_runs/<run>/, including
penetration_test_report.md) are appended to the transcript after the run.

Not a paired arm, and not scored like one. Strix brings its own agent loop, sandbox and provider
route, so a Strix cell differs from a mythos cell in more than the treatment. Its transcript is
plain text rather than a parsable event stream, so this harness cannot read its token counts, its
per-agent models or its flag provenance. In the one sweep it ran, every cell hit the stall
deadline or a runner error."""
import os
from pathlib import Path
from . import base

import xben  # bench/ is on sys.path (run.py / labs.py insert it)

STRIX_DIR = os.environ.get("STRIX_DIR") or str(xben.BENCH_ROOT / "strix")


def grants(workdir, model=None):
    """The roots this arm is handed and the treatments it carries, for the run record.

    Strix is not a paired arm. It brings its own agent loop, its own sandbox container and its
    own LiteLLM provider route, so a Strix cell differs from a mythos cell in more than the
    scaffolding and the two are not comparable as a pair.
    """
    return {"roots": [str(Path(workdir) / "cwd")],
            "treatment": {"scaffolding": "third-party", "paired": False,
                          "own_sandbox": True, "own_provider_route": True,
                          "tools": "strix default"}}


def run(target_url, workdir, model, budget_s):
    workdir, cwd, _ = base.dirs(workdir)
    env = dict(os.environ, **({"STRIX_LLM": model} if model else {}))
    if not env.get("STRIX_LLM"):
        raise RuntimeError("strix needs a model: pass --strix-model or set STRIX_LLM (+ LLM_API_KEY)")
    argv = ["uv", "run", "--project", STRIX_DIR, "strix", "-n", "-t", target_url,
            "--instruction", base.prompt(target_url)]
    # Strix writes into cwd/strix_runs/ while it runs and its transcript is
    # assembled afterwards, so the stall detector has to watch the directory
    # or it kills every cell at the stall deadline.
    transcript = base.run_proc(argv, cwd, env, budget_s, workdir,
                               progress_roots=[Path(cwd) / "strix_runs"])
    with open(transcript, "a") as t:
        for p in sorted((cwd / "strix_runs").rglob("*")):
            if p.is_file() and p.suffix in (".md", ".json", ".jsonl", ".txt", ".log"):
                t.write(f"\n===== {p.relative_to(cwd)} =====\n{p.read_text(errors='replace')}")
    return transcript
