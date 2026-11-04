"""CAI: not runnable in this harness."""


def run(target_url, workdir, model, budget_s):
    raise NotImplementedError(
        "cai: interactive-only. The open-source line is an interactive REPL (`cai`) frozen at 0.5.10; "
        "the repository was archived on 2026-08-28 with known unpatched prompt-injection issues, so it "
        "is at most a frozen snapshot, and there is no supported headless mode to drive it unattended.")
