# Mythos Roadmap

Status of the skill-driven Mythos framework. The agent host (OpenCode first,
Claude Code second) is the agent; phase skills are the playbooks; real security
tools run in the Kali toolbox. No Python engine, no external API key of its own.

The phase plan comes from `docs/research/2026-11-ausbau-red-team-suite.md`
(measurability first: harness before capability work). Durations there are
single-developer estimates, not sourced figures. Status below reflects the
working tree; "done" means implemented, not that the benchmark result exists.

Legend: done / in progress / partly / planned

| Phase | Content | Status | Notes |
|---|---|---|---|
| 0 Verification | pinned OpenCode versions, hook behavior, XBEN build list | done | OpenCode 1.x >= 1.18.29 and 2.x. XBEN build check with apt fix: `bench/xben.py check`. Open item: whether the scope guard fires inside OpenCode sub-agents is not confirmed. |
| 1 Port | `AGENTS.md` canonical, `scripts/build-hosts.py` (+ `--check`), `.opencode/` agents/command/plugin, `opencode.json`, single-gate orchestrator | done | Self-test also runs through OpenCode (`scripts/selftest.sh --host opencode`). |
| 2 Toolbox and harness | two-stage Kali image, GHCR multi-arch CI, Python shim; `bench/` harness with compose isolation, harness-side scoring, bare-model control | done | Image workflow `.github/workflows/toolbox.yml`. Cosign signing, GHCR pull limits and Docker Hub rate limits for the base image: unverified. Native Windows and macOS tests: not yet run. |
| 3 Capabilities 1 and 2 | `auth-session` (two accounts), `business-logic` (BOLA, mass assignment, race), closure states and evidence gating in `exploit` / `report` | done | Skills exist. Measured gain against the phase-2 baseline and the gating on/off ablation: not yet measured. |
| 4 Main comparison | stage-2 benchmarks: mythos vs bare control (same model), Strix; Wilson CIs, McNemar | done, null result | Seven sweeps. 2026-11-04: 40 challenges on Claude Sonnet, 12 on GLM 5.3, a rerun of the seven shared failures. 2026-11-05: VAmPI recall against its nine documented vulnerabilities, and the 40 challenges again after an invalid plugin manifest was found to have kept the Claude Code mythos arm unscaffolded. The mythos arm never separates from the control, scaffolded or not (every paired p = 1.0, VAmPI recall 0.89 in both arms); numbers in `docs/poster/poster.md`. Also 2026-11-05: DVGA recall against its 21 documented vulnerabilities (mythos 12, control 11, precision 1.00 in both arms; tied at 10 of 16 once the five denial-of-service classes the safety rules forbid proving are excluded). Vuln Bank recall (76 entries): mythos 27, control 29, precision 1.00 in both arms, and neither arm reached the target's GraphQL, merchant, bill-payment or card surfaces. Open: repeats per cell, crAPI recall, and Strix kept only 2 of 12 valid cells. PentestGPT and CAI are refused by the harness (see `bench/README.md`). |
| 5 Capabilities 3 and 4 | `stored-xss-oast` with `lab/oast` and `lab/admin-bot`, `deep-server`; knowledge notes for cache poisoning, request smuggling, race conditions | partly | Skills, lab services and notes exist. Deserialization / XXE coverage and the re-measurement (per-class delta, the four classes Strix missed) are pending. |
| 6 Publication | README, per-OS install guide, responsible-use notice, poster, paper, tagged release with pinned image tag | in progress | README and poster written, results table filled. Release `v0.2.0` is tagged and the GHCR image is published for amd64 and arm64. Paper PDF pending. |

## Backlog

- Ablation: evidence gating on/off; skills on/off beyond the bare control.
- Recall on the remaining flagless target: crAPI (needs more RAM than the current host).
- Repeats per cell (the one-run-per-cell design cannot separate variance).
- Make the agent spend its budget: on Vuln Bank both arms stopped after a few
  minutes of 3600s with 45+ documented entries untested, whole surfaces
  (GraphQL, merchant, bills, cards) never touched. A coverage checklist that
  the orchestrator must close out would bite here, unlike on the small targets.
- Enforce the non-destructive rule in code, not only in the prompt: on DVGA both
  arms modified seed data (the control deleted another user's paste) and
  reported it afterwards.
- Enforce the anti-give-up rule in code, not only in the orchestrator prompt:
  four cells in the verified-scaffolding sweep still ended unsolved after
  15-24 seconds.
- Windows and macOS smoke test of `scripts/mythos` and the GHCR image.
- Verify scope-guard coverage in OpenCode sub-agents.
- Per-agent model assignment (cheap for recon, strong for exploit) via a small
  `models.json`: planned in the report, not implemented.
- Extend targets beyond XBOW (crAPI needs more RAM than the current host).

## Superseded

The earlier engine-based design and its `scripts/eval/` harness were removed in
the skill-driven pivot. Numbers from that era are not carried forward.

## References

`docs/research/2026-11-ausbau-red-team-suite.md` (roadmap source),
`docs/research/frameworks-analysis.md`, `docs/architecture.md`,
`bench/README.md`, `lab/README.md`.
