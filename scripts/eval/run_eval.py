#!/usr/bin/env python3
"""Mythos evaluation harness.

Runs the engine against the ground-truth vuln app (or any target with a
ground-truth file) and computes the metrics the poster reports:

  * detection coverage = detected expected classes / total expected
  * false-positive rate = findings that contradict must_not_flag / total findings
  * precision / recall over the labelled vulnerability classes

Usage:
  python scripts/eval/run_eval.py --target http://localhost:5001 \\
      --ground-truth lab/vulnapp/ground_truth.json --out docs/poster/eval.json

Run it inside the toolbox (so external tools count too) or with the engine on
PATH. Results are written as JSON and printed as a table.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# allow running from a source checkout without install
SRC = Path(__file__).resolve().parents[2] / "engine" / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))

from mythos.http_client import HttpClient          # noqa: E402
from mythos.orchestrator import run_engagement      # noqa: E402
from mythos.scope import Scope                       # noqa: E402


def score(findings: list[dict], gt: dict) -> dict:
    expected = gt.get("expected_findings", [])
    must_not = gt.get("must_not_flag", [])

    detected = set()
    for f in findings:
        detected.add((f["kind"], _path(f["url"])))

    # a class counts as covered if any finding of that kind hits the right path
    covered, missed = [], []
    for e in expected:
        hit = any(f["kind"] == e["kind"] and e["path"] in f["url"] for f in findings)
        (covered if hit else missed).append(e)

    false_positives = []
    for f in findings:
        for bad in must_not:
            if f["kind"] == bad["kind"] and bad["path"] in f["url"]:
                false_positives.append(f)

    n_expected = len(expected)
    n_covered = len(covered)
    n_findings = len(findings)
    coverage = n_covered / n_expected if n_expected else 0.0
    fp_rate = len(false_positives) / n_findings if n_findings else 0.0
    # precision/recall over labelled classes
    tp = n_covered
    fp = len(false_positives)
    fn = len(missed)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "expected": n_expected,
        "covered": n_covered,
        "missed": [m["kind"] for m in missed],
        "total_findings": n_findings,
        "false_positives": [f["kind"] + "@" + _path(f["url"]) for f in false_positives],
        "coverage": round(coverage, 4),
        "false_positive_rate": round(fp_rate, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _path(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--ground-truth", required=True,
                    help="one path, or several comma-separated (merged)")
    ap.add_argument("--mode", default="standard", choices=["quick", "standard", "deep"])
    ap.add_argument("--out")
    ap.add_argument("--max-pages", type=int, default=80)
    args = ap.parse_args(argv)

    gt = {"expected_findings": [], "must_not_flag": []}
    for p in args.ground_truth.split(","):
        part = json.loads(Path(p.strip()).read_text())
        gt["expected_findings"] += part.get("expected_findings", [])
        gt["must_not_flag"] += part.get("must_not_flag", [])
    host = args.target.split("://")[-1].split("/")[0].split(":")[0]
    scope = Scope.from_dict({
        "target": args.target, "in_scope": [host],
        "rules": {"rate_limit_rps": 1000, "allow_active": True, "allow_exploit": True},
    })
    client = HttpClient(scope=scope)
    res = run_engagement(client, args.target, max_pages=args.max_pages,
                         mode=args.mode, log=lambda *a: print(*a, file=sys.stderr))
    findings = [f.to_dict() for f in res.store.findings]
    report = score(findings, gt)
    report["target"] = args.target
    report["requests"] = client.request_count
    report["tools_used"] = {k: v for k, v in res.tools_used.items() if v}

    print("\n=== Mythos evaluation ===")
    for k in ("target", "expected", "covered", "coverage", "total_findings",
              "false_positive_rate", "precision", "recall", "f1", "requests"):
        print(f"  {k:22} {report[k]}")
    if report["missed"]:
        print(f"  missed classes        {report['missed']}")
    if report["false_positives"]:
        print(f"  false positives       {report['false_positives']}")

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
