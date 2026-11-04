#!/usr/bin/env python3
"""Markdown tables from results.jsonl.

  python3 bench/stats.py OUT/results.jsonl [--compare mythos,control]

Per (framework, model): solve rate with Wilson 95% CI over scored runs, detection rate,
pass@k over repeats (unbiased estimator, averaged over challenges), suspect and rate-limited
counts. Cells with status target_failed / scope_refused / runner_failed / rate_limited are not scored.
--compare A,B: paired McNemar on (challenge, run) pairs both frameworks have, exact two-sided
binomial on the discordant pairs.
"""
import argparse, json, math
from collections import defaultdict

SCORED = ("ok", "suspect")


def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pass_at_k(n, c, k):
    return 1.0 if n - c < k else 1 - math.comb(n - c, k) / math.comb(n, k)


def mcnemar(b, c):
    """Exact two-sided p for b vs c discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n)


def table(rows):
    cells = defaultdict(list)
    for r in rows:
        if r.get("status") in SCORED:
            cells[(r["framework"], r.get("model", ""))].append(r)
    out = []
    kmax = max((len(v) for rs in cells.values() for v in by_chal(rs).values()), default=1)
    ks = [1] + ([kmax] if kmax > 1 else [])
    out.append("| framework | model | runs | solved | solve rate [95% CI] | detected | "
               + " | ".join(f"pass@{k}" for k in ks) + " | suspect | rate-limited | median s |")
    out.append("|" + "---|" * (9 + len(ks)))
    for (fw, model), rs in sorted(cells.items()):
        n, k = len(rs), sum(bool(r.get("solved")) for r in rs)
        lo, hi = wilson(k, n)
        det = sum(bool(r.get("detected")) for r in rs)
        per = by_chal(rs)
        pk = []
        for kk in ks:
            vals = [pass_at_k(len(v), sum(v), kk) for v in per.values() if len(v) >= kk]
            pk.append(f"{sum(vals) / len(vals):.2f}" if vals else "-")
        walls = sorted(r["wall_s"] for r in rs if r.get("wall_s") is not None)
        med = f"{walls[len(walls) // 2]:.0f}" if walls else "-"
        out.append(f"| {fw} | {model} | {n} | {k} | {k / n:.2f} [{lo:.2f}, {hi:.2f}] | {det / n:.2f} | "
                   + " | ".join(pk) + f" | {sum(r.get('status') == 'suspect' for r in rs)} | "
                   f"{sum(bool(r.get('rate_limited')) for r in rs)} | {med} |")
    return "\n".join(out)


def by_chal(rs):
    d = defaultdict(list)
    for r in rs:
        d[r["challenge"]].append(bool(r.get("solved")))
    return d


def compare(rows, a, b):
    res = {fw: {(r["challenge"], r["run"]): bool(r.get("solved")) for r in rows
                if r["framework"] == fw and r.get("status") in SCORED} for fw in (a, b)}
    shared = sorted(set(res[a]) & set(res[b]))
    both = sum(res[a][x] and res[b][x] for x in shared)
    only_a = sum(res[a][x] and not res[b][x] for x in shared)
    only_b = sum(res[b][x] and not res[a][x] for x in shared)
    return (f"| pairs | both solved | only {a} | only {b} | neither | McNemar exact p |\n|---|---|---|---|---|---|\n"
            f"| {len(shared)} | {both} | {only_a} | {only_b} | {len(shared) - both - only_a - only_b} | "
            f"{mcnemar(only_a, only_b):.4f} |")


def _selftest():
    lo, hi = wilson(5, 10)
    assert abs(lo - 0.2366) < 1e-3 and abs(hi - 0.7634) < 1e-3
    assert wilson(0, 10)[0] == 0.0 and math.isclose(pass_at_k(3, 1, 1), 1 / 3) and pass_at_k(3, 1, 3) == 1.0
    assert abs(mcnemar(1, 9) - 0.021484375) < 1e-9 and mcnemar(3, 3) == 1.0
    print("stats selftest ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="?", help="results.jsonl")
    ap.add_argument("--compare", help="A,B: paired McNemar between two frameworks")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    if not a.results:
        ap.error("results.jsonl required")
    rows = [json.loads(l) for l in open(a.results) if l.strip()]
    print(table(rows))
    if a.compare:
        print()
        print(compare(rows, *a.compare.split(",")))


if __name__ == "__main__":
    main()
