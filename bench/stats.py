#!/usr/bin/env python3
"""Markdown tables from results.jsonl.

  python3 bench/stats.py OUT/results.jsonl [--compare mythos,control]

Per (framework, model): the solve rate over all cells and over scored cells, both, with a
Wilson 95% CI on the scored one; detection rate; pass@k over repeats (unbiased estimator,
averaged over challenges); suspect count; median wall clock. Cells whose status is an
infrastructure failure (see score.EXCLUDED) are not scored, and the excluded counts are
printed, because the choice of exclusion rule moves the rate by more than any effect measured
so far.
--compare A,B: paired McNemar on (challenge, run) pairs both frameworks have, exact two-sided
binomial on the discordant pairs, with the minimum number of discordant pairs that could have
reached p < 0.05 at that pair count. A high p on few discordant pairs is an absence of power,
not evidence of no difference.
"""
import argparse, json, math, sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score as _score

SCORED = _score.SCORED


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


def power(pairs, psi, delta, alpha=0.05):
    """Exact-McNemar power by enumeration, for a design of `pairs` paired cells.

    `psi` is the discordance rate (the share of pairs on which the two arms disagree) and
    `delta` the true difference in solve rate. The discordant count is Binomial(pairs, psi) and,
    within it, the split is Binomial(D, (psi+delta)/(2*psi)); a design rejects when the exact
    two-sided test on that split clears `alpha`. Stated here rather than in prose so the
    benchmark's minimum detectable difference can be recomputed from the repository.
    """
    p10, p01 = (psi + delta) / 2, (psi - delta) / 2
    if psi <= 0 or p01 < 0 or p10 < 0:
        return None
    q = p10 / psi
    total = 0.0
    for d in range(pairs + 1):
        pd = math.comb(pairs, d) * psi ** d * (1 - psi) ** (pairs - d)
        if not pd:
            continue
        total += pd * sum(math.comb(d, k) * q ** k * (1 - q) ** (d - k)
                          for k in range(d + 1) if mcnemar(k, d - k) < alpha)
    return total


def mdd(pairs, psi=0.3, target=0.80, alpha=0.05):
    """Smallest true difference this design detects with `target` power. Bisection on `power`."""
    lo, hi = 0.0, psi
    for _ in range(60):
        mid = (lo + hi) / 2
        pw = power(pairs, psi, mid, alpha)
        if pw is None or pw < target:
            lo = mid
        else:
            hi = mid
    return hi


def mde_discordant(pairs):
    """Fewest discordant pairs, all in one direction, that reach p < 0.05 at this pair count."""
    for b in range(1, max(pairs, 1) + 1):
        if mcnemar(0, b) < 0.05:
            return b
    return None


def table(rows):
    allcells, cells = defaultdict(list), defaultdict(list)
    for r in rows:
        allcells[(r["framework"], r.get("model", ""))].append(r)
        if r.get("status") in SCORED:
            cells[(r["framework"], r.get("model", ""))].append(r)
    out = []
    kmax = max((len(v) for rs in cells.values() for v in by_chal(rs).values()), default=1)
    ks = [1] + ([kmax] if kmax > 1 else [])
    out.append("| framework | model | cells | rate over all cells | scored | solved | "
               "solve rate [95% CI] | verified | detected | "
               + " | ".join(f"pass@{k}" for k in ks) + " | suspect | excluded | median s |")
    out.append("|" + "---|" * (12 + len(ks)))
    for key, allrs in sorted(allcells.items()):
        fw, model = key
        rs = cells.get(key, [])
        total = len(allrs)
        pre = sum(bool(r.get("solved")) for r in allrs)
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
        exc = defaultdict(int)
        for r in allrs:
            if r.get("status") not in SCORED:
                exc[r.get("status")] += 1
        exc_s = ", ".join(f"{v} {kk}" for kk, v in sorted(exc.items())) or "0"
        out.append(f"| {fw} | {model} | {total} | {pre}/{total} = {pre / total:.2f} | {n} | {k} | "
                   + (f"{k / n:.2f} [{lo:.2f}, {hi:.2f}]" if n else "-") + " | "
                   + str(sum(bool(r.get("solved_verified")) for r in rs)) + " | "
                   + (f"{det / n:.2f}" if n else "-") + " | "
                   + " | ".join(pk) + f" | {sum(r.get('status') == 'suspect' for r in rs)} | "
                   f"{exc_s} | {med} |")
    out.append("")
    out.append("`rate over all cells` applies no exclusion at all; `solve rate` applies the "
               "infrastructure exclusions listed under `excluded`. Both are shown because the "
               "exclusion rule has moved this number by more than any measured effect. "
               "`verified` counts the solved cells whose flag first appeared in tool output "
               "after a request to the target; a lower number than `solved` means flags were "
               "reported that the target was never seen to return.")
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
    p = mcnemar(only_a, only_b)
    need = mde_discordant(len(shared))
    out = [f"| pairs | both solved | only {a} | only {b} | neither | discordant | McNemar exact p |",
           "|---|---|---|---|---|---|---|",
           f"| {len(shared)} | {both} | {only_a} | {only_b} | {len(shared) - both - only_a - only_b} | "
           f"{only_a + only_b} | {p:.4f} |", ""]
    if need is None:
        out.append(f"No number of discordant pairs reaches p < 0.05 with {len(shared)} pairs: this "
                   "comparison cannot produce a significant result.")
    else:
        out.append(f"With {len(shared)} pairs the test needs {need} discordant pairs in one "
                   f"direction to reach p < 0.05, about {need / max(len(shared), 1) * 100:.0f} "
                   f"percentage points of difference. Observed: {only_a + only_b} discordant.")
    if p > 0.05:
        d = mdd(len(shared))
        out.append(f"A high p here means no detectable difference, not no difference. At "
                   f"{len(shared)} pairs and a discordance rate of 0.3, the smallest true "
                   f"difference this design detects with 80% power is {d:.2f}, i.e. "
                   f"{d * 100:.0f} percentage points. Report that figure with the p.")
    return "\n".join(out)


def _selftest():
    lo, hi = wilson(5, 10)
    assert abs(lo - 0.2366) < 1e-3 and abs(hi - 0.7634) < 1e-3
    assert wilson(0, 10)[0] == 0.0 and math.isclose(pass_at_k(3, 1, 1), 1 / 3) and pass_at_k(3, 1, 3) == 1.0
    assert abs(mcnemar(1, 9) - 0.021484375) < 1e-9 and mcnemar(3, 3) == 1.0
    # 26 pairs with 1 discordant gives p = 1.0 and carries no information: the test needs 6
    # discordant pairs in one direction before it can reach p < 0.05 at all.
    assert mcnemar(0, 1) == 1.0 and mde_discordant(26) == 6 and mde_discordant(4) is None
    # Minimum detectable difference, exact enumeration, two-sided alpha 0.05, 80% power,
    # discordance 0.3. These pin the figures quoted in METHODOLOGY.md and the README.
    assert abs(mdd(26) - 0.293) < 0.002, mdd(26)
    assert abs(mdd(30) - 0.274) < 0.002, mdd(30)
    assert abs(mdd(40) - 0.242) < 0.002, mdd(40)
    # a true 0.2 difference is missed three times in five at 30 pairs
    assert abs(power(30, 0.3, 0.2) - 0.403) < 0.005, power(30, 0.3, 0.2)
    assert power(26, 0.3, 0.0) < 0.05 and power(400, 0.3, 0.2) > 0.99
    # one discordant pair against needs 9 pairs of it, two need 12
    assert mcnemar(1, 8) < 0.05 <= mcnemar(1, 7) and mcnemar(2, 10) < 0.05 <= mcnemar(2, 9)
    assert abs(mcnemar(2, 9) - 0.0654) < 1e-3
    assert mcnemar(0, mde_discordant(26)) < 0.05 and mcnemar(0, mde_discordant(26) - 1) > 0.05
    # both rates are printed, and an excluded cell lowers the all-cells rate but not the other
    rows = [{"framework": "a", "model": "m", "challenge": "c1", "run": 0, "status": "ok",
             "solved": True, "detected": True, "wall_s": 1.0},
            {"framework": "a", "model": "m", "challenge": "c2", "run": 0, "status": "rate_limited",
             "solved": False, "detected": False, "wall_s": 1.0}]
    tbl = table(rows)
    assert "1/2 = 0.50" in tbl and "1.00 [" in tbl and "1 rate_limited" in tbl, tbl
    cmp = compare(rows + [{"framework": "b", "model": "m", "challenge": "c1", "run": 0,
                           "status": "ok", "solved": False}], "a", "b")
    assert "no detectable difference" in cmp and "cannot produce a significant result" in cmp, cmp
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
