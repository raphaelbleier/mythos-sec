#!/usr/bin/env python3
"""XBOW validation-benchmarks: catalog, stratified subset, per-run target lifecycle.

  python3 bench/xben.py list [--buildable] [--sample 30 --seed 1]
  python3 bench/xben.py check [IDS...]      # build with apt fix, write build TSV

Targets are started from a resolved compose file (``docker compose config``) with
every published port rebound to ``BIND_IP:<random>`` so parallel runs never clash
and the vulnerable apps are not exposed on the LAN. The default bind IP is the
docker0 gateway: reachable from host processes (opencode) and from sandbox
containers via host-gateway (Strix).
"""
import argparse, json, os, random, subprocess
from collections import defaultdict
from pathlib import Path

BENCH_ROOT = Path(os.environ.get("XBEN_ROOT", "/mnt/linux-data/mythos-bench"))
XBEN_DIR = BENCH_ROOT / "validation-benchmarks" / "benchmarks"
REPO_DATA = Path(__file__).resolve().parent / "data"
# --buildable uses the apt-fixed list (102/104 on 2026-11-04); XBEN_BUILD_TSV overrides.
BUILD_TSV = Path(os.environ.get("XBEN_BUILD_TSV", REPO_DATA / "xben-build-aptfix-20261104.tsv"))
WEB_PORTS = {80, 443, 8080, 8000, 8081, 5000, 3000, 8443}

# Upstream rots: buster/stretch/jessie left deb.debian.org, bullseye-security points at
# packages the mirror no longer serves (checked 2026-11-04). Injected after every FROM
# via dockerfile_inline, the checkout stays untouched. Recorded as apt_fix in result.json.
APT_FIX = ("RUN if [ -f /etc/os-release ]; then . /etc/os-release; case \"$VERSION_CODENAME\" in "
           "jessie|stretch|buster) sed -i -e 's|deb.debian.org|archive.debian.org|g' "
           "-e 's|security.debian.org|archive.debian.org|g' -e '/-updates/d' /etc/apt/sources.list; "
           "echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99archive;; "
           "bullseye) sed -i 's|deb.debian.org/debian-security|archive.debian.org/debian-security|' "
           "/etc/apt/sources.list /etc/apt/sources.list.d/*.sources;; esac; fi 2>/dev/null || true")


def patch_dockerfile(text):
    out = []
    for line in text.splitlines():
        out.append(line)
        if line.strip().upper().startswith("FROM ") and "scratch" not in line.lower():
            out.append(APT_FIX)
    return "\n".join(out) + "\n"


def load_challenges(xben_dir=XBEN_DIR):
    out = []
    for d in sorted(Path(xben_dir).glob("XBEN-*")):
        meta = json.loads((d / "benchmark.json").read_text())
        out.append({"id": d.name, "dir": str(d), "level": int(meta["level"]),  # level is str or int upstream
                    "tags": meta.get("tags", []), "win_condition": meta.get("win_condition", "flag")})
    return out


def load_build_status(tsv=BUILD_TSV):
    """{challenge_id: True|False} from the pre-flight build check (dir, ok|fail, seconds)."""
    status = {}
    if Path(tsv).exists():
        for line in Path(tsv).read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                status[parts[0]] = parts[1] == "ok"
    return status


def stratified_subset(challenges, n, seed=0):
    """n challenges, levels allocated proportionally (largest remainder), and inside a
    level round-robin over primary tags so tag coverage is maximal. Deterministic per seed."""
    rng = random.Random(seed)
    by_level = defaultdict(list)
    for c in challenges:
        by_level[c["level"]].append(c)
    total = len(challenges)
    n = min(n, total)
    quota = {lv: n * len(cs) / total for lv, cs in by_level.items()}
    alloc = {lv: int(q) for lv, q in quota.items()}
    for lv in sorted(quota, key=lambda lv: quota[lv] - alloc[lv], reverse=True)[: n - sum(alloc.values())]:
        alloc[lv] += 1
    picked = []
    for lv in sorted(by_level):
        by_tag = defaultdict(list)
        for c in by_level[lv]:
            by_tag[sorted(c["tags"])[0] if c["tags"] else ""].append(c)
        queues = [rng.sample(v, len(v)) for _, v in sorted(by_tag.items())]
        rng.shuffle(queues)
        take = []
        while len(take) < alloc[lv]:
            for q in queues:
                if q and len(take) < alloc[lv]:
                    take.append(q.pop())
        picked += take
    return sorted(picked, key=lambda c: c["id"])


def docker_gateway():
    try:
        return subprocess.run(["docker", "network", "inspect", "bridge", "-f",
                               "{{(index .IPAM.Config 0).Gateway}}"],
                              capture_output=True, text=True, check=True).stdout.strip() or "127.0.0.1"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "127.0.0.1"


class Target:
    """One isolated instance of a challenge with its own FLAG and compose project."""

    def __init__(self, challenge, project, flag, run_dir, bind_ip, apt_fix=True):
        self.c, self.project, self.flag, self.apt_fix = challenge, project, flag, apt_fix
        self.run_dir, self.bind_ip = Path(run_dir), bind_ip
        self.compose = self.run_dir / "compose.json"
        self.log = self.run_dir / "target.log"

    def _dc(self, *args, timeout=1800, check=True):
        env = dict(os.environ, FLAG=self.flag, flag=self.flag)
        with open(self.log, "a") as log:
            return subprocess.run(["docker", "compose", "-p", self.project, "-f", str(self.compose), *args],
                                  env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=check)

    def write_compose(self):
        d = self.c["dir"]
        env = dict(os.environ, FLAG=self.flag, flag=self.flag)
        cfg = json.loads(subprocess.run(
            ["docker", "compose", "--project-directory", d, "-f", f"{d}/docker-compose.yml",
             "config", "--format", "json"], env=env, capture_output=True, text=True, check=True).stdout)
        cfg.pop("name", None)
        for kind in ("networks", "volumes"):  # config pins names to the upstream project: re-scope to ours
            for v in (cfg.get(kind) or {}).values():
                if not v.get("external"):
                    v.pop("name", None)
        for svc in cfg.get("services", {}).values():
            b = svc.get("build")
            if self.apt_fix and b and not b.get("dockerfile_inline"):
                df = Path(b["context"]) / b.pop("dockerfile", "Dockerfile")
                b["dockerfile_inline"] = patch_dockerfile(df.read_text()).replace("$", "$$")  # no compose interpolation
            if svc.get("expose"):  # upstream writes "3306:3306", which up rejects
                svc["expose"] = [str(e).split(":")[-1] for e in svc["expose"]]
            if svc.get("ports"):
                svc["ports"] = [{"target": p["target"], "protocol": p.get("protocol", "tcp"),
                                 "host_ip": self.bind_ip} for p in svc["ports"]]
        self.compose.write_text(json.dumps(cfg, indent=1))

    def build(self):
        self.write_compose()
        self._dc("build", "--build-arg", f"FLAG={self.flag}", "--build-arg", f"flag={self.flag}")

    def up(self):
        """Build with this run's FLAG (late ARG -> only the last layers rebuild), start, return endpoints."""
        self.build()
        self._dc("up", "-d", "--wait", "--wait-timeout", "600", timeout=900)
        return self.endpoints()

    def endpoints(self):
        env = dict(os.environ, FLAG=self.flag)
        ps = subprocess.run(["docker", "compose", "-p", self.project, "-f", str(self.compose), "ps",
                             "--format", "json"], env=env, capture_output=True, text=True, check=True).stdout
        rows = json.loads(ps) if ps.strip().startswith("[") else [json.loads(l) for l in ps.splitlines() if l.strip()]
        pubs = {(p.get("TargetPort") not in WEB_PORTS, f"{self.bind_ip}:{p['PublishedPort']}") for r in rows
                for p in r.get("Publishers") or [] if p.get("PublishedPort")}
        return [e for _, e in sorted(pubs)]  # web-looking ports first: endpoints[0] is the target

    def down(self):
        self._dc("down", "-v", "--remove-orphans", "--rmi", "local", "-t", "5", timeout=600, check=False)


def check(a):
    import time, tempfile
    chals = [c for c in load_challenges() if not a.ids or c["id"] in a.ids]
    logs = Path(a.out).with_suffix(".logs")
    logs.mkdir(exist_ok=True)
    with open(a.out, "w") as out:
        for c in chals:
            t0, ok = time.time(), True
            with tempfile.TemporaryDirectory() as tmp:
                t = Target(c, "xbencheck_" + c["id"].lower().replace("-", "_"), "FLAG{check}", tmp, "127.0.0.1",
                           apt_fix=not a.no_apt_fix)
                try:
                    t.build()
                except (subprocess.SubprocessError, OSError, KeyError):
                    ok = False
                if t.log.exists():
                    (logs / f"{c['id']}.log").write_text(t.log.read_text())
            line = f"{c['id']}\t{'ok' if ok else 'fail'}\t{int(time.time() - t0)}"
            print(line, flush=True)
            out.write(line + "\n")
            out.flush()
        out.write("DONE\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="print challenges as TSV (id, level, build, tags)")
    ls.add_argument("--buildable", action="store_true", help="only challenges with build=ok")
    ls.add_argument("--sample", "--subset", dest="subset", type=int, help="stratified sample of this size")
    ls.add_argument("--seed", type=int, default=0)
    ck = sub.add_parser("check", help="build challenges (with apt fix) and write a build TSV")
    ck.add_argument("ids", nargs="*", help="default: all")
    ck.add_argument("--out", default=str(BENCH_ROOT / "build_results_fixed.tsv"))
    ck.add_argument("--no-apt-fix", action="store_true")
    a = ap.parse_args()
    if a.cmd == "check":
        return check(a)
    chals, built = load_challenges(), load_build_status()
    if a.buildable:
        chals = [c for c in chals if built.get(c["id"])]
    if a.subset:
        chals = stratified_subset(chals, a.subset, a.seed)
    for c in chals:
        b = {True: "ok", False: "fail"}.get(built.get(c["id"]), "?")
        print(f"{c['id']}\t{c['level']}\t{b}\t{','.join(c['tags'])}")


if __name__ == "__main__":
    main()
