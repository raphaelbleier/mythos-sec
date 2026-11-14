#!/usr/bin/env bash
# Mythos repository check. No network, no model, no API key.
#
#   scripts/selftest.sh                 # offline checks only (what CI runs)
#   scripts/selftest.sh --with-docker   # also the toolbox flow and the lab target
#
# It runs, in order:
#   1. every deterministic script's own --selftest
#   2. the CLI typecheck and cli/dist/selftest.js
#   3. the two guards end to end against a temporary scope file
#   4. with --with-docker: the toolbox, and a loopback lab target via MYTHOS_NET=host
#
# The first failure ends the run with a non-zero exit code and the failing
# command's output.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

WITH_DOCKER=0
case "${1:-}" in
  "") ;;
  --with-docker) WITH_DOCKER=1 ;;
  -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "selftest: unknown argument '$1' (use --with-docker)" >&2; exit 2 ;;
esac

ok()   { printf 'ok    %s\n' "$1"; }
skip() { printf 'skip  %s\n' "$1"; }
die()  { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

# run <name> <command...>: print one line, or print the output and stop.
run() {
  local name="$1"; shift
  local out
  if out=$("$@" 2>&1); then ok "$name"; else
    printf '%s\n' "$out" >&2
    die "$name"
  fi
}

# want <name> <expected> <actual>
want() {
  [ "$2" = "$3" ] && ok "$1" || die "$1 (expected '$2', got '$3')"
}

echo "== deterministic scripts =="
# Every deterministic script and both guards. Keep this list complete: a script
# without a check here is one whose breakage shows up as a bad engagement rather
# than as a failing build.
for s in scripts/probe scripts/verify scripts/coverage scripts/findings scripts/cvefeed \
         scripts/sourcemap scripts/traffic scripts/watch scripts/lessons \
         scripts/lessons-record scripts/models \
         hooks/scope-guard.py hooks/budget-guard.py; do
  run "$s --selftest" python3 "$s" --selftest
done

echo
echo "== cli =="
# Read-only on purpose: this never installs and never builds, so running it
# cannot disturb a cli/dist an engagement is using. A fresh clone skips both
# checks and says so.
if [ -d cli/node_modules ]; then
  run "cli typecheck (npm run check)" npm run --silent --prefix cli check
else
  skip "cli typecheck: no cli/node_modules (npm ci --prefix cli)"
fi
if [ -f cli/dist/selftest.js ]; then
  run "cli/dist/selftest.js" node cli/dist/selftest.js
else
  skip "cli selftest: no cli/dist (npm run build --prefix cli)"
fi

echo
echo "== guards =="
# The guards are no longer host hooks: cli/src/agent/guards.ts shells out to
# `--check` from inside every tool that can reach the target. So this exercises
# exactly the interface the agent uses.
G="$(mktemp -d)"
TOOLBOX_UP=0
cleanup() {
  rm -rf "$G"
  [ "$TOOLBOX_UP" = 1 ] && MYTHOS_CONTAINER=mythos-selftest scripts/mythos down >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

cat > "$G/scope.yaml" <<'YAML'
target: http://127.0.0.1:5001
in_scope: [127.0.0.1, localhost]
out_of_scope: []
rules:
  rate_limit_rps: 10
YAML
export MYTHOS_SCOPE="$G/scope.yaml"
# The defaults are the policy under test, so no inherited mode may change them.
unset MYTHOS_SCOPE_ENFORCE MYTHOS_BUDGET_ENFORCE MYTHOS_DESTRUCTIVE

scoped() { python3 hooks/scope-guard.py --check "$1"; }
# The budget guard's verdict for one command.
action() {
  python3 hooks/budget-guard.py --check "$1" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("action","?"))'
}
unrecorded() {
  python3 hooks/budget-guard.py --check "$1" \
    | python3 -c 'import json,sys; print("yes" if "unrecorded" in (json.load(sys.stdin).get("message") or "") else "no")'
}

out=$(scoped "curl -sS https://out-of-scope.example/")
case "$out" in
  *"OUT OF SCOPE"*out-of-scope.example*) ok "scope guard names an out-of-scope host" ;;
  *) printf '%s\n' "$out" >&2; die "scope guard names an out-of-scope host" ;;
esac
out=$(scoped "curl -sS http://127.0.0.1:5001/search?q=1")
case "$out" in
  *"OUT OF SCOPE"*) printf '%s\n' "$out" >&2; die "scope guard is silent on an in-scope host" ;;
  *) ok "scope guard is silent on an in-scope host" ;;
esac

want "a DELETE against the target is refused" block \
     "$(action 'curl -X DELETE http://127.0.0.1:5001/paste/7')"
# A denylist shaped like a shell command does not see mass destruction named in
# a request body; a live run emptied a target's table through exactly this.
want "a mass-deletion GraphQL operation is refused" block \
     "$(action 'curl -X POST http://127.0.0.1:5001/graphql -d {"query":"{deleteAllPastes}"}')"

# Recording. With the proxy up a bare host curl sends a request no record shows,
# while the same curl through the toolbox carries the proxy variables. The first
# assert is the control: without it the second one passes even when the guard
# never noticed the proxy at all.
mkdir -p "$G/traffic" && echo '{}' > "$G/traffic/proxy.json"
want "a bare curl is flagged unrecorded while the proxy is up" yes \
     "$(unrecorded 'curl -sS http://127.0.0.1:5001/')"
want "a toolbox-wrapped curl is not flagged unrecorded" no \
     "$(unrecorded "scripts/mythos sh 'curl -sS http://127.0.0.1:5001/'")"
rm -f "$G/traffic/proxy.json"

# scripts/mythos asks scripts/traffic for the proxy variables whenever
# MYTHOS_SCOPE is set, and refuses to run while the proxy is down.
unset MYTHOS_SCOPE

echo
echo "== toolbox =="
if [ "$WITH_DOCKER" != 1 ]; then
  skip "toolbox: pass --with-docker to run it"
elif ! docker info >/dev/null 2>&1; then
  skip "toolbox: no reachable Docker daemon"
else
  # A dedicated container, so this never stops or renetworks the toolbox an
  # engagement is using.
  export MYTHOS_CONTAINER=mythos-selftest
  TOOLBOX_UP=1
  out=$(scripts/mythos sh 'echo toolbox-ok' 2>&1)
  case "$out" in
    *toolbox-ok*) ok "scripts/mythos sh runs a command in the toolbox" ;;
    *) printf '%s\n' "$out" >&2; die "scripts/mythos sh runs a command in the toolbox" ;;
  esac

  # The lab binds to the host's loopback, which a bridged container cannot reach
  # at all. MYTHOS_NET=host is the only way in, and the network is chosen when
  # the container starts, so the bridged one has to go first.
  if [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5001/ 2>/dev/null)" = "200" ]; then
    scripts/mythos down >/dev/null 2>&1
    code=$(MYTHOS_NET=host scripts/mythos sh \
      'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5001/' 2>/dev/null)
    want "MYTHOS_NET=host reaches the loopback lab target" 200 "$code"
  else
    skip "lab target on 127.0.0.1:5001 is not up (docker compose -f lab/docker-compose.yml up -d vulnapp)"
  fi
fi

echo
echo "== all checks passed =="
