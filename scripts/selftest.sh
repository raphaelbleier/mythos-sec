#!/usr/bin/env bash
# Mythos self-test — a repeatable regression check for the skill-driven flow.
#
# Starts the ground-truth lab app (lab/vulnapp) and drives the Kali toolbox the
# same way the skills do, asserting that each expected vulnerability class is
# found with real tool output, and that a safe endpoint is NOT flagged (no false
# positive). This is the automated test for the toolbox-driven architecture
# (there is no Python engine to unit-test).
#
#   scripts/selftest.sh                  # full run (starts + stops the lab)
#   KEEP_LAB=1 scripts/selftest.sh       # leave the lab running afterwards
#   scripts/selftest.sh --host opencode  # same 10 checks, but the mythos agent
#                                        # does the work via `opencode run` and
#                                        # its report is scored
#
# --host opencode env: MYTHOS_MODEL (default opencode/glm-5.3-flash-free),
# MYTHOS_TIMEOUT seconds for the agent run (default 3600).
#
# Exit code 0 = all checks passed.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
T="http://host.docker.internal:5001"
PASS=0; FAIL=0
HOST=claude
[ "${1:-}" = "--host" ] && HOST="${2:-claude}"

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

# assert <name> <needle> <command-output...>
assert_has() { if printf '%s' "$3" | grep -qiF "$2"; then ok "$1"; else bad "$1 (missing: $2)"; fi; }
assert_not() { if printf '%s' "$3" | grep -qiF "$2"; then bad "$1 (unexpected: $2)"; else ok "$1"; fi; }
# assert_line <name> <path> <class-regex> <text>: one line names both the path and the class
assert_line() { if printf '%s' "$4" | grep -iF -- "$2" | grep -qiE -- "$3"; then ok "$1"; else bad "$1 (no line with $2 + /$3/)"; fi; }

echo "== Mythos self-test (host: $HOST) =="
echo "-- starting toolbox + lab --"
scripts/mythos up >/dev/null 2>&1
docker compose -f lab/docker-compose.yml up -d vulnapp >/dev/null 2>&1
for i in $(seq 1 20); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5001/ 2>/dev/null)" = "200" ] && break
  sleep 1
done

if [ "$HOST" = "opencode" ]; then
  echo "-- running the mythos agent through opencode --"
  MODEL="${MYTHOS_MODEL:-opencode/glm-5.3-flash-free}"
  tmp=$(mktemp -d)
  cat > "$tmp/scope.yaml" <<YAML
target: $T
in_scope: [host.docker.internal, 127.0.0.1, localhost]
out_of_scope: []
rules:
  rate_limit_rps: 10
  max_requests: 20000
  allow_active: true
  allow_exploit: true
notes: "Mythos self-test against the local ground-truth lab app (lab/vulnapp)."
YAML
  mkdir -p engagements
  touch "$tmp/start"
  log="engagements/selftest-opencode-$(date +%Y%m%d-%H%M%S).jsonl"
  timeout "${MYTHOS_TIMEOUT:-3600}" opencode run --agent mythos --model "$MODEL" \
    --format json --auto "$T --scope $tmp/scope.yaml" > "$log" 2>&1 < /dev/null
  echo "   agent exit $?, event log: $log"
  # score what the agent claims: its report and findings, not raw tool output
  corpus=$(find engagements -newer "$tmp/start" -type f \
    \( -name 'report.md' -o -path '*/findings/*' \) -exec cat {} + 2>/dev/null)
  [ -n "$corpus" ] || echo "   (no report.md / findings/ written by the agent)"

  echo "-- scoring the agent's report --"
  assert_has  "fingerprint (Flask detected)"     "Flask" "$corpus"
  assert_line "reflected XSS /search?q="         "/search"   "xss|cross-site" "$corpus"
  assert_line "SQLi /user?id="                   "/user"     "sql" "$corpus"
  assert_line "open redirect /go?next="          "/go"       "redirect" "$corpus"
  assert_line "path traversal /download?file="   "/download" "traversal|lfi|file (read|inclusion|disclosure)" "$corpus"
  assert_line "CORS reflects Origin /api/data"   "/api/data" "cors|origin" "$corpus"
  assert_has  "sensitive exposure /.env"         "/.env" "$corpus"
  # negative control (ground_truth must_not_flag): /safe escapes its output
  fp=$(printf '%s' "$corpus" | grep -iF "/safe" | grep -iE "xss|cross-site" \
       | grep -viE "not |no |false|escaped|negative")
  if [ -z "$fp" ]; then ok "no false-positive XSS on /safe"; else bad "no false-positive XSS on /safe (claimed: $fp)"; fi

  echo "-- fast probe (deterministic, no model) --"
  pr=$(timeout 120 scripts/probe "http://127.0.0.1:5001" --depth 2 2>&1)
  assert_has "probe maps the search form"      "form GET /search"              "$pr"
  assert_has "probe reaches /.env"             "/.env"                         "$pr"
  assert_has "probe ranks q as xss/sqli"       "reflected-xss"                 "$pr"
  assert_has "probe ranks file as traversal"   "path-traversal"                "$pr"
  assert_has "probe flags missing headers"     "missing_headers"               "$pr"

  echo "-- scope-guard core (what the OpenCode plugin calls) --"
  out=$(MYTHOS_SCOPE="$tmp/scope.yaml" python3 hooks/scope-guard.py --check "nuclei -u https://out-of-scope.example")
  assert_has "scope-guard warns out-of-scope" "OUT OF SCOPE" "$out"
  out=$(MYTHOS_SCOPE="$tmp/scope.yaml" python3 hooks/scope-guard.py --check "httpx -u http://host.docker.internal:5001")
  assert_not "scope-guard silent in-scope" "OUT OF SCOPE" "$out"
  rm -rf "$tmp"
else

echo "-- running checks through the toolbox --"

out=$(scripts/mythos sh "httpx -silent -title -tech-detect -u $T" 2>/dev/null)
assert_has "fingerprint (Flask detected)" "Flask" "$out"

out=$(scripts/mythos run curl -s -G "$T/search" --data-urlencode "q=<script>alert(1)</script>")
assert_has "reflected XSS /search?q=" "<script>alert(1)</script>" "$out"

out=$(scripts/mythos run curl -s -G "$T/user" --data-urlencode "id=1'")
assert_has "SQLi error leak /user?id=" "sqlite" "$out"

out=$(scripts/mythos run curl -s -o /dev/null -w '%{redirect_url}' "$T/go?next=https://evil.example")
assert_has "open redirect /go?next=" "evil.example" "$out"

out=$(scripts/mythos run curl -s -G "$T/download" --data-urlencode "file=../../../../etc/passwd")
assert_has "path traversal /download?file=" "root:x:0:0" "$out"

out=$(scripts/mythos sh "curl -s -I -H 'Origin: https://evil.example' $T/api/data")
assert_has "CORS reflects Origin /api/data" "access-control-allow-origin: https://evil.example" "$out"

out=$(scripts/mythos run curl -s -o /dev/null -w '%{http_code}' "$T/.env")
assert_has "sensitive exposure /.env" "200" "$out"

# negative control: the home page must NOT reflect an injected marker (no FP)
out=$(scripts/mythos run curl -s -G "$T/" --data-urlencode "x=<script>alert(777)</script>")
assert_not "no false-positive XSS on /" "<script>alert(777)</script>" "$out"

echo "-- scope-guard hook --"
tmp=$(mktemp -d)
cat > "$tmp/scope.yaml" <<YAML
in_scope: [host.docker.internal]
out_of_scope: []
YAML
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"nuclei -u https://out-of-scope.example"}}' \
  | MYTHOS_SCOPE="$tmp/scope.yaml" python3 hooks/scope-guard.py 2>&1)
assert_has "scope-guard warns out-of-scope" "OUT OF SCOPE" "$out"
out=$(echo '{"tool_name":"Bash","tool_input":{"command":"httpx -u http://host.docker.internal:5001"}}' \
  | MYTHOS_SCOPE="$tmp/scope.yaml" python3 hooks/scope-guard.py 2>&1)
assert_not "scope-guard silent in-scope" "OUT OF SCOPE" "$out"
rm -rf "$tmp"
fi

if [ "${KEEP_LAB:-0}" != "1" ]; then
  docker compose -f lab/docker-compose.yml down >/dev/null 2>&1
fi

echo
echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
