#!/usr/bin/env bash
# Release gate: run before every push that claims "done".
# Stdlib only, no install step, no network. Three checks: the package imports,
# the unittest suite passes, and the CLI does real work offline.
set -uo pipefail
cd "$(dirname "$0")/.."

fail() { echo "GATE FAILED: $*"; exit 1; }

out=$(mktemp)
trap 'rm -f "$out"' EXIT

echo "== check 1/3: import"
python3 -c "import perimeter_watch" || fail "import"

echo "== check 2/3: unittest suite"
python3 -m unittest discover -s tests -q || fail "tests"

echo "== check 3/3: CLI smoke on an empty watchlist (offline)"
policy=$(mktemp)
printf '{"domains": []}' > "$policy"
python3 -m perimeter_watch --watchlist "$policy" > "$out" 2>&1 || { cat "$out"; rm -f "$policy"; fail "cli exit"; }
rm -f "$policy"
grep -qi "no issues found by ruleset" "$out" || { cat "$out"; fail "cli output: expected the ruleset label"; }
echo "smoke ok: $(grep -m1 -i "no issues found by ruleset" "$out")"
echo "ALL CHECKS PASSED"
