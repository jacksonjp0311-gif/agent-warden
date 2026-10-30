#!/usr/bin/env bash
# Run the misbehaving demo agent under agent-warden and show what happens.
#
#   ./demo/run-demo.sh            # the full rogue sequence (ends with the kill switch)
#   ./demo/run-demo.sh threshold  # too many denials -> automatic halt
#   ./demo/run-demo.sh exfil      # credential in an HTTP body -> halt
#   ./demo/run-demo.sh kill       # `warden kill` takes down a detached process tree
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --quiet --bins
W=./target/debug/warden
A=./target/debug/rogue-agent
STATE=$(mktemp -d "${TMPDIR:-/tmp}/warden-demo.XXXXXX")
trap 'rm -rf "$STATE"' EXIT
scenario=${1:-full}
rm -rf demo/workspace/out

echo "== policy =="
$W check -p policies/demo.toml -w demo/workspace | head -7
echo
if [[ $scenario == kill ]]; then
  echo "== starting an agent that daemonizes a grandchild, then pressing the kill switch =="
  $W run -q -p policies/demo.toml -w demo/workspace --state-dir "$STATE" -- $A escape &
  WPID=$!
  while [[ ! -e $STATE/warden.json ]]; do sleep 0.1; done
  sleep 0.5
  $W kill --state-dir "$STATE" --reason "operator pressed the big red button"
  set +e; wait $WPID; code=$?; set -e
else
  echo "== running rogue-agent ($scenario) under warden =="
  set +e
  $W run -p policies/demo.toml -w demo/workspace --state-dir "$STATE" -- $A "$scenario"
  code=$?
  set -e
fi
echo
echo "== warden exit code: $code (99 = agent halted by warden) =="
echo
echo "== audit log =="
$W verify-log "$STATE/audit.jsonl"
grep -o '"kind":"halt"[^}]*' "$STATE/audit.jsonl" || true
