#!/usr/bin/env bash
# Gap 6: reproducible flakiness harness for adversarial Test E.
#
# Runs `quorum_adversarial --only E` RUNS times, optionally under background
# CPU/memory pressure (stress-ng), and records every outcome. A failing run
# keeps its complete output so the cause can be diagnosed, not retried away.
# There are deliberately NO retries here: a single failure is a failure.
#
# Usage: ci/stress_test_e.sh [RUNS=100] [OUT_DIR=stress_out]
# Env:   BIN          adversarial binary (default target/debug/quorum_adversarial)
#        PROPOSERS    if set, run opt-in group X with N concurrent proposers
#                     (default unset = the original 2-proposer Test E)
#        STRESS_CPU   stress-ng cpu workers (default 0 = no stress)
#        STRESS_VM    stress-ng vm workers  (default 0)
# Exit:  0 only if every run passed; 1 if any failed; 2 on harness error.
set -uo pipefail

RUNS="${1:-100}"
OUT="${2:-stress_out}"
BIN="${BIN:-target/debug/quorum_adversarial}"
STRESS_CPU="${STRESS_CPU:-0}"
STRESS_VM="${STRESS_VM:-0}"
PROPOSERS="${PROPOSERS:-}"
if [ -n "$PROPOSERS" ]; then GROUP=X; ARGS=(--only X --proposers "$PROPOSERS"); else GROUP=E; ARGS=(--only E); fi

[ -x "$BIN" ] || { echo "harness error: $BIN not built (cargo build -p quorum_adversarial -p quorum_node -p quorum_notary)" >&2; exit 2; }
mkdir -p "$OUT"
: > "$OUT/summary.tsv"

stress_pid=""
if [ "$STRESS_CPU" -gt 0 ] || [ "$STRESS_VM" -gt 0 ]; then
  command -v stress-ng >/dev/null || { echo "harness error: stress-ng not installed" >&2; exit 2; }
  stress-ng --cpu "$STRESS_CPU" --vm "$STRESS_VM" --vm-bytes 128M --timeout 0 >/dev/null 2>&1 &
  stress_pid=$!
  trap '[ -n "$stress_pid" ] && kill "$stress_pid" 2>/dev/null' EXIT
  sleep 2
fi

pass=0; fail=0
for i in $(seq 1 "$RUNS"); do
  start=$(date +%s.%N)
  "$BIN" "${ARGS[@]}" >"$OUT/run_$i.log" 2>&1
  rc=$?
  secs=$(awk -v a="$start" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
  # PASS requires the explicit PASS line AND exit 0, so a run that printed
  # nothing (e.g. crashed at startup) cannot be counted as a pass.
  if [ "$rc" -eq 0 ] && grep -q "\[PASS\] $GROUP:" "$OUT/run_$i.log"; then
    pass=$((pass+1)); verdict=PASS; rm -f "$OUT/run_$i.log"
  else
    fail=$((fail+1)); verdict=FAIL
  fi
  printf '%s\t%s\t%s\t%s\n' "$i" "$verdict" "$rc" "$secs" >> "$OUT/summary.tsv"
done

echo "Test $GROUP${PROPOSERS:+ (proposers=$PROPOSERS)}: runs=$RUNS pass=$pass fail=$fail stress_cpu=$STRESS_CPU stress_vm=$STRESS_VM"
[ "$fail" -eq 0 ]
