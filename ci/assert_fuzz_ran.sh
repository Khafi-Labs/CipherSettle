#!/usr/bin/env bash
# Gap 8: fail unless a libFuzzer log shows a CLEAN run of the REQUESTED length.
#   usage: ci/assert_fuzz_ran.sh <fuzz.log> <required_seconds>
# Requires: (1) libFuzzer's final "Done N runs in S second(s)" with N>0 and
# S >= required_seconds, and (2) none of libFuzzer/sanitizer failure markers.
# Independent of cargo-fuzz's exit status, so a swallowed exit code cannot pass.
set -uo pipefail
log="${1:?usage: assert_fuzz_ran.sh <log> <seconds>}"; need="${2:?usage: assert_fuzz_ran.sh <log> <seconds>}"
[[ "$need" =~ ^[0-9]+$ ]] || { echo "FAIL: seconds must be an integer, got '$need'" >&2; exit 1; }
[ -s "$log" ] || { echo "FAIL: log '$log' is missing or empty" >&2; exit 1; }
if grep -E -n "ERROR: libFuzzer|SUMMARY: |==ERROR|Test unit written to|panicked at|timeout after|out-of-memory|deadly signal|ABORTING" "$log" | head -5 | grep -q .; then
  echo "FAIL: failure marker(s) in $log:" >&2
  grep -E -n "ERROR: libFuzzer|SUMMARY: |==ERROR|Test unit written to|panicked at|timeout after|out-of-memory|deadly signal|ABORTING" "$log" | head -5 >&2
  exit 1
fi
done_line=$(grep -E "^Done [0-9]+ runs in [0-9]+ second\(s\)" "$log" | tail -1)
[ -n "$done_line" ] || { echo "FAIL: no 'Done N runs in S second(s)' line (the run did not finish cleanly)" >&2; exit 1; }
runs=$(sed -E 's/^Done ([0-9]+) runs.*/\1/' <<<"$done_line"); secs=$(sed -E 's/.* in ([0-9]+) second.*/\1/' <<<"$done_line")
[ "$runs" -gt 0 ] || { echo "FAIL: 0 runs executed" >&2; exit 1; }
[ "$secs" -ge "$need" ] || { echo "FAIL: ran ${secs}s, required ${need}s" >&2; exit 1; }
echo "ok: $runs runs in ${secs}s (>= ${need}s), no failure markers"
