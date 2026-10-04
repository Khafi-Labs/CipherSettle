#!/usr/bin/env bash
# Self-test of ci/assert_fuzz_ran.sh against SYNTHETIC libFuzzer logs. Proves the
# gate rejects a short run, a crash, a timeout, a missing Done line and an empty
# log, and accepts a clean full-length run. Needs no nightly toolchain.
set -uo pipefail
cd "$(dirname "$0")/.."
A=ci/assert_fuzz_ran.sh; d=$(mktemp -d); fail=0
mk() { printf '%s\n' "${@:2}" > "$d/$1.log"; }
chk() { # name expected_rc seconds
  bash $A "$d/$1.log" "$3" >/dev/null 2>&1; rc=$?
  if { [ "$2" = 0 ] && [ $rc -eq 0 ]; } || { [ "$2" = fail ] && [ $rc -ne 0 ]; }; then echo "  ok:   $1 (rc=$rc, expected $2)"; else echo "  FAIL: $1 (rc=$rc, expected $2)"; fail=1; fi
}
mk good '#1 INITED cov: 10' 'Done 5000000 runs in 3601 second(s)'
mk exact '#2 NEW' 'Done 9 runs in 3600 second(s)'
mk short '#1 INITED' 'Done 5000000 runs in 120 second(s)'
mk crash '==1== ERROR: libFuzzer: deadly signal' 'SUMMARY: libFuzzer: deadly signal' 'Test unit written to ./crash-abc'
mk panic "thread '<unnamed>' panicked at src/x.rs:1:1:" 'Done 10 runs in 4000 second(s)'
mk timeout 'ALARM: working on the last Unit for 31 seconds' '==1== ERROR: libFuzzer: timeout after 31 seconds' 'Done 10 runs in 4000 second(s)'
mk oom 'ERROR: libFuzzer: out-of-memory (used: 2100Mb; limit: 2048Mb)'
mk nodone '#1 INITED' '#2 NEW'
mk zeroruns 'Done 0 runs in 4000 second(s)'
: > "$d/empty.log"
chk good 0 3600; chk exact 0 3600; chk short fail 3600; chk crash fail 3600; chk panic fail 3600
chk timeout fail 3600; chk oom fail 3600; chk nodone fail 3600; chk zeroruns fail 3600; chk empty fail 3600
bash $A "$d/missing.log" 3600 >/dev/null 2>&1; [ $? -ne 0 ] && echo "  ok:   missing file rejected" || { echo "  FAIL: missing file accepted"; fail=1; }
bash $A "$d/good.log" abc >/dev/null 2>&1; [ $? -ne 0 ] && echo "  ok:   non-numeric seconds rejected" || { echo "  FAIL: non-numeric seconds accepted"; fail=1; }
rm -rf "$d"; [ $fail -eq 0 ] && echo "RESULT: fuzz-run gate behaves as required" || echo "RESULT: GATE SELF-TEST FAILED"; exit $fail
