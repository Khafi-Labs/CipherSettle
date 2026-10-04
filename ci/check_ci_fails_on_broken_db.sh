#!/usr/bin/env bash
# Gap 6 "closed when": a deliberately broken DB setup must make CI FAIL, not skip.
# This script is itself the negative test. It needs NO database; it points the
# DB tests at a port nothing listens on and asserts the failure behaviour:
#   N1  REQUIRED=1  -> cargo test exits non-zero AND says DB_REQUIRED_BUT_UNREACHABLE
#   N2  REQUIRED=1  -> assert_db_tests_ran.sh also fails (markers are `started`)
#   N3  REQUIRED unset (the silent-skip case): cargo test exits 0 BUT
#       assert_db_tests_ran.sh still fails (markers are `skipped`)
# Exit 0 means every expectation held. Any deviation exits 1.
set -uo pipefail
cd "$(dirname "$0")/.."
export CIPHERSETTLE_TEST_DB_URL="postgres://postgres:unused@127.0.0.1:1/nonexistent"
T=(cargo test -q --locked -p quorum_service --test db_pool_concurrency --test migrations)
fail=0
expect() { if [ "$2" = "yes" ]; then echo "  ok:   $1"; else echo "  FAIL: $1"; fail=1; fi; }

echo "N1/N2: REQUIRED=1 with an unreachable DB"
out=$(CIPHERSETTLE_TEST_DB_REQUIRED=1 "${T[@]}" 2>&1); rc=$?
expect "cargo test exits non-zero (rc=$rc)" "$([ "$rc" -ne 0 ] && echo yes)"
expect "output contains DB_REQUIRED_BUT_UNREACHABLE" "$(grep -q DB_REQUIRED_BUT_UNREACHABLE <<<"$out" && echo yes)"
ci/assert_db_tests_ran.sh >/dev/null 2>&1; rc2=$?
expect "assert_db_tests_ran.sh fails (rc=$rc2)" "$([ "$rc2" -ne 0 ] && echo yes)"

echo "N3: REQUIRED unset, unreachable DB (silent-skip case)"
out=$(env -u CIPHERSETTLE_TEST_DB_REQUIRED "${T[@]}" 2>&1); rc=$?
expect "cargo test alone reports success (rc=$rc), which is exactly the hazard" "$([ "$rc" -eq 0 ] && echo yes)"
ci/assert_db_tests_ran.sh >/dev/null 2>&1; rc2=$?
expect "assert_db_tests_ran.sh still fails (rc=$rc2)" "$([ "$rc2" -ne 0 ] && echo yes)"

[ "$fail" -eq 0 ] && echo "RESULT: broken DB setup fails CI as required" || echo "RESULT: NEGATIVE TEST FAILED"
exit "$fail"
