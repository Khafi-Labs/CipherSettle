#!/usr/bin/env bash
# One command that mirrors the CI jobs locally and writes a per-step verdict.
#   usage: ci/run_local_regression.sh [OUTDIR=verification_out]
# Needs: the toolchain pinned in rust-toolchain.toml, and Postgres reachable as
# CIPHERSETTLE_TEST_DB_URL (default postgres://postgres:ciphersettle_dev@127.0.0.1:5432/ciphersettle_test)
# with the databases from `bash ci/setup_test_db.sh`.
# Exit 0 only if EVERY step passed, including that the active rustc equals the pin.
# A run on a different rustc exits non-zero by design (VERIFICATION_RUNBOOK.md section 0).
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-verification_out}"; mkdir -p "$OUT"; rm -f "$OUT"/*.log "$OUT"/summary.txt
export CIPHERSETTLE_TEST_DB_REQUIRED=1
export CIPHERSETTLE_TEST_DB_URL="${CIPHERSETTLE_TEST_DB_URL:-postgres://postgres:ciphersettle_dev@127.0.0.1:5432/ciphersettle_test}"
rm -rf "${CARGO_TARGET_DIR:-target}/tmp"
overall=0
{ echo "date:    $(date -u +%FT%TZ)"; echo "git:     $(git rev-parse HEAD 2>/dev/null) $(git diff --quiet 2>/dev/null || echo '(+uncommitted changes)')"
  echo "rustc:   $(rustc --version)"; echo "pinned:  $(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"; echo; } > "$OUT/summary.txt"
step() {
  local name="$1"; shift
  "$@" > "$OUT/$name.log" 2>&1; local rc=$?
  if [ $rc -eq 0 ]; then echo "EXECUTED + PASSED   $name" | tee -a "$OUT/summary.txt"
  else echo "EXECUTED + FAILED   $name (rc=$rc, see $OUT/$name.log)" | tee -a "$OUT/summary.txt"; overall=1; fi
}
step toolchain_pinned       bash ci/assert_toolchain_pinned.sh
step dep_pin_policy         bash ci/check_pin_policy.sh
step fuzz_setup_consistency bash ci/check_fuzz_setup.sh
step docs_claims            bash ci/check_docs_claims.sh
step docs_claims_selftest   bash ci/check_docs_claims_selftest.sh
step dockerfile_policy      bash ci/check_dockerfile.sh
step fuzz_gate_selftest     bash ci/check_fuzz_assert.sh
step fmt                    cargo fmt --all -- --check
step clippy                 cargo clippy --workspace --locked --all-targets -- -D warnings
step fuzz_crate_typecheck   cargo check --locked --manifest-path fuzz/Cargo.toml --bins
step build                  cargo build --workspace --locked --all-targets
step unit_tests             cargo test --workspace --locked
step db_tests_really_ran    bash ci/assert_db_tests_ran.sh "${CARGO_TARGET_DIR:-target}/tmp"
step broken_db_must_fail_ci bash ci/check_ci_fails_on_broken_db.sh
step adversarial_run        bash -c "cargo run -q --locked -p quorum_adversarial -- --only A,B,C,D,M,L,E,I,F,G,J,K,N,Z,P,Q,R,S,T,W > '$OUT/adversarial.out' 2>&1"
step adversarial_80_of_80   bash -c "grep -q '^80/80 checks passed as expected\\.' '$OUT/adversarial.out' && ! grep -q '^\\[FAIL\\]' '$OUT/adversarial.out'"
grep -E "^test result" "$OUT/unit_tests.log" | awk '{p+=$4; f+=$6} END {print "unit tests: passed",p,"failed",f}' | tee -a "$OUT/summary.txt"
grep -E "checks passed" "$OUT/adversarial.out" | tee -a "$OUT/summary.txt"
echo; [ $overall -eq 0 ] && echo "OVERALL: ALL STEPS PASSED" | tee -a "$OUT/summary.txt" || echo "OVERALL: AT LEAST ONE STEP FAILED" | tee -a "$OUT/summary.txt"
echo "NOT covered: GitHub Actions, cargo audit/deny, fuzzing, orchestrator e2e, power-loss rehearsal, Test E flake campaign." | tee -a "$OUT/summary.txt"
exit $overall
