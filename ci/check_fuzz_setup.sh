#!/usr/bin/env bash
# Gap 8: static consistency check of the fuzz setup (no nightly needed). The SAME
# seven names must appear in: fuzz_bodies.rs ALL, fuzz/fuzz_targets/*.rs,
# fuzz/Cargo.toml [[bin]], the fuzz.yml matrix and fuzz/corpus/<name>/ (with
# >=1 seed-* and >=1 regress-*); each target must call its own body; and the
# workflow must keep its failure-propagation guarantees. This proves the files
# agree. It does NOT prove a fuzz run passes.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0; bad() { echo "  FAIL: $*"; fail=1; }; ok() { echo "  ok:   $*"; }
bodies=$(sed -n 's/^    ("\([a-z_0-9]*\)", [a-z_0-9]*),$/\1/p' src/quorum_adversarial/src/fuzz_bodies.rs | sort)
targets=$(ls fuzz/fuzz_targets | sed 's/\.rs$//' | sort)
bins=$(awk '/^\[\[bin\]\]/{b=1;next} b&&/^name = /{gsub(/name = |"/,"");print;b=0}' fuzz/Cargo.toml | sort)
matrix=$(sed -n 's/^          - \([a-z_0-9]*\)$/\1/p' .github/workflows/fuzz.yml | sort)
[ -n "$bodies" ] || bad "no bodies parsed from fuzz_bodies.rs"
for name in bodies targets bins matrix; do
  [ "$(echo "${!name}" | wc -l)" -eq 7 ] && ok "$name lists 7 names" || bad "$name does not list exactly 7 names: $(echo ${!name})"
done
[ "$bodies" = "$targets" ] && [ "$bodies" = "$bins" ] && [ "$bodies" = "$matrix" ] && ok "bodies == fuzz_targets == [[bin]] == workflow matrix" || bad "name sets differ"
for t in $bodies; do
  grep -q "fuzz_bodies::$t(data)" "fuzz/fuzz_targets/$t.rs" && ok "$t target calls fuzz_bodies::$t" || bad "$t target does not call its body"
  grep -q "path = \"fuzz_targets/$t.rs\"" fuzz/Cargo.toml || bad "$t [[bin]] path wrong"
  [ "$(find fuzz/corpus/$t -type f -name 'seed-*' 2>/dev/null | wc -l)" -ge 1 ] || bad "$t: no seed-* corpus file"
  [ "$(find fuzz/corpus/$t -type f -name 'regress-*' 2>/dev/null | wc -l)" -ge 1 ] || bad "$t: no regress-* corpus file"
done
w=.github/workflows/fuzz.yml
grep -q '^defaults:' $w && grep -q 'shell: bash' $w && ok "workflow sets shell: bash (pipefail)" || bad "workflow lacks defaults.run.shell: bash"
grep -q -- '-max_total_time="\$FUZZ_SECONDS"' $w && ok "duration comes from FUZZ_SECONDS" || bad "max_total_time not bound to FUZZ_SECONDS"
grep -q "default: \"3600\"" $w && grep -q "|| '3600'" $w && ok "default duration is 3600 s" || bad "default duration is not 3600"
grep -q 'assert_fuzz_ran.sh' $w && ok "workflow runs the independent log gate" || bad "log gate missing"
grep -q 'fuzz-crash-' $w && grep -q 'if: failure()' $w && ok "crash artifacts uploaded on failure" || bad "crash artifact upload missing"
grep -q 'needs.fuzz.result' $w && ok "fuzz-gate requires the whole matrix" || bad "fuzz-gate missing"
grep -q 'cargo +nightly fuzz run' $w && grep -q 'channel = "nightly"' fuzz/rust-toolchain.toml && ok "nightly is explicit (workflow + fuzz/rust-toolchain.toml)" || bad "nightly not explicit"
if grep -rn -E '\|\| *true|continue-on-error|set \+e' .github/workflows ci --exclude=check_fuzz_setup.sh >/dev/null 2>&1; then bad "hidden-failure pattern present"; grep -rn -E '\|\| *true|continue-on-error|set \+e' .github/workflows ci --exclude=check_fuzz_setup.sh; else ok "no '|| true' / continue-on-error / set +e in workflows or ci scripts"; fi
[ $fail -eq 0 ] && echo "RESULT: fuzz setup is internally consistent" || echo "RESULT: FUZZ SETUP CHECK FAILED"; exit $fail
