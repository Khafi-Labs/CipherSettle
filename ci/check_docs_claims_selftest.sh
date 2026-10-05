#!/usr/bin/env bash
# Proves ci/check_docs_claims.sh can FAIL: builds a tiny broken repo and requires
# every check class (C1..C5) to fire, and a clean repo to pass.
set -uo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/ci" "$T/docs" "$T/.github/workflows" "$T/src"
cp ci/check_docs_claims.sh ci/audit_ignores.sh deny.toml "$T/ci/" 2>/dev/null; cp deny.toml "$T/"; mkdir -p "$T/docs/security" "$T/docs/cryptography"
printf "| T-1 | a |\n| T-2 | b |\n" > "$T/docs/security/THREAT_MODEL.md"
printf "CRYPTO-001\nCRYPTO-002\n" > "$T/docs/cryptography/CRYPTO_DECISIONS.md"
printf '[toolchain]\nchannel = "1.97"\n' > "$T/rust-toolchain.toml"
printf 'checks:\n  - run: grep "80/80 checks passed"\n' > "$T/.github/workflows/ci.yml"
printf '# ok\nSee `src/exists.rs`. Built with Rust 1.97. 80/80 checks. Threat table T-1…T-2, CRYPTO-001…CRYPTO-002.\n' > "$T/README.md"
printf '| 1.1 | a |\n| 1.2 | b |\n' > "$T/docs/PRODUCTION_READINESS.md"
touch "$T/src/exists.rs"
mkdir -p "$T/src/quorum_service/src"
printf 'let app = Router::new().route("/known", get(h));\n' > "$T/src/quorum_service/src/main.rs"
printf "GET /known\n" >> "$T/README.md"
( cd "$T" && bash ci/check_docs_claims.sh >/dev/null 2>&1 ) && echo "  ok:   clean mini-repo passes" || { echo "  FAIL: clean mini-repo was rejected"; exit 1; }
printf '| 1.1 | a |\n| 1.1 | dup |\n' > "$T/docs/PRODUCTION_READINESS.md"
printf 'let app = Router::new().route("/known", get(h)).route("/secret-undocumented", post(h));\n' > "$T/src/quorum_service/src/main.rs"
printf '# bad\nSee `src/missing.rs`. Rust 1.75 is required. 41/41 checks pass. Set TEST_DATABASE_URL. Seven advisories are knowingly accepted. Run cargo build -p not_a_crate. GET /ghost-route is documented. See T-1…T-9 and CRYPTO-001…CRYPTO-009.\n' > "$T/README.md"
out=$( cd "$T" && bash ci/check_docs_claims.sh 2>&1 ); rc=$?
fail=0
[ $rc -ne 0 ] && echo "  ok:   broken mini-repo is rejected (rc=$rc)" || { echo "  FAIL: broken repo passed"; fail=1; }
for c in C1 C2 C3 C4 C5 C6 C7 C8 C9; do
  grep -q "FAIL: $c" <<<"$out" && echo "  ok:   $c fired" || { echo "  FAIL: $c did not fire"; fail=1; }
done
exit $fail
