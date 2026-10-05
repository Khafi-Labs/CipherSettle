#!/usr/bin/env bash
# Gap 17: mechanically verify the documentation claims that CAN be verified.
#   C1 docs/PRODUCTION_READINESS.md row ids are unique
#   C2 every backticked repo path in the maintained docs exists
#   C3 maintained docs name no Rust version other than the pin in rust-toolchain.toml
#   C4 any "N/N checks" adversarial count in maintained docs equals the count CI asserts
#   C5 maintained docs never tell the reader to set the env var nothing reads (TEST_DATABASE_URL)
#   C6 'N (known) advisories accepted' equals the number of ignores in deny.toml
#   C8 every HTTP route registered by quorum_service is documented, and every documented route exists
#   C9 every `cargo ... -p <name>` in docs, scripts and workflows names a package that exists
#   C7 documented id ranges (T-1…T-N, CRYPTO-001…N) match the documents that define them
# "Maintained docs" = root *.md (except the dated roadmap/review), docs/**, deploy/**.
# Historical notes (agent_memory/**, SECURITY_REVIEW.md, the roadmap) are dated records and are NOT checked.
# This does not prove the PROSE is true; it removes the classes of drift a machine can see.
set -uo pipefail
cd "$(dirname "$0")/.."
bad=0; fail() { echo "FAIL: $*"; bad=1; }
mapfile -t DOCS < <(ls README.md CONTRIBUTING.md SECURITY.md PHASE*_README.md VERIFICATION_RUNBOOK.md 2>/dev/null; find docs deploy -name '*.md' 2>/dev/null)

# C1
dups=$(grep -oE '^\| [0-9]+\.[0-9]+ ' docs/PRODUCTION_READINESS.md | sort | uniq -d)
[ -z "$dups" ] || fail "C1 duplicate readiness row ids: $(echo $dups | tr '\n' ' ')"

# C2
for d in "${DOCS[@]}"; do
  while read -r p; do
    p="${p%%[:#]*}"; p="${p%,}"; p="${p%.}"
    case "$p" in *\**|*\<*|*\{*|*\$*) continue;; esac          # globs / placeholders
    [ -e "$p" ] || [ -e "$(dirname "$d")/$p" ] || fail "C2 $d references missing path: $p"
  done < <(grep -oE '`(src|ci|docs|deploy|fuzz|agent_memory|\.github)/[A-Za-z0-9_./-]+`' "$d" | tr -d '`' | sort -u)
done

# C3
pin=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
for d in "${DOCS[@]}"; do
  while read -r v; do
    case "$v" in "$pin"|"$pin".*) ;; *) fail "C3 $d mentions Rust $v but the pin is $pin";; esac
  done < <(grep -oiE '(rust|rustc|toolchain)[ -]+(version )?1\.[0-9]+(\.[0-9]+)?' "$d" | grep -oE '1\.[0-9]+(\.[0-9]+)?' | sort -u)
done

# C4
ci_n=$(grep -oE "[0-9]+/[0-9]+ checks passed" .github/workflows/ci.yml | head -1 | grep -oE '^[0-9]+')
for d in "${DOCS[@]}"; do
  while read -r n; do
    [ "$n" = "$ci_n" ] || fail "C4 $d claims $n adversarial checks but CI asserts $ci_n"
  done < <(grep -oE '[0-9]+/[0-9]+ (adversarial )?checks|[0-9]+ (adversarial )?checks across' "$d" | grep -oE '^[0-9]+' | sort -u)
done

# C5
for d in "${DOCS[@]}"; do
  grep -n 'TEST_DATABASE_URL' "$d" | grep -viE 'nothing reads|no code reads|not read|never read|wrong|said' >/dev/null && fail "C5 $d instructs TEST_DATABASE_URL"
done
# C6
acc=$(bash ci/audit_ignores.sh | grep -c -- '--ignore')
word2n() { case "${1,,}" in one) echo 1;; two) echo 2;; three) echo 3;; four) echo 4;; five) echo 5;; six) echo 6;; seven) echo 7;; eight) echo 8;; nine) echo 9;; ten) echo 10;; [0-9]*) echo "$1";; esac; }
for d in "${DOCS[@]}"; do
  while read -r w; do
    n=$(word2n "$w"); [ "$n" = "$acc" ] || fail "C6 $d says $w accepted advisories but deny.toml ignores $acc"
  done < <(grep -oiE '\b(one|two|three|four|five|six|seven|eight|nine|ten|[0-9]+) (known |knowingly )?(security )?advisories (remain|are) (knowingly )?accepted' "$d" | awk '{print $1}' | sort -u)
done

# C7
tmax=$(grep -oE '^\| T-[0-9]+' docs/security/THREAT_MODEL.md | grep -oE '[0-9]+' | sort -n | tail -1)
cmax=$(grep -oE 'CRYPTO-[0-9]+' docs/cryptography/CRYPTO_DECISIONS.md | grep -oE '[0-9]+' | sort -n | tail -1)
for d in "${DOCS[@]}"; do
  while read -r n; do [ "$n" = "$tmax" ] || fail "C7 $d cites T-1…T-$n but THREAT_MODEL defines up to T-$tmax"; done < <(grep -oE 'T-1…T-[0-9]+' "$d" | grep -oE '[0-9]+$' | sort -u)
  while read -r n; do [ "$((10#$n))" = "$((10#$cmax))" ] || fail "C7 $d cites CRYPTO-001…$n but CRYPTO_DECISIONS defines up to $cmax"; done < <(grep -oE 'CRYPTO-001…CRYPTO-[0-9]+' "$d" | grep -oE '[0-9]+$' | sort -u)
done
# C8
grep -oE '\.route\("[^"]+", *(get|post|delete|put)' src/quorum_service/src/main.rs \
  | sed -E 's/\.route\("([^"]+)", *([a-z]+)/\U\2\E \1/' | sort -u > "${TMPDIR:-/tmp}/routes_code.$$"
grep -ohE '\b(GET|POST|DELETE|PUT) /[A-Za-z0-9_/:.{}-]+' "${DOCS[@]}" 2>/dev/null \
  | sed -E 's/\{[a-z_]+\}/:id/g; s#/:invoice_id#/:id#' | sort -u > "${TMPDIR:-/tmp}/routes_docs.$$"
while read -r r; do grep -qxF "$r" "${TMPDIR:-/tmp}/routes_docs.$$" || fail "C8 route '$r' is registered in quorum_service but documented nowhere"; done < "${TMPDIR:-/tmp}/routes_code.$$"
while read -r r; do grep -qxF "$r" "${TMPDIR:-/tmp}/routes_code.$$" || fail "C8 docs mention route '$r' that quorum_service does not register"; done < "${TMPDIR:-/tmp}/routes_docs.$$"
rm -f "${TMPDIR:-/tmp}/routes_code.$$" "${TMPDIR:-/tmp}/routes_docs.$$"
# C9
while read -r f n; do
  [ -d "src/$n" ] || fail "C9 $f uses 'cargo -p $n' but there is no such package under src/"
done < <(grep -rHoE '(^|[ "])(-p|--package)[ =][a-z_0-9-]+' "${DOCS[@]}" ci .github Dockerfile --exclude=check_docs_claims.sh --exclude=check_docs_claims_selftest.sh 2>/dev/null | sed -E 's/^([^:]+):.*(-p|--package)[ =]([a-z_0-9-]+)$/\1 \3/' | sort -u)
[ $bad -eq 0 ] && echo "docs claims: ok (${#DOCS[@]} maintained docs)"; exit $bad
