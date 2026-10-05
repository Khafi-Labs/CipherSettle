#!/usr/bin/env bash
# Gap 17: mechanically verify the documentation claims that CAN be verified.
#   C1 docs/PRODUCTION_READINESS.md row ids are unique
#   C2 every backticked repo path in the maintained docs exists
#   C3 maintained docs name no Rust version other than the pin in rust-toolchain.toml
#   C4 any "N/N checks" adversarial count in maintained docs equals the count CI asserts
#   C5 maintained docs never tell the reader to set the env var nothing reads (TEST_DATABASE_URL)
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
  done < <(grep -oE '[0-9]+/[0-9]+ (adversarial )?checks' "$d" | grep -oE '^[0-9]+' | sort -u)
done

# C5
for d in "${DOCS[@]}"; do
  grep -n 'TEST_DATABASE_URL' "$d" | grep -viE 'nothing reads|no code reads|not read|never read|wrong|said' >/dev/null && fail "C5 $d instructs TEST_DATABASE_URL"
done
[ $bad -eq 0 ] && echo "docs claims: ok (${#DOCS[@]} maintained docs)"; exit $bad
