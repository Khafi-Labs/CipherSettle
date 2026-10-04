#!/usr/bin/env bash
# Audit findings A3 (step 4 of its implementation plan) and A9 (CI must
# enforce dependency-pin hygiene going forward): fails if any Cargo.toml
# in the tree contains an exact-version pin (`dep = "=x.y.z"` or
# `dep = { version = "=x.y.z", ... }`) that isn't immediately preceded by
# an explanatory `#` comment.
#
# This isn't stylistic. A3 exists because this workspace accumulated
# hard `=` pins (to work around the rustc-1.75-vs-edition2024 toolchain
# wall -- see A6) and, in three of the eleven crates that carry one,
# nobody wrote down *why* next to the pin. An exact pin with no stated
# reason is indistinguishable, six months later, from "someone forgot to
# unpin this" versus "this is load-bearing, do not touch" -- which is
# exactly the ambiguity that lets a pin quietly sit behind a since-patched
# CVE (A3's actual finding) without anyone noticing it was safe to lift.
# A dated, reasoned comment is cheap; re-deriving the reason from git
# blame during an incident is not.
#
# Run from the repository root: ci/check_pin_policy.sh
set -euo pipefail

fail=0

while IFS= read -r -d '' manifest; do
  if ! awk -v file="$manifest" '
    function is_pin_line(line) {
      return (line ~ /=[[:space:]]*"=[0-9]/) || (line ~ /version[[:space:]]*=[[:space:]]*"=[0-9]/)
    }
    function is_comment(line,    t) {
      t = line
      gsub(/^[[:space:]]+/, "", t)
      return t ~ /^#/
    }
    function is_blank(line,    t) {
      t = line
      gsub(/[[:space:]]/, "", t)
      return t == ""
    }
    { lines[NR] = $0 }
    END {
      found = 0
      for (i = 1; i <= NR; i++) {
        if (!is_pin_line(lines[i])) continue
        # Only check the first pin line of a contiguous run (a shared
        # comment above a multi-crate pin block, e.g. zeroize +
        # zeroize_derive together, is fine) -- find the nearest
        # non-blank line above this one.
        p = i - 1
        while (p >= 1 && is_blank(lines[p])) p--
        if (p >= 1 && is_pin_line(lines[p])) continue
        if (p < 1 || !is_comment(lines[p])) {
          print file ":" i ": exact-version pin with no explanatory comment directly above it -- " lines[i]
          found = 1
        }
      }
      exit found
    }
  ' "$manifest"; then
    fail=1
  fi
done < <(find . -name Cargo.toml -not -path "*/target/*" -print0)

if [ "$fail" -ne 0 ]; then
  echo
  echo "One or more exact-version dependency pins have no explanatory comment directly above them."
  echo "Add a '#' comment stating why the pin exists (e.g. \"pinned pending A6's toolchain-wall"
  echo "removal, see A3\") immediately above it before merging."
  exit 1
fi

echo "OK: every exact-version dependency pin has an explanatory comment above it."
