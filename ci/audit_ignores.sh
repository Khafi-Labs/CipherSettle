#!/usr/bin/env bash
# Gap 6: derive `cargo audit --ignore` flags from deny.toml so the two tools
# cannot disagree about which advisories are knowingly accepted (the design
# the roadmap's A9 describes). Only quoted IDs on non-comment lines count, so
# an ID merely mentioned in a justification comment is NOT ignored.
set -euo pipefail
cd "$(dirname "$0")/.."
grep -v '^[[:space:]]*#' deny.toml | grep -o '"RUSTSEC-[0-9]\{4\}-[0-9]\{4\}"' | tr -d '"' | sort -u | sed 's/^/--ignore /'
