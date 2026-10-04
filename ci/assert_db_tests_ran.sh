#!/usr/bin/env bash
# Gap 6: fail unless every database test actually RAN against a live database.
#
# `cargo test` reports a skipped DB test as plain `ok`. The tests leave an
# outcome marker (see quorum_service/tests/db_pool_concurrency.rs) whose
# content is exactly `ran` only after all assertions passed against Postgres;
# `skipped: ...` and `started` (did not finish) mean it did NOT run. This
# check does not depend on any environment variable being set, so a green
# run with a skipped DB test cannot slip through even if CI is misconfigured.
#
# Usage: ci/assert_db_tests_ran.sh [MARKER_DIR=target/tmp]
set -uo pipefail
dir="${1:-target/tmp}"
shopt -s nullglob
markers=("$dir"/*.outcome)

if [ "${#markers[@]}" -eq 0 ]; then
  echo "FAIL: no DB test outcome markers in $dir (the DB tests did not run at all)" >&2
  exit 1
fi
bad=0
for m in "${markers[@]}"; do
  content="$(cat "$m")"
  if [ "$content" = "ran" ]; then
    echo "ok:   $(basename "$m") => ran"
  else
    echo "FAIL: $(basename "$m") => ${content}" >&2
    bad=1
  fi
done
exit "$bad"
