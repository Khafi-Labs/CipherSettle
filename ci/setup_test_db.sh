#!/usr/bin/env bash
# Gap 6: single source of truth for the databases the tests need.
# Idempotent. Test-only credentials: quorum_adversarial hard-codes
# `postgres` / `ciphersettle_dev` (finding F-06), so CI and local setups must
# use the same. NEVER reuse these credentials anywhere real.
#
#   ciphersettle_test         quorum_service/tests/db_pool_concurrency.rs
#   ciphersettle_adversarial  quorum_adversarial groups G, J, K
# (Group N creates and drops its own database through the admin connection.)
set -euo pipefail
export PGHOST="${PGHOST:-127.0.0.1}" PGPORT="${PGPORT:-5432}" PGUSER="${PGUSER:-postgres}"
export PGPASSWORD="${PGPASSWORD:-ciphersettle_dev}"

#   ciphersettle_phase3       quorum_orchestrator end-to-end demo (phases 1-3)
for db in ciphersettle_test ciphersettle_adversarial ciphersettle_phase3; do
  if [ "$(psql -tAqc "SELECT 1 FROM pg_database WHERE datname='${db}'" postgres)" = "1" ]; then
    echo "exists:  ${db}"
  else
    psql -qc "CREATE DATABASE ${db}" postgres
    echo "created: ${db}"
  fi
done
