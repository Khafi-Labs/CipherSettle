# Audit reconciler (F-24)

`quorum_service` can run a background audit reconciler. Config keys (JSON config):

- `audit_public_keys`: list of `{id, key_b64}` ed25519 public keys of the quorum nodes (required to enable it).
- `reconcile_interval_secs`: default 60; `0` disables.

Without `audit_public_keys` the reconciler does not start and logs the reason. The reference is the longest prefix whose entries carry at least t+1 verifying co-signatures (F-25). Status per node is exported on `/metrics`; alert on any node that is not `Matches`/`Behind`. Verified by unit tests only; no live multi-host test has been run.

# Related deploy settings added with F-26 / F-27

- `public_read_endpoints` (default `false`): when false, `GET /audit-log` and `GET /invoices/:id/merkle-proof` need an API key.
- `db_tls_ca_der_b64`: list of base64 DER CA certificates for the database. Required with `?sslmode=require`, which is itself required for any non-loopback database host.
- Test-only: `bash ci/setup_ssl_test_db.sh` creates a throwaway TLS Postgres cluster (port 5433) for the live DB-TLS tests.
