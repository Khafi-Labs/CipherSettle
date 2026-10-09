# Audit reconciler (F-24)

`quorum_service` can run a background audit reconciler. Config keys (JSON config):

- `audit_public_keys`: list of `{id, key_b64}` ed25519 public keys of the quorum nodes (required to enable it).
- `reconcile_interval_secs`: default 60; `0` disables.

Without `audit_public_keys` the reconciler does not start and logs the reason. The reference is the longest prefix whose entries carry at least t+1 verifying co-signatures (F-25). Status per node is exported on `/metrics`; alert on any node that is not `Matches`/`Behind`. Verified by unit tests only; no live multi-host test has been run.
