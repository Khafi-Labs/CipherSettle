# Deployment notes (Gap 10) — PILOT TIER, non-real data only

Status of every statement is labelled. Nothing here has been run on a real host, a
real orchestrator or a real registry.

## Images (UNVERIFIED build; policy EXECUTED statically)
`Dockerfile` builds one image per binary (`--build-arg BIN=quorum_node|quorum_service|quorum_notary`)
on `rust:1.97-slim-bookworm`, runs on `gcr.io/distroless/cc-debian12:nonroot` as UID 65532, exec-form
entrypoint, no shell. `ci/check_dockerfile.sh` enforces the policy (and rejects a bad fixture); the CI
job `container-image` builds all three and checks user / no shell / no key or config files in the
filesystem. That job has never run. Base images are tagged, NOT digest-pinned: pin by digest before any
non-pilot use.

## Run-time hardening to apply (READ: standard options, not yet exercised here)
`--read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory <limit>`;
mount config and keys read-only (`-v node-0.json:/app/config.json:ro`), and give a node ONE writable
volume for its share/audit-log directory. Never bake config, KEKs, shares or API keys into an image.

## Database schema
Versioned migrations (`src/quorum_service/src/migrations.rs`): checksummed, one transaction under an advisory
lock, refuse newer-than-binary and edited-after-applied. Apply as a deploy step with
`quorum_service migrate <db_url>` (the service also applies on start). No down migrations: rollback = restore.

## Backup / restore
* Postgres tier: `ci/backup_restore_rehearsal.sh` (pg_dump -Fc -> pg_restore into an empty DB -> per-table row
  count + content digest -> migrator sees it as current -> negative check). EXECUTED on this sandbox's
  Postgres 16 with 2,000-row tables: backup 0.13 s, restore 0.14 s. That is NOT an RTO for production data.
* Node tier (key share + audit log + group pubkey): back up the node's data directory only while the node is
  stopped (atomic writes protect against crash, not against a copy taken mid-write by a tool that reads
  across two files). The share is envelope-encrypted; the KEK file must be backed up SEPARATELY and never
  alongside the share. Restore = place both back and start: `share_store` verifies and resumes without a
  DKG. The restore of a node has unit-test and adversarial coverage (group P) but has NEVER been rehearsed
  by an operator on a second host.
* Not covered: point-in-time recovery (WAL archiving), cross-version restore, off-site/encrypted backup
  storage, backup retention, a restore done by someone other than the author.

## Secrets from files (Gap 9 slice; EXECUTED tests, no secret-manager integration)
Any of these config fields may be supplied as `<name>_file` (a path) instead of inline: `service_auth_key_file`,
`audit_keypair_file`, `key_der_file`, `client_key_der_file`, `tls_key_der_file`, and `api_keys[].key_file`. The file holds
exactly what the inline `_b64` value would (base64 text; surrounding whitespace is trimmed). Rules, enforced at start:
exactly one source per secret; the file must not be accessible by group/other (chmod 600/400); non-empty; errors name the
field and path but never the value. Mount secrets from your secret manager (Kubernetes secret volume, Vault agent, Docker
secret) at those paths. LIMITS: read once at process start (a rotated secret needs a restart; there is no online rotation);
the value lives in process memory; Kubernetes secret mounts default to mode 0644 so set `defaultMode: 0400`; relative
paths resolve against the process working directory (use absolute paths); `cert_der_b64` fields are public and stay inline.
The KEK file for share encryption (`share_store`) is already a separate 0600 file and is unchanged.

## Operational endpoints (EXECUTED tests, group Z)
* `GET /healthz` — liveness, unauthenticated, always `200 ok` while the process serves HTTP.
* `GET /readyz` — readiness, unauthenticated: `200 ready` only if Postgres answers AND at least t+1 (3 of 5) quorum nodes
  answer a filtered read over the pinned mTLS channel; otherwise `503` (`database unavailable` / `quorum unavailable`, no
  node or address in the body). Result cached 1 s. Reachability, not proof that nodes hold shares.
* `GET /metrics` — Prometheus text, ADMIN API key required (401 without a key, 403 for a non-admin key): audit outbox rows
  by status, age of the oldest undelivered audit, invoices, audit failures. No latency or error-rate series yet.
