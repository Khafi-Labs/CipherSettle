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
