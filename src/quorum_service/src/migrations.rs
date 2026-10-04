//! Gap 10: versioned, checksummed, transactional schema migrations.
//!
//! The database schema is an ORDERED LIST of migrations (`MIGRATIONS`), each
//! applied at most once and recorded in `schema_migrations` with the SHA-256
//! of its SQL. Rules enforced at every start (`migrate`):
//!
//! * all pending migrations run in ONE transaction under a Postgres advisory
//!   lock, so concurrent service starts apply each migration exactly once and
//!   a failing migration leaves NO partial DDL behind;
//! * a database whose recorded version is NEWER than this binary knows is
//!   refused (no silent downgrade of a schema newer code may rely on);
//! * an already-applied migration whose SQL has since been edited is refused
//!   (checksum drift): never edit an applied migration, add a new one;
//! * a legacy database created by the pre-Gap-10 idempotent blob is adopted as
//!   version 1 (migration 1 is that blob, unchanged and idempotent), so no
//!   data is touched.
//!
//! Not provided (honest limits): there are no DOWN migrations (rollback is by
//! restoring a backup, see `ci/backup_restore_rehearsal.sh`), and no
//! online/zero-downtime migration strategy: migrations hold locks as Postgres
//! DDL does.

use sha2::{Digest, Sha256};
use tokio_postgres::Client;

#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
}

#[derive(Debug)]
pub enum MigrateError {
    Db(String),
    ChecksumMismatch {
        version: i32,
        name: String,
        recorded: String,
        expected: String,
    },
    DatabaseNewerThanBinary {
        db_version: i32,
        binary_version: i32,
    },
    InvalidMigrationList(String),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrateError::Db(e) => write!(f, "database error during migration: {e}"),
            MigrateError::ChecksumMismatch { version, name, recorded, expected } => write!(
                f,
                "migration {version} ({name}) was edited after it was applied (recorded checksum {recorded}, this binary has {expected}); never edit an applied migration, add a new one"
            ),
            MigrateError::DatabaseNewerThanBinary { db_version, binary_version } => write!(
                f,
                "database schema is at version {db_version} but this binary only knows up to {binary_version}; refusing to run an older binary against a newer schema"
            ),
            MigrateError::InvalidMigrationList(why) => write!(f, "invalid migration list: {why}"),
        }
    }
}

fn db_err(e: tokio_postgres::Error) -> MigrateError {
    // `Display` of a tokio_postgres::Error is only "db error"; the Debug form
    // carries the SQLSTATE and message.
    MigrateError::Db(format!("{e:?}"))
}

/// Arbitrary constant identifying "the ciphersettle schema migration lock".
const MIGRATION_LOCK_KEY: i64 = 0x6369_7068_6572_0001;

pub fn checksum(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_schema",
    sql: V1_INITIAL_SCHEMA,
}];

/// Applies every pending migration of the built-in list. Returns the versions
/// applied by THIS call (empty when the database was already current).
pub async fn migrate(client: &mut Client) -> Result<Vec<i32>, MigrateError> {
    migrate_with(client, MIGRATIONS).await
}

pub async fn migrate_with(
    client: &mut Client,
    migrations: &[Migration],
) -> Result<Vec<i32>, MigrateError> {
    for (i, m) in migrations.iter().enumerate() {
        let want = i32::try_from(i + 1).unwrap_or(i32::MAX);
        if m.version != want {
            return Err(MigrateError::InvalidMigrationList(format!(
                "entry {i} has version {} but versions must be 1..n without gaps",
                m.version
            )));
        }
    }
    let binary_version = migrations.last().map(|m| m.version).unwrap_or(0);

    let tx = client.transaction().await.map_err(db_err)?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(db_err)?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INT PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at_ms BIGINT NOT NULL
        )",
    )
    .await
    .map_err(db_err)?;

    let rows = tx
        .query(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version",
            &[],
        )
        .await
        .map_err(db_err)?;
    let mut db_version = 0i32;
    for r in &rows {
        let version: i32 = r.get(0);
        let name: String = r.get(1);
        let recorded: String = r.get(2);
        db_version = db_version.max(version);
        if version > binary_version {
            continue; // reported below as a whole
        }
        let expected = migrations
            .iter()
            .find(|m| m.version == version)
            .map(|m| checksum(m.sql))
            .unwrap_or_default();
        if recorded != expected {
            return Err(MigrateError::ChecksumMismatch {
                version,
                name,
                recorded,
                expected,
            });
        }
    }
    if db_version > binary_version {
        return Err(MigrateError::DatabaseNewerThanBinary {
            db_version,
            binary_version,
        });
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let mut applied = Vec::new();
    for m in migrations.iter().filter(|m| m.version > db_version) {
        tx.batch_execute(m.sql).await.map_err(db_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at_ms) VALUES ($1, $2, $3, $4)",
            &[&m.version, &m.name, &checksum(m.sql), &now_ms],
        )
        .await
        .map_err(db_err)?;
        applied.push(m.version);
    }
    tx.commit().await.map_err(db_err)?;
    Ok(applied)
}

/// Migration 1 is the pre-Gap-10 schema blob, byte-for-byte and idempotent
/// (`IF NOT EXISTS` everywhere), so a legacy database adopts it as a no-op.
/// DO NOT EDIT: its checksum is recorded in every database that applied it.
const V1_INITIAL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier_hash TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS invoices (
    invoice_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    bank TEXT,
    ciphertext BYTEA,
    status TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    settled_at_ms BIGINT,
    ciphertext_pruned BOOLEAN NOT NULL DEFAULT FALSE,
    -- `ciphersettle_core::InvoiceCommitment::to_bytes()` -- an opaque,
    -- salted commitment blob the caller computed client-side over the
    -- invoice's plaintext fields. This service never sees, and has no
    -- way to see, those fields themselves (see `commitment.rs`'s module
    -- doc comment); it only stores and logs the already-opaque blob,
    -- the same trust boundary it already keeps for `ciphertext`.
    commitment_bytes BYTEA,
    -- Assigned once this row's commitment is appended to the in-process
    -- `MerkleLog` (see `main.rs`'s `AppState::merkle_log`). NULL until
    -- that append happens; see `register_invoice`'s handler for why
    -- those are two separate steps rather than one.
    merkle_leaf_index BIGINT,
    -- Insertion-order tiebreaker used only to rebuild the in-memory
    -- Merkle log in the same order at startup (`created_at_ms` alone
    -- isn't guaranteed unique). Not meaningful on its own.
    merkle_seq BIGSERIAL
);

CREATE TABLE IF NOT EXISTS regulators (
    caller_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS derive_call_times (
    caller_id TEXT NOT NULL,
    called_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_derive_call_times_caller ON derive_call_times (caller_id);

-- Cutover guard (see `enforce_crypto_epoch`): durable key/value markers
-- recording which cryptographic scheme this database's contents belong to.
CREATE TABLE IF NOT EXISTS crypto_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- F-14: transactional outbox for audit events. Every state-changing handler
-- inserts its audit event HERE in the SAME statement/transaction as the state
-- change, so a committed change always has a durable record of the audit
-- obligation. status: pending -> inflight -> done (or back to pending with
-- last_error and a backoff on failure). Delivery to the audit quorum is
-- at-least-once: a crash between the audit append and the `done` update can
-- cause one duplicate audit entry after the stale-claim timeout.
CREATE TABLE IF NOT EXISTS audit_outbox (
    id BIGSERIAL PRIMARY KEY,
    invoice_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp_unix_ms BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at_ms BIGINT NOT NULL,
    claimed_at_ms BIGINT,
    next_attempt_at_ms BIGINT NOT NULL DEFAULT 0,
    done_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_status ON audit_outbox (status, id);

-- F-13: failed audit appends for operations that have NO state change to hold
-- an outbox row (derive-key is fail-closed: the key is denied). Diagnosable
-- record of every such denial.
CREATE TABLE IF NOT EXISTS audit_failures (
    id BIGSERIAL PRIMARY KEY,
    at_ms BIGINT NOT NULL,
    invoice_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    error TEXT NOT NULL
);
"#;
