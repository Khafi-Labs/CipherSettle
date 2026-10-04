//! Postgres storage layer. Replaces the earlier IC canister prototype's
//! stable-memory `StableBTreeMap`s 1:1 -- same tables an in-canister
//! design would have used if it kept its own schema instead of stable
//! structures. All the *decisions* about what's allowed still come from
//! `ciphersettle_core` (called from `main.rs`'s handlers, unchanged); this
//! module only reads and writes rows.

use tokio_postgres::Client;

pub const SCHEMA_SQL: &str = r#"
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
"#;

/// Identifies the cryptographic scheme the stored invoice ciphertexts were
/// sealed under: blstrs-only BLS12-381, RFC 9380 hash-to-G2 with the
/// `quorum_core::bls::SIG_DST` tag. Keys derived under the earlier
/// `threshold_crypto` scheme do NOT verify or decrypt under this one (the
/// A6 cutover was not backward compatible), so a database written before
/// the cutover must never be silently served by a post-cutover quorum.
/// Bump this string on any future change that invalidates derived keys.
pub const CRYPTO_EPOCH: &str = "blstrs-rfc9380-v1";
const CRYPTO_EPOCH_KEY: &str = "crypto_epoch";

/// What startup should do, given what the database says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochDecision {
    /// Marker already matches: proceed.
    Proceed,
    /// No marker, and it is safe to write one now: write it, then proceed.
    Stamp,
    /// Refuse to start; the string says why and what the operator can do.
    Refuse(String),
}

/// Pure decision rule for the cutover guard (no I/O, so it is unit-tested
/// exhaustively). `invoice_count` is the number of rows already in
/// `invoices`; `acknowledged` is the operator's explicit statement that any
/// existing rows have been purged or re-encrypted under the current scheme.
pub fn decide_crypto_epoch(
    stored: Option<&str>,
    invoice_count: i64,
    expected: &str,
    acknowledged: bool,
) -> EpochDecision {
    match stored {
        Some(s) if s == expected => EpochDecision::Proceed,
        Some(other) => EpochDecision::Refuse(format!(
            "database is stamped with crypto epoch {other:?} but this build is {expected:?}: keys derived \
             under the stamped scheme are not compatible. Migrate or purge the data explicitly; there is \
             deliberately no override for a mismatched marker."
        )),
        None if invoice_count == 0 => EpochDecision::Stamp,
        None if acknowledged => EpochDecision::Stamp,
        None => EpochDecision::Refuse(format!(
            "database holds {invoice_count} invoice(s) but no crypto-epoch marker, so they pre-date the \
             blstrs cutover and their ciphertexts cannot be opened with keys from the current quorum. \
             Purge or re-encrypt them, then set `acknowledge_pre_cutover_data: true` once to stamp the \
             database as {expected:?}."
        )),
    }
}

/// Enforces the cutover guard against a live database. Call once at
/// startup, right after [`init_schema`], and abort startup on `Err`.
pub async fn enforce_crypto_epoch(client: &Client, acknowledged: bool) -> Result<(), String> {
    let stored: Option<String> = client
        .query_opt(
            "SELECT value FROM crypto_meta WHERE key = $1",
            &[&CRYPTO_EPOCH_KEY],
        )
        .await
        .map_err(|e| format!("reading crypto epoch marker failed: {e}"))?
        .map(|row| row.get(0));
    let invoice_count: i64 = client
        .query_one("SELECT COUNT(*) FROM invoices", &[])
        .await
        .map_err(|e| format!("counting invoices failed: {e}"))?
        .get(0);
    match decide_crypto_epoch(stored.as_deref(), invoice_count, CRYPTO_EPOCH, acknowledged) {
        EpochDecision::Proceed => Ok(()),
        EpochDecision::Refuse(why) => Err(why),
        EpochDecision::Stamp => {
            client
                .execute(
                    "INSERT INTO crypto_meta (key, value) VALUES ($1, $2) \
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    &[&CRYPTO_EPOCH_KEY, &CRYPTO_EPOCH],
                )
                .await
                .map_err(|e| format!("writing crypto epoch marker failed: {e}"))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    const E: &str = "blstrs-rfc9380-v1";

    #[test]
    fn matching_marker_proceeds_regardless_of_data() {
        assert_eq!(
            decide_crypto_epoch(Some(E), 0, E, false),
            EpochDecision::Proceed
        );
        assert_eq!(
            decide_crypto_epoch(Some(E), 500, E, false),
            EpochDecision::Proceed
        );
    }

    #[test]
    fn empty_unstamped_database_is_stamped() {
        assert_eq!(decide_crypto_epoch(None, 0, E, false), EpochDecision::Stamp);
    }

    #[test]
    fn unstamped_database_with_invoices_is_refused_without_acknowledgement() {
        assert!(matches!(
            decide_crypto_epoch(None, 1, E, false),
            EpochDecision::Refuse(_)
        ));
    }

    #[test]
    fn acknowledgement_stamps_an_unstamped_database_with_invoices() {
        assert_eq!(decide_crypto_epoch(None, 7, E, true), EpochDecision::Stamp);
    }

    #[test]
    fn mismatched_marker_is_refused_even_when_acknowledged() {
        assert!(matches!(
            decide_crypto_epoch(Some("old-scheme"), 0, E, true),
            EpochDecision::Refuse(_)
        ));
        assert!(matches!(
            decide_crypto_epoch(Some("old-scheme"), 9, E, false),
            EpochDecision::Refuse(_)
        ));
    }
}

#[derive(Debug, Clone)]
pub struct InvoiceRow {
    pub issuer: String,
    pub bank: Option<String>,
    pub status: String, // "active" | "settled"
    pub settled_at_ms: Option<i64>,
    pub ciphertext_pruned: bool,
}

pub async fn init_schema(client: &Client) -> Result<(), tokio_postgres::Error> {
    client.batch_execute(SCHEMA_SQL).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    Inserted,
    NullifierAlreadyClaimed,
    InvoiceIdAlreadyExists,
}

/// Atomically checks nullifier + invoice-id uniqueness and inserts both
/// rows. The nullifier decision itself is delegated to
/// `ciphersettle_core::check_nullifier` UNCHANGED -- this function only
/// supplies the boolean lookup result, exactly the same division of
/// responsibility the earlier canister prototype used against stable memory.
pub async fn register_invoice_tx(
    client: &mut Client,
    invoice_id: &str,
    nullifier_hash: &str,
    issuer: &str,
    ciphertext: &[u8],
    commitment_bytes: &[u8],
    created_at_ms: i64,
) -> Result<RegisterOutcome, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    let null_row = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM nullifiers WHERE nullifier_hash = $1)",
            &[&nullifier_hash],
        )
        .await?;
    let already_claimed: bool = null_row.get(0);
    if ciphersettle_core::check_nullifier(already_claimed).is_err() {
        tx.rollback().await?;
        return Ok(RegisterOutcome::NullifierAlreadyClaimed);
    }
    let inv_row = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM invoices WHERE invoice_id = $1)",
            &[&invoice_id],
        )
        .await?;
    let exists: bool = inv_row.get(0);
    if exists {
        tx.rollback().await?;
        return Ok(RegisterOutcome::InvoiceIdAlreadyExists);
    }
    tx.execute(
        "INSERT INTO nullifiers (nullifier_hash) VALUES ($1)",
        &[&nullifier_hash],
    )
    .await?;
    tx.execute(
        "INSERT INTO invoices (invoice_id, issuer, bank, ciphertext, status, created_at_ms, settled_at_ms, ciphertext_pruned, commitment_bytes) \
         VALUES ($1, $2, NULL, $3, 'active', $4, NULL, false, $5)",
        &[&invoice_id, &issuer, &ciphertext, &created_at_ms, &commitment_bytes],
    )
    .await?;
    tx.commit().await?;
    Ok(RegisterOutcome::Inserted)
}

/// Records the leaf index `MerkleLog::append` assigned this invoice's
/// commitment. A separate step from `register_invoice_tx` deliberately:
/// the DB row (source of truth for "this commitment exists") is
/// committed first, then the in-memory log append happens, then this
/// records where it landed -- see `main.rs`'s `register_invoice` for
/// the ordering rationale and what happens if the process dies between
/// steps.
pub async fn set_merkle_leaf_index(
    client: &Client,
    invoice_id: &str,
    leaf_index: i64,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE invoices SET merkle_leaf_index = $1 WHERE invoice_id = $2",
            &[&leaf_index, &invoice_id],
        )
        .await?;
    Ok(())
}

/// Every invoice with a stored commitment, in the exact order they were
/// originally inserted (`merkle_seq`), so the in-memory `MerkleLog` can
/// be rebuilt identically after a restart -- see `main.rs`'s startup
/// sequence. Rows with no commitment (shouldn't occur once every caller
/// sends one, but tolerated for rows from before this column existed)
/// are skipped rather than appended as a hole in the log.
pub async fn commitments_in_insertion_order(
    client: &Client,
) -> Result<Vec<(String, Vec<u8>)>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT invoice_id, commitment_bytes FROM invoices WHERE commitment_bytes IS NOT NULL ORDER BY merkle_seq ASC",
            &[],
        )
        .await?;
    Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// The commitment bytes and (if already appended) Merkle leaf index for
/// one invoice, for `GET /invoices/:id/merkle-proof`.
pub async fn fetch_commitment(
    client: &Client,
    invoice_id: &str,
) -> Result<Option<(Vec<u8>, Option<i64>)>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT commitment_bytes, merkle_leaf_index FROM invoices WHERE invoice_id = $1",
            &[&invoice_id],
        )
        .await?;
    Ok(row.and_then(|r| {
        let bytes: Option<Vec<u8>> = r.get(0);
        bytes.map(|b| (b, r.get(1)))
    }))
}

pub async fn fetch_invoice(
    client: &Client,
    invoice_id: &str,
) -> Result<Option<InvoiceRow>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT issuer, bank, status, settled_at_ms, ciphertext_pruned FROM invoices WHERE invoice_id = $1",
            &[&invoice_id],
        )
        .await?;
    Ok(row.map(|r| InvoiceRow {
        issuer: r.get(0),
        bank: r.get(1),
        status: r.get(2),
        settled_at_ms: r.get(3),
        ciphertext_pruned: r.get(4),
    }))
}

pub async fn set_bank(
    client: &Client,
    invoice_id: &str,
    bank: Option<&str>,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE invoices SET bank = $1 WHERE invoice_id = $2",
            &[&bank, &invoice_id],
        )
        .await?;
    Ok(())
}

pub async fn mark_settled(
    client: &Client,
    invoice_id: &str,
    settled_at_ms: i64,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE invoices SET status = 'settled', settled_at_ms = $1 WHERE invoice_id = $2",
            &[&settled_at_ms, &invoice_id],
        )
        .await?;
    Ok(())
}

pub async fn prune_ciphertext(
    client: &Client,
    invoice_id: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE invoices SET ciphertext = NULL, ciphertext_pruned = true WHERE invoice_id = $1",
            &[&invoice_id],
        )
        .await?;
    Ok(())
}

pub async fn fetch_regulators(client: &Client) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query("SELECT caller_id FROM regulators", &[])
        .await?;
    Ok(rows.into_iter().map(|r| r.get(0)).collect())
}

pub async fn register_regulator(
    client: &Client,
    caller_id: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO regulators (caller_id) VALUES ($1) ON CONFLICT (caller_id) DO NOTHING",
            &[&caller_id],
        )
        .await?;
    Ok(())
}

/// Returns `false` if the principal wasn't registered (so the caller can
/// turn that into a non-silent-no-op error, matching the original
/// canister's `revoke_regulator` behavior).
pub async fn revoke_regulator(
    client: &Client,
    caller_id: &str,
) -> Result<bool, tokio_postgres::Error> {
    let n = client
        .execute("DELETE FROM regulators WHERE caller_id = $1", &[&caller_id])
        .await?;
    Ok(n > 0)
}

/// Fetches this caller's derive-call timestamps within the trailing
/// window, runs `ciphersettle_core::check_rate_limit` against them
/// UNCHANGED, and if it allows the call, records this call and prunes
/// timestamps outside the window -- the same "record_and_check" shape
/// the earlier canister prototype used against its stable-memory map, just against
/// a Postgres table instead.
///
/// Note the field name mismatch: `RateLimitPolicy::window_nanos` says
/// "nanos" because that's ic_cdk::api::time()'s unit; this service is off
/// the IC and uses milliseconds throughout instead. `check_rate_limit`
/// itself is unit-agnostic (it just compares u64s), so reusing it
/// unchanged is correct as long as every timestamp passed in is
/// consistently milliseconds -- which they are here. Worth a comment,
/// not a code change.
pub async fn record_and_check_rate_limit(
    client: &Client,
    caller_id: &str,
    policy: &ciphersettle_core::RateLimitPolicy,
    now_ms: u64,
) -> Result<Result<(), ciphersettle_core::RateLimitError>, tokio_postgres::Error> {
    let window_start = (now_ms as i64).saturating_sub(policy.window_nanos as i64);
    let rows = client
        .query(
            "SELECT called_at_ms FROM derive_call_times WHERE caller_id = $1 AND called_at_ms >= $2",
            &[&caller_id, &window_start],
        )
        .await?;
    let prior_call_times: Vec<u64> = rows
        .into_iter()
        .map(|r| r.get::<_, i64>(0) as u64)
        .collect();

    let decision = ciphersettle_core::check_rate_limit(policy, &prior_call_times, now_ms);
    if decision.is_ok() {
        client
            .execute(
                "INSERT INTO derive_call_times (caller_id, called_at_ms) VALUES ($1, $2)",
                &[&caller_id, &(now_ms as i64)],
            )
            .await?;
        // Housekeeping: drop this caller's timestamps that are now outside
        // any future window, so the table doesn't grow unboundedly.
        client
            .execute(
                "DELETE FROM derive_call_times WHERE caller_id = $1 AND called_at_ms < $2",
                &[&caller_id, &window_start],
            )
            .await?;
    }
    Ok(decision)
}

/// Exhaustive matrix over every input combination of the cutover guard, kept
/// separate from the `epoch_tests` module above so the matrix's own expected
/// results stay readable in one place. `E` is bound to the real
/// `CRYPTO_EPOCH` rather than a second literal, so this test cannot silently
/// drift out of agreement with the value the guard actually enforces.
#[cfg(test)]
mod decision_matrix_tests {
    use super::*;

    const E: &str = CRYPTO_EPOCH;

    /// Exhaustive matrix over every input combination: the decision is
    /// Proceed iff the marker matches; a stamped-but-different marker is never
    /// stamped over; an unstamped non-empty database is stamped only when acknowledged.
    #[test]
    fn decision_matrix_is_exhaustive_and_never_overwrites_a_foreign_marker() {
        for stored in [None, Some(E), Some("other")] {
            for count in [0i64, 1, 1_000] {
                for ack in [false, true] {
                    let d = decide_crypto_epoch(stored, count, E, ack);
                    match stored {
                        Some(s) if s == E => assert_eq!(d, EpochDecision::Proceed),
                        Some(_) => assert!(
                            matches!(d, EpochDecision::Refuse(_)),
                            "foreign marker overwritten"
                        ),
                        None if count == 0 || ack => assert_eq!(d, EpochDecision::Stamp),
                        None => assert!(matches!(d, EpochDecision::Refuse(_))),
                    }
                }
            }
        }
    }
}
