//! Phase 3 of the threshold-quorum roadmap: the product API, ported from
//! the earlier IC canister prototype (`ciphersettle_backend`, an
//! `ic-cdk` + vetKD canister, since deleted -- see finding A14 of the
//! audit remediation roadmap) onto a plain REST service backed by
//! Postgres, with `derive_invoice_key` brokered against the Phase 1 quorum
//! instead of a vetKD call, and every state-changing action logged
//! through the Phase 2 tamper-evident audit log instead of an in-canister
//! `Vec<AuditEvent>`.
//!
//! `ciphersettle_core`'s decision functions (`resolve_access`,
//! `check_rate_limit`, `check_payload_size`, `check_nullifier`,
//! `audit_action_for`) are called UNCHANGED -- exactly the roadmap's
//! instruction. Only the storage (Postgres instead of stable memory), the
//! caller-identity source (an API key instead of `candid::Principal`), and
//! the derive mechanism (the quorum instead of vetKD) have changed.
//!
//! ## API surface (mirrors the original `.did` 1:1 where possible)
//! - `POST   /invoices`                  -- register_invoice
//! - `POST   /invoices/:id/grant`        -- grant_settlement_access
//! - `POST   /invoices/:id/revoke`       -- revoke_settlement_access
//! - `POST   /invoices/:id/settle`       -- mark_settled
//! - `POST   /invoices/:id/prune`        -- prune_ciphertext
//! - `POST   /invoices/:id/derive-key`   -- derive_invoice_key
//! - `GET    /audit-log?invoice_id=...`  -- get_audit_log (public)
//! - `POST   /regulators`                -- register_regulator (admin)
//! - `DELETE /regulators/:id`            -- revoke_regulator (admin)
//!
//! ## Named gaps (see PHASE3_README.md for the full list, and the audit
//! remediation roadmap for what's been closed since)
//! - ~~This HTTP API is plaintext, not TLS-terminated...~~ Fixed (audit
//!   finding A5): see `tls_serve`'s module doc. `main` refuses to bind
//!   to anything off loopback without `tls_cert_der_b64`/
//!   `tls_key_der_b64` configured; loopback-only plaintext (the shape
//!   every existing test/demo config already used) still works
//!   unchanged.
//! - ~~`db`'s single `Mutex<Client>`...~~ Fixed (audit finding A10): `db`
//!   is now a real `deadpool-postgres` pool; see `db.rs`'s module doc for
//!   what each query looks like.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
mod config;
mod db;
mod error;
mod http_metrics;
mod migrations;
mod tls_serve;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use config::ServiceConfig;
use error::ApiError;
use quorum_client::collect_sealed_derived_key;
use quorum_core::config::{fatal, or_fatal};
use quorum_core::PublicKeySet;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsConnector;

/// One configured API key, held only as its SHA-256 digest -- see
/// `authenticate` below (audit finding A15). Never construct this from
/// anything other than `ApiKeyEntry::new`, so the raw key never ends up
/// on `AppState` by accident.
struct ApiKeyEntry {
    key_hash: [u8; 32],
    caller_id: String,
}

impl ApiKeyEntry {
    fn new(raw_key: &str, caller_id: String) -> Self {
        Self {
            key_hash: hash_api_key(raw_key),
            caller_id,
        }
    }
}

fn hash_api_key(raw_key: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hasher.finalize().into()
}

struct AppState {
    /// Gap 11: per-route request/error/latency series (see `http_metrics`).
    http_metrics: Arc<http_metrics::HttpMetrics>,
    /// Audit finding A10: previously a single `Mutex<tokio_postgres::Client>`,
    /// which serializes every database operation across every concurrent
    /// request regardless of whether they touch the same rows. Replaced with
    /// a real pool; each handler below checks out its own connection for
    /// the duration of the request.
    db: deadpool_postgres::Pool,
    /// Audit finding A15: previously `HashMap<String, String>` holding raw
    /// API keys in plaintext for the lifetime of the process. Now only
    /// SHA-256 digests are held; see `authenticate` for the accompanying
    /// constant-time comparison.
    api_keys: Vec<ApiKeyEntry>,
    admin_caller_id: String,
    connector: TlsConnector,
    service_auth_key: Vec<u8>,
    quorum_nodes: Vec<(usize, String)>,
    threshold: usize,
    /// Loaded at startup and cross-checked implicitly (every quorum node
    /// publishes the same file; a mismatch would mean this service is
    /// pointed at the wrong quorum) but no longer read by any handler as
    /// of the Finding 2.3 fix: `derive_invoice_key` now only collects and
    /// combines *sealed* shares (`collect_sealed_derived_key`), and
    /// verifying the final result against this key is the true end
    /// caller's job (`open_sealed_derived_key`), not this broker's --
    /// this service must never be in a position to check a plaintext
    /// signature, because it must never hold one. Kept on `AppState`
    /// rather than deleted: a future admin/introspection endpoint (e.g.
    /// "what's this deployment's group public key") would want it.
    /// Now read by `derive_invoice_key` -- but only to verify each node's
    /// NIZK against its public key share (public data). The service still
    /// never holds a plaintext signature or anything that opens a sealed one.
    group_pks: PublicKeySet,
    /// `Require` unless the test-only `insecure_skip_share_proofs` is set.
    proof_policy: quorum_client::ProofPolicy,
    max_ciphertext_bytes: usize,
    ciphertext_retention_ms: u64,
    derive_rate_limit: ciphersettle_core::RateLimitPolicy,
    /// Phase 6a follow-through: every registered invoice's
    /// `InvoiceCommitment` bytes, appended in insertion order. In-memory
    /// only -- rebuilt at startup from `db::commitments_in_insertion_order`
    /// (see `main`), not itself persisted. As `merkle.rs`'s own doc
    /// comment insists: this log's root is signed by nobody but this
    /// process, so it is NOT wired into any access-control decision
    /// (`resolve_access`, `derive_invoice_key`) anywhere in this
    /// service -- it exists only for batching, storage efficiency, and
    /// tamper-evident audit history, per that module's "what this is
    /// not" section. A `Mutex` (not `RwLock`): appends are the only
    /// operation that matters for correctness here, reads are cheap and
    /// infrequent, and a plain mutex is simpler to reason about than a
    /// reader/writer lock for that access pattern.
    merkle_log: tokio::sync::Mutex<ciphersettle_core::MerkleLog>,
    /// F-13: serializes audit appends so this process is a single proposer
    /// (never held together with a DB connection or transaction).
    audit_lock: tokio::sync::Mutex<()>,
    /// Gap 11: last `/readyz` quorum-reachability result and when it was taken,
    /// so an unauthenticated endpoint cannot be used to make this service open
    /// a TLS connection to every node on every request.
    ready_cache: tokio::sync::Mutex<Option<(std::time::Instant, bool)>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Audit finding A15: this used to be a direct `HashMap::get(key)` lookup
/// on the raw, plaintext-stored key -- not a documented constant-time
/// guarantee. It now compares SHA-256 digests via `subtle::ConstantTimeEq`
/// against every configured key, with no early exit, so the check's
/// running time depends only on the fixed, public number of configured
/// keys, never on how many leading bytes of a guess happened to match or
/// on which entry (if any) matched. This is intentionally a simple linear
/// scan: adequate for "a handful of integrators" per the audit's own
/// framing (see PHASE_ROADMAP.md / the audit-remediation notes) -- migrate
/// to a proper API-key/OAuth layer if the number of integrators grows past
/// that.
/// The comparison itself, factored out so it's testable without needing a
/// full `AppState` (which requires a live Postgres connection to
/// construct). See `authenticate` for how this is used against a real
/// request.
fn find_caller_id_constant_time(
    presented_hash: &[u8; 32],
    api_keys: &[ApiKeyEntry],
) -> Option<String> {
    use subtle::ConstantTimeEq;

    let mut found_caller_id: Option<String> = None;
    for entry in api_keys {
        if bool::from(presented_hash.ct_eq(&entry.key_hash)) {
            found_caller_id = Some(entry.caller_id.clone());
            // No `break`: every entry is always compared, so the loop's
            // cost doesn't depend on where (or whether) a match occurred.
        }
    }
    found_caller_id
}

fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<String, ApiError> {
    let header = headers.get("authorization").ok_or(ApiError::Unauthorized)?;
    let value = header.to_str().map_err(|_| ApiError::Unauthorized)?;
    let key = value
        .strip_prefix("Bearer ")
        .ok_or(ApiError::Unauthorized)?;
    let presented_hash = hash_api_key(key);
    find_caller_id_constant_time(&presented_hash, &state.api_keys).ok_or(ApiError::Unauthorized)
}

#[cfg(test)]
mod api_key_auth_tests {
    use super::*;

    fn keys() -> Vec<ApiKeyEntry> {
        vec![
            ApiKeyEntry::new("alpha-bank-key", "alpha-bank".to_string()),
            ApiKeyEntry::new("beta-factor-key", "beta-factor".to_string()),
        ]
    }

    #[test]
    fn correct_key_resolves_to_its_caller_id() {
        let hash = hash_api_key("alpha-bank-key");
        assert_eq!(
            find_caller_id_constant_time(&hash, &keys()),
            Some("alpha-bank".to_string())
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let hash = hash_api_key("not-a-real-key");
        assert_eq!(find_caller_id_constant_time(&hash, &keys()), None);
    }

    #[test]
    fn near_miss_key_sharing_a_long_prefix_is_still_rejected() {
        // Regression guard: a naive byte-by-byte compare would short-circuit
        // fast on this near-miss versus a totally different guess. We can't
        // directly assert timing in a unit test, but we can at least assert
        // correctness of the constant-time path doesn't accidentally match.
        let real = ApiKeyEntry::new("alpha-bank-key-0000000000", "alpha-bank".to_string());
        let near_miss_hash = hash_api_key("alpha-bank-key-0000000001");
        assert_eq!(find_caller_id_constant_time(&near_miss_hash, &[real]), None);
    }

    #[test]
    fn raw_key_is_never_recoverable_from_the_stored_entry() {
        let entry = ApiKeyEntry::new("super-secret-value", "someone".to_string());
        // The only field is the digest; there is no way to get the raw
        // key back out of an ApiKeyEntry short of a preimage attack on
        // SHA-256. This test exists mainly to document that invariant.
        assert_eq!(entry.key_hash.len(), 32);
        assert_ne!(entry.key_hash.to_vec(), b"super-secret-value".to_vec());
    }

    #[test]
    fn empty_key_list_rejects_everything() {
        let hash = hash_api_key("anything");
        assert_eq!(find_caller_id_constant_time(&hash, &[]), None);
    }
}

/// Appends one event to the audit quorum, serialized through
/// `AppState::audit_lock` so this process is never two concurrent proposers
/// (F-13: concurrent proposers can split the quorum's votes). The lock is held
/// across the network append but NEVER together with a DB connection or
/// transaction (F-14: no DB <-> audit wait cycle). The retry budget and vote
/// TTL are not widened; failure is typed and the caller records it.
async fn append_audit_locked(
    state: &AppState,
    event: quorum_audit::AuditEvent,
) -> Result<(), quorum_client::ProposeError> {
    quorum_client::propose_audit_entry(
        &state.connector,
        &state.quorum_nodes,
        state.threshold,
        event,
    )
    .await
    .map(|_| ())
}

/// Audit for an operation with NO state change (derive-key). Fail-closed:
/// on failure the caller is denied (503) and the failure is recorded in
/// `audit_failures` (best effort) and logged.
async fn log_audit_event(
    state: &AppState,
    invoice_id: &str,
    actor: &str,
    action: &str,
) -> Result<(), ApiError> {
    let event = quorum_audit::AuditEvent {
        invoice_id: invoice_id.to_string(),
        actor: actor.to_string(),
        action: action.to_string(),
        timestamp_unix_ms: now_ms(),
    };
    let result = {
        let _guard = state.audit_lock.lock().await;
        append_audit_locked(state, event).await
    };
    if let Err(e) = result {
        let msg = e.to_string();
        eprintln!("[service] AUDIT FAILURE (denied, fail-closed) action={action} invoice={invoice_id}: {msg}");
        if let Ok(client) = state.db.get().await {
            let _ =
                db::record_audit_failure(&client, now_ms() as i64, invoice_id, actor, action, &msg)
                    .await;
        }
        return Err(ApiError::AuditUnavailable(format!(
            "audit log unavailable, request denied: {msg}"
        )));
    }
    Ok(())
}

/// Backoff before the background drainer retries a failed outbox row.
fn outbox_backoff_ms(attempts: i32) -> i64 {
    let exp = attempts.clamp(1, 5) as u32;
    (1_000i64 << exp).min(30_000)
}

/// Delivers one claimed outbox row. Caller holds `audit_lock`. No DB
/// connection is held across the append.
async fn deliver_outbox_row(state: &AppState, row: db::OutboxRow) -> Result<(), String> {
    let event = quorum_audit::AuditEvent {
        invoice_id: row.invoice_id.clone(),
        actor: row.actor.clone(),
        action: row.action.clone(),
        timestamp_unix_ms: row.timestamp_ms as u64,
    };
    match append_audit_locked(state, event).await {
        Ok(()) => {
            match state.db.get().await {
                Ok(client) => {
                    if let Err(e) = db::outbox_mark_done(&client, row.id, now_ms() as i64).await {
                        eprintln!("[service] outbox {} appended but mark-done failed (will be re-delivered after the stale-claim timeout; at-least-once): {e}", row.id);
                    }
                }
                Err(e) => eprintln!(
                    "[service] outbox {} appended but no db connection to mark done: {e}",
                    row.id
                ),
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            eprintln!(
                "[service] AUDIT PENDING outbox_id={} action={} invoice={} attempts={}: {msg}",
                row.id, row.action, row.invoice_id, row.attempts
            );
            let next = now_ms() as i64 + outbox_backoff_ms(row.attempts);
            if let Ok(client) = state.db.get().await {
                let _ = db::outbox_mark_failed(&client, row.id, &msg, next).await;
            }
            Err(msg)
        }
    }
}

/// Inline delivery attempt for the outbox row a handler just committed. If it
/// cannot be delivered now the state change STANDS and the caller gets an
/// explicit 202 `audit: pending` (never a bare 500 after a committed change).
async fn audit_outbox_commit(state: &AppState, outbox_id: i64) -> Result<(), ApiError> {
    let _guard = state.audit_lock.lock().await;
    let claimed = {
        let client = state
            .db
            .get()
            .await
            .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
        db::outbox_claim(&client, now_ms() as i64, Some(outbox_id)).await?
    };
    match claimed {
        Some(row) => deliver_outbox_row(state, row)
            .await
            .map_err(|detail| ApiError::AuditPending { outbox_id, detail }),
        None => {
            // Already delivered (e.g. by the background drainer while we
            // waited for the lock) or being handled elsewhere.
            let client = state
                .db
                .get()
                .await
                .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
            match db::outbox_status(&client, outbox_id).await?.as_deref() {
                Some("done") => Ok(()),
                _ => Err(ApiError::AuditPending {
                    outbox_id,
                    detail: "queued; delivery in progress".to_string(),
                }),
            }
        }
    }
}

/// Background delivery of outbox rows whose inline attempt failed (or whose
/// process crashed). Single in-process proposer, shared lock with the request
/// path. Runs for the life of the process.
async fn audit_outbox_drainer(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _guard = state.audit_lock.lock().await;
        let claimed = match state.db.get().await {
            Ok(client) => db::outbox_claim(&client, now_ms() as i64, None).await,
            Err(e) => {
                eprintln!("[service] outbox drainer: no db connection: {e}");
                continue;
            }
        };
        match claimed {
            Ok(Some(row)) => {
                let _ = deliver_outbox_row(&state, row).await;
            }
            Ok(None) => {}
            Err(e) => eprintln!("[service] outbox drainer: claim failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------
// register_invoice
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterInvoiceReq {
    invoice_id: String,
    nullifier_hash: String,
    ciphertext_b64: String,
    /// Base64 of `ciphersettle_core::InvoiceCommitment::to_bytes()` --
    /// version + salt + hash, computed by the caller against the
    /// invoice's own plaintext fields (`InvoiceFields`), which this
    /// service never receives and never needs to. This service treats
    /// the decoded bytes as opaque except to check their length and
    /// version tag; see `commitment.rs`'s module doc comment for why
    /// verifying a commitment is the caller's job, not this service's.
    commitment_b64: String,
}

#[derive(Serialize)]
struct RegisterInvoiceResp {
    invoice_id: String,
    /// This invoice commitment's position in the append-only Merkle
    /// log, for later use with `GET /invoices/:id/merkle-proof`.
    merkle_leaf_index: u64,
    /// The log's root immediately after this append, hex-encoded. Not
    /// signed by anything external yet -- see `AppState::merkle_log`'s
    /// doc comment on why this is audit evidence, not an authorization
    /// input.
    merkle_root_hex: String,
}

/// Gap 11: liveness. No auth, no state, no secrets: "the process is serving HTTP".
/// Gap 11: Prometheus metrics, ADMIN-ONLY (operational data about audit
/// backlog; scrape with the admin API key as a bearer token). Database-derived
/// gauges plus the per-route HTTP request/error/latency series from
/// `http_metrics` (matched route patterns only, bounded cardinality).
async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<
    (
        StatusCode,
        [(axum::http::header::HeaderName, &'static str); 1],
        String,
    ),
    ApiError,
> {
    let caller_id = authenticate(&headers, &state)?;
    if caller_id != state.admin_caller_id {
        return Err(ApiError::Forbidden(
            "only the admin can read metrics".to_string(),
        ));
    }
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let snap = db::metrics_snapshot(&client)
        .await
        .map_err(|e| ApiError::Internal(format!("metrics query failed: {e}")))?;
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        format!(
            "{}{}",
            db::render_metrics(&snap, now),
            state.http_metrics.render()
        ),
    ))
}

async fn healthz() -> &'static str {
    "ok"
}

/// Gap 11: readiness. 200 only if a database connection can be checked out and
/// answers a trivial query; otherwise 503 with a fixed, non-sensitive body
/// (the underlying error is deliberately not echoed).
/// How long a quorum-reachability result is reused by `/readyz`.
const READY_CACHE_TTL: Duration = Duration::from_secs(1);

/// True when at least `threshold + 1` quorum nodes answer a cheap, filtered
/// read over the pinned mTLS channel. This proves reachability and a protocol
/// response, NOT that a node holds a share or is `Ready` (a node still in DKG
/// also answers); it is the strongest cheap signal the node protocol offers.
async fn quorum_reachable(state: &AppState) -> bool {
    let needed = state.threshold + 1;
    let mut probes = tokio::task::JoinSet::new();
    for (_, addr) in state.quorum_nodes.iter() {
        let addr = addr.clone();
        let connector = state.connector.clone();
        probes.spawn(async move {
            matches!(
                quorum_client::send_request_with_timeout(
                    &connector,
                    &addr,
                    &quorum_core::Message::GetAuditLog {
                        invoice_id: Some("__readyz_probe__".to_string()),
                    },
                    Duration::from_secs(1),
                )
                .await,
                Some(quorum_core::Message::AuditLogEntries { .. })
            )
        });
    }
    let mut up = 0usize;
    while let Some(r) = probes.join_next().await {
        if matches!(r, Ok(true)) {
            up += 1;
        }
    }
    up >= needed
}

async fn readyz(State(state): State<Arc<AppState>>) -> (StatusCode, &'static str) {
    let db_ok = match state.db.get().await {
        Ok(client) => client.simple_query("SELECT 1").await.is_ok(),
        Err(_) => false,
    };
    if !db_ok {
        return (StatusCode::SERVICE_UNAVAILABLE, "database unavailable");
    }
    let mut cache = state.ready_cache.lock().await;
    let quorum_ok = match *cache {
        Some((at, ok)) if at.elapsed() < READY_CACHE_TTL => ok,
        _ => {
            let ok = quorum_reachable(&state).await;
            *cache = Some((std::time::Instant::now(), ok));
            ok
        }
    };
    if quorum_ok {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "quorum unavailable")
    }
}

async fn register_invoice(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterInvoiceReq>,
) -> Result<(StatusCode, Json<RegisterInvoiceResp>), ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    let ciphertext = b64_decode_request_field(&req.ciphertext_b64)
        .map_err(|e| ApiError::BadRequest(format!("ciphertext_b64: invalid base64: {e}")))?;

    ciphersettle_core::check_payload_size(ciphertext.len(), state.max_ciphertext_bytes)
        .map_err(ApiError::BadRequest)?;

    let commitment_bytes = b64_decode_request_field(&req.commitment_b64)
        .map_err(|e| ApiError::BadRequest(format!("commitment_b64: invalid base64: {e}")))?;
    // Validates length and version tag without needing the plaintext
    // fields this service never has -- `InvoiceCommitment::from_bytes`
    // requires an exact-size array, so this is also where a
    // malformed/truncated commitment gets rejected as 400 rather than
    // silently stored as garbage the log would faithfully commit to.
    let commitment_array: [u8; 65] = commitment_bytes.clone().try_into().map_err(|_| {
        ApiError::BadRequest(
            "commitment_b64: expected exactly 65 bytes (version + 32-byte salt + 32-byte hash)"
                .to_string(),
        )
    })?;
    ciphersettle_core::InvoiceCommitment::from_bytes(&commitment_array)
        .map_err(ApiError::BadRequest)?;

    let mut client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let outcome = db::register_invoice_tx(
        &mut client,
        &req.invoice_id,
        &req.nullifier_hash,
        &caller_id,
        &ciphertext,
        &commitment_bytes,
        now_ms() as i64,
    )
    .await?;

    let outbox_id = match outcome {
        db::RegisterOutcome::Inserted(id) => id,
        db::RegisterOutcome::NullifierAlreadyClaimed => {
            drop(client);
            return Err(ApiError::Conflict("nullifier already registered (replay/idempotency check — not a double-financing determination)".to_string()));
        }
        db::RegisterOutcome::InvoiceIdAlreadyExists => {
            drop(client);
            return Err(ApiError::Conflict("invoice_id already exists".to_string()));
        }
    };

    // The DB row (source of truth that this commitment exists) is
    // already committed at this point. The in-memory log append and
    // the row's `merkle_leaf_index` update happen after -- if the
    // process crashes in between, the next startup's
    // `commitments_in_insertion_order` rebuild still appends this row
    // (ordered by `merkle_seq`, assigned at insert time) exactly once,
    // so no leaf is duplicated or lost; the only externally-visible
    // effect of a crash right here is that this one response never
    // arrives, which is the same failure mode this endpoint already
    // had for e.g. a crash right after `tx.commit()` and before the
    // response is written.
    let (leaf_index, root) = {
        let mut log = state.merkle_log.lock().await;
        let leaf_index = log.append(&commitment_bytes);
        let root = log.root().ok_or_else(|| {
            ApiError::Internal("merkle log empty immediately after an append".to_string())
        })?;
        (leaf_index, root)
    };
    db::set_merkle_leaf_index(&client, &req.invoice_id, leaf_index as i64).await?;
    drop(client);

    audit_outbox_commit(&state, outbox_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterInvoiceResp {
            invoice_id: req.invoice_id,
            merkle_leaf_index: leaf_index,
            merkle_root_hex: hex_encode(&root),
        }),
    ))
}

// ---------------------------------------------------------------------
// grant_settlement_access
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct GrantReq {
    bank: String,
}

async fn grant_settlement_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
    Json(req): Json<GrantReq>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let invoice = db::fetch_invoice(&client, &invoice_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("invoice not found".to_string()))?;
    if invoice.issuer != caller_id {
        return Err(ApiError::Forbidden(
            "only the issuer can grant settlement access".to_string(),
        ));
    }
    let outbox_id = db::set_bank(
        &client,
        &invoice_id,
        Some(&req.bank),
        &db::AuditIntent {
            invoice_id: &invoice_id,
            actor: &caller_id,
            action: "settlement_access_granted",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------
// revoke_settlement_access
// ---------------------------------------------------------------------

async fn revoke_settlement_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let invoice = db::fetch_invoice(&client, &invoice_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("invoice not found".to_string()))?;
    if invoice.issuer != caller_id {
        return Err(ApiError::Forbidden(
            "only the issuer can revoke settlement access".to_string(),
        ));
    }
    if invoice.bank.is_none() {
        return Err(ApiError::Conflict(
            "no settlement access is currently granted for this invoice".to_string(),
        ));
    }
    let outbox_id = db::set_bank(
        &client,
        &invoice_id,
        None,
        &db::AuditIntent {
            invoice_id: &invoice_id,
            actor: &caller_id,
            action: "settlement_access_revoked",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------
// mark_settled
// ---------------------------------------------------------------------

async fn mark_settled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let invoice = db::fetch_invoice(&client, &invoice_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("invoice not found".to_string()))?;
    let is_participant =
        invoice.issuer == caller_id || invoice.bank.as_deref() == Some(caller_id.as_str());
    if !is_participant {
        return Err(ApiError::Forbidden(
            "only the issuer or the granted bank can mark an invoice settled".to_string(),
        ));
    }
    if invoice.status == "settled" {
        return Err(ApiError::Conflict("invoice is already settled".to_string()));
    }
    let outbox_id = db::mark_settled(
        &client,
        &invoice_id,
        now_ms() as i64,
        &db::AuditIntent {
            invoice_id: &invoice_id,
            actor: &caller_id,
            action: "invoice_settled",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------
// prune_ciphertext -- callable by anyone, gated only by eligibility,
// exactly matching the original canister's documented design choice.
// ---------------------------------------------------------------------

async fn prune_ciphertext(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let invoice = db::fetch_invoice(&client, &invoice_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("invoice not found".to_string()))?;
    if invoice.ciphertext_pruned {
        return Err(ApiError::Conflict(
            "ciphertext already pruned for this invoice".to_string(),
        ));
    }
    let eligible = invoice.status == "settled"
        && invoice
            .settled_at_ms
            .map(|settled_at| {
                (now_ms() as i64).saturating_sub(settled_at) >= state.ciphertext_retention_ms as i64
            })
            .unwrap_or(false);
    if !eligible {
        return Err(ApiError::Conflict(
            "invoice is not yet eligible for pruning (must be settled and past the retention window)".to_string(),
        ));
    }
    let outbox_id = db::prune_ciphertext(
        &client,
        &invoice_id,
        &db::AuditIntent {
            invoice_id: &invoice_id,
            actor: &caller_id,
            action: "ciphertext_pruned",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------
// derive_invoice_key
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct DeriveReq {
    /// Required as of the Finding 2.3 fix: the caller's transport public
    /// key, base64-encoded compressed G2 point (`quorum_vetseal::
    /// TransportPublicKey::to_bytes`). The matching secret key MUST be
    /// generated and held by the true end caller (browser/CLI) and MUST
    /// NEVER be sent to this service -- this service only ever forwards
    /// the public half and returns a sealed result it cannot itself open.
    transport_public_key_b64: String,
    /// Audit finding A12's retry protocol. Empty/omitted on a first
    /// attempt. If a previous call's `used_node_ids` produced a sealed
    /// result that failed client-side verification (via
    /// `quorum_client::open_sealed_derived_key` or equivalent), the
    /// caller retries by appending that `used_node_ids` list to
    /// `tried_subsets` and sending the whole accumulated history back.
    /// This is a combination search, not simple node exclusion -- see
    /// `quorum_client::collect_sealed_derived_key`'s doc comment for why
    /// that distinction matters for this project's actual 3-of-5
    /// deployment shape, and for the full protocol.
    #[serde(default)]
    tried_subsets: Vec<Vec<usize>>,
}

#[derive(Serialize)]
struct DeriveResp {
    /// A `quorum_vetseal::SealedDerivedKey`, base64-encoded. This service
    /// never holds, and structurally cannot produce, the plaintext
    /// derived key -- decrypt this client-side with the transport secret
    /// key that generated `transport_public_key_b64`, via
    /// `quorum_client::open_sealed_derived_key` (or the WASM/browser
    /// equivalent). See `quorum_vetseal`'s crate docs and Finding 2.3 in
    /// the whitepaper.
    sealed_derived_key_b64: String,
    /// Audit finding A12: exactly which node IDs' sealed shares were
    /// combined into `sealed_derived_key_b64`. If this result fails
    /// client-side verification, retry this same request with this list
    /// appended to `tried_subsets`.
    used_node_ids: Vec<usize>,
}

async fn derive_invoice_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(invoice_id): Path<String>,
    Json(req): Json<DeriveReq>,
) -> Result<Json<DeriveResp>, ApiError> {
    let caller_id = authenticate(&headers, &state)?;

    let transport_public_key_bytes = b64_decode_request_field(&req.transport_public_key_b64)
        .map_err(|_| {
            ApiError::BadRequest("transport_public_key_b64 is not valid base64".to_string())
        })?;
    let transport_public_key_arr: [u8; quorum_vetseal::G2_COMPRESSED_SIZE] =
        transport_public_key_bytes.try_into().map_err(|_| {
            ApiError::BadRequest(format!(
                "transport_public_key_b64 must decode to exactly {} bytes",
                quorum_vetseal::G2_COMPRESSED_SIZE
            ))
        })?;
    let transport_public_key =
        quorum_vetseal::TransportPublicKey::from_bytes(&transport_public_key_arr)
            .map_err(|e| ApiError::BadRequest(format!("invalid transport_public_key_b64: {e}")))?;

    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    db::record_and_check_rate_limit(&client, &caller_id, &state.derive_rate_limit, now_ms())
        .await?
        .map_err(|_| {
            ApiError::Conflict(
                "rate limit exceeded for key derivation; please wait before retrying".to_string(),
            )
        })?;

    let invoice = db::fetch_invoice(&client, &invoice_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("invoice not found".to_string()))?;
    let regulators = db::fetch_regulators(&client).await?;
    drop(client);

    let role =
        ciphersettle_core::resolve_access(&caller_id, &invoice.issuer, &invoice.bank, &regulators)
            .map_err(|_| {
                ApiError::Forbidden(
                    "not authorized to derive a decryption key for this invoice".to_string(),
                )
            })?;
    let action = ciphersettle_core::audit_action_for(&role);

    // Log BEFORE deriving, same ordering the earlier canister used.
    log_audit_event(&state, &invoice_id, &caller_id, action).await?;

    // Finding 2.3 fix: this service collects and combines *sealed*
    // shares only. It never calls `open_sealed_derived_key` and never
    // holds a `TransportSecretKey` -- decrypting the result happens
    // client-side, using a transport secret key this service has never
    // seen. See `quorum_vetseal`'s module docs and `INTEGRATION.md`.
    //
    // Audit finding A12: `tried_subsets` lets the caller drive a retry
    // after a previous sealed result failed client-side verification
    // (see `DeriveReq::tried_subsets`'s doc comment for the full
    // protocol and why this service can't detect a bad subset on its
    // own).
    let collected = collect_sealed_derived_key(
        &state.connector,
        &state.quorum_nodes,
        &invoice_id,
        state.threshold,
        &state.service_auth_key,
        &transport_public_key,
        &state.group_pks,
        state.proof_policy,
        &req.tried_subsets,
    )
    .await
    .map_err(|e| match e {
        // Terminal: no fresh subset remains to try. Distinguished from
        // InsufficientNodes (also possible on a bare first attempt, e.g.
        // a quorum that's simply down) so a caller's retry loop can tell
        // "give up, this identity is past the fault-tolerance budget"
        // apart from "transient, could retry the same request later".
        quorum_client::CollectSealedError::SubsetsExhausted { .. } => {
            ApiError::Conflict(e.to_string())
        }
        _ => ApiError::Internal(e.to_string()),
    })?;

    Ok(Json(DeriveResp {
        sealed_derived_key_b64: b64_encode(&collected.sealed.to_bytes()),
        used_node_ids: collected.used_node_ids,
    }))
}

// ---------------------------------------------------------------------
// get_audit_log -- public, metadata only (no ciphertext/plaintext ever;
// the underlying AuditEntry never carried either).
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditLogQuery {
    invoice_id: Option<String>,
}

async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditLogQuery>,
) -> Result<Json<Vec<quorum_audit::AuditEntry>>, ApiError> {
    let (_, addr) = state
        .quorum_nodes
        .first()
        .ok_or_else(|| ApiError::Internal("no quorum nodes configured".to_string()))?;
    let log = quorum_client::fetch_full_log(&state.connector, addr)
        .await
        .map_err(ApiError::Internal)?;
    let entries = log
        .filter_by_invoice(q.invoice_id.as_deref())
        .into_iter()
        .cloned()
        .collect();
    Ok(Json(entries))
}

// ---------------------------------------------------------------------
// get_merkle_proof -- public, same reasoning as get_audit_log: this
// returns an opaque commitment blob (never plaintext invoice fields,
// which this service doesn't have) plus a proof against the log's
// *current* root. As with `merkle.rs`'s own doc comment: a caller who
// wants to prove "the data used now is what I originally committed to"
// still separately reveals fields to whoever checks that, via
// `InvoiceCommitment::verify` -- this endpoint doesn't do that
// revealing, it only proves batch inclusion.
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct MerkleProofResp {
    invoice_id: String,
    commitment_b64: String,
    proof: ciphersettle_core::MerkleProof,
    root_hex: String,
}

async fn get_merkle_proof(
    State(state): State<Arc<AppState>>,
    Path(invoice_id): Path<String>,
) -> Result<Json<MerkleProofResp>, ApiError> {
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let (commitment_bytes, leaf_index) = db::fetch_commitment(&client, &invoice_id)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound("invoice not found, or has no stored commitment".to_string())
        })?;
    drop(client);
    let leaf_index = leaf_index.ok_or_else(|| {
        ApiError::Internal("invoice has a commitment but no merkle_leaf_index yet -- register may not have finished".to_string())
    })?;

    let log = state.merkle_log.lock().await;
    let proof = log.prove(leaf_index as u64).ok_or_else(|| {
        ApiError::Internal("recorded leaf_index out of range for the current log".to_string())
    })?;
    let root = log.root().ok_or_else(|| {
        ApiError::Internal("merkle log has no root despite a recorded leaf".to_string())
    })?;
    drop(log);

    Ok(Json(MerkleProofResp {
        invoice_id,
        commitment_b64: b64_encode(&commitment_bytes),
        proof,
        root_hex: hex_encode(&root),
    }))
}

// ---------------------------------------------------------------------
// register_regulator / revoke_regulator -- admin only
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct RegulatorReq {
    principal: String,
}

async fn register_regulator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<RegulatorReq>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    if caller_id != state.admin_caller_id {
        return Err(ApiError::Forbidden(
            "only the admin can register regulators".to_string(),
        ));
    }
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let outbox_id = db::register_regulator(
        &client,
        &req.principal,
        &db::AuditIntent {
            invoice_id: "*",
            actor: &caller_id,
            action: "regulator_registered",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

async fn revoke_regulator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(principal): Path<String>,
) -> Result<StatusCode, ApiError> {
    let caller_id = authenticate(&headers, &state)?;
    if caller_id != state.admin_caller_id {
        return Err(ApiError::Forbidden(
            "only the admin can revoke regulators".to_string(),
        ));
    }
    let client = state
        .db
        .get()
        .await
        .map_err(|e| ApiError::Internal(format!("db pool error: {e}")))?;
    let revoked = db::revoke_regulator(
        &client,
        &principal,
        &db::AuditIntent {
            invoice_id: "*",
            actor: &caller_id,
            action: "regulator_revoked",
            timestamp_ms: now_ms() as i64,
        },
    )
    .await?;
    drop(client);
    let Some(outbox_id) = revoked else {
        return Err(ApiError::Conflict(
            "that principal is not a registered regulator".to_string(),
        ));
    };
    audit_outbox_commit(&state, outbox_id).await?;
    Ok(StatusCode::OK)
}

/// Plain lowercase hex, no external crate needed for something this
/// small. Used only for display (Merkle roots in API responses) --
/// nothing in this service parses hex back into bytes.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String cannot fail; ignoring the Ok(()) keeps this panic-free.
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Request bodies are untrusted input over HTTP: a malformed value must
/// produce a 400, never a panic or a dropped connection (F-21).
/// Startup-only decode of a base64 config field (exits cleanly on bad input).
fn cfg_b64(field: &str, s: &str) -> Vec<u8> {
    or_fatal("service", field, quorum_core::config::b64_decode(s))
}

fn b64_decode_request_field(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    // Deploy-time subcommand (Gap 10): apply pending schema migrations and
    // exit, without a quorum, config file or listener:
    //   quorum_service migrate <db_url>
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let Some(db_url) = std::env::args().nth(2) else {
            quorum_core::config::fatal("service", "usage: quorum_service migrate <db_url>");
        };
        let (mut client, conn) = or_fatal(
            "service",
            "cannot connect to the database",
            tokio_postgres::connect(&db_url, tokio_postgres::NoTls).await,
        );
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let applied = or_fatal(
            "service",
            "schema migration",
            migrations::migrate(&mut client).await,
        );
        println!("migrations applied by this run: {applied:?}");
        return;
    }
    let Some(config_path) = std::env::args().nth(1) else {
        fatal("service", "usage: quorum_service <config.json>");
    };
    let config: ServiceConfig = {
        let raw = or_fatal(
            "service",
            "failed to read config",
            std::fs::read_to_string(&config_path),
        );
        or_fatal(
            "service",
            "invalid config",
            quorum_core::secret_files::load_config::<ServiceConfig>(&raw),
        )
    };

    // Audit finding A5: checked immediately after config parsing, before
    // touching Postgres or anything else -- a misconfigured deployment
    // should fail fast on its own config, not fail (or worse, half-start)
    // for a reason that depends on which infra happened to be reachable
    // first. See `tls_serve::refuse_plaintext_off_loopback`'s doc comment
    // for why this check is independent of whether TLS config happens to
    // be present.
    if config.tls_cert_der_b64.is_none() && config.tls_key_der_b64.is_none() {
        if let Err(e) = tls_serve::refuse_plaintext_off_loopback(&config.listen_addr) {
            eprintln!("[service] refusing to start: {e}");
            std::process::exit(1);
        }
    }
    if config.tls_cert_der_b64.is_some() != config.tls_key_der_b64.is_some() {
        eprintln!("[service] refusing to start: tls_cert_der_b64 and tls_key_der_b64 must both be set, or both absent");
        std::process::exit(1);
    }

    eprintln!("[service] connecting to Postgres (pooled)...");
    // Audit finding A10: this used to be a single `tokio_postgres::connect`
    // wrapped in a `Mutex`, which serializes every DB operation across
    // every concurrent request. `deadpool-postgres` manages a real pool of
    // connections (each with its own background driver task, handled
    // internally by the pool) and hands out one per checkout.
    let pg_config: tokio_postgres::Config =
        or_fatal("service", "invalid db_url", config.db_url.parse());
    let manager = deadpool_postgres::Manager::from_config(
        pg_config,
        tokio_postgres::NoTls,
        deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        },
    );
    let db_pool = or_fatal(
        "service",
        "failed to build db connection pool",
        deadpool_postgres::Pool::builder(manager)
            .max_size(config.db_pool_max_size)
            .build(),
    );

    {
        let mut init_client = or_fatal(
            "service",
            "failed to get initial db connection",
            db_pool.get().await,
        );
        let applied = or_fatal(
            "service",
            "schema migration",
            db::init_schema(&mut init_client).await,
        );
        if !applied.is_empty() {
            eprintln!("[service] applied schema migration(s): {applied:?}");
        }
        // Cutover guard: refuse to serve a database written under a
        // different cryptographic scheme (see `db::CRYPTO_EPOCH`).
        if let Err(why) =
            db::enforce_crypto_epoch(&init_client, config.acknowledge_pre_cutover_data).await
        {
            eprintln!("[service] REFUSING TO START (crypto cutover guard): {why}");
            std::process::exit(1);
        }
        eprintln!(
            "[service] crypto epoch {:?} confirmed for this database.",
            db::CRYPTO_EPOCH
        );
    }
    eprintln!(
        "[service] schema ready ({} max pooled connections).",
        config.db_pool_max_size
    );

    // Rebuild the in-memory Merkle log from every previously-stored
    // commitment, in original insertion order, so a restart doesn't
    // reset the log (and therefore every previously-issued
    // merkle_leaf_index / root) back to empty. See `db::
    // commitments_in_insertion_order` and `AppState::merkle_log`'s doc
    // comments for what this does and doesn't guarantee.
    let mut merkle_log = ciphersettle_core::MerkleLog::new();
    {
        let init_client = or_fatal(
            "service",
            "failed to get db connection for merkle rebuild",
            db_pool.get().await,
        );
        let commitments = or_fatal(
            "service",
            "failed to load stored commitments for merkle log rebuild",
            db::commitments_in_insertion_order(&init_client).await,
        );
        for (_, bytes) in &commitments {
            merkle_log.append(bytes);
        }
        eprintln!("[service] merkle log rebuilt: {} leaves.", merkle_log.len());
    }

    let group_pks: PublicKeySet = {
        let raw = or_fatal(
            "service",
            "failed to read group public key file",
            std::fs::read(&config.group_pubkey_file),
        );
        or_fatal(
            "service",
            "group public key file is corrupt",
            serde_json::from_slice(&raw),
        )
    };

    let mut allowed_certs: Vec<Vec<u8>> = config
        .quorum_nodes
        .iter()
        .map(|n| cfg_b64("quorum_nodes[].cert_der_b64", &n.cert_der_b64))
        .collect();
    if let Some(notary_cert) = &config.notary_cert_der_b64 {
        allowed_certs.push(cfg_b64("notary_cert_der_b64", notary_cert));
    }
    let connector = or_fatal(
        "service",
        "client TLS identity",
        quorum_client::build_connector(
            cfg_b64("client_cert_der_b64", &config.client_cert_der_b64),
            cfg_b64("client_key_der_b64", &config.client_key_der_b64),
            allowed_certs,
        ),
    );

    // Audit finding A15: hash each configured key immediately at load time
    // so the raw value never makes it into `AppState` / long-lived process
    // memory; `config` (which does hold the raw keys, read once from the
    // operator-provisioned JSON file) goes out of scope at the end of
    // `main` and is not referenced again after this point.
    if cfg_b64("service_auth_key_b64", &config.service_auth_key_b64).len()
        < quorum_core::MIN_AUTH_MASTER_BYTES
    {
        eprintln!(
            "[service] refusing to start: service_auth_key_b64 (the derive-auth MASTER secret, from which each node's key is derived) must decode to at least {} bytes",
            quorum_core::MIN_AUTH_MASTER_BYTES
        );
        std::process::exit(1);
    }

    let api_keys: Vec<ApiKeyEntry> = config
        .api_keys
        .iter()
        .map(|k| ApiKeyEntry::new(&k.key, k.caller_id.clone()))
        .collect();

    or_fatal(
        "service",
        "insecure test flags",
        config::check_insecure_flags(
            config.insecure_skip_share_proofs,
            std::env::var(config::INSECURE_TEST_FLAGS_ENV)
                .ok()
                .as_deref(),
        ),
    );
    let http_metrics = Arc::new(http_metrics::HttpMetrics::new());
    let state = Arc::new(AppState {
        db: db_pool,
        api_keys,
        admin_caller_id: config.admin_caller_id.clone(),
        connector,
        service_auth_key: cfg_b64("service_auth_key_b64", &config.service_auth_key_b64),
        quorum_nodes: config
            .quorum_nodes
            .iter()
            .map(|n| (n.id, n.addr.clone()))
            .collect(),
        threshold: config.quorum_threshold,
        group_pks,
        proof_policy: if config.insecure_skip_share_proofs {
            eprintln!(
                "[service] WARNING: insecure_skip_share_proofs is set -- sealed-share NIZK verification is \
                 DISABLED. This is for the adversarial test suite only; never run a deployment this way."
            );
            quorum_client::ProofPolicy::Skip
        } else {
            quorum_client::ProofPolicy::Require
        },
        max_ciphertext_bytes: config.max_ciphertext_bytes,
        ciphertext_retention_ms: config.ciphertext_retention_ms,
        derive_rate_limit: ciphersettle_core::RateLimitPolicy {
            max_calls: config.derive_rate_limit_max_calls,
            window_nanos: config.derive_rate_limit_window_ms,
        },
        merkle_log: tokio::sync::Mutex::new(merkle_log),
        audit_lock: tokio::sync::Mutex::new(()),
        ready_cache: tokio::sync::Mutex::new(None),
        http_metrics: http_metrics.clone(),
    });
    tokio::spawn(audit_outbox_drainer(state.clone()));

    let app = Router::new()
        .route("/invoices", post(register_invoice))
        .route("/invoices/:id/grant", post(grant_settlement_access))
        .route("/invoices/:id/revoke", post(revoke_settlement_access))
        .route("/invoices/:id/settle", post(mark_settled))
        .route("/invoices/:id/prune", post(prune_ciphertext))
        .route("/invoices/:id/derive-key", post(derive_invoice_key))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/audit-log", get(get_audit_log))
        .route("/invoices/:id/merkle-proof", get(get_merkle_proof))
        .route("/regulators", post(register_regulator))
        .route("/regulators/:id", delete(revoke_regulator))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            http_metrics,
            http_metrics::track,
        ));

    eprintln!("[service] listening on {}", config.listen_addr);

    let listener = or_fatal(
        "service",
        &format!("failed to bind {}", config.listen_addr),
        tokio::net::TcpListener::bind(&config.listen_addr).await,
    );
    match (&config.tls_cert_der_b64, &config.tls_key_der_b64) {
        (Some(cert_b64), Some(key_b64)) => {
            eprintln!("[service] TLS enabled");
            let acceptor = or_fatal(
                "service",
                "TLS server identity",
                tls_serve::build_acceptor(
                    cfg_b64("tls_cert_der_b64", cert_b64),
                    cfg_b64("tls_key_der_b64", key_b64),
                ),
            );
            tls_serve::serve(app, listener, acceptor).await;
        }
        _ => {
            // The mixed case (exactly one of the two set) and the
            // off-loopback-without-TLS case were both already refused
            // right after config parsing, above -- reaching here with
            // both absent means plaintext-on-loopback, the one
            // configuration that's actually allowed.
            eprintln!("[service] TLS not configured -- only permitted because listen_addr is loopback (checked at startup)");
            or_fatal("service", "server error", axum::serve(listener, app).await);
        }
    }
}

#[cfg(test)]
mod f21_regression_tests {
    use super::*;

    /// Regression (F-21): request-body base64 must be an `Err` (-> HTTP 400), never
    /// a panic. Pins the helper; handler-level behaviour is pinned by adversarial Z4/Z5.
    #[test]
    fn regression_malformed_request_base64_is_an_error_not_a_panic() {
        let long = "A".repeat((1 << 20) + 1);
        for bad in [
            "!!! not base64 !!!",
            "=",
            "A",
            "AAAAA",
            "\u{0}",
            "\u{feff}AAAA",
            long.as_str(),
        ] {
            let _ = b64_decode_request_field(bad);
        }
        assert!(b64_decode_request_field("!!! not base64 !!!").is_err());
        assert!(b64_decode_request_field("A").is_err());
        assert_eq!(b64_decode_request_field("eA==").unwrap(), b"x");
    }
}
