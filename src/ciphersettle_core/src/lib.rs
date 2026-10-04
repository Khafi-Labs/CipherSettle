//! Pure decision logic for the confidential settlement protocol, deliberately
//! kept free of any ic-cdk / candid dependency so it can be built and tested
//! on any Rust toolchain, independent of the Internet Computer SDK version.
//! The earlier IC canister prototype (`ciphersettle_backend`, since
//! deleted -- see finding A14 of the audit remediation roadmap) was meant
//! to call into this module rather than re-implementing these decisions
//! inline, so the rules are tested once here and simply wired up there.
//!
//! ## `check_nullifier` and the `commitment` module: a note on positioning
//!
//! `check_nullifier` below is a *local* double-registration guard --
//! this system refusing to accept the same nullifier twice within its
//! own database. It is not, and this project's documentation should not
//! describe it as, a substitute for Egypt's FRA-operated invoice
//! verification and duplicate-financing prevention (Decision No. 51 of
//! 2026): that system is now the authoritative check, and this one
//! remains useful as defense-in-depth, not as this project's value
//! proposition. `commitment`, added after that same design review,
//! exists for a different, complementary reason: proving that the
//! invoice data used at financing time is exactly the data originally
//! committed to -- a question the *authoritative* verification result
//! doesn't answer on its own. `merkle`, added after `commitment`, batches
//! many commitments under one root for cheap inclusion proofs and
//! tamper-evident audit history -- see that module's own doc comment for
//! why it is *not*, on its own, a fix for the oracle problem above: a
//! Merkle proof only proves inclusion under a root, not who was entitled
//! to publish that root.

pub mod commitment;
pub use commitment::{
    InvoiceCommitment, InvoiceFields, INVOICE_COMMITMENT_SALT_LEN, INVOICE_COMMITMENT_VERSION,
};

pub mod merkle;
pub use merkle::{MerkleLog, MerkleProof, Side, MERKLE_VERSION};

/// A caller identity. In the real canister this wraps `candid::Principal`;
/// here it's a plain string so this crate has zero IC dependencies.
pub type CallerId = String;

#[derive(Debug, PartialEq, Eq)]
pub enum NullifierError {
    AlreadyClaimed,
}

/// Replay/idempotency check: a nullifier may be claimed exactly once
/// within this system's own registry. This is not a double-financing
/// determination (see the module-level note above on `check_nullifier`'s
/// positioning). `already_present` is the caller's lookup result against
/// the registry.
pub fn check_nullifier(already_present: bool) -> Result<(), NullifierError> {
    if already_present {
        Err(NullifierError::AlreadyClaimed)
    } else {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessRole {
    Issuer,
    Bank,
    Regulator,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessError {
    NotAuthorized,
}

/// Decide whether `caller` may derive a decryption key for an invoice, and
/// which role that access should be logged under. Regulator access always
/// wins the label even if a regulator happens to also be the issuer or bank,
/// because the log's job is to flag every possible disclosure event, not to
/// pick the "most convenient" explanation for a given call.
pub fn resolve_access(
    caller: &CallerId,
    issuer: &CallerId,
    bank: &Option<CallerId>,
    regulators: &[CallerId],
) -> Result<AccessRole, AccessError> {
    if regulators.iter().any(|r| r == caller) {
        return Ok(AccessRole::Regulator);
    }
    if caller == issuer {
        return Ok(AccessRole::Issuer);
    }
    if bank.as_ref() == Some(caller) {
        return Ok(AccessRole::Bank);
    }
    Err(AccessError::NotAuthorized)
}

/// Maps an access role to the exact audit-log action string the canister
/// should record. Centralized here so the log vocabulary can't drift between
/// call sites.
pub fn audit_action_for(role: &AccessRole) -> &'static str {
    match role {
        AccessRole::Regulator => "disclosure_request",
        AccessRole::Bank => "key_derived_bank",
        AccessRole::Issuer => "key_derived_issuer",
    }
}

// ---------------------------------------------------------------------------
// Rate limiting / cycle-guard decision logic. Pure and clock-injected so it's
// testable without a live replica. The canister supplies "now" (ic_cdk::api::time,
// nanoseconds) and the caller's recent call timestamps; this module only
// decides whether the call should be allowed.
// ---------------------------------------------------------------------------

/// A fixed-window rate limit: at most `max_calls` calls per `window_nanos`
/// per caller, evaluated against that caller's own call history for the
/// gated endpoint (e.g. derive_invoice_key).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitPolicy {
    pub max_calls: usize,
    pub window_nanos: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RateLimitError {
    TooManyRequests,
}

/// Decide whether a new call is allowed given the caller's prior call
/// timestamps (nanoseconds, ascending or unordered -- order doesn't matter
/// here) and the current time. Timestamps outside the trailing window are
/// ignored, so this is a sliding window, not a hard reset-at-boundary window.
pub fn check_rate_limit(
    policy: &RateLimitPolicy,
    prior_call_times: &[u64],
    now: u64,
) -> Result<(), RateLimitError> {
    let window_start = now.saturating_sub(policy.window_nanos);
    let calls_in_window = prior_call_times
        .iter()
        .filter(|&&t| t >= window_start && t <= now)
        .count();
    if calls_in_window >= policy.max_calls {
        Err(RateLimitError::TooManyRequests)
    } else {
        Ok(())
    }
}

/// Payload-size guard: reject ciphertext uploads above a configured cap so a
/// single caller can't inflate paid stable-memory storage with arbitrary
/// blobs. Kept as a pure function so the threshold logic has a single
/// tested home even though the byte slice itself lives in the canister.
pub fn check_payload_size(payload_len: usize, max_bytes: usize) -> Result<(), String> {
    if payload_len > max_bytes {
        Err(format!(
            "payload of {payload_len} bytes exceeds the {max_bytes}-byte limit"
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Full protocol state machine. This mirrors the earlier IC canister
// prototype's stable-structure logic exactly (nullifier set, invoice map,
// regulator set, append-only audit log) but uses plain std collections so
// it compiles and tests on any Rust toolchain. Treat this as the
// executable specification: if you change
// a rule in the canister, change it here first, get the test passing, then
// port the same change over.
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: u64,
    pub invoice_id: String,
    pub actor: CallerId,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvoiceStatus {
    Active,
    Settled,
}

#[derive(Debug, Clone)]
struct Invoice {
    issuer: CallerId,
    bank: Option<CallerId>,
    status: InvoiceStatus,
    // Kept for future use (e.g. reporting/expiry-of-unsettled-invoices
    // policies) even though no current rule reads it yet.
    #[allow(dead_code)]
    created_at: u64,
    settled_at: Option<u64>,
}

#[derive(Debug, Default)]
pub struct ProtocolState {
    admin: Option<CallerId>,
    nullifiers: HashSet<String>,
    invoices: HashMap<String, Invoice>,
    regulators: HashSet<CallerId>,
    audit_log: Vec<AuditEvent>,
    next_event_id: u64,
}

impl ProtocolState {
    pub fn new(admin: CallerId) -> Self {
        Self {
            admin: Some(admin),
            ..Default::default()
        }
    }

    fn log(&mut self, invoice_id: &str, actor: &CallerId, action: &'static str) {
        let event = AuditEvent {
            id: self.next_event_id,
            invoice_id: invoice_id.to_string(),
            actor: actor.clone(),
            action: action.to_string(),
        };
        self.next_event_id += 1;
        self.audit_log.push(event);
    }

    pub fn register_regulator(
        &mut self,
        caller: &CallerId,
        regulator: CallerId,
    ) -> Result<(), String> {
        if self.admin.as_ref() != Some(caller) {
            return Err("only the admin can register regulators".to_string());
        }
        self.regulators.insert(regulator);
        self.log("*", caller, "regulator_registered");
        Ok(())
    }

    /// Admin-only removal of a previously registered regulator. Errors if the
    /// principal was never registered, so callers can't get a silent no-op
    /// that looks like a successful revoke.
    pub fn revoke_regulator(
        &mut self,
        caller: &CallerId,
        regulator: &CallerId,
    ) -> Result<(), String> {
        if self.admin.as_ref() != Some(caller) {
            return Err("only the admin can revoke regulators".to_string());
        }
        if !self.regulators.remove(regulator) {
            return Err("that principal is not a registered regulator".to_string());
        }
        self.log("*", caller, "regulator_revoked");
        Ok(())
    }

    pub fn register_invoice(
        &mut self,
        caller: &CallerId,
        invoice_id: String,
        nullifier_hash: String,
        created_at: u64,
    ) -> Result<(), String> {
        let already_claimed = self.nullifiers.contains(&nullifier_hash);
        check_nullifier(already_claimed).map_err(|_| {
            "nullifier already registered: invoice already submitted elsewhere".to_string()
        })?;
        if self.invoices.contains_key(&invoice_id) {
            return Err("invoice_id already exists".to_string());
        }
        self.nullifiers.insert(nullifier_hash);
        self.invoices.insert(
            invoice_id.clone(),
            Invoice {
                issuer: caller.clone(),
                bank: None,
                status: InvoiceStatus::Active,
                created_at,
                settled_at: None,
            },
        );
        self.log(&invoice_id, caller, "invoice_registered");
        Ok(())
    }

    pub fn grant_settlement_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
        bank: CallerId,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if &invoice.issuer != caller {
            return Err("only the issuer can grant settlement access".to_string());
        }
        invoice.bank = Some(bank);
        self.log(invoice_id, caller, "settlement_access_granted");
        Ok(())
    }

    /// Issuer-only revocation of a previously granted counterparty. This is
    /// the missing half of `grant_settlement_access`: a financing
    /// arrangement falling through, or a bank's access needing to be pulled,
    /// no longer requires waiting for the invoice to reach a terminal state.
    /// Errors rather than silently no-op'ing if there was nothing to revoke,
    /// so a caller can't mistake "nothing happened" for "access removed".
    pub fn revoke_settlement_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        if &invoice.issuer != caller {
            return Err("only the issuer can revoke settlement access".to_string());
        }
        if invoice.bank.take().is_none() {
            return Err("no settlement access is currently granted for this invoice".to_string());
        }
        self.log(invoice_id, caller, "settlement_access_revoked");
        Ok(())
    }

    pub fn request_key_access(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
    ) -> Result<AccessRole, String> {
        let invoice = self
            .invoices
            .get(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let regulators: Vec<CallerId> = self.regulators.iter().cloned().collect();
        let role =
            resolve_access(caller, &invoice.issuer, &invoice.bank, &regulators).map_err(|_| {
                "not authorized to derive a decryption key for this invoice".to_string()
            })?;
        self.log(invoice_id, caller, audit_action_for(&role));
        Ok(role)
    }

    /// Issuer or the currently-granted bank may mark an invoice settled.
    /// Settlement itself (moving money) happens off-canister, per the
    /// project's "don't touch the money" design constraint -- this just
    /// records the terminal state so pruning eligibility can be evaluated.
    pub fn mark_settled(
        &mut self,
        caller: &CallerId,
        invoice_id: &str,
        settled_at: u64,
    ) -> Result<(), String> {
        let invoice = self
            .invoices
            .get_mut(invoice_id)
            .ok_or_else(|| "invoice not found".to_string())?;
        let is_participant = &invoice.issuer == caller || invoice.bank.as_ref() == Some(caller);
        if !is_participant {
            return Err(
                "only the issuer or the granted bank can mark an invoice settled".to_string(),
            );
        }
        if invoice.status == InvoiceStatus::Settled {
            return Err("invoice is already settled".to_string());
        }
        invoice.status = InvoiceStatus::Settled;
        invoice.settled_at = Some(settled_at);
        self.log(invoice_id, caller, "invoice_settled");
        Ok(())
    }

    /// Pruning eligibility for an invoice's *ciphertext payload* -- not the
    /// audit log, which stays append-only forever regardless of pruning,
    /// since the audit trail is the compliance artifact and is metadata-only
    /// (no ciphertext, no plaintext) so it doesn't carry the same storage-cost
    /// pressure that raw ciphertext blobs do. An invoice is eligible once it
    /// is Settled AND has sat past `retention_nanos` since settlement.
    /// Active invoices are never eligible, regardless of age, since pruning
    /// an unsettled invoice would destroy data a bank or regulator may still
    /// need.
    pub fn is_eligible_for_ciphertext_pruning(
        &self,
        invoice_id: &str,
        now: u64,
        retention_nanos: u64,
    ) -> bool {
        match self.invoices.get(invoice_id) {
            Some(inv) => match (&inv.status, inv.settled_at) {
                (InvoiceStatus::Settled, Some(settled_at)) => {
                    now.saturating_sub(settled_at) >= retention_nanos
                }
                _ => false,
            },
            None => false,
        }
    }

    pub fn audit_log(&self, invoice_id: Option<&str>) -> Vec<&AuditEvent> {
        self.audit_log
            .iter()
            .filter(|e| invoice_id.is_none_or(|id| e.invoice_id == id))
            .collect()
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn full_lifecycle_issuer_registers_grants_and_bank_derives() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        let role = state
            .request_key_access(&"bank-1".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Bank);

        let log = state.audit_log(Some("inv-1"));
        let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "invoice_registered",
                "settlement_access_granted",
                "key_derived_bank"
            ]
        );
    }

    #[test]
    fn duplicate_nullifier_blocks_second_invoice() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "shared-null".to_string(),
                0,
            )
            .unwrap();
        let result = state.register_invoice(
            &"issuer-2".to_string(),
            "inv-2".to_string(),
            "shared-null".to_string(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_invoice_id_is_rejected_even_with_new_nullifier() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-a".to_string(),
                0,
            )
            .unwrap();
        let result = state.register_invoice(
            &"issuer-1".to_string(),
            "inv-1".to_string(),
            "null-b".to_string(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn non_issuer_cannot_grant_settlement_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        let result =
            state.grant_settlement_access(&"attacker".to_string(), "inv-1", "bank-1".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn non_admin_cannot_register_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        let result = state.register_regulator(&"not-admin".to_string(), "fake-reg".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn regulator_access_is_logged_as_disclosure_in_full_flow() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        let role = state
            .request_key_access(&"regulator-1".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Regulator);
        let log = state.audit_log(Some("inv-1"));
        assert!(log.iter().any(|e| e.action == "disclosure_request"));
    }

    #[test]
    fn unrelated_invoice_events_are_excluded_by_filter() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .register_invoice(
                &"issuer-2".to_string(),
                "inv-2".to_string(),
                "null-2".to_string(),
                0,
            )
            .unwrap();
        let log = state.audit_log(Some("inv-1"));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].invoice_id, "inv-1");
    }

    // ---- Access revocation ----

    #[test]
    fn issuer_can_revoke_previously_granted_bank_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state
            .revoke_settlement_access(&"issuer-1".to_string(), "inv-1")
            .unwrap();

        // the revoked bank can no longer derive a key
        let result = state.request_key_access(&"bank-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn revoking_settlement_access_with_nothing_granted_is_an_error_not_a_noop() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        let result = state.revoke_settlement_access(&"issuer-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn non_issuer_cannot_revoke_settlement_access() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        let result = state.revoke_settlement_access(&"bank-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn issuer_can_regrant_after_revoking() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state
            .revoke_settlement_access(&"issuer-1".to_string(), "inv-1")
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-2".to_string())
            .unwrap();
        let role = state
            .request_key_access(&"bank-2".to_string(), "inv-1")
            .unwrap();
        assert_eq!(role, AccessRole::Bank);
    }

    #[test]
    fn admin_can_revoke_a_registered_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .revoke_regulator(&"admin".to_string(), &"regulator-1".to_string())
            .unwrap();
        // revoked regulator no longer gets disclosure access
        let result = state.request_key_access(&"regulator-1".to_string(), "inv-1");
        assert!(result.is_err());
    }

    #[test]
    fn revoking_an_unregistered_regulator_is_an_error() {
        let mut state = ProtocolState::new("admin".to_string());
        let result = state.revoke_regulator(&"admin".to_string(), &"never-registered".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn non_admin_cannot_revoke_regulator() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_regulator(&"admin".to_string(), "regulator-1".to_string())
            .unwrap();
        let result = state.revoke_regulator(&"not-admin".to_string(), &"regulator-1".to_string());
        assert!(result.is_err());
    }

    // ---- Settlement lifecycle & pruning eligibility ----

    #[test]
    fn issuer_or_bank_can_mark_settled() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .grant_settlement_access(&"issuer-1".to_string(), "inv-1", "bank-1".to_string())
            .unwrap();
        state
            .mark_settled(&"bank-1".to_string(), "inv-1", 1_000)
            .unwrap();
        let log = state.audit_log(Some("inv-1"));
        assert!(log.iter().any(|e| e.action == "invoice_settled"));
    }

    #[test]
    fn stranger_cannot_mark_settled() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        let result = state.mark_settled(&"stranger".to_string(), "inv-1", 1_000);
        assert!(result.is_err());
    }

    #[test]
    fn double_settlement_is_rejected() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .mark_settled(&"issuer-1".to_string(), "inv-1", 1_000)
            .unwrap();
        let result = state.mark_settled(&"issuer-1".to_string(), "inv-1", 2_000);
        assert!(result.is_err());
    }

    #[test]
    fn active_invoice_is_never_prune_eligible_regardless_of_age() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        let far_future = 999_999_999_999u64;
        assert!(!state.is_eligible_for_ciphertext_pruning("inv-1", far_future, 1));
    }

    #[test]
    fn settled_invoice_is_prune_eligible_only_after_retention_window() {
        let mut state = ProtocolState::new("admin".to_string());
        state
            .register_invoice(
                &"issuer-1".to_string(),
                "inv-1".to_string(),
                "null-1".to_string(),
                0,
            )
            .unwrap();
        state
            .mark_settled(&"issuer-1".to_string(), "inv-1", 1_000)
            .unwrap();

        let retention = 500u64;
        assert!(!state.is_eligible_for_ciphertext_pruning("inv-1", 1_200, retention)); // too soon
        assert!(state.is_eligible_for_ciphertext_pruning("inv-1", 1_500, retention)); // right at boundary
        assert!(state.is_eligible_for_ciphertext_pruning("inv-1", 5_000, retention));
        // well past
    }

    #[test]
    fn unknown_invoice_is_not_prune_eligible() {
        let state = ProtocolState::new("admin".to_string());
        assert!(!state.is_eligible_for_ciphertext_pruning("does-not-exist", 1_000_000, 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_allows_first_claim() {
        assert_eq!(check_nullifier(false), Ok(()));
    }

    #[test]
    fn nullifier_rejects_second_claim() {
        assert_eq!(check_nullifier(true), Err(NullifierError::AlreadyClaimed));
    }

    #[test]
    fn issuer_is_granted_access() {
        let issuer = "issuer-1".to_string();
        let role = resolve_access(&issuer, &issuer, &None, &[]).unwrap();
        assert_eq!(role, AccessRole::Issuer);
        assert_eq!(audit_action_for(&role), "key_derived_issuer");
    }

    #[test]
    fn granted_bank_is_granted_access() {
        let issuer = "issuer-1".to_string();
        let bank = "bank-1".to_string();
        let role = resolve_access(&bank, &issuer, &Some(bank.clone()), &[]).unwrap();
        assert_eq!(role, AccessRole::Bank);
        assert_eq!(audit_action_for(&role), "key_derived_bank");
    }

    #[test]
    fn ungranted_bank_is_denied() {
        let issuer = "issuer-1".to_string();
        let granted_bank = "bank-1".to_string();
        let other_bank = "bank-2".to_string();
        let result = resolve_access(&other_bank, &issuer, &Some(granted_bank), &[]);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    #[test]
    fn stranger_is_denied() {
        let issuer = "issuer-1".to_string();
        let stranger = "stranger".to_string();
        let result = resolve_access(&stranger, &issuer, &None, &[]);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    #[test]
    fn registered_regulator_is_granted_access_and_flagged_as_disclosure() {
        let issuer = "issuer-1".to_string();
        let regulator = "regulator-1".to_string();
        let role =
            resolve_access(&regulator, &issuer, &None, std::slice::from_ref(&regulator)).unwrap();
        assert_eq!(role, AccessRole::Regulator);
        assert_eq!(audit_action_for(&role), "disclosure_request");
    }

    #[test]
    fn regulator_who_is_also_issuer_is_still_logged_as_disclosure() {
        // A regulator principal that happens to equal the issuer must still
        // be flagged as a disclosure event, not silently treated as routine
        // issuer access -- the log's purpose is to never under-report.
        let dual_role_principal = "dual-1".to_string();
        let role = resolve_access(
            &dual_role_principal,
            &dual_role_principal,
            &None,
            std::slice::from_ref(&dual_role_principal),
        )
        .unwrap();
        assert_eq!(role, AccessRole::Regulator);
    }

    #[test]
    fn unregistered_caller_claiming_to_be_regulator_is_denied() {
        let issuer = "issuer-1".to_string();
        let fake_regulator = "not-actually-registered".to_string();
        let real_regulators = vec!["regulator-1".to_string()];
        let result = resolve_access(&fake_regulator, &issuer, &None, &real_regulators);
        assert_eq!(result, Err(AccessError::NotAuthorized));
    }

    // ---- Rate limiting ----

    #[test]
    fn rate_limit_allows_calls_under_the_cap() {
        let policy = RateLimitPolicy {
            max_calls: 3,
            window_nanos: 1_000_000_000,
        };
        let prior = vec![100, 200];
        assert_eq!(check_rate_limit(&policy, &prior, 300), Ok(()));
    }

    #[test]
    fn rate_limit_blocks_calls_at_the_cap() {
        let policy = RateLimitPolicy {
            max_calls: 3,
            window_nanos: 1_000_000_000,
        };
        let prior = vec![100, 200, 300];
        assert_eq!(
            check_rate_limit(&policy, &prior, 400),
            Err(RateLimitError::TooManyRequests)
        );
    }

    #[test]
    fn rate_limit_ignores_calls_outside_the_window() {
        let policy = RateLimitPolicy {
            max_calls: 2,
            window_nanos: 1_000,
        };
        // two calls happened, but both are far outside the trailing window
        let prior = vec![0, 1];
        assert_eq!(check_rate_limit(&policy, &prior, 100_000), Ok(()));
    }

    #[test]
    fn rate_limit_boundary_timestamp_counts_as_inside_the_window() {
        let policy = RateLimitPolicy {
            max_calls: 1,
            window_nanos: 1_000,
        };
        let now = 5_000u64;
        let prior = vec![now - 1_000]; // exactly at the window edge
        assert_eq!(
            check_rate_limit(&policy, &prior, now),
            Err(RateLimitError::TooManyRequests)
        );
    }

    // ---- Payload size guard ----

    #[test]
    fn payload_within_limit_is_accepted() {
        assert_eq!(check_payload_size(100, 1_000), Ok(()));
    }

    #[test]
    fn payload_at_exact_limit_is_accepted() {
        assert_eq!(check_payload_size(1_000, 1_000), Ok(()));
    }

    #[test]
    fn payload_over_limit_is_rejected() {
        assert!(check_payload_size(1_001, 1_000).is_err());
    }
}
