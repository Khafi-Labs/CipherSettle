//! Gap 8 / T-9: shared fuzz bodies.
//!
//! Every function takes arbitrary attacker-controlled bytes and exercises one
//! parser / verifier that the system feeds from the network, the database or
//! a config file. The contract for ALL of them: never panic, never hang,
//! never allocate unboundedly. Where a decode succeeds, a re-encode must
//! round-trip (a canonical-encoding / malleability check).
//!
//! Two drivers use these exact functions:
//!   * `quorum_adversarial --only W` (stable Rust, seeded random + mutation
//!     of valid seeds, runs in CI), and
//!   * `fuzz/fuzz_targets/*` (cargo-fuzz / libFuzzer, nightly) for long
//!     coverage-guided runs.
//!
//! Keep this file dependency-light: it is `#[path]`-included by the fuzz crate.

use std::collections::BTreeMap;

use ciphersettle_core::{InvoiceCommitment, MerkleProof};
use quorum_audit::{wire::NotaryMessage, AuditEntry, AuditLog};
use quorum_core::{
    bls::{FR_BYTES, G2_COMPRESSED_SIZE},
    scalar_from_bytes, scalar_to_bytes, Commitment, Message, Signature, SignatureShare,
};

/// DKG commitment decode: validating (length, on-curve, subgroup). A success
/// must re-encode to exactly the input bytes.
pub fn commitment_decode(data: &[u8]) {
    if let Ok(c) = Commitment::from_bytes(data) {
        assert_eq!(c.to_bytes(), data, "Commitment decode is not canonical");
        let _ = c.len();
        let _ = c.evaluate(1);
    }
}

/// Signature / signature-share decode (96-byte compressed G2).
pub fn signature_decode(data: &[u8]) {
    if let Ok(arr) = <[u8; G2_COMPRESSED_SIZE]>::try_from(data) {
        if let Ok(s) = Signature::from_bytes(&arr) {
            assert_eq!(s.to_bytes(), arr, "Signature decode is not canonical");
        }
        if let Ok(s) = SignatureShare::from_bytes(&arr) {
            assert_eq!(s.to_bytes(), arr, "SignatureShare decode is not canonical");
        }
    }
}

/// Scalar decode (32 bytes): only canonical field elements are accepted.
pub fn scalar_decode(data: &[u8]) {
    if let Ok(arr) = <[u8; FR_BYTES]>::try_from(data) {
        if let Some(s) = scalar_from_bytes(&arr) {
            assert_eq!(scalar_to_bytes(&s), arr, "scalar decode is not canonical");
        }
    }
}

/// Invoice commitment blob (version byte + salt + hash).
pub fn invoice_commitment_decode(data: &[u8]) {
    const LEN: usize = 1 + ciphersettle_core::INVOICE_COMMITMENT_SALT_LEN + 32;
    // from_bytes takes a fixed array: zero-pad / truncate arbitrary input to it
    // (so the version byte, salt and hash all see attacker-chosen bytes), and
    // also try the exact-length case when the input already has it.
    let mut buf = [0u8; LEN];
    let n = data.len().min(LEN);
    buf[..n].copy_from_slice(&data[..n]);
    if let Ok(c) = InvoiceCommitment::from_bytes(&buf) {
        assert_eq!(
            c.to_bytes(),
            buf,
            "InvoiceCommitment decode is not canonical"
        );
    }
}

/// Node wire protocol line (JSON `Message`) and notary wire protocol.
pub fn wire_message_json(data: &[u8]) {
    if let Ok(m) = serde_json::from_slice::<Message>(data) {
        if let Ok(bytes) = serde_json::to_vec(&m) {
            let _ = serde_json::from_slice::<Message>(&bytes);
        }
    }
    if let Ok(m) = serde_json::from_slice::<NotaryMessage>(data) {
        if let Ok(bytes) = serde_json::to_vec(&m) {
            let _ = serde_json::from_slice::<NotaryMessage>(&bytes);
        }
    }
}

/// Merkle proof JSON: any proof that deserializes must be verifiable against
/// any leaf/root without panicking (empty peaks, bad peak_index, huge
/// leaf_count, mismatched sibling paths...).
pub fn merkle_proof_json(data: &[u8]) {
    if let Ok(p) = serde_json::from_slice::<MerkleProof>(data) {
        let root = [7u8; 32];
        let _ = p.verify(b"leaf", &root);
        let _ = p.verify(&[], &[0u8; 32]);
    }
}

/// Audit-log JSON as read back from a node / a peer: every public operation
/// the readers perform on an untrusted log must be panic-free.
pub fn audit_log_json(data: &[u8]) {
    if let Ok(log) = serde_json::from_slice::<AuditLog>(data) {
        let _ = log.verify_chain();
        let _ = log.tip_hash();
        let _ = log.next_seq();
        let _ = log.filter_by_invoice(Some("x"));
        let _ = log.filter_by_invoice(None);
        let mut other = log.clone();
        other.entries.pop();
        let _ = log.diverges_from(&other);
        let mut logs = BTreeMap::new();
        logs.insert(0usize, log.clone());
        logs.insert(1usize, other);
        logs.insert(2usize, AuditLog::default());
        let _ = AuditLog::majority_reference(&logs);
        let key = ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]);
        for e in &log.entries {
            let _ = e.verify_hash();
            if let Ok(k) = &key {
                let _ = e.verify_signature(0, k);
            }
        }
    }
    if let Ok(e) = serde_json::from_slice::<AuditEntry>(data) {
        let _ = e.verify_hash();
    }
}

/// A named fuzz body.
pub type Body = (&'static str, fn(&[u8]));

/// All bodies, for the stable driver.
pub const ALL: &[Body] = &[
    ("commitment_decode", commitment_decode),
    ("signature_decode", signature_decode),
    ("scalar_decode", scalar_decode),
    ("invoice_commitment_decode", invoice_commitment_decode),
    ("wire_message_json", wire_message_json),
    ("merkle_proof_json", merkle_proof_json),
    ("audit_log_json", audit_log_json),
];
