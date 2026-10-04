//! Exercises `commitment` and `merkle` together, the way a real caller
//! would: build several invoice commitments, batch them into one
//! `MerkleLog`, and prove/verify inclusion of individual invoices
//! against the batch root without touching any other invoice's fields.
//! Each module's own unit tests only exercise it in isolation; this is
//! the integration those don't cover.

use ciphersettle_core::{InvoiceCommitment, InvoiceFields, MerkleLog};
use rand::rngs::OsRng;

fn sample_invoice(n: u32) -> InvoiceFields {
    InvoiceFields {
        invoice_reference: format!("INV-{n:05}"),
        issuer: format!("Issuer Co {n}"),
        debtor: format!("Debtor Co {n}"),
        amount_minor_units: 1_000_000 + n as i64 * 777,
        currency: "EGP".to_string(),
        issue_date: "2026-09-01".to_string(),
        due_date: "2026-12-01".to_string(),
    }
}

/// A batch of invoice commitments, appended to a Merkle log, each
/// independently provable against the one published root -- the core
/// promise from `merkle.rs`'s own doc comment ("Batching & inclusion
/// proofs").
#[test]
fn a_batch_of_invoice_commitments_is_individually_provable_under_one_root() {
    let mut rng = OsRng;
    let mut log = MerkleLog::new();
    let mut commitments = Vec::new();

    for n in 0..50u32 {
        let fields = sample_invoice(n);
        let commitment = InvoiceCommitment::compute(&fields, &mut rng);
        log.append(&commitment.to_bytes());
        commitments.push((fields, commitment));
    }

    let root = log.root().expect("non-empty log has a root");

    for (i, (_, commitment)) in commitments.iter().enumerate() {
        let proof = log
            .prove(i as u64)
            .unwrap_or_else(|| panic!("missing proof for invoice {i}"));
        assert!(
            proof.verify(&commitment.to_bytes(), &root),
            "invoice {i}'s commitment did not verify against the batch root"
        );
    }
}

/// A Merkle proof for invoice A must not verify against invoice B's
/// commitment bytes, even though both are legitimate leaves of the
/// same, correctly-rooted log -- inclusion proofs are leaf-specific,
/// not "any leaf in this batch."
#[test]
fn a_proof_does_not_transfer_to_a_different_invoice_in_the_same_batch() {
    let mut rng = OsRng;
    let mut log = MerkleLog::new();
    let mut commitments = Vec::new();
    for n in 0..8u32 {
        let fields = sample_invoice(n);
        let commitment = InvoiceCommitment::compute(&fields, &mut rng);
        log.append(&commitment.to_bytes());
        commitments.push(commitment);
    }
    let root = log.root().unwrap();

    let proof_for_invoice_2 = log.prove(2).unwrap();
    assert!(proof_for_invoice_2.verify(&commitments[2].to_bytes(), &root));
    assert!(
        !proof_for_invoice_2.verify(&commitments[5].to_bytes(), &root),
        "invoice 2's proof must not verify against invoice 5's commitment bytes"
    );
}

/// If a commitment is tampered with after being batched (any single
/// byte of its salt or hash flipped), its Merkle proof stops verifying
/// -- the batching layer inherits the commitment layer's tamper
/// detection rather than silently trusting whatever bytes it was
/// handed at append time.
#[test]
fn tampering_with_a_batched_commitment_is_caught_by_its_merkle_proof() {
    let mut rng = OsRng;
    let fields = sample_invoice(0);
    let commitment = InvoiceCommitment::compute(&fields, &mut rng);

    let mut log = MerkleLog::new();
    log.append(&commitment.to_bytes());
    log.append(b"a second, unrelated leaf so this log has more than one node");
    let root = log.root().unwrap();

    let proof = log.prove(0).unwrap();
    assert!(proof.verify(&commitment.to_bytes(), &root));

    let mut tampered_bytes = commitment.to_bytes();
    tampered_bytes[10] ^= 0xFF; // flip a byte inside the salt
    assert!(!proof.verify(&tampered_bytes, &root));
}

/// A commitment's own `verify` (does this plaintext match this
/// commitment?) and its Merkle inclusion proof (is this commitment in
/// this batch?) are independent checks -- an invoice can pass one and
/// fail the other, and a caller relying on batch inclusion alone would
/// wrongly treat forged fields as legitimate if it skipped the
/// commitment-level check.
#[test]
fn batch_inclusion_does_not_substitute_for_the_commitment_s_own_field_check() {
    let mut rng = OsRng;
    let fields = sample_invoice(0);
    let commitment = InvoiceCommitment::compute(&fields, &mut rng);

    let mut log = MerkleLog::new();
    log.append(&commitment.to_bytes());
    let root = log.root().unwrap();
    let proof = log.prove(0).unwrap();

    // Included in the batch: yes.
    assert!(proof.verify(&commitment.to_bytes(), &root));

    // But forged fields (a different amount) do not match the
    // commitment's hash, regardless of batch inclusion.
    let forged_fields = InvoiceFields {
        amount_minor_units: fields.amount_minor_units + 999,
        ..fields
    };
    assert!(!commitment.verify(&forged_fields));
}
