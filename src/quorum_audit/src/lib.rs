//! Tamper-evident audit log core: hash-chained entries, per-node
//! co-signatures, reconciliation (divergence detection), and the receipt
//! shape for external notarization. Phase 2 of the threshold-quorum
//! roadmap.
//!
//! Same design principle as `quorum_core`/`ciphersettle_core`: this crate
//! has zero networking. `quorum_node` wires it to real mTLS; this module
//! only defines what a valid append is and what "the logs agree" means.
//!
//! ## The core trick: "no single node can silently rewrite"
//!
//! Every entry commits to the hash of the entry before it
//! (`entry_hash = H(prev_hash || seq || event)`), and [`AuditLog::try_append`]
//! refuses anything that doesn't extend the log's *current* tip. That means
//! rewriting entry `i` on one node's copy either:
//!   - leaves that node's own later entries mismatched against the new
//!     (recomputed) hash of entry `i` -- `verify_chain` catches it locally, or
//!   - if the attacker painstakingly recomputes every entry after `i` too
//!     (fully re-deriving the tail of *their own* copy) to keep their own
//!     chain internally consistent, [`AuditLog::diverges_from`] still
//!     catches it the moment that node's copy is compared against any
//!     other node's, because the other nodes never saw the rewritten
//!     history and won't have co-signed it.
//! That second case is exactly why co-signatures and cross-node
//! reconciliation both matter: a self-consistent *local* chain proves
//! nothing on its own. Multi-node signing plus reconciliation is what
//! stops it, and external notarization (below) is what stops it even for
//! a colluding *majority* of nodes -- see this module's `notary` types.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Hash = [u8; 32];
pub const GENESIS_HASH: Hash = [0u8; 32];

/// The business content of one audit event. Deliberately metadata-only --
/// no ciphertext, no plaintext, ever -- mirroring the canister's
/// `get_audit_log` shape and `ciphersettle_core::audit_action_for`'s
/// action-string vocabulary directly (see `quorum_orchestrator` for where
/// that reuse happens).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub invoice_id: String,
    pub actor: String,
    pub action: String,
    pub timestamp_unix_ms: u64,
}

fn hash_entry(prev_hash: &Hash, seq: u64, event: &AuditEvent) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash);
    hasher.update(seq.to_be_bytes());
    hasher.update(serde_json::to_vec(event).expect("AuditEvent always serializes"));
    let out = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&out);
    h
}

/// One hash-chained, (eventually) multi-signed log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: Hash,
    pub entry_hash: Hash,
    pub event: AuditEvent,
    /// node_id -> raw ed25519 signature bytes over `entry_hash`.
    /// Deliberately a set of INDIVIDUAL signatures, not a combined
    /// threshold signature: this layer's job is individual
    /// accountability ("node 2 personally attests to this exact entry"),
    /// a different property from the derive protocol's threshold
    /// agreement ("some k-of-n subset agreed to derive X" without
    /// necessarily saying which). "Whichever k nodes participated in the
    /// triggering derive call" (the roadmap's phrasing) co-sign here.
    pub signatures: BTreeMap<usize, Vec<u8>>,
}

impl AuditEntry {
    pub fn verify_hash(&self) -> bool {
        hash_entry(&self.prev_hash, self.seq, &self.event) == self.entry_hash
    }

    /// Audit finding A4 migration note: `ed25519_dalek::Signature::
    /// from_bytes` changed from fallible (`Result`, 1.x, which validated
    /// the S-component's range at parse time) to infallible (2.x, which
    /// defers that check to `verify` itself) -- and now takes a fixed-size
    /// `&[u8; 64]` rather than a runtime-length-checked `&[u8]`. The
    /// wrong-length case (`sig_bytes` not exactly 64 bytes -- malformed
    /// or truncated data, not a cryptographic failure) is now handled
    /// explicitly via `try_into()` below, rather than being folded into
    /// the same `Result` `from_bytes` used to return in 1.x. Same
    /// observable behavior (`false` for anything malformed), different
    /// mechanism.
    pub fn verify_signature(&self, node_id: usize, public_key: &VerifyingKey) -> bool {
        let Some(sig_bytes) = self.signatures.get(&node_id) else {
            return false;
        };
        let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_array);
        public_key.verify(&self.entry_hash, &sig).is_ok()
    }
}

/// One node's local replica of the log.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The two copies agree up to `seq - 1` but disagree at `seq`.
    HashMismatch { seq: u64 },
    /// The two copies agree on every entry they both have, but have a
    /// different number of entries (one is behind, not necessarily
    /// tampered -- e.g. a node that was offline during an append).
    LengthMismatch { ours: usize, theirs: usize },
}

impl AuditLog {
    pub fn tip_hash(&self) -> Hash {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(GENESIS_HASH)
    }

    pub fn next_seq(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Builds (but does not append) the next entry that would validly
    /// chain from this log's current tip. Signing/appending happens via
    /// [`AuditLog::try_append`] once co-signatures are collected --
    /// mirroring the real flow: propose, collect signatures from
    /// participating nodes, then append everywhere that agreed.
    pub fn propose_next(&self, event: AuditEvent) -> AuditEntry {
        let seq = self.next_seq();
        let prev_hash = self.tip_hash();
        let entry_hash = hash_entry(&prev_hash, seq, &event);
        AuditEntry {
            seq,
            prev_hash,
            entry_hash,
            event,
            signatures: BTreeMap::new(),
        }
    }

    /// Appends `entry` iff it validly extends this log's current tip and
    /// its own hash is internally consistent; otherwise returns an error
    /// WITHOUT mutating the log. This refusal is the actual mechanism
    /// behind "no single node can silently rewrite": every honest node
    /// enforces it locally, regardless of who's asking -- including its
    /// own operator.
    pub fn try_append(&mut self, entry: AuditEntry) -> Result<(), String> {
        self.check_extends(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// Read-only form of the checks in [`AuditLog::try_append`]: would this
    /// entry be accepted as the next entry of this log right now? Nodes use
    /// it to decide whether to cast a (pending) co-signing vote without
    /// mutating the log (roadmap T1-1 / TASK-011).
    pub fn check_extends(&self, entry: &AuditEntry) -> Result<(), String> {
        if entry.seq != self.next_seq() {
            return Err(format!(
                "entry seq {} does not extend this log's current length {}",
                entry.seq,
                self.next_seq()
            ));
        }
        if entry.prev_hash != self.tip_hash() {
            return Err(
                "entry's prev_hash does not match this log's current tip -- refusing a fork/rewrite attempt"
                    .to_string(),
            );
        }
        if !entry.verify_hash() {
            return Err("entry_hash does not match recomputed hash of its own content".to_string());
        }
        Ok(())
    }

    /// Merges a newly-arrived signature into an already-appended entry
    /// (the common case: node A appends with only its own signature, then
    /// later receives node B's signature on the same entry to merge in).
    pub fn merge_signature(
        &mut self,
        seq: u64,
        node_id: usize,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let entry = self
            .entries
            .get_mut(seq as usize)
            .ok_or_else(|| format!("no entry at seq {seq}"))?;
        entry.signatures.insert(node_id, signature);
        Ok(())
    }

    /// Full internal chain verification: every entry's hash is correct and
    /// links to the previous one, from genesis. This alone does NOT prove
    /// the log hasn't been rewritten -- a sufficiently careful attacker
    /// can recompute an entirely self-consistent alternate chain. That's
    /// exactly why [`AuditLog::diverges_from`] (cross-node) and external
    /// notarization both exist; see this module's doc comment.
    pub fn verify_chain(&self) -> Result<(), String> {
        let mut prev = GENESIS_HASH;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.seq as usize != i {
                return Err(format!("entry at position {i} has seq {}", entry.seq));
            }
            if entry.prev_hash != prev {
                return Err(format!(
                    "entry {i}'s prev_hash does not match the previous entry's hash"
                ));
            }
            if !entry.verify_hash() {
                return Err(format!(
                    "entry {i}'s hash does not match its own content -- this copy has been tampered with"
                ));
            }
            prev = entry.entry_hash;
        }
        Ok(())
    }

    /// The reconciliation check: compares this log against another node's
    /// reported copy and returns the first point of disagreement, if any.
    /// Run pairwise across every quorum node's replica on a schedule;
    /// alert on any `Some(_)`.
    pub fn diverges_from(&self, other: &AuditLog) -> Option<Divergence> {
        let n = self.entries.len().min(other.entries.len());
        for i in 0..n {
            if self.entries[i].entry_hash != other.entries[i].entry_hash {
                return Some(Divergence::HashMismatch { seq: i as u64 });
            }
        }
        if self.entries.len() != other.entries.len() {
            return Some(Divergence::LengthMismatch {
                ours: self.entries.len(),
                theirs: other.entries.len(),
            });
        }
        None
    }

    pub fn filter_by_invoice<'a>(&'a self, invoice_id: Option<&str>) -> Vec<&'a AuditEntry> {
        self.entries
            .iter()
            .filter(|e| invoice_id.map_or(true, |id| e.event.invoice_id == id))
            .collect()
    }

    /// Builds a majority-agreed reference log from several nodes' reported
    /// copies, for reconciliation to compare every individual copy against
    /// -- instead of picking one named node's copy as "the truth."
    ///
    /// ## Phase 4 Stage F: closing Finding 2.2
    /// The original reconciliation demo (`quorum_orchestrator`) compared
    /// every node's copy pairwise against node 0's, with node 0 picked
    /// only because it's first in a config list, not because anything
    /// establishes it as trustworthy. That inverts the audit log's own
    /// threat model: "no single node can rewrite history" ends up
    /// depending on node 0 specifically not being the compromised one --
    /// exactly the single point of trust hash-chaining and multi-node
    /// signing were supposed to remove.
    ///
    /// This builds the reference the honest way instead: for each
    /// sequence number, take a hash-value vote across every log that has
    /// an entry there, and keep the entry only a strict majority of
    /// respondents agree on. A node being *behind* (no entry at that seq
    /// yet) doesn't count against it or skew the vote -- only nodes that
    /// actually report a (disagreeing) entry at that seq do. Voting stops
    /// at the first sequence number with no majority winner, since no
    /// entry could have validly chained past a point nobody agrees on.
    ///
    /// This is still not perfect Byzantine fault tolerance -- a majority
    /// of *reporting* nodes colluding to rewrite history the same way
    /// would still win the vote, which is precisely why external
    /// notarization (this module's `notary` types) exists as a check
    /// that doesn't depend on the quorum's own honesty at all. But it is
    /// strictly better than trusting one hardcoded node, and it's the
    /// specific "majority/median check" this module's docs call for
    /// (the fix for the hardcoded-reference-node defect recorded as
    /// Finding 2.2 in the project's Phase 4 review).
    pub fn majority_reference(logs: &BTreeMap<usize, AuditLog>) -> AuditLog {
        let max_len = logs.values().map(|l| l.entries.len()).max().unwrap_or(0);
        let mut reference_entries: Vec<AuditEntry> = Vec::new();

        'seq: for seq in 0..max_len {
            let mut votes: Vec<(Hash, &AuditEntry)> = Vec::new();
            for log in logs.values() {
                if let Some(entry) = log.entries.get(seq) {
                    votes.push((entry.entry_hash, entry));
                }
            }
            if votes.is_empty() {
                break 'seq;
            }
            let mut counts: BTreeMap<Hash, usize> = BTreeMap::new();
            for (hash, _) in &votes {
                *counts.entry(*hash).or_insert(0) += 1;
            }
            let (winning_hash, winning_count) = counts
                .iter()
                .max_by_key(|(_, count)| **count)
                .map(|(h, c)| (*h, *c))
                .unwrap();
            if winning_count * 2 <= votes.len() {
                // No strict majority at this seq -- stop extending the
                // reference here rather than guessing; reconciliation
                // will correctly report every node as diverging (or
                // behind) from this point on, which is the honest
                // outcome when there's no agreement to anchor to.
                break 'seq;
            }
            let winning_entry = votes.iter().find(|(h, _)| *h == winning_hash).unwrap().1;
            reference_entries.push(winning_entry.clone());
        }

        AuditLog {
            entries: reference_entries,
        }
    }
}

pub fn sign_entry_hash(keypair: &SigningKey, entry_hash: &Hash) -> Vec<u8> {
    keypair.sign(entry_hash).to_bytes().to_vec()
}

// ---------------------------------------------------------------------
// External notarization. This crate only defines the receipt shape; the
// actual "somewhere outside every quorum member's control" destination
// (an RFC 3161 TSA, a public git commit, a third-party transparency-log
// service -- the roadmap names all three) is `quorum_notary`'s job.
// ---------------------------------------------------------------------

/// A published anchor: proof that a given root hash existed at a given
/// time, attested by a party outside the quorum's own control. Stops even
/// a colluding *majority* of quorum nodes from rewriting history
/// undetected after the fact -- reconciliation alone only stops a
/// *minority* of dishonest nodes, since a majority could reconcile with
/// each other on a rewritten history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationReceipt {
    pub sequence: u64,
    pub root_hash: Hash,
    pub notarized_at_unix_ms: u64,
    /// The notary's own signature over `signable_bytes(..)`, so the
    /// receipt is independently verifiable without trusting whoever hands
    /// it to you -- including not trusting the quorum operator who might
    /// relay it.
    pub notary_signature: Vec<u8>,
}

impl NotarizationReceipt {
    pub fn signable_bytes(sequence: u64, root_hash: &Hash, notarized_at_unix_ms: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 + 8);
        buf.extend_from_slice(&sequence.to_be_bytes());
        buf.extend_from_slice(root_hash);
        buf.extend_from_slice(&notarized_at_unix_ms.to_be_bytes());
        buf
    }

    /// See `AuditEntry::verify_signature`'s doc comment for why the
    /// wrong-length case is now handled via `try_into()` rather than
    /// `Signature::from_bytes` itself (infallible in 2.x, fixed-size
    /// input).
    pub fn verify(&self, notary_public_key: &VerifyingKey) -> bool {
        let bytes = Self::signable_bytes(self.sequence, &self.root_hash, self.notarized_at_unix_ms);
        let Ok(sig_array) = <[u8; 64]>::try_from(self.notary_signature.as_slice()) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_array);
        notary_public_key.verify(&bytes, &sig).is_ok()
    }
}

/// Wire message shape for the external notary service (`quorum_notary`).
/// Shared here (rather than duplicated) since both the notary binary and
/// any client of it (the orchestrator, playing "whoever runs the
/// scheduled notarization job") need to agree on it exactly.
pub mod wire {
    use super::NotarizationReceipt;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum NotaryMessage {
        NotarizeRequest { root_hash: [u8; 32] },
        NotarizeResponse { receipt: NotarizationReceipt },
        ListRequest,
        ListResponse { receipts: Vec<NotarizationReceipt> },
    }
}

/// One node's "pending co-signing vote" slot (T1-1, extracted so the race
/// semantics can be tested deterministically with an injected clock instead
/// of by hoping two real proposers collide -- see `vote_slot_tests`).
///
/// A node grants at most one entry hash per `seq` until that vote is
/// resolved by a commit (`on_commit`) or expires after `ttl_ms`.
///
/// KNOWN HAZARD (review finding R-2, NEEDS_HUMAN_REVIEW): expiry lets a node
/// vote for a second, different entry at the same `seq`. If proposer A is
/// slower than the TTL, two different entries can each gather a quorum.
/// `vote_slot_tests::ttl_expiry_can_split_quorums_documented_hazard` pins
/// this behaviour so it cannot be forgotten or silently "fixed" by accident.
#[derive(Debug, Clone, Copy, Default)]
pub struct VoteSlot {
    pending: Option<PendingVote>,
}

#[derive(Debug, Clone, Copy)]
struct PendingVote {
    seq: u64,
    entry_hash: Hash,
    cast_at_ms: u64,
}

impl VoteSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to cast a vote for `entry_hash` at `seq`. `Err` carries the
    /// refusal reason. Re-voting for the SAME hash is always allowed (and
    /// refreshes the timestamp), so a proposer retrying its own entry is
    /// never blocked by itself.
    pub fn try_vote(
        &mut self,
        seq: u64,
        entry_hash: Hash,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<(), String> {
        if let Some(p) = self.pending.as_ref() {
            if p.seq == seq
                && p.entry_hash != entry_hash
                && now_ms.saturating_sub(p.cast_at_ms) < ttl_ms
            {
                return Err(format!(
                    "already voted for a different entry at seq {seq}; awaiting its commit"
                ));
            }
        }
        self.pending = Some(PendingVote {
            seq,
            entry_hash,
            cast_at_ms: now_ms,
        });
        Ok(())
    }

    /// An entry at `committed_seq` was appended: any vote at or below it is resolved.
    pub fn on_commit(&mut self, committed_seq: u64) {
        if self.pending.map_or(false, |p| p.seq <= committed_seq) {
            self.pending = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn event(invoice_id: &str, action: &str) -> AuditEvent {
        AuditEvent {
            invoice_id: invoice_id.to_string(),
            actor: "test-actor".to_string(),
            action: action.to_string(),
            timestamp_unix_ms: 1_700_000_000_000,
        }
    }

    /// T1-1: casting a co-signing vote must not mutate the log, and two
    /// competing proposals for the same seq must each pass the read-only
    /// check independently (the node's pending-vote slot, not the log,
    /// arbitrates between them).
    #[test]
    fn check_extends_does_not_mutate_and_admits_competing_proposals() {
        let log = AuditLog::default();
        let a = log.propose_next(event("inv-race", "action_a"));
        let b = log.propose_next(event("inv-race", "action_b"));
        assert_ne!(a.entry_hash, b.entry_hash);
        assert!(log.check_extends(&a).is_ok());
        assert!(log.check_extends(&b).is_ok());
        assert_eq!(log.entries.len(), 0, "check_extends must be read-only");
    }

    #[test]
    fn check_extends_rejects_what_try_append_rejects() {
        let mut log = AuditLog::default();
        let a = log.propose_next(event("inv-race", "action_a"));
        let b = log.propose_next(event("inv-race", "action_b"));
        log.try_append(a).unwrap();
        // b was built against the empty log; it is now a stale fork.
        assert!(log.check_extends(&b).is_err());
        assert!(log.clone().try_append(b).is_err());
    }

    #[test]
    fn honest_chain_of_three_entries_verifies() {
        let mut log = AuditLog::default();
        for i in 0..3 {
            let e = log.propose_next(event("inv-1", &format!("action-{i}")));
            log.try_append(e).unwrap();
        }
        assert!(log.verify_chain().is_ok());
        assert_eq!(log.entries.len(), 3);
    }

    #[test]
    fn append_rejects_an_entry_that_does_not_extend_the_tip() {
        let mut log = AuditLog::default();
        let e0 = log.propose_next(event("inv-1", "a"));
        log.try_append(e0).unwrap();

        // Craft a "replacement" entry 1 that skips ahead as if entry 0
        // never happened (prev_hash = GENESIS instead of the real tip).
        let forged = AuditEntry {
            seq: 1,
            prev_hash: GENESIS_HASH,
            entry_hash: hash_entry(&GENESIS_HASH, 1, &event("inv-1", "forged")),
            event: event("inv-1", "forged"),
            signatures: BTreeMap::new(),
        };
        assert!(log.try_append(forged).is_err());
    }

    #[test]
    fn tampering_with_an_entrys_content_breaks_verify_chain() {
        let mut log = AuditLog::default();
        for i in 0..3 {
            let e = log.propose_next(event("inv-1", &format!("action-{i}")));
            log.try_append(e).unwrap();
        }
        // Directly mutate entry 1's event content without recomputing its
        // hash or any downstream hash -- simulating a naive rewrite.
        log.entries[1].event.action = "tampered".to_string();
        assert!(log.verify_chain().is_err());
    }

    #[test]
    fn a_fully_recomputed_alternate_chain_still_diverges_from_an_honest_copy() {
        // The harder case: an attacker who tampers with entry 1 AND
        // recomputes every hash after it, so their own copy still passes
        // verify_chain() in isolation.
        let mut honest = AuditLog::default();
        for i in 0..3 {
            let e = honest.propose_next(event("inv-1", &format!("action-{i}")));
            honest.try_append(e).unwrap();
        }

        let mut tampered = AuditLog::default();
        let e0 = tampered.propose_next(event("inv-1", "action-0"));
        tampered.try_append(e0).unwrap();
        let e1 = tampered.propose_next(event("inv-1", "TAMPERED"));
        tampered.try_append(e1).unwrap();
        let e2 = tampered.propose_next(event("inv-1", "action-2"));
        tampered.try_append(e2).unwrap();

        assert!(
            tampered.verify_chain().is_ok(),
            "attacker's own copy is self-consistent"
        );
        assert_eq!(
            tampered.diverges_from(&honest),
            Some(Divergence::HashMismatch { seq: 1 }),
            "but reconciliation against an honest copy still catches it"
        );
    }

    #[test]
    fn a_node_that_is_simply_behind_reports_length_mismatch_not_hash_mismatch() {
        let mut ahead = AuditLog::default();
        let mut behind = AuditLog::default();
        for i in 0..3 {
            let e = ahead.propose_next(event("inv-1", &format!("action-{i}")));
            ahead.try_append(e.clone()).unwrap();
            if i < 2 {
                behind.try_append(e).unwrap();
            }
        }
        assert_eq!(
            behind.diverges_from(&ahead),
            Some(Divergence::LengthMismatch { ours: 2, theirs: 3 })
        );
    }

    #[test]
    fn signatures_verify_against_the_correct_node_and_reject_a_forged_one() {
        let mut csprng = OsRng {};
        let honest_kp = SigningKey::generate(&mut csprng);
        let attacker_kp = SigningKey::generate(&mut csprng);

        let mut log = AuditLog::default();
        let mut entry = log.propose_next(event("inv-1", "key_derived_bank"));
        let sig = sign_entry_hash(&honest_kp, &entry.entry_hash);
        entry.signatures.insert(0, sig);
        log.try_append(entry).unwrap();

        assert!(log.entries[0].verify_signature(0, &honest_kp.verifying_key()));
        assert!(!log.entries[0].verify_signature(0, &attacker_kp.verifying_key()));
        assert!(!log.entries[0].verify_signature(1, &honest_kp.verifying_key()));
        // no sig for node 1 at all
    }

    #[test]
    fn majority_reference_outvotes_a_tampered_minority_including_node_zero() {
        // The specific case the old "always trust node 0" reconciliation
        // code (Finding 2.2) could NOT handle: node 0 itself is the
        // tampered one. Nodes 1-4 honestly agree; node 0's copy has a
        // fully self-consistent but different entry 1.
        let mut honest = AuditLog::default();
        for i in 0..3 {
            let e = honest.propose_next(event("inv-1", &format!("action-{i}")));
            honest.try_append(e).unwrap();
        }

        let mut tampered_node0 = AuditLog::default();
        let e0 = tampered_node0.propose_next(event("inv-1", "action-0"));
        tampered_node0.try_append(e0).unwrap();
        let e1 = tampered_node0.propose_next(event("inv-1", "TAMPERED-BY-NODE-0"));
        tampered_node0.try_append(e1).unwrap();
        let e2 = tampered_node0.propose_next(event("inv-1", "action-2"));
        tampered_node0.try_append(e2).unwrap();
        assert!(
            tampered_node0.verify_chain().is_ok(),
            "node 0's own rewritten copy is self-consistent"
        );

        let mut logs = BTreeMap::new();
        logs.insert(0, tampered_node0.clone());
        logs.insert(1, honest.clone());
        logs.insert(2, honest.clone());
        logs.insert(3, honest.clone());
        logs.insert(4, honest.clone());

        let reference = AuditLog::majority_reference(&logs);

        // The old code (`&logs[&0]` as reference) would have produced
        // "node 0 matches itself; nodes 1-4 all diverge" -- exactly
        // backwards. The majority-vote reference gets it right:
        assert_eq!(reference.entries.len(), 3);
        assert_eq!(
            reference.entries[1].event.action, "action-1",
            "majority wins, not node 0"
        );
        assert_eq!(
            reference.diverges_from(&tampered_node0),
            Some(Divergence::HashMismatch { seq: 1 }),
            "node 0 -- the tampered one -- is correctly flagged as diverging from the majority"
        );
        assert_eq!(
            reference.diverges_from(&honest),
            None,
            "the honest majority correctly matches the reference"
        );
    }

    #[test]
    fn majority_reference_treats_a_behind_node_as_behind_not_a_vote_against_the_majority() {
        let mut ahead = AuditLog::default();
        for i in 0..2 {
            let e = ahead.propose_next(event("inv-1", &format!("action-{i}")));
            ahead.try_append(e).unwrap();
        }
        let behind = AuditLog::default(); // never received anything

        let mut logs = BTreeMap::new();
        logs.insert(0, ahead.clone());
        logs.insert(1, ahead.clone());
        logs.insert(2, ahead.clone());
        logs.insert(3, behind.clone());

        let reference = AuditLog::majority_reference(&logs);
        assert_eq!(
            reference.entries.len(),
            2,
            "an empty, honestly-behind log shouldn't drag the vote down"
        );
        assert_eq!(
            reference.diverges_from(&behind),
            Some(Divergence::LengthMismatch { ours: 2, theirs: 0 }),
            "reported as behind, not as tampering"
        );
    }

    #[test]
    fn notarization_receipt_round_trips_and_rejects_forgery() {
        let mut csprng = OsRng {};
        let notary_kp = SigningKey::generate(&mut csprng);
        let attacker_kp = SigningKey::generate(&mut csprng);

        let root_hash = [7u8; 32];
        let bytes = NotarizationReceipt::signable_bytes(5, &root_hash, 1_800_000_000_000);
        let sig = notary_kp.sign(&bytes).to_bytes().to_vec();
        let receipt = NotarizationReceipt {
            sequence: 5,
            root_hash,
            notarized_at_unix_ms: 1_800_000_000_000,
            notary_signature: sig,
        };
        assert!(receipt.verify(&notary_kp.verifying_key()));
        assert!(!receipt.verify(&attacker_kp.verifying_key()));
    }
}

#[cfg(test)]
mod vote_slot_tests {
    use super::*;

    const TTL: u64 = 5_000;
    const N: usize = 5;
    const QUORUM: usize = 3; // t + 1 with t = 2

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    /// Delivers proposals A (hash 1) and B (hash 2) to N fresh nodes. Bit `i` of
    /// `order` set means node `i` receives B before A. All timestamps are equal,
    /// so nothing expires. Returns (grants_for_A, grants_for_B).
    fn run(order: u32, reachable: &[usize]) -> (usize, usize) {
        let (mut a, mut b) = (0, 0);
        for &i in reachable {
            let mut slot = VoteSlot::new();
            let b_first = (order >> i) & 1 == 1;
            let (first, second) = if b_first { (h(2), h(1)) } else { (h(1), h(2)) };
            let _ = slot.try_vote(0, first, 0, TTL);
            let second_ok = slot.try_vote(0, second, 0, TTL).is_ok();
            assert!(
                !second_ok,
                "a node must never grant both entries at one seq inside the TTL"
            );
            if b_first {
                b += 1
            } else {
                a += 1
            }
        }
        (a, b)
    }

    /// SAFETY, exhaustive: over all 2^5 = 32 delivery orders with every node
    /// reachable, exactly one proposal reaches quorum -- never both, never neither.
    #[test]
    fn exactly_one_proposer_wins_under_every_delivery_order() {
        let all: Vec<usize> = (0..N).collect();
        for order in 0..(1u32 << N) {
            let (a, b) = run(order, &all);
            assert_eq!(a + b, N);
            let (a_wins, b_wins) = (a >= QUORUM, b >= QUORUM);
            assert!(
                a_wins ^ b_wins,
                "order {order:05b}: A={a} B={b} must have exactly one winner"
            );
        }
    }

    /// LIVENESS: with one node down (4 reachable) a 2/2 split is possible under
    /// some orders, so neither commits that round -- but once the TTL passes a
    /// re-proposal is granted everywhere and reaches quorum.
    #[test]
    fn split_round_recovers_after_ttl_and_never_double_commits() {
        let four = [0usize, 1, 2, 3];
        let mut saw_split = false;
        for order in 0..(1u32 << N) {
            let (a, b) = run(order, &four);
            assert!(
                !(a >= QUORUM && b >= QUORUM),
                "double commit with 4 reachable nodes"
            );
            if a < QUORUM && b < QUORUM {
                saw_split = true;
                // A retries with a later timestamp, after every vote has expired.
                let mut granted = 0;
                for i in four {
                    let mut slot = VoteSlot::new();
                    let first = if (order >> i) & 1 == 1 { h(2) } else { h(1) };
                    slot.try_vote(0, first, 0, TTL).unwrap();
                    if slot.try_vote(0, h(1), TTL + 1, TTL).is_ok() {
                        granted += 1;
                    }
                }
                assert!(
                    granted >= QUORUM,
                    "retry after TTL must be able to reach quorum, got {granted}"
                );
            }
        }
        assert!(
            saw_split,
            "the 2/2 split shape must actually occur among the 32 orders (test premise)"
        );
    }

    /// Committing the winner clears the slot, so the next seq is not blocked.
    #[test]
    fn commit_clears_the_slot_for_the_next_seq() {
        let mut slot = VoteSlot::new();
        slot.try_vote(0, h(1), 0, TTL).unwrap();
        slot.on_commit(0);
        assert!(slot.try_vote(1, h(9), 1, TTL).is_ok());
        // Committing an OLDER seq must not clear a newer pending vote.
        slot.on_commit(0);
        assert!(slot.try_vote(1, h(8), 2, TTL).is_err());
    }

    #[test]
    fn same_hash_revote_is_idempotent_and_clock_going_backwards_does_not_panic() {
        let mut slot = VoteSlot::new();
        slot.try_vote(0, h(1), 10_000, TTL).unwrap();
        assert!(slot.try_vote(0, h(1), 10_001, TTL).is_ok());
        // now < cast_at (non-monotonic input) saturates to 0 elapsed => still blocked.
        assert!(slot.try_vote(0, h(2), 0, TTL).is_err());
    }

    /// R-2 (documented hazard, asserts CURRENT behaviour): after the TTL a node
    /// grants a different entry at the same seq, so with overlap the two entries
    /// can both reach quorum. If a future change makes this test fail because
    /// the hazard was fixed, update finding R-2 in SECURITY_REVIEW.md, not just
    /// this test.
    #[test]
    fn ttl_expiry_can_split_quorums_documented_hazard() {
        // A collects votes from nodes 0,1,2 at t=0 (slow to finish replicating);
        // B arrives after the TTL and collects nodes 2,3,4 -- node 2 voted twice.
        let mut nodes = [VoteSlot::new(); N];
        let a_votes = [0usize, 1, 2]
            .iter()
            .filter(|&&i| nodes[i].try_vote(0, h(1), 0, TTL).is_ok())
            .count();
        let b_votes = [2usize, 3, 4]
            .iter()
            .filter(|&&i| nodes[i].try_vote(0, h(2), TTL + 1, TTL).is_ok())
            .count();
        assert!(
            a_votes >= QUORUM && b_votes >= QUORUM,
            "two conflicting quorums at one seq (R-2)"
        );
    }
}
