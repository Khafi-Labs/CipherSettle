//! Append-only Merkle log (Merkle Mountain Range) over invoice
//! commitments.
//!
//! ## Why this exists
//!
//! [`crate::commitment::InvoiceCommitment`] gives a single invoice a
//! salted, hiding, binding hash -- but a caller holding one commitment
//! has no cheap way to prove it belongs to a larger batch, or that a
//! batch's contents haven't been silently altered after the fact,
//! without either re-sending every commitment in the batch or trusting
//! whoever assembled it. This module adds that layer: commitments (or
//! any other 32-byte-hashable data) are appended to a log; the log
//! exposes one short root; anyone holding a leaf plus its
//! [`MerkleProof`] can verify inclusion under that root without seeing
//! any other leaf.
//!
//! ## What this is not
//!
//! **This module does not solve the oracle problem on its own.** A
//! Merkle proof only ever proves "this leaf is included under this
//! root" -- it says nothing about *who computed the root* or whether
//! they were entitled to. If `quorum_service` computes and signs the
//! root itself, a node checking a proof against it has verified
//! nothing beyond what it could already verify against the existing
//! shared-secret HMAC (see `quorum_core::verify_derive_auth`) -- the
//! trust relationship is unchanged, only its shape looks more
//! sophisticated. This module is only a genuine improvement on the
//! oracle problem once the root is signed by an actual external
//! authority (e.g. a `VerificationAttestation`-shaped object from
//! FRA/e-Finance) and that signature is what nodes check -- something
//! this codebase does not yet do anywhere, and which depends on
//! confirming an external API/signature surface this project has not
//! confirmed exists. Wiring a proof against a self-signed root into
//! any authorization path would be worse than not building this at
//! all, because it would look like a fix for a problem it does not
//! fix. Until that confirmation happens, treat this module as useful
//! purely for batching, storage/bandwidth efficiency, and
//! privacy-preserving auditability (`quorum_audit`) -- not as an
//! authorization mechanism.
//!
//! ## Construction
//!
//! This is a *Merkle Mountain Range*: an append-only structure that,
//! at any leaf count `n`, is a forest of one or more perfectly
//! balanced binary "mountains" whose sizes are exactly the powers of
//! two in `n`'s binary representation, ordered left-to-right from the
//! earliest leaves (largest mountain) to the most recent (smallest).
//! This shape falls out of the classic append algorithm (each new leaf
//! merges with the previous one if they're the same height, carrying
//! upward exactly like binary addition) but this implementation
//! derives it directly from `n`'s bit pattern instead of maintaining
//! incremental state, trading O(log n) amortized append for a simpler,
//! more obviously-correct implementation that recomputes what it needs
//! on demand. A production deployment appending at high volume may
//! want to maintain the peak stack incrementally instead; the on-disk
//! /ordering semantics would be identical.
//!
//! Every mountain's own root ("peak") is combined into a single log
//! root by [`bag_peaks`] -- see that function's doc comment for the
//! exact, independently-reimplementable fold.
//!
//! As in `commitment.rs`, leaf and internal-node hashing use distinct
//! domain tags, which stops a second-preimage attack where an internal
//! node's hash is replayed as if it were a leaf (the same construction
//! RFC 6962 uses for Certificate Transparency logs, for the same
//! reason).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Bumped whenever the leaf hashing, node hashing, or bagging fold
/// changes. [`MerkleProof::verify`] refuses to check a proof claiming
/// an unsupported version rather than silently reinterpreting it under
/// today's construction -- same reasoning as
/// `InvoiceCommitment::version`.
pub const MERKLE_VERSION: u8 = 1;

const LEAF_DOMAIN_TAG: &[u8] = b"ciphersettle-merkle-leaf-v1";
const NODE_DOMAIN_TAG: &[u8] = b"ciphersettle-merkle-node-v1";

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN_TAG);
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN_TAG);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Combines mountain peak hashes, given left-to-right (earliest
/// leaves' mountain first), into a single root, as a right fold:
///
/// ```text
/// root = H(P0, H(P1, H(P2, ... H(P_{k-2}, P_{k-1}) ...)))
/// ```
///
/// With one peak, the root *is* that peak's hash unchanged -- so a log
/// whose leaf count is exactly a power of two (a single mountain) has
/// a root identical to that mountain's own Merkle root, with no extra
/// hashing layered on top. Panics if `peaks` is empty; callers only
/// reach this with at least one peak (an empty log has no root at
/// all, see [`MerkleLog::root`]).
fn bag_peaks(peaks: &[[u8; 32]]) -> [u8; 32] {
    let mut iter = peaks.iter().rev();
    let mut acc = *iter.next().expect("bag_peaks called with no peaks");
    for p in iter {
        acc = hash_node(p, &acc);
    }
    acc
}

/// Decomposes `leaf_count` into `(start, size)` ranges, one per
/// mountain, left-to-right, largest (earliest leaves) first. `size` is
/// always a power of two; the ranges partition `0..leaf_count` exactly.
fn mountains(leaf_count: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut start = 0u64;
    for bit in (0..64).rev() {
        let size = 1u64 << bit;
        if leaf_count & size != 0 {
            ranges.push((start, size));
            start += size;
        }
    }
    ranges
}

/// Which side of the current hash a proof step's sibling sits on, so
/// [`MerkleProof::verify`] concatenates in the right order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Left,
    Right,
}

/// An append-only log of 32-byte leaf hashes. Holds every leaf's raw
/// bytes (not just its hash) so it can produce proofs for any past
/// leaf on demand; a deployment that needs to discard raw leaf data
/// after it's no longer needed should keep leaves elsewhere and store
/// only hashes here (swap `Vec<Vec<u8>>` for `Vec<[u8; 32]>` and call
/// sites accordingly -- everything else is unchanged).
#[derive(Debug, Clone, Default)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Appends `data` (arbitrary bytes -- e.g. an
    /// `InvoiceCommitment::to_bytes()`) as a new leaf, hashed with this
    /// module's leaf domain tag. Returns the new leaf's index.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        self.leaves.push(hash_leaf(data));
        (self.leaves.len() - 1) as u64
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    fn subtree_root(&self, start: u64, size: u64) -> [u8; 32] {
        if size == 1 {
            return self.leaves[start as usize];
        }
        let half = size / 2;
        let left = self.subtree_root(start, half);
        let right = self.subtree_root(start + half, half);
        hash_node(&left, &right)
    }

    /// This log's current root, or `None` if it has no leaves yet --
    /// there is no well-defined root over zero leaves, and returning
    /// e.g. an all-zero placeholder would invite a caller to compare
    /// against it by accident.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        let peaks: Vec<[u8; 32]> = mountains(self.len())
            .into_iter()
            .map(|(start, size)| self.subtree_root(start, size))
            .collect();
        Some(bag_peaks(&peaks))
    }

    /// Builds the bottom-up (leaf-to-peak) sibling path for `idx`
    /// inside the mountain spanning `start..start+size`, appending each
    /// step to `out`, and returns that mountain's own root.
    fn build_path(
        &self,
        start: u64,
        size: u64,
        idx: u64,
        out: &mut Vec<(Side, [u8; 32])>,
    ) -> [u8; 32] {
        if size == 1 {
            return self.leaves[start as usize];
        }
        let half = size / 2;
        if idx < start + half {
            let left = self.build_path(start, half, idx, out);
            let right = self.subtree_root(start + half, half);
            out.push((Side::Right, right));
            hash_node(&left, &right)
        } else {
            let right = self.build_path(start + half, half, idx, out);
            let left = self.subtree_root(start, half);
            out.push((Side::Left, left));
            hash_node(&left, &right)
        }
    }

    /// Produces a proof that the leaf at `leaf_index` is included in
    /// this log's current root. `None` if `leaf_index` is out of
    /// range. The proof is only valid against the root *as it stood
    /// when this was called* -- appending more leaves afterward
    /// changes the root (see this module's doc comment on why that's
    /// a feature, not a limitation: a consistency proof between two
    /// roots is a separate, not-yet-built primitive, analogous to
    /// Certificate Transparency's).
    pub fn prove(&self, leaf_index: u64) -> Option<MerkleProof> {
        if leaf_index >= self.len() {
            return None;
        }
        let ranges = mountains(self.len());
        let (peak_index, &(start, size)) = ranges
            .iter()
            .enumerate()
            .find(|(_, &(start, size))| leaf_index >= start && leaf_index < start + size)?;
        let mut siblings = Vec::new();
        self.build_path(start, size, leaf_index, &mut siblings);
        let peaks: Vec<[u8; 32]> = ranges
            .iter()
            .map(|&(start, size)| self.subtree_root(start, size))
            .collect();
        Some(MerkleProof {
            version: MERKLE_VERSION,
            leaf_index,
            leaf_count: self.len(),
            siblings,
            peak_index,
            peaks,
        })
    }
}

/// A self-contained proof that some leaf is included in a Merkle log
/// with a particular root, at a particular leaf count. Verifying it
/// requires only the original leaf's bytes and the claimed root --
/// nothing else in the log needs to be revealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub version: u8,
    pub leaf_index: u64,
    /// The log's total leaf count when this proof was generated.
    /// Carried along so a verifier can tell *which* root this proof
    /// was made against without needing to be told out of band (a
    /// leaf count uniquely determines the mountain decomposition, and
    /// therefore which of the `peaks` entries is this leaf's own
    /// mountain).
    pub leaf_count: u64,
    /// Sibling hashes from the leaf up to its mountain's own peak,
    /// bottom-up.
    pub siblings: Vec<(Side, [u8; 32])>,
    /// Index into `peaks` of the mountain this leaf belongs to.
    pub peak_index: usize,
    /// Every mountain peak hash, left-to-right, at proof-generation
    /// time -- needed to re-derive the full root via [`bag_peaks`]
    /// once this leaf's own mountain has been checked.
    pub peaks: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Checks that `leaf_data`, combined with this proof's sibling
    /// path and peaks, reproduces `expected_root` -- without needing
    /// access to the log itself or any other leaf. Uses constant-time
    /// comparison for the final hash checks, consistent with how this
    /// workspace already treats hash/digest comparisons elsewhere
    /// (`InvoiceCommitment::verify`, audit finding A15) -- defense in
    /// depth rather than load-bearing, since a Merkle root is public
    /// once published.
    pub fn verify(&self, leaf_data: &[u8], expected_root: &[u8; 32]) -> bool {
        if self.version != MERKLE_VERSION {
            return false;
        }
        if self.peak_index >= self.peaks.len() {
            return false;
        }
        // Internal consistency: the peaks this proof carries must
        // actually match the mountain shape implied by leaf_count, or
        // a proof could claim a leaf_count/peaks pairing that never
        // corresponded to any real log state.
        let expected_mountain_count = mountains(self.leaf_count).len();
        if self.peaks.len() != expected_mountain_count {
            return false;
        }

        let mut acc = hash_leaf(leaf_data);
        for (side, sibling) in &self.siblings {
            acc = match side {
                Side::Left => hash_node(sibling, &acc),
                Side::Right => hash_node(&acc, sibling),
            };
        }

        if bool::from(!acc.ct_eq(&self.peaks[self.peak_index])) {
            return false;
        }

        let root = bag_peaks(&self.peaks);
        bool::from(root.ct_eq(expected_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_log(n: usize) -> (MerkleLog, Vec<Vec<u8>>) {
        let mut log = MerkleLog::new();
        let mut data = Vec::new();
        for i in 0..n {
            let leaf = format!("invoice-commitment-{i}").into_bytes();
            log.append(&leaf);
            data.push(leaf);
        }
        (log, data)
    }

    /// Every leaf, at every log size from 1 to 16 (deliberately
    /// crossing several power-of-two boundaries, since that's where a
    /// mountain-decomposition bug would show up), produces a proof
    /// that verifies against that log's own root.
    #[test]
    fn every_leaf_proves_inclusion_at_every_size_up_to_sixteen() {
        for n in 1..=16 {
            let (log, data) = build_log(n);
            let root = log.root().expect("non-empty log has a root");
            for (i, leaf) in data.iter().enumerate().take(n) {
                let proof = log
                    .prove(i as u64)
                    .unwrap_or_else(|| panic!("missing proof for leaf {i} at n={n}"));
                assert!(
                    proof.verify(leaf, &root),
                    "leaf {i} of {n} failed to verify against the log's own root"
                );
            }
        }
    }

    #[test]
    fn a_single_leaf_log_roots_to_its_own_leaf_hash() {
        let mut log = MerkleLog::new();
        log.append(b"only-leaf");
        let root = log.root().unwrap();
        assert_eq!(root, hash_leaf(b"only-leaf"));
    }

    #[test]
    fn an_empty_log_has_no_root() {
        let log = MerkleLog::new();
        assert!(log.root().is_none());
    }

    #[test]
    fn appending_more_leaves_changes_the_root() {
        let (mut log, _) = build_log(3);
        let root_before = log.root().unwrap();
        log.append(b"a-fourth-leaf");
        let root_after = log.root().unwrap();
        assert_ne!(root_before, root_after);
    }

    /// A proof made at one leaf count does not verify against the
    /// root after more leaves are appended -- it should require a
    /// fresh proof, not silently "still work" against a root it
    /// wasn't made for.
    #[test]
    fn a_proof_does_not_verify_against_a_later_root() {
        let (mut log, data) = build_log(3);
        let proof = log.prove(1).unwrap();
        log.append(b"a-fourth-leaf");
        let new_root = log.root().unwrap();
        assert!(!proof.verify(&data[1], &new_root));
    }

    #[test]
    fn tampering_with_the_leaf_data_is_detected() {
        let (log, data) = build_log(5);
        let root = log.root().unwrap();
        let proof = log.prove(2).unwrap();
        assert!(proof.verify(&data[2], &root));
        assert!(!proof.verify(b"some-other-invoice-entirely", &root));
    }

    #[test]
    fn tampering_with_a_sibling_hash_is_detected() {
        let (log, data) = build_log(6);
        let root = log.root().unwrap();
        let mut proof = log.prove(4).unwrap();
        assert!(
            !proof.siblings.is_empty(),
            "test needs at least one sibling to tamper with"
        );
        proof.siblings[0].1[0] ^= 0xFF;
        assert!(!proof.verify(&data[4], &root));
    }

    #[test]
    fn tampering_with_a_peak_hash_is_detected() {
        let (log, data) = build_log(6);
        let root = log.root().unwrap();
        let mut proof = log.prove(0).unwrap();
        let other_peak = (proof.peak_index + 1) % proof.peaks.len();
        proof.peaks[other_peak][0] ^= 0xFF;
        assert!(!proof.verify(&data[0], &root));
    }

    #[test]
    fn a_proof_claiming_an_unsupported_version_is_rejected() {
        let (log, data) = build_log(4);
        let root = log.root().unwrap();
        let mut proof = log.prove(0).unwrap();
        proof.version = 99;
        assert!(!proof.verify(&data[0], &root));
    }

    /// A proof carrying a `leaf_count` that doesn't match its own
    /// `peaks` list (an internal-consistency forgery, not just a bad
    /// hash) must be rejected rather than accepted on the strength of
    /// its hashes alone.
    #[test]
    fn a_proof_with_mismatched_leaf_count_and_peaks_is_rejected() {
        let (log, data) = build_log(4);
        let root = log.root().unwrap();
        let mut proof = log.prove(0).unwrap();
        proof.leaf_count = 999;
        assert!(!proof.verify(&data[0], &root));
    }

    /// Two unrelated logs of the same size should essentially never
    /// share a root -- a basic sanity check that leaf content actually
    /// drives the root, not just leaf count.
    #[test]
    fn unrelated_logs_of_the_same_size_do_not_collide() {
        let (log_a, _) = build_log(7);
        let mut log_b = MerkleLog::new();
        for i in 0..7 {
            log_b.append(format!("totally-different-{i}").as_bytes());
        }
        assert_ne!(log_a.root().unwrap(), log_b.root().unwrap());
    }
}
