//! Feldman-VSS DKG and BLS threshold-derive primitives on `blstrs` only.
//!
//! Replaces the former `threshold_crypto` / `ff 0.6` / `pairing 0.16`
//! implementation. NEEDS_HUMAN_CRYPTO_REVIEW: this is a from-scratch
//! translation, not a verified equivalence.
//!
//! Conventions (a reviewer must confirm these):
//! - Secret scalars and Feldman commitments live in G1; signatures and
//!   sealed partials live in G2 ("minimal-pubkey-size" layout).
//! - Hash-to-G2 follows RFC 9380 via `blstrs`, with the DST below. Outputs
//!   are NOT compatible with the old `threshold_crypto` deployment: this
//!   is a cutover, never a mixed deployment.
//! - Node `i` evaluates the dealer polynomials at `x = i + 1`; `x = 0` is
//!   the group secret.
//!
//! Hardening over the spike (C-1, NEEDS_HUMAN_CRYPTO_REVIEW): a dealer
//! whose commitment does not have exactly `t + 1` coefficients is rejected
//! with a `Complaint` at receipt, instead of panicking later in `finalize`.
//! Decoding of commitments from the wire validates length and every point
//! (on-curve, in-subgroup) and never panics.

use base64::Engine;
use blstrs::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use group::{Curve, Group};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// Hash-to-G2 domain-separation tag (RFC 9380 naming).
pub const SIG_DST: &[u8] = b"CIPHERSETTLE_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_V1_";

pub const G2_COMPRESSED_SIZE: usize = 96;
pub const G1_COMPRESSED_SIZE: usize = 48;
pub const FR_BYTES: usize = 32;

/// Upper bound on commitment length accepted from the wire (degree + 1).
pub const MAX_COMMITMENT_POINTS: usize = 256;

/// Every node's DKG evaluation point is `node_id + 1`; `x = 0` is reserved
/// for the group secret and never evaluated by anyone.
pub fn point_of(node_id: usize) -> u64 {
    (node_id as u64) + 1
}

fn scalar_from_u64(x: u64) -> Scalar {
    Scalar::from(x)
}

/// Serializes a scalar to 32 big-endian bytes (DKG share wire format).
pub fn scalar_to_bytes(s: &Scalar) -> [u8; FR_BYTES] {
    s.to_bytes_be()
}

/// Inverse of [`scalar_to_bytes`]; `None` if the bytes are not a canonical
/// field element. Callers MUST treat `None` as a protocol fault.
pub fn scalar_from_bytes(bytes: &[u8; FR_BYTES]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_bytes_be(bytes))
}

fn hash_to_g2(msg: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, SIG_DST, &[])
}

// ---------------------------------------------------------------------
// Polynomials and commitments
// ---------------------------------------------------------------------

#[derive(Clone)]
pub struct Poly {
    coeffs: Vec<Scalar>,
}

impl Drop for Poly {
    fn drop(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = Scalar::ZERO;
        }
    }
}

impl Poly {
    /// Random polynomial of degree `t` (`t + 1` coefficients).
    pub fn random<R: rand::RngCore>(t: usize, rng: &mut R) -> Self {
        Self {
            coeffs: (0..=t).map(|_| Scalar::random(&mut *rng)).collect(),
        }
    }

    pub fn evaluate(&self, x: u64) -> Scalar {
        let x = scalar_from_u64(x);
        let mut acc = Scalar::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    pub fn commitment(&self) -> Commitment {
        let g = G1Projective::generator();
        Commitment {
            coeffs: self.coeffs.iter().map(|c| g * c).collect(),
        }
    }
}

/// Feldman commitment: the dealer polynomial's coefficients times G1.
#[derive(Clone, PartialEq, Eq)]
pub struct Commitment {
    coeffs: Vec<G1Projective>,
}

impl Commitment {
    pub fn evaluate(&self, x: u64) -> G1Projective {
        let x = scalar_from_u64(x);
        let mut acc = G1Projective::identity();
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    /// Number of coefficients (degree + 1).
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    fn add(&self, other: &Commitment) -> Result<Commitment, String> {
        if self.coeffs.len() != other.coeffs.len() {
            return Err("commitments from different-degree dealers".to_string());
        }
        Ok(Commitment {
            coeffs: self
                .coeffs
                .iter()
                .zip(other.coeffs.iter())
                .map(|(a, b)| a + b)
                .collect(),
        })
    }

    /// Concatenated compressed G1 points.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.coeffs.len() * G1_COMPRESSED_SIZE);
        for c in &self.coeffs {
            out.extend_from_slice(&c.to_affine().to_compressed());
        }
        out
    }

    /// Validating decode: length multiple of 48, 1..=MAX points, every
    /// point on-curve and in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(G1_COMPRESSED_SIZE) {
            return Err(format!(
                "commitment length {} is not a positive multiple of {G1_COMPRESSED_SIZE}",
                bytes.len()
            ));
        }
        let n = bytes.len() / G1_COMPRESSED_SIZE;
        if n > MAX_COMMITMENT_POINTS {
            return Err(format!(
                "commitment has {n} points, more than the {MAX_COMMITMENT_POINTS} allowed"
            ));
        }
        let mut coeffs = Vec::with_capacity(n);
        for chunk in bytes.chunks_exact(G1_COMPRESSED_SIZE) {
            let arr: [u8; G1_COMPRESSED_SIZE] =
                chunk.try_into().map_err(|_| "chunk size".to_string())?;
            let p: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
            coeffs.push(
                p.ok_or_else(|| "invalid compressed G1 point in commitment".to_string())?
                    .into(),
            );
        }
        Ok(Commitment { coeffs })
    }
}

fn ser_b64<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn de_b64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Commitment({} points)", self.coeffs.len())
    }
}

impl Serialize for Commitment {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ser_b64(&self.to_bytes(), s)
    }
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = de_b64(d)?;
        Commitment::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------
// DKG session
// ---------------------------------------------------------------------

/// A share or commitment failed verification against its dealer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complaint {
    pub accuser: usize,
    pub accused_dealer: usize,
    pub reason: String,
}

/// One node's view of an in-progress DKG round.
pub struct DkgSession {
    my_id: usize,
    n: usize,
    t: usize,
    my_poly: Poly,
    commitments: BTreeMap<usize, Commitment>,
    received_shares: BTreeMap<usize, Scalar>,
    complaints: Vec<Complaint>,
}

impl DkgSession {
    pub fn new<R: rand::RngCore>(
        my_id: usize,
        n: usize,
        t: usize,
        rng: &mut R,
    ) -> (Self, Commitment) {
        let my_poly = Poly::random(t, rng);
        let my_commitment = my_poly.commitment();
        (
            Self {
                my_id,
                n,
                t,
                my_poly,
                commitments: BTreeMap::new(),
                received_shares: BTreeMap::new(),
                complaints: Vec::new(),
            },
            my_commitment,
        )
    }

    /// The share this node (as dealer) owes `peer_id`, in wire form.
    pub fn share_for(&self, peer_id: usize) -> [u8; FR_BYTES] {
        scalar_to_bytes(&self.my_poly.evaluate(point_of(peer_id)))
    }

    fn complain(&mut self, dealer_id: usize, reason: &str) -> Complaint {
        let c = Complaint {
            accuser: self.my_id,
            accused_dealer: dealer_id,
            reason: reason.to_string(),
        };
        self.complaints.push(c.clone());
        c
    }

    /// C-1 (NEEDS_HUMAN_CRYPTO_REVIEW): rejects a dealer id outside `0..n`
    /// and any commitment whose length is not exactly `t + 1`.
    pub fn receive_commitment(
        &mut self,
        dealer_id: usize,
        commitment: Commitment,
    ) -> Result<(), Complaint> {
        if dealer_id >= self.n {
            return Err(self.complain(dealer_id, "commitment from a dealer id outside 0..n"));
        }
        if commitment.len() != self.t + 1 {
            return Err(self.complain(
                dealer_id,
                "commitment degree is not t (wrong number of coefficients)",
            ));
        }
        self.commitments.insert(dealer_id, commitment);
        Ok(())
    }

    pub fn receive_share(
        &mut self,
        dealer_id: usize,
        share_bytes: [u8; FR_BYTES],
    ) -> Result<(), Complaint> {
        let Some(share) = scalar_from_bytes(&share_bytes) else {
            return Err(self.complain(
                dealer_id,
                "share bytes do not decode to a valid field element",
            ));
        };
        let Some(commitment) = self.commitments.get(&dealer_id).cloned() else {
            return Err(self.complain(
                dealer_id,
                "received a share before that dealer's commitment",
            ));
        };
        let expected = commitment.evaluate(point_of(self.my_id));
        let actual = G1Projective::generator() * share;
        if actual != expected {
            return Err(self.complain(
                dealer_id,
                "share fails Feldman verification against dealer's own commitment",
            ));
        }
        self.received_shares.insert(dealer_id, share);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.complaints.is_empty()
            && self.commitments.len() == self.n
            && self.received_shares.len() == self.n
    }

    pub fn outstanding_complaints(&self) -> &[Complaint] {
        &self.complaints
    }

    pub fn finalize(self) -> Result<(SecretKeyShare, PublicKeySet), String> {
        if !self.is_ready() {
            return Err(format!(
                "DKG not ready: {}/{} commitments, {}/{} shares, {} outstanding complaint(s)",
                self.commitments.len(),
                self.n,
                self.received_shares.len(),
                self.n,
                self.complaints.len()
            ));
        }
        let sum: Scalar = self
            .received_shares
            .values()
            .fold(Scalar::ZERO, |acc, s| acc + s);

        let mut it = self.commitments.values();
        let first = it.next().ok_or("no commitments received")?.clone();
        let mut group_commitment = first;
        for c in it {
            group_commitment = group_commitment.add(c)?;
        }
        let group_pks = PublicKeySet {
            commitment: group_commitment,
        };
        let secret_share = SecretKeyShare { sk: sum };

        if secret_share.public_key_share() != group_pks.public_key_share(self.my_id) {
            return Err(
                "final share does not match the group's public commitment -- DKG failed silently"
                    .to_string(),
            );
        }
        Ok((secret_share, group_pks))
    }
}

// ---------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------

/// A node's final DKG share. Zeroed on drop (best effort; see roadmap T3-2).
pub struct SecretKeyShare {
    sk: Scalar,
}

impl Drop for SecretKeyShare {
    fn drop(&mut self) {
        self.sk = Scalar::ZERO;
    }
}

impl std::fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKeyShare(..)")
    }
}

impl SecretKeyShare {
    pub fn public_key_share(&self) -> G1Projective {
        G1Projective::generator() * self.sk
    }

    pub fn sign(&self, msg: &[u8]) -> SignatureShare {
        SignatureShare(hash_to_g2(msg) * self.sk)
    }

    /// Gap 1: exports the raw share (32 big-endian bytes, DKG wire encoding)
    /// so the caller can ENCRYPT it for at-rest storage. The caller MUST wrap
    /// it in a zeroizing container and never log or write it unencrypted.
    /// NEEDS_HUMAN_CRYPTO_REVIEW.
    pub fn export_for_sealed_storage(&self) -> [u8; FR_BYTES] {
        scalar_to_bytes(&self.sk)
    }

    /// Gap 1: inverse of [`Self::export_for_sealed_storage`] with the same
    /// check `DkgSession::finalize` performs: canonical scalar AND
    /// `share * G1 == group_pks.public_key_share(my_id)`.
    pub fn restore_verified(
        bytes: &[u8; FR_BYTES],
        my_id: usize,
        group_pks: &PublicKeySet,
    ) -> Result<Self, String> {
        let sk = scalar_from_bytes(bytes)
            .ok_or_else(|| "stored share is not a canonical field element".to_string())?;
        let share = SecretKeyShare { sk };
        if share.public_key_share() != group_pks.public_key_share(my_id) {
            return Err(
                "stored share does not match the group public commitment for this node id"
                    .to_string(),
            );
        }
        Ok(share)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureShare(G2Projective);

impl SignatureShare {
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_affine().to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self, String> {
        let p: Option<G2Affine> = G2Affine::from_compressed(bytes).into();
        p.map(|a| SignatureShare(a.into()))
            .ok_or_else(|| "invalid G2 compressed encoding".to_string())
    }

    /// A uniformly random valid G2 point, for adversarial tests that need
    /// a well-formed but wrong partial.
    pub fn random_for_test<R: rand::RngCore>(rng: &mut R) -> Self {
        SignatureShare(G2Projective::random(&mut *rng))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(G2Projective);

impl Signature {
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        self.0.to_affine().to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self, String> {
        let p: Option<G2Affine> = G2Affine::from_compressed(bytes).into();
        p.map(|a| Signature(a.into()))
            .ok_or_else(|| "invalid G2 compressed encoding".to_string())
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes.iter().take(8) {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str("..");
    s
}

impl std::fmt::Debug for SignatureShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignatureShare({})", hex_preview(&self.to_bytes()))
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({})", hex_preview(&self.to_bytes()))
    }
}

/// Group public key material: the summed Feldman commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeySet {
    commitment: Commitment,
}

impl PublicKeySet {
    /// The group public key (commitment to the group secret).
    pub fn public_key(&self) -> G1Projective {
        self.commitment.coeffs[0]
    }

    pub fn public_key_share(&self, id: usize) -> G1Projective {
        self.commitment.evaluate(point_of(id))
    }

    /// Gap 1: SHA-256 over a domain tag and the compressed commitment points;
    /// a stable public identifier of the group key (AEAD AAD and operator pin).
    pub fn fingerprint_sha256(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciphersettle/group-pubkey-fingerprint/v1");
        h.update(self.commitment.to_bytes());
        h.finalize().into()
    }

    /// The threshold `t` (degree of the group polynomial); `t + 1` shares
    /// are needed to sign.
    pub fn threshold(&self) -> usize {
        self.commitment.len() - 1
    }
}

impl Serialize for PublicKeySet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.commitment.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicKeySet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(PublicKeySet {
            commitment: Commitment::deserialize(d)?,
        })
    }
}

fn lagrange_at_zero(my_x: u64, other_xs: &[u64]) -> Result<Scalar, String> {
    let my_x = scalar_from_u64(my_x);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &xj in other_xs {
        let xj = scalar_from_u64(xj);
        num *= xj;
        den *= xj - my_x;
    }
    let inv = Option::<Scalar>::from(den.invert()).ok_or("duplicate evaluation points")?;
    Ok(num * inv)
}

fn pairing_eq(a1: &G1Projective, a2: &G2Projective, b1: &G1Projective, b2: &G2Projective) -> bool {
    pairing(&a1.to_affine(), &a2.to_affine()) == pairing(&b1.to_affine(), &b2.to_affine())
}

pub fn sign_partial(secret_share: &SecretKeyShare, identity: &str) -> SignatureShare {
    secret_share.sign(identity.as_bytes())
}

pub fn verify_partial(
    group_pks: &PublicKeySet,
    node_id: usize,
    identity: &str,
    partial: &SignatureShare,
) -> bool {
    pairing_eq(
        &group_pks.public_key_share(node_id),
        &hash_to_g2(identity.as_bytes()),
        &G1Projective::generator(),
        &partial.0,
    )
}

/// Seals this node's genuine partial for `identity` under `recipient` and
/// attaches a NIZK (`quorum_vetseal::nizk`) that the ciphertext encrypts
/// `H(identity)^s` for the same `s` behind this node's public key share.
///
/// The raw scalar never leaves this module: it is copied into a temporary
/// buffer only to call the vetseal API, and that buffer is overwritten
/// afterwards (best effort, see roadmap T3-2).
pub fn seal_partial_with_proof<R: rand::RngCore>(
    secret_share: &SecretKeyShare,
    identity: &str,
    recipient: &quorum_vetseal::TransportPublicKey,
    rng: &mut R,
) -> Result<
    (
        quorum_vetseal::SealedShare,
        quorum_vetseal::nizk::EncryptionProof,
    ),
    quorum_vetseal::VetsealError,
> {
    // vetseal's nizk decodes scalars with `from_repr` (little-endian), NOT the
    // big-endian DKG wire format used by `scalar_to_bytes`.
    let mut sk_bytes = [0u8; FR_BYTES];
    sk_bytes.copy_from_slice(secret_share.sk.to_repr().as_ref());
    let identity_hash = hash_to_g2(identity.as_bytes()).to_affine().to_compressed();
    let result =
        quorum_vetseal::nizk::seal_share_with_proof(&sk_bytes, &identity_hash, recipient, rng);
    sk_bytes.fill(0);
    result.map(|(sealed, _pk_share, proof)| (sealed, proof))
}

/// Verifies a node's sealed partial BEFORE it is combined. The expected
/// public key share is derived here from the group's Feldman commitment
/// for `node_id` -- never taken from the node -- so a valid proof means
/// "this ciphertext encrypts THIS node's genuine partial for `identity`",
/// closing the binding gap `nizk.rs` documents.
///
/// NEEDS_HUMAN_CRYPTO_REVIEW: the proof system itself is unreviewed.
pub fn verify_sealed_partial(
    group_pks: &PublicKeySet,
    node_id: usize,
    identity: &str,
    recipient: &quorum_vetseal::TransportPublicKey,
    sealed: &quorum_vetseal::SealedShare,
    proof: &quorum_vetseal::nizk::EncryptionProof,
) -> bool {
    let pk_bytes = group_pks
        .public_key_share(node_id)
        .to_affine()
        .to_compressed();
    let Ok(pk_share) = quorum_vetseal::nizk::PublicKeyShare::from_bytes(&pk_bytes) else {
        return false;
    };
    let identity_hash = hash_to_g2(identity.as_bytes()).to_affine().to_compressed();
    quorum_vetseal::nizk::verify_sealed_share(sealed, &pk_share, &identity_hash, recipient, proof)
        .unwrap_or(false)
}

/// Lagrange-combines at least `t + 1` partials. Fewer is an error.
pub fn combine(
    group_pks: &PublicKeySet,
    shares: &BTreeMap<usize, SignatureShare>,
) -> Result<Signature, String> {
    if shares.len() <= group_pks.threshold() {
        return Err(format!(
            "combine failed: {} share(s) provided, need at least {}",
            shares.len(),
            group_pks.threshold() + 1
        ));
    }
    let xs: Vec<u64> = shares.keys().map(|&id| point_of(id)).collect();
    let mut acc = G2Projective::identity();
    for (&id, share) in shares {
        let my_x = point_of(id);
        let others: Vec<u64> = xs.iter().copied().filter(|&x| x != my_x).collect();
        acc += share.0 * lagrange_at_zero(my_x, &others)?;
    }
    Ok(Signature(acc))
}

pub fn verify_combined(group_pks: &PublicKeySet, identity: &str, sig: &Signature) -> bool {
    pairing_eq(
        &group_pks.public_key(),
        &hash_to_g2(identity.as_bytes()),
        &G1Projective::generator(),
        &sig.0,
    )
}

/// Test-support (used by `quorum_vetseal`'s tests): compressed hash-to-G2.
#[doc(hidden)]
pub fn hash_identity_to_g2_for_test(msg: &[u8]) -> [u8; G2_COMPRESSED_SIZE] {
    hash_to_g2(msg).to_affine().to_compressed()
}

/// Test-support: compressed G1 encoding.
#[doc(hidden)]
pub fn g1_to_bytes_for_test(p: &G1Projective) -> [u8; G1_COMPRESSED_SIZE] {
    p.to_affine().to_compressed()
}

/// Test-support: a node's raw secret scalar in wire form. Never call from
/// production code.
impl SecretKeyShare {
    #[doc(hidden)]
    pub fn secret_scalar_bytes_for_test(&self) -> [u8; FR_BYTES] {
        let repr = self.sk.to_repr();
        let mut out = [0u8; FR_BYTES];
        out.copy_from_slice(repr.as_ref());
        out
    }
}
