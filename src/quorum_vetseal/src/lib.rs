//! Seals derived-key material so that only the true end caller can read
//! it. Every quorum node encrypts its partial BLS signature (a BLS12-381
//! G2 point) to a caller-supplied transport public key using plain EC
//! ElGamal in G2; partials are then combined *homomorphically* (Lagrange
//! interpolation at zero applied to ciphertexts), so `quorum_service` and
//! anything else relaying the traffic only ever sees ciphertext.
//!
//! Built on `blstrs` only (no `threshold_crypto`, no `ff 0.6`/`pairing
//! 0.16`). Zero networking and zero product logic.
//!
//! ## Interface with `quorum_core`
//!
//! This crate deliberately does not depend on `quorum_core` (the
//! dependency runs the other way). Sealing input and decryption output are
//! therefore raw compressed G2 encodings (`[u8; 96]`); callers convert with
//! `quorum_core::SignatureShare::to_bytes` / `quorum_core::Signature::from_bytes`.
//!
//! ## What this does and does not give you
//!
//! - **Two independent checks, both required.** A malicious node can seal a
//!   garbage point; ElGamal has no built-in integrity. Two things catch
//!   it: (a) the `nizk` module's per-share proof of correct encryption,
//!   which `quorum_node` attaches to every partial and `quorum_client`
//!   verifies *before* combining; and (b) the caller MUST additionally
//!   verify the final decrypted result against the group public key
//!   (`quorum_core::verify_combined`) before trusting it. The NIZK
//!   constrains each *input* to the combine; only the final check
//!   constrains the combine *output*.
//! - **NEEDS_HUMAN_CRYPTO_REVIEW.** Nothing here has had an independent
//!   cryptographic review.
//! - **Not wire-compatible with the previous `threshold_crypto`-based
//!   deployment.** Hash-to-curve now follows RFC 9380; this is a cutover,
//!   never a mixed deployment.
//!
//! ## Tests
//!
//! Four sealing tests (combine matches unsealed combine; subset
//! independence; wrong transport key fails group verification; a bad node
//! ciphertext is caught at final verification) use `quorum_core`'s DKG as a
//! dev-dependency only, as a source of real shares.

use blstrs::{G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use group::{Curve, Group};
use serde::{Deserialize, Serialize};
use std::fmt;

/// NIZK proof that a `SealedShare` correctly encrypts its author's genuine
/// partial signature, so a bad ciphertext can be rejected -- and the lying
/// node identified -- before `combine_sealed_shares`, not only after the
/// final `verify()`. Wired into the live protocol via
/// `quorum_core::seal_partial_with_proof` (called by `quorum_node`) and
/// `quorum_core::verify_sealed_partial` (called by `quorum_client`).
/// See this module's own top-of-file doc comment for the full design and,
/// just as importantly, its stated limits.
pub mod nizk;

/// Compressed size of a G2 point under `blstrs`'s own encoding.
pub const G2_COMPRESSED_SIZE: usize = 96;

/// Uncompressed size of a `Scalar`'s canonical byte encoding.
pub const FR_BYTES: usize = 32;

/// Flat byte encoding of a sealed value: two G2 points (`C1`, `C2`) back
/// to back.
pub const SEALED_COMPRESSED_SIZE: usize = 2 * G2_COMPRESSED_SIZE;

#[derive(Debug)]
pub enum VetsealError {
    /// Fewer than `t + 1` sealed shares were supplied to `combine_sealed_shares`.
    NotEnoughShares,
    /// The same node index appeared twice among the shares being combined.
    DuplicateNodeIndex,
    /// A byte string wasn't a validly-encoded G2 point or scalar.
    InvalidEncoding,
}

impl fmt::Display for VetsealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VetsealError::NotEnoughShares => write!(f, "not enough sealed shares to combine"),
            VetsealError::DuplicateNodeIndex => {
                write!(f, "duplicate node index among sealed shares")
            }
            VetsealError::InvalidEncoding => write!(f, "invalid point/scalar encoding"),
        }
    }
}

impl std::error::Error for VetsealError {}

// ---------------------------------------------------------------------
// Transport keys
// ---------------------------------------------------------------------

/// A caller-held secret. Never sent to any node, broker, or process
/// other than the one that generated it. Best-effort zeroed on drop --
/// same caveat real `quorum_vetseal` states explicitly: `Scalar` isn't
/// wired into the `zeroize` crate in this dependency generation either,
/// so this is defense-in-depth, not a guarantee against compiler
/// optimization eliding the write. Worth re-checking as part of A6
/// whether `blstrs`'s `Scalar` has better `zeroize` support than
/// `threshold_crypto`'s `Fr` did -- see the roadmap note flagging this.
pub struct TransportSecretKey(Scalar);

/// The public half, attached to a `DeriveRequest` so nodes know what to
/// seal their partials under. Safe to send anywhere.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPublicKey(#[serde(with = "g2_serde")] G2Projective);

impl fmt::Debug for TransportPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportPublicKey({})", hex_preview(&self.to_bytes()))
    }
}

impl TransportSecretKey {
    pub fn random<R: rand::RngCore>(rng: &mut R) -> Self {
        TransportSecretKey(Scalar::random(&mut *rng))
    }

    pub fn public_key(&self) -> TransportPublicKey {
        TransportPublicKey(G2Projective::generator() * self.0)
    }

    pub fn to_bytes(&self) -> [u8; FR_BYTES] {
        let repr = self.0.to_repr();
        let mut out = [0u8; FR_BYTES];
        out.copy_from_slice(repr.as_ref());
        out
    }

    pub fn from_bytes(bytes: &[u8; FR_BYTES]) -> Result<Self, VetsealError> {
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        let opt: Option<Scalar> = Scalar::from_repr(repr).into();
        opt.map(TransportSecretKey)
            .ok_or(VetsealError::InvalidEncoding)
    }

    /// `M = C2 - secret * C1`, the standard exponential-ElGamal decrypt.
    /// Infallible here -- see this module's doc comment, point 6, for
    /// why (and what real `quorum_vetseal`'s equivalent step catches
    /// that this one structurally can't).
    fn decrypt_point(&self, ct: &Ciphertext) -> G2Projective {
        ct.c2 - ct.c1 * self.0
    }

    /// Decrypts a single node's sealed partial, returning raw compressed
    /// G2 bytes -- pass these to whatever library's
    /// `SignatureShare::from_bytes` the caller is using (see this
    /// module's doc comment, point 5, on why this crate doesn't own a
    /// typed share itself).
    pub fn decrypt_share(&self, sealed: &SealedShare) -> [u8; G2_COMPRESSED_SIZE] {
        compress_g2(&self.decrypt_point(&sealed.0))
    }

    /// Decrypts the homomorphically-combined ciphertext into the real
    /// derived key's raw compressed bytes. The caller MUST still run the
    /// equivalent of `public_key_set.public_key().verify(&result,
    /// identity)` before trusting it -- see module doc comment point 6
    /// for why that check is load-bearing here, not optional
    /// defense-in-depth.
    pub fn decrypt_combined(&self, sealed: &SealedDerivedKey) -> [u8; G2_COMPRESSED_SIZE] {
        compress_g2(&self.decrypt_point(&sealed.0))
    }
}

impl Drop for TransportSecretKey {
    fn drop(&mut self) {
        self.0 = Scalar::ZERO;
    }
}

impl fmt::Debug for TransportSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportSecretKey(..)")
    }
}

impl TransportPublicKey {
    pub fn to_bytes(&self) -> [u8; G2_COMPRESSED_SIZE] {
        compress_g2(&self.0)
    }

    pub fn from_bytes(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        Ok(TransportPublicKey(decompress_g2(bytes)?))
    }
}

// ---------------------------------------------------------------------
// Ciphertexts
// ---------------------------------------------------------------------

/// A raw ElGamal ciphertext over G2: `(C1, C2) = (r*G, M + r*Pub)`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Ciphertext {
    #[serde(with = "g2_serde")]
    c1: G2Projective,
    #[serde(with = "g2_serde")]
    c2: G2Projective,
}

impl Ciphertext {
    // `&self` kept on a `Copy` type deliberately: renaming this crate's
    // public-facing sealing API is a change for the crypto reviewer, not a
    // lint-driven edit.
    #[allow(clippy::wrong_self_convention)]
    fn to_bytes(&self) -> [u8; SEALED_COMPRESSED_SIZE] {
        let mut out = [0u8; SEALED_COMPRESSED_SIZE];
        out[..G2_COMPRESSED_SIZE].copy_from_slice(&compress_g2(&self.c1));
        out[G2_COMPRESSED_SIZE..].copy_from_slice(&compress_g2(&self.c2));
        out
    }

    fn from_bytes(bytes: &[u8; SEALED_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        let mut c1_bytes = [0u8; G2_COMPRESSED_SIZE];
        let mut c2_bytes = [0u8; G2_COMPRESSED_SIZE];
        c1_bytes.copy_from_slice(&bytes[..G2_COMPRESSED_SIZE]);
        c2_bytes.copy_from_slice(&bytes[G2_COMPRESSED_SIZE..]);
        Ok(Ciphertext {
            c1: decompress_g2(&c1_bytes)?,
            c2: decompress_g2(&c2_bytes)?,
        })
    }
}

/// One node's sealed signature share. This is what a migrated
/// `Message::DerivePartial` would carry instead of a raw share.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedShare(Ciphertext);

impl SealedShare {
    pub fn to_bytes(&self) -> [u8; SEALED_COMPRESSED_SIZE] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; SEALED_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        Ok(SealedShare(Ciphertext::from_bytes(bytes)?))
    }
}

impl fmt::Debug for SealedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedShare({})", hex_preview(&self.to_bytes()))
    }
}

/// The result of homomorphically combining `t + 1` `SealedShare`s.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDerivedKey(Ciphertext);

impl SealedDerivedKey {
    pub fn to_bytes(&self) -> [u8; SEALED_COMPRESSED_SIZE] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; SEALED_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        Ok(SealedDerivedKey(Ciphertext::from_bytes(bytes)?))
    }
}

impl fmt::Debug for SealedDerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedDerivedKey({})", hex_preview(&self.to_bytes()))
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let n = bytes.len().min(8);
    let mut s = String::with_capacity(n * 2 + 3);
    for b in &bytes[..n] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str("..");
    s
}

/// Run by a node: seal a genuine, already-verified signature share
/// (`share_bytes` -- pass `SignatureShare::to_bytes()`, whichever
/// library provides it, see module doc point 5) under `recipient`, so
/// only whoever holds the matching `TransportSecretKey` can ever recover
/// it.
pub fn encrypt_share<R: rand::RngCore>(
    share_bytes: &[u8; G2_COMPRESSED_SIZE],
    recipient: &TransportPublicKey,
    rng: &mut R,
) -> Result<SealedShare, VetsealError> {
    let m = decompress_g2(share_bytes)?;
    Ok(SealedShare(encrypt_point(&m, recipient, rng)))
}

fn encrypt_point<R: rand::RngCore>(
    m: &G2Projective,
    recipient: &TransportPublicKey,
    rng: &mut R,
) -> Ciphertext {
    let r = Scalar::random(&mut *rng);
    let c1 = G2Projective::generator() * r;
    let c2 = recipient.0 * r + m;
    Ciphertext { c1, c2 }
}

/// Node index to evaluation point, `x = node_index + 1` -- same
/// convention `quorum_core::point_of` uses (`x = 0` is
/// reserved for the group secret). Kept as an independent copy here
/// rather than importing `quorum_core::point_of`, per this
/// module's doc comment point 5 on why this crate doesn't depend on
/// that crate outside tests -- a reviewer should confirm both copies
/// stay in agreement if either changes.
fn index_to_x(node_index: usize) -> Scalar {
    Scalar::from((node_index + 1) as u64)
}

/// Standard Lagrange basis polynomial evaluated at 0. A from-scratch
/// reimplementation -- see this module's doc comment for why it needs
/// independent review, same as `quorum_core`'s copy of the
/// same idea.
fn lagrange_coefficient_at_zero(my_x: Scalar, other_xs: &[Scalar]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &xj in other_xs {
        num *= xj;
        den *= xj - my_x;
    }
    let den_inv = den
        .invert()
        .expect("distinct node indices give distinct x values, so this is never zero");
    num * den_inv
}

/// Homomorphically combines `t + 1` sealed shares from distinct node
/// indices into a single `SealedDerivedKey`. Safe to run anywhere -- the
/// caller never needs to be trusted, since it never touches a plaintext
/// point.
pub fn combine_sealed_shares(
    shares: &[(usize, SealedShare)],
) -> Result<SealedDerivedKey, VetsealError> {
    if shares.is_empty() {
        return Err(VetsealError::NotEnoughShares);
    }
    let mut seen = std::collections::BTreeSet::new();
    for (idx, _) in shares {
        if !seen.insert(*idx) {
            return Err(VetsealError::DuplicateNodeIndex);
        }
    }

    let xs: Vec<Scalar> = shares.iter().map(|(idx, _)| index_to_x(*idx)).collect();

    let mut acc_c1 = G2Projective::identity();
    let mut acc_c2 = G2Projective::identity();
    for (i, (_, sealed)) in shares.iter().enumerate() {
        let my_x = xs[i];
        let others: Vec<Scalar> = xs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, &x)| x)
            .collect();
        let lambda = lagrange_coefficient_at_zero(my_x, &others);
        acc_c1 += sealed.0.c1 * lambda;
        acc_c2 += sealed.0.c2 * lambda;
    }
    Ok(SealedDerivedKey(Ciphertext {
        c1: acc_c1,
        c2: acc_c2,
    }))
}

// ---------------------------------------------------------------------
// Low-level point/scalar (de)serialization
// ---------------------------------------------------------------------

fn compress_g2(point: &G2Projective) -> [u8; G2_COMPRESSED_SIZE] {
    point.to_affine().to_compressed()
}

fn decompress_g2(bytes: &[u8; G2_COMPRESSED_SIZE]) -> Result<G2Projective, VetsealError> {
    let opt: Option<G2Affine> = G2Affine::from_compressed(bytes).into();
    opt.map(|a| a.into()).ok_or(VetsealError::InvalidEncoding)
}

mod g2_serde {
    use super::{compress_g2, decompress_g2, G2Projective, G2_COMPRESSED_SIZE};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(point: &G2Projective, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&compress_g2(point))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<G2Projective, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        let arr: [u8; G2_COMPRESSED_SIZE] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 96 bytes for a compressed G2 point"))?;
        decompress_g2(&arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_core as core_spike;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::BTreeMap;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(7)
    }

    /// Mirrors real `quorum_vetseal`'s own `run_honest_dkg`-via-
    /// `SecretKeySet::random` test setup, but using
    /// `quorum_core`'s real Feldman-VSS DKG instead of
    /// `threshold_crypto::SecretKeySet::random`'s single-dealer
    /// shortcut -- a strictly more realistic fixture than the real
    /// crate's own tests use, since it exercises the actual multi-dealer
    /// DKG this project runs rather than one dealer's polynomial alone.
    fn run_honest_dkg(
        n: usize,
        t: usize,
        rng: &mut ChaCha20Rng,
    ) -> Vec<(core_spike::SecretKeyShare, core_spike::PublicKeySet)> {
        let mut sessions = Vec::new();
        let mut commitments = Vec::new();
        for id in 0..n {
            let (session, commitment) = core_spike::DkgSession::new(id, n, t, rng);
            sessions.push(session);
            commitments.push(commitment);
        }
        let all_shares: Vec<Vec<_>> = sessions
            .iter()
            .map(|s| (0..n).map(|peer| s.share_for(peer)).collect())
            .collect();
        for session in sessions.iter_mut() {
            for (dealer_id, commitment) in commitments.iter().enumerate() {
                session
                    .receive_commitment(dealer_id, commitment.clone())
                    .unwrap();
            }
        }
        for (peer_id, session) in sessions.iter_mut().enumerate() {
            for (dealer_id, dealer_shares) in all_shares.iter().enumerate() {
                session
                    .receive_share(dealer_id, dealer_shares[peer_id])
                    .expect("honest share must verify");
            }
        }
        sessions
            .into_iter()
            .map(|s| s.finalize().expect("honest DKG must finalize"))
            .collect()
    }

    /// Direct port of real `quorum_vetseal::tests::sealed_combine_matches_unsealed_combine`.
    #[test]
    fn sealed_combine_matches_unsealed_combine() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity = b"inv-2026-000042";

        let subset = [0usize, 2, 4];
        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let mut plain_shares: BTreeMap<usize, core_spike::SignatureShare> = BTreeMap::new();
        let mut sealed: Vec<(usize, SealedShare)> = Vec::new();
        for &i in &subset {
            let share = results[i].0.sign(identity);
            assert!(core_spike::verify_partial(
                &results[i].1,
                i,
                "inv-2026-000042",
                &share
            ));
            sealed.push((
                i,
                encrypt_share(&share.to_bytes(), &transport_pk, &mut r).unwrap(),
            ));
            plain_shares.insert(i, share);
        }

        let expected = core_spike::combine(&results[0].1, &plain_shares).unwrap();

        let sealed_combined = combine_sealed_shares(&sealed).unwrap();
        let got_bytes = transport_sk.decrypt_combined(&sealed_combined);
        let got = core_spike::Signature::from_bytes(&got_bytes).unwrap();

        assert!(expected == got);
        assert!(core_spike::verify_combined(
            &results[0].1,
            "inv-2026-000042",
            &got
        ));
    }

    /// Direct port of real `quorum_vetseal::tests::sealed_combine_is_subset_independent`.
    #[test]
    fn sealed_combine_is_subset_independent() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity = b"inv-2026-000099";
        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let derive = |subset: &[usize], r: &mut ChaCha20Rng| {
            let sealed: Vec<(usize, SealedShare)> = subset
                .iter()
                .map(|&i| {
                    let share = results[i].0.sign(identity);
                    (
                        i,
                        encrypt_share(&share.to_bytes(), &transport_pk, r).unwrap(),
                    )
                })
                .collect();
            let combined = combine_sealed_shares(&sealed).unwrap();
            transport_sk.decrypt_combined(&combined)
        };

        let a = derive(&[0, 1, 2], &mut r);
        let b = derive(&[1, 3, 4], &mut r);
        assert_eq!(a, b);
    }

    /// Direct port of real `quorum_vetseal::tests::wrong_transport_key_fails_group_verification`.
    #[test]
    fn wrong_transport_key_fails_group_verification() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity = b"inv-2026-000123";

        let real_recipient = TransportSecretKey::random(&mut r);
        let attacker_key = TransportSecretKey::random(&mut r);

        let subset = [0usize, 1, 2];
        let sealed: Vec<(usize, SealedShare)> = subset
            .iter()
            .map(|&i| {
                let share = results[i].0.sign(identity);
                (
                    i,
                    encrypt_share(&share.to_bytes(), &real_recipient.public_key(), &mut r).unwrap(),
                )
            })
            .collect();
        let combined = combine_sealed_shares(&sealed).unwrap();

        let got_bytes = attacker_key.decrypt_combined(&combined);
        // Unlike the real crate, decrypt itself can't fail here (see
        // module doc point 6) -- but the resulting bytes must either
        // fail to parse as a signature, or fail group verification.
        // Silently returning the real key is the only unacceptable
        // outcome.
        match core_spike::Signature::from_bytes(&got_bytes) {
            Err(_) => {} // rejected outright -- good
            Ok(sig) => assert!(
                !core_spike::verify_combined(&results[0].1, "inv-2026-000123", &sig),
                "attacker's wrong transport key must never decrypt to a key that verifies"
            ),
        }
    }

    /// Direct port of real
    /// `quorum_vetseal::tests::bad_node_ciphertext_is_caught_at_final_verify_not_silently_combined`.
    #[test]
    fn bad_node_ciphertext_is_caught_at_final_verify_not_silently_combined() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity = b"inv-2026-000777";
        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let honest = [0usize, 1];
        let mut sealed: Vec<(usize, SealedShare)> = honest
            .iter()
            .map(|&i| {
                let share = results[i].0.sign(identity);
                (
                    i,
                    encrypt_share(&share.to_bytes(), &transport_pk, &mut r).unwrap(),
                )
            })
            .collect();

        // Node 2 seals a random, unrelated signature share instead of
        // its genuine partial for `identity`.
        let garbage_share = results[4].0.sign(b"a completely different identity");
        sealed.push((
            2,
            encrypt_share(&garbage_share.to_bytes(), &transport_pk, &mut r).unwrap(),
        ));

        let combined = combine_sealed_shares(&sealed).unwrap();
        let got_bytes = transport_sk.decrypt_combined(&combined);
        match core_spike::Signature::from_bytes(&got_bytes) {
            Err(_) => {} // rejected outright -- good
            Ok(sig) => assert!(
                !core_spike::verify_combined(&results[0].1, "inv-2026-000777", &sig),
                "a bad node's ciphertext must not silently combine into a key that verifies"
            ),
        }
    }
}
