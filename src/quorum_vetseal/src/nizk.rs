//! "Cryptographic Verification": a NIZK proof that a `SealedShare`
//! really does encrypt its author's genuine BLS partial signature, so a
//! bad ciphertext is rejected -- and the lying node identified --
//! *before* `combine_sealed_shares`, not only after decrypting the final
//! result.
//!
//! This module's top-of-file doc comment on `lib.rs` ("Why plain ElGamal,
//! not a NIZK proof of correct encryption") named this exact gap and
//! deferred it. This is that deferred piece, and it is **wired into the
//! live protocol**: `quorum_node` produces a proof for every partial it
//! emits (`quorum_core::seal_partial_with_proof`), and `quorum_client`
//! verifies each node's proof against the group's own Feldman commitment
//! before combining (`quorum_core::verify_sealed_partial`).
//!
//! Built mechanically against `blstrs` and **pending human cryptographic
//! review** -- see the "What this proof does NOT do" section below
//! before treating it as load-bearing.
//!
//! ## The statement being proved
//!
//! A node holds a DKG secret share `s` (a scalar) whose public half is
//! `pk_share = g1^s` -- already public, published as part of the
//! group's Feldman commitment, nothing secret about it. Its genuine
//! partial signature for an identity is `m = H(identity)^s`, a point in
//! G2. Sealing that partial under a recipient's transport key with
//! ElGamal randomness `r` produces `(C1, C2) = (g2^r, recipient^r * m)`.
//!
//! This module proves, in zero knowledge, that a `(C1, C2)` pair was
//! built this way for the *same* `s` whose G1 image is a stated
//! `pk_share`, without revealing `s`, `r`, or `m`. Concretely, it's a
//! Fiat-Shamir'd generalized Schnorr / Okamoto-style proof of knowledge
//! of representation, over a witness `(s, r)` shared across three
//! linear equations spanning both G1 and G2:
//!
//! ```text
//! pk_share = g1^s                     (public, in G1)
//! C1       = g2^r                     (in G2)
//! C2       = recipient^r * H^s        (in G2)
//! ```
//!
//! A single challenge `c` (hashed over every public value plus three
//! prover commitments `R1, R2, R3`) ties all three equations to the
//! *same* `(s, r)`, exactly the way Chaum-Pedersen ties a DLEQ proof's
//! two equations to the same witness -- this is the direct three-equation
//! generalization of that, spanning two groups instead of one.
//!
//! ## What this proof does NOT do (read this before treating it as
//! load-bearing)
//!
//! - **It does not bind `pk_share` to any specific node index or DKG
//!   session on its own.** `verify_sealed_share` takes `pk_share` as a
//!   caller-supplied input and only checks internal consistency between
//!   it and the ciphertext. **The caller MUST independently confirm
//!   `pk_share` equals `PublicKeySet::public_key_share(node_id)` for the
//!   node index the share claims to come from.** The live path does
//!   exactly this: `quorum_core::verify_sealed_partial` re-derives the
//!   expected public key share from the group's own Feldman commitment
//!   for the claimed `node_id` and never trusts the node's own value --
//!   without that outer check, a dishonest node could produce a
//!   perfectly valid-looking proof for some *other* scalar it knows,
//!   unrelated to its real DKG share. This proof closes "does this
//!   ciphertext encrypt *a* value consistent with *some* stated public
//!   key," not "is that public key actually this node's."
//! - **It says nothing about authorization.** The `VerificationAttestation`
//!   object -- a per-invoice result signed by a real external authority
//!   and independently checked by each node -- is a completely separate,
//!   still-fully-open gap; see `README.md`'s "The VerificationAttestation
//!   gap" and §6a of `CipherSettle_Audit_Remediation_Roadmap.md`. This
//!   proof only strengthens *which ciphertext gets accepted into the
//!   combine*, not *whether the derivation should have happened at all*.
//! - **Not a substitute for the final `verify()` check.** Even with
//!   every individual proof passing, the caller must still run the
//!   combined-signature verification this crate's existing tests already
//!   rely on -- a NIZK on the shares doesn't prove the *combine* step
//!   (homomorphic Lagrange interpolation over ciphertexts) was itself
//!   correct, only that each input to it was.
//! - **Fiat-Shamir challenge hashing uses SHA-256 with rejection
//!   sampling** (hash-then-retry with an incrementing counter until the
//!   digest happens to be a canonical field element) rather than a
//!   library-provided hash-to-scalar routine, because this dependency
//!   generation's `ff`/`group` crates don't expose one for `blstrs`'s
//!   `Scalar`. This is a standard, sound technique under the random-oracle
//!   model, but -- consistent with every other cryptographic judgment
//!   call in this project -- it's flagged here for a reviewer to confirm
//!   rather than assumed uncontroversial.
//! - **Not benchmarked.** Three group exponentiations per proof
//!   generation, six (three equality checks, each with two
//!   exponentiations/multiplications) per verification, done the
//!   "obviously correct" way with no batching, matching this project's
//!   stated preference (see `quorum_core`'s `pairing_eq` doc comment) for
//!   auditability over speed pre-review.
//! - **No wire-format compatibility claim with anything.** This proof
//!   shape doesn't exist anywhere else in this codebase to be compatible
//!   with -- there's nothing to be inconsistent with yet, only a design
//!   for a reviewer to bless before it becomes one.

use crate::{
    decompress_g2, Ciphertext, SealedShare, TransportPublicKey, VetsealError, FR_BYTES,
    G2_COMPRESSED_SIZE,
};
use blstrs::{G1Affine, G1Projective, G2Projective, Scalar};
use ff::{Field, PrimeField};
use group::{Curve, Group};
use sha2::{Digest, Sha256};
use std::fmt;

/// Compressed size of a G1 point under `blstrs`'s own encoding (half a
/// G2 point's size on BLS12-381 -- G1 is the smaller group).
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Flat byte encoding of an `EncryptionProof`: one G1 point (`r1`), two
/// G2 points (`r2`, `r3`), then two scalars (`z_s`, `z_r`).
pub const PROOF_COMPRESSED_SIZE: usize = G1_COMPRESSED_SIZE + 2 * G2_COMPRESSED_SIZE + 2 * FR_BYTES;

/// Domain separation tag for this proof's Fiat-Shamir transcript.
/// Distinct from `quorum_core::SIG_DST` (a different
/// construction entirely) and versioned so a future revision of this
/// proof's transcript shape can't be replayed against this one, or vice
/// versa.
const PROOF_DST: &[u8] = b"CIPHERSETTLE_VETSEAL_ENCRYPTION_PROOF_BLSTRS_V1_";

/// A node's public key share, `g1^s` -- the public half of the DKG
/// secret share this proof binds a `SealedShare` to. Deliberately a thin
/// wrapper (not a bare `G1Projective`) so callers can't accidentally
/// pass a G2 point where a G1 one is required -- the two are
/// different-sized byte strings, but the type system catching it is
/// cheaper than a reviewer catching it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyShare(pub(crate) G1Projective);

impl PublicKeyShare {
    /// Recovers a `PublicKeyShare` from a raw secret-share scalar, i.e.
    /// `g1^s`. A node calls this on its own secret share; a verifier
    /// never calls this -- see this module's doc comment on why a
    /// verifier must instead obtain the expected value from the group's
    /// public Feldman commitment, not trust whatever a node claims here.
    pub fn from_secret_share_bytes(sk_share: &[u8; FR_BYTES]) -> Result<Self, VetsealError> {
        let s = scalar_from_bytes(sk_share)?;
        Ok(PublicKeyShare(G1Projective::generator() * s))
    }

    pub fn to_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_affine().to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        let opt: Option<G1Affine> = G1Affine::from_compressed(bytes).into();
        opt.map(|a| PublicKeyShare(a.into()))
            .ok_or(VetsealError::InvalidEncoding)
    }
}

impl fmt::Debug for PublicKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyShare({})", hex_preview(&self.to_bytes()))
    }
}

/// The proof itself: three Sigma-protocol commitments and two Fiat-Shamir
/// responses. See this module's top-of-file doc comment for what it
/// proves and, just as importantly, what it doesn't.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EncryptionProof {
    r1: G1Projective,
    r2: G2Projective,
    r3: G2Projective,
    z_s: Scalar,
    z_r: Scalar,
}

impl EncryptionProof {
    pub fn to_bytes(&self) -> [u8; PROOF_COMPRESSED_SIZE] {
        let mut out = [0u8; PROOF_COMPRESSED_SIZE];
        let mut off = 0;
        out[off..off + G1_COMPRESSED_SIZE].copy_from_slice(&self.r1.to_affine().to_compressed());
        off += G1_COMPRESSED_SIZE;
        out[off..off + G2_COMPRESSED_SIZE].copy_from_slice(&self.r2.to_affine().to_compressed());
        off += G2_COMPRESSED_SIZE;
        out[off..off + G2_COMPRESSED_SIZE].copy_from_slice(&self.r3.to_affine().to_compressed());
        off += G2_COMPRESSED_SIZE;
        out[off..off + FR_BYTES].copy_from_slice(&scalar_to_bytes(&self.z_s));
        off += FR_BYTES;
        out[off..off + FR_BYTES].copy_from_slice(&scalar_to_bytes(&self.z_r));
        out
    }

    pub fn from_bytes(bytes: &[u8; PROOF_COMPRESSED_SIZE]) -> Result<Self, VetsealError> {
        let mut off = 0;
        let mut g1_bytes = [0u8; G1_COMPRESSED_SIZE];
        g1_bytes.copy_from_slice(&bytes[off..off + G1_COMPRESSED_SIZE]);
        off += G1_COMPRESSED_SIZE;
        let r1_opt: Option<G1Affine> = G1Affine::from_compressed(&g1_bytes).into();
        let r1: G1Projective = r1_opt.ok_or(VetsealError::InvalidEncoding)?.into();

        let mut g2_bytes = [0u8; G2_COMPRESSED_SIZE];
        g2_bytes.copy_from_slice(&bytes[off..off + G2_COMPRESSED_SIZE]);
        off += G2_COMPRESSED_SIZE;
        let r2 = decompress_g2(&g2_bytes)?;

        g2_bytes.copy_from_slice(&bytes[off..off + G2_COMPRESSED_SIZE]);
        off += G2_COMPRESSED_SIZE;
        let r3 = decompress_g2(&g2_bytes)?;

        let mut fr_bytes = [0u8; FR_BYTES];
        fr_bytes.copy_from_slice(&bytes[off..off + FR_BYTES]);
        off += FR_BYTES;
        let z_s = scalar_from_bytes(&fr_bytes)?;

        fr_bytes.copy_from_slice(&bytes[off..off + FR_BYTES]);
        let z_r = scalar_from_bytes(&fr_bytes)?;

        Ok(EncryptionProof {
            r1,
            r2,
            r3,
            z_s,
            z_r,
        })
    }
}

impl fmt::Debug for EncryptionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionProof({})", hex_preview(&self.to_bytes()))
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

fn scalar_to_bytes(s: &Scalar) -> [u8; FR_BYTES] {
    let repr = s.to_repr();
    let mut out = [0u8; FR_BYTES];
    out.copy_from_slice(repr.as_ref());
    out
}

fn scalar_from_bytes(bytes: &[u8; FR_BYTES]) -> Result<Scalar, VetsealError> {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let opt: Option<Scalar> = Scalar::from_repr(repr).into();
    opt.ok_or(VetsealError::InvalidEncoding)
}

/// Hashes an arbitrary-length transcript down to a canonical `Scalar` by
/// rejection sampling: hash `transcript || counter`, and if the digest
/// happens not to be a canonical field element (roughly a coin flip's
/// chance, since BLS12-381's scalar field is a little under 2^255),
/// increment the counter and retry. See this module's doc comment for
/// why this approach, not a library hash-to-field call, is used here.
fn hash_to_scalar(transcript: &[u8]) -> Scalar {
    let mut counter: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(transcript);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut repr = <Scalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&digest);
        let opt: Option<Scalar> = Scalar::from_repr(repr).into();
        if let Some(s) = opt {
            return s;
        }
        counter += 1;
    }
}

/// Builds the Fiat-Shamir transcript and hashes it to the challenge `c`.
/// Every public value either side of the proof can compute goes in --
/// nothing here is secret. Order is fixed and every field is
/// fixed-width, so there's no ambiguity a malleability attack could
/// exploit (no length-prefixing needed since every component's byte
/// length is a compile-time constant).
#[allow(clippy::too_many_arguments)]
fn fiat_shamir_challenge(
    pk_share: &G1Projective,
    recipient_pk: &G2Projective,
    identity_hash: &G2Projective,
    c1: &G2Projective,
    c2: &G2Projective,
    r1: &G1Projective,
    r2: &G2Projective,
    r3: &G2Projective,
) -> Scalar {
    let mut t =
        Vec::with_capacity(PROOF_DST.len() + G1_COMPRESSED_SIZE * 2 + G2_COMPRESSED_SIZE * 6);
    t.extend_from_slice(PROOF_DST);
    t.extend_from_slice(&pk_share.to_affine().to_compressed());
    t.extend_from_slice(&recipient_pk.to_affine().to_compressed());
    t.extend_from_slice(&identity_hash.to_affine().to_compressed());
    t.extend_from_slice(&c1.to_affine().to_compressed());
    t.extend_from_slice(&c2.to_affine().to_compressed());
    t.extend_from_slice(&r1.to_affine().to_compressed());
    t.extend_from_slice(&r2.to_affine().to_compressed());
    t.extend_from_slice(&r3.to_affine().to_compressed());
    hash_to_scalar(&t)
}

/// Seals a genuine partial signature under `recipient`, exactly like
/// `encrypt_share`, but additionally produces an `EncryptionProof` and
/// the node's `PublicKeyShare` -- everything a verifier needs to check
/// the ciphertext before it's ever combined.
///
/// Unlike `encrypt_share` (which takes an already-computed share point),
/// this takes the node's raw secret share scalar and the identity's
/// already-hashed-to-G2 point directly, because the proof needs to bind
/// the *same* `s` used in both `pk_share = g1^s` and `m = H^s` -- there's
/// no way to produce that binding from `m` alone after the fact.
pub fn seal_share_with_proof<R: rand::RngCore>(
    sk_share: &[u8; FR_BYTES],
    identity_hash: &[u8; G2_COMPRESSED_SIZE],
    recipient: &TransportPublicKey,
    rng: &mut R,
) -> Result<(SealedShare, PublicKeyShare, EncryptionProof), VetsealError> {
    let s = scalar_from_bytes(sk_share)?;
    let h = decompress_g2(identity_hash)?;
    let recipient_pk = recipient.0;

    let pk_share = G1Projective::generator() * s;
    let m = h * s;

    let r = Scalar::random(&mut *rng);
    let c1 = G2Projective::generator() * r;
    let c2 = recipient_pk * r + m;

    let k_s = Scalar::random(&mut *rng);
    let k_r = Scalar::random(&mut *rng);
    let r1 = G1Projective::generator() * k_s;
    let r2 = G2Projective::generator() * k_r;
    let r3 = recipient_pk * k_r + h * k_s;

    let c = fiat_shamir_challenge(&pk_share, &recipient_pk, &h, &c1, &c2, &r1, &r2, &r3);

    let z_s = k_s + c * s;
    let z_r = k_r + c * r;

    Ok((
        SealedShare(Ciphertext { c1, c2 }),
        PublicKeyShare(pk_share),
        EncryptionProof {
            r1,
            r2,
            r3,
            z_s,
            z_r,
        },
    ))
}

/// Verifies that `sealed` correctly encrypts, under `recipient`, the
/// value `H(identity)^s` for the same `s` whose G1 image is `pk_share`.
///
/// **Does not itself confirm `pk_share` is the right node's share** --
/// see this module's top-of-file doc comment. The caller must check
/// that separately against the DKG's public commitment before trusting
/// a `true` result here as "this node behaved."
pub fn verify_sealed_share(
    sealed: &SealedShare,
    pk_share: &PublicKeyShare,
    identity_hash: &[u8; G2_COMPRESSED_SIZE],
    recipient: &TransportPublicKey,
    proof: &EncryptionProof,
) -> Result<bool, VetsealError> {
    let h = decompress_g2(identity_hash)?;
    let recipient_pk = recipient.0;
    let pk_share = pk_share.0;

    let c = fiat_shamir_challenge(
        &pk_share,
        &recipient_pk,
        &h,
        &sealed.0.c1,
        &sealed.0.c2,
        &proof.r1,
        &proof.r2,
        &proof.r3,
    );

    let lhs1 = G1Projective::generator() * proof.z_s;
    let rhs1 = proof.r1 + pk_share * c;

    let lhs2 = G2Projective::generator() * proof.z_r;
    let rhs2 = proof.r2 + sealed.0.c1 * c;

    let lhs3 = recipient_pk * proof.z_r + h * proof.z_s;
    let rhs3 = proof.r3 + sealed.0.c2 * c;

    Ok(lhs1 == rhs1 && lhs2 == rhs2 && lhs3 == rhs3)
}

impl serde::Serialize for EncryptionProof {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionProof {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        let arr: [u8; PROOF_COMPRESSED_SIZE] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("encryption proof has the wrong length"))?;
        EncryptionProof::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportSecretKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    /// Mirrors `crate::tests::run_honest_dkg`, but this module can't see
    /// that private test helper (different `#[cfg(test)] mod` in a
    /// different file), so it's a short independent copy against the
    /// same dev-dependency DKG.
    fn run_honest_dkg(
        n: usize,
        t: usize,
        rng: &mut ChaCha20Rng,
    ) -> Vec<(quorum_core::SecretKeyShare, quorum_core::PublicKeySet)> {
        use quorum_core as core_spike;
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

    /// The core happy path: an honest node's proof verifies, and the
    /// sealed share it produced still decrypts (via the existing,
    /// untouched `combine_sealed_shares`/`decrypt_share` path) to exactly
    /// its genuine partial.
    #[test]
    fn honest_proof_verifies_and_sealed_share_still_decrypts_correctly() {
        use quorum_core as core_spike;
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity = "inv-nizk-000001";
        let node = 3usize;

        let sk_bytes = results[node].0.secret_scalar_bytes_for_test();
        let h_point = quorum_core::hash_identity_to_g2_for_test(identity.as_bytes());

        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let (sealed, pk_share, proof) =
            seal_share_with_proof(&sk_bytes, &h_point, &transport_pk, &mut r).unwrap();

        // The verifier's `pk_share` comes from the *public* commitment,
        // exactly the check this module's doc comment says callers must
        // do -- not from trusting whatever the node sent.
        let expected_pk_share = results[node].1.public_key_share(node);
        assert_eq!(
            pk_share.to_bytes(),
            core_spike::g1_to_bytes_for_test(&expected_pk_share)
        );

        assert!(verify_sealed_share(&sealed, &pk_share, &h_point, &transport_pk, &proof).unwrap());

        // And the existing, unmodified decrypt path still recovers
        // exactly the node's genuine partial for this identity.
        let decrypted = transport_sk.decrypt_share(&sealed);
        let expected_share = results[node].0.sign(identity.as_bytes());
        assert_eq!(decrypted, expected_share.to_bytes());
    }

    /// A malicious node seals a share for a *different* identity than
    /// the one it claims, while still presenting its real `pk_share`.
    /// The proof must fail -- this is the "reject and identify invalid
    /// node contributions immediately," pre-combine, that
    /// "reject and identify invalid node contributions immediately" this
    /// module exists for, an improvement over the sealed-combine tests
    /// above, which only catch this kind of thing at final `verify()`,
    /// after combine and decrypt.
    #[test]
    fn wrong_identity_share_fails_proof_before_combine() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let node = 1usize;

        let sk_bytes = results[node].0.secret_scalar_bytes_for_test();
        let real_h = quorum_core::hash_identity_to_g2_for_test(b"inv-real-0001");
        let claimed_h = quorum_core::hash_identity_to_g2_for_test(b"inv-real-0001");
        let wrong_h = quorum_core::hash_identity_to_g2_for_test(b"a-completely-different-invoice");

        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        // Node dishonestly seals its partial for `wrong_h` instead of
        // the identity it was actually asked to derive for.
        let (sealed, pk_share, proof) =
            seal_share_with_proof(&sk_bytes, &wrong_h, &transport_pk, &mut r).unwrap();

        // The broker/verifier checks against the identity the request
        // actually named.
        assert_eq!(real_h, claimed_h);
        assert!(
            !verify_sealed_share(&sealed, &pk_share, &real_h, &transport_pk, &proof).unwrap(),
            "a proof built for a different identity must not verify against the requested one"
        );
    }

    /// A malicious node presents a `pk_share` that doesn't correspond to
    /// the secret scalar it actually used -- simulating an attempt to
    /// dodge the "caller must check `pk_share` against the public
    /// commitment" requirement by just lying about whose share this is.
    /// Even without that external check, internal consistency alone
    /// must fail here, since the proof ties `pk_share` to the *same* `s`
    /// used inside the ciphertext.
    #[test]
    fn mismatched_pk_share_fails_proof() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity_h = quorum_core::hash_identity_to_g2_for_test(b"inv-mismatch-0001");

        let sk_bytes_of_node_0 = results[0].0.secret_scalar_bytes_for_test();
        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let (sealed, _honest_pk_share, proof) =
            seal_share_with_proof(&sk_bytes_of_node_0, &identity_h, &transport_pk, &mut r).unwrap();

        // Swap in node 1's public key share instead of node 0's real one.
        let impostor_pk_share = PublicKeyShare::from_bytes(&{
            let expected = results[1].1.public_key_share(1);
            core_spike_g1_bytes(&expected)
        })
        .unwrap();

        assert!(
            !verify_sealed_share(
                &sealed,
                &impostor_pk_share,
                &identity_h,
                &transport_pk,
                &proof
            )
            .unwrap(),
            "a proof must not verify against a public key share other than the one actually used"
        );
    }

    fn core_spike_g1_bytes(p: &blstrs::G1Projective) -> [u8; G1_COMPRESSED_SIZE] {
        quorum_core::g1_to_bytes_for_test(p)
    }

    /// Tampering with even one byte of the ciphertext after the proof
    /// was generated must be caught -- the proof binds `C1`/`C2`
    /// themselves into the Fiat-Shamir transcript, so any change to
    /// either invalidates the challenge recomputation on the verifier's
    /// side.
    #[test]
    fn tampered_ciphertext_fails_proof() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity_h = quorum_core::hash_identity_to_g2_for_test(b"inv-tamper-0001");
        let sk_bytes = results[2].0.secret_scalar_bytes_for_test();

        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let (sealed, pk_share, proof) =
            seal_share_with_proof(&sk_bytes, &identity_h, &transport_pk, &mut r).unwrap();

        let mut tampered_bytes = sealed.to_bytes();
        tampered_bytes[0] ^= 0x01;
        // If flipping this bit still happens to be a valid point
        // encoding, the tamper is meaningful (a different point); if not,
        // `from_bytes` itself rejects it, which is an equally acceptable
        // "caught" outcome for this test's purpose.
        // (An `Err` here means it was rejected at decode time -- also an
        // acceptable "caught" outcome.)
        if let Ok(tampered) = SealedShare::from_bytes(&tampered_bytes) {
            assert!(
                !verify_sealed_share(&tampered, &pk_share, &identity_h, &transport_pk, &proof)
                    .unwrap(),
                "a proof must not verify against a ciphertext it wasn't generated for"
            );
        }
    }

    /// Round-trips `PublicKeyShare` and `EncryptionProof` through their
    /// byte encodings, including a garbage-bytes rejection case for
    /// each, matching this crate's existing round-trip test conventions
    /// for `TransportPublicKey`/`SealedShare`/`SealedDerivedKey`.
    #[test]
    fn public_key_share_and_proof_bytes_round_trip() {
        let mut r = rng();
        let (n, t) = (5, 2);
        let results = run_honest_dkg(n, t, &mut r);
        let identity_h = quorum_core::hash_identity_to_g2_for_test(b"inv-roundtrip-0001");
        let sk_bytes = results[0].0.secret_scalar_bytes_for_test();
        let transport_sk = TransportSecretKey::random(&mut r);
        let transport_pk = transport_sk.public_key();

        let (_sealed, pk_share, proof) =
            seal_share_with_proof(&sk_bytes, &identity_h, &transport_pk, &mut r).unwrap();

        let pk_bytes = pk_share.to_bytes();
        let pk_back = PublicKeyShare::from_bytes(&pk_bytes).unwrap();
        assert!(pk_share == pk_back);

        let proof_bytes = proof.to_bytes();
        let proof_back = EncryptionProof::from_bytes(&proof_bytes).unwrap();
        assert!(proof == proof_back);

        let garbage_g1 = [0xFFu8; G1_COMPRESSED_SIZE];
        assert!(PublicKeyShare::from_bytes(&garbage_g1).is_err());

        let garbage_proof = [0xFFu8; PROOF_COMPRESSED_SIZE];
        assert!(EncryptionProof::from_bytes(&garbage_proof).is_err());
    }

    // ------------------------------------------------------------------
    // Adversarial / sweep tests (review pass; NEEDS_HUMAN_CRYPTO_REVIEW).
    // Seeded loops, not `proptest`: no new dependency, fully reproducible.
    // ------------------------------------------------------------------

    #[allow(clippy::type_complexity)]
    fn fixture(
        seed: u64,
        node: usize,
        identity: &str,
    ) -> (
        crate::SealedShare,
        PublicKeyShare,
        [u8; G2_COMPRESSED_SIZE],
        crate::TransportPublicKey,
        EncryptionProof,
    ) {
        let mut r = ChaCha20Rng::seed_from_u64(seed);
        let results = run_honest_dkg(5, 2, &mut r);
        let sk_bytes = results[node].0.secret_scalar_bytes_for_test();
        let h_point = quorum_core::hash_identity_to_g2_for_test(identity.as_bytes());
        let tpk = TransportSecretKey::random(&mut r).public_key();
        let (sealed, pk_share, proof) =
            seal_share_with_proof(&sk_bytes, &h_point, &tpk, &mut r).unwrap();
        (sealed, pk_share, h_point, tpk, proof)
    }

    /// Honest proofs verify for every node across many independent seeds.
    #[test]
    fn honest_proofs_verify_across_seeds_and_nodes() {
        for seed in 0..6u64 {
            for node in 0..5usize {
                let (sealed, pk, h, tpk, proof) =
                    fixture(seed, node, &format!("inv-sweep-{seed}-{node}"));
                assert!(
                    verify_sealed_share(&sealed, &pk, &h, &tpk, &proof).unwrap(),
                    "seed {seed} node {node}"
                );
            }
        }
    }

    /// Flip every bit-0 and bit-7 of every byte of a valid proof's wire
    /// encoding: the result must either fail to decode or fail to verify --
    /// never verify. (Malleability / sloppy-decoding check.)
    #[test]
    fn every_byte_flip_in_the_proof_encoding_is_rejected() {
        let (sealed, pk, h, tpk, proof) = fixture(7, 2, "inv-flip-proof");
        let good = proof.to_bytes();
        assert!(verify_sealed_share(&sealed, &pk, &h, &tpk, &proof).unwrap());
        for i in 0..PROOF_COMPRESSED_SIZE {
            for mask in [0x01u8, 0x80u8] {
                let mut bad = good;
                bad[i] ^= mask;
                match EncryptionProof::from_bytes(&bad) {
                    Err(_) => {}
                    Ok(p2) => {
                        let ok = verify_sealed_share(&sealed, &pk, &h, &tpk, &p2).unwrap_or(false);
                        assert!(!ok, "flip of byte {i} mask {mask:#x} still verified");
                    }
                }
            }
        }
    }

    /// Same for the sealed ciphertext the proof is bound to.
    #[test]
    fn every_byte_flip_in_the_sealed_share_is_rejected() {
        let (sealed, pk, h, tpk, proof) = fixture(8, 1, "inv-flip-sealed");
        let good = sealed.to_bytes();
        for i in 0..crate::SEALED_COMPRESSED_SIZE {
            let mut bad = good;
            bad[i] ^= 0x01;
            match crate::SealedShare::from_bytes(&bad) {
                Err(_) => {}
                Ok(s2) => assert!(
                    !verify_sealed_share(&s2, &pk, &h, &tpk, &proof).unwrap_or(false),
                    "sealed byte {i}"
                ),
            }
        }
    }

    /// A proof is bound to (ciphertext, pk_share, identity, recipient): reusing
    /// it against any other identity or a swapped node's material fails.
    #[test]
    fn proof_cannot_be_replayed_across_identities_or_nodes() {
        let (s_a, pk_a, h_a, tpk_a, proof_a) = fixture(9, 1, "inv-replay-A");
        let (_, _, h_b, _, _) = fixture(9, 1, "inv-replay-B");
        assert!(verify_sealed_share(&s_a, &pk_a, &h_a, &tpk_a, &proof_a).unwrap());
        assert!(
            !verify_sealed_share(&s_a, &pk_a, &h_b, &tpk_a, &proof_a).unwrap(),
            "other identity"
        );
        // Node 2's public key share with node 1's ciphertext + proof (same DKG seed => same group).
        let (_, pk_other, _, _, _) = fixture(9, 2, "inv-replay-A");
        assert!(
            !verify_sealed_share(&s_a, &pk_other, &h_a, &tpk_a, &proof_a).unwrap(),
            "other node's pk_share"
        );
    }

    /// All-zero / all-0xFF proof blobs must be rejected by decoding or verification, never panic.
    #[test]
    fn degenerate_proof_blobs_never_verify_and_never_panic() {
        let (sealed, pk, h, tpk, _) = fixture(10, 0, "inv-degenerate");
        for fill in [0x00u8, 0xFF, 0xC0, 0xA0] {
            let blob = [fill; PROOF_COMPRESSED_SIZE];
            if let Ok(p) = EncryptionProof::from_bytes(&blob) {
                assert!(
                    !verify_sealed_share(&sealed, &pk, &h, &tpk, &p).unwrap_or(false),
                    "fill {fill:#x}"
                );
            }
        }
    }
}
