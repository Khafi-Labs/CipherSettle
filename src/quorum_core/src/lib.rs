//! Transport-agnostic threshold-BLS DKG and derive protocol logic.
//!
//! This crate is deliberately free of any networking, TLS, or product logic
//! -- exactly the same design principle `ciphersettle_core` follows for the
//! access-control rules, applied here to the crypto core. `quorum_node`
//! (the actual service binary) owns the mTLS transport and drives this
//! state machine by feeding it messages it received over the wire and
//! sending out whatever this module tells it to.
//!
//! ## Relationship to the Phase 0 PoC (`quorum_poc`)
//!
//! Same DKG construction (each node is its own Feldman-VSS dealer of a
//! degree-`t` polynomial; final share = sum of received shares) and the
//! same derive construction (Boneh-Franklin-style: `sk_id` = combined BLS
//! signature over `id`). The one substantive upgrade over the PoC: a
//! **bad share no longer panics.** `DkgSession::receive_share` returns a
//! `Complaint` instead, so the caller (the real node service) can decide
//! what to do -- broadcast it, exclude the dealer, whatever the
//! surrounding protocol requires -- rather than the whole process crashing
//! because one peer misbehaved. A full dispute-resolution protocol (where
//! the accused dealer can publicly reveal the disputed share to prove
//! innocence, per Pedersen/GJKR) is still not implemented; see the
//! `Complaint` doc comment for exactly where that would plug in.

use serde::{Deserialize, Serialize};

pub mod bls;
pub mod config;

// The DKG and threshold-BLS primitives live in `bls` (blstrs only).
pub use bls::{
    combine, point_of, scalar_from_bytes, scalar_to_bytes, seal_partial_with_proof, sign_partial,
    verify_combined, verify_partial, verify_sealed_partial, Commitment, Complaint, DkgSession,
    Poly, PublicKeySet, SecretKeyShare, Signature, SignatureShare,
};
#[doc(hidden)]
pub use bls::{g1_to_bytes_for_test, hash_identity_to_g2_for_test};

// ---------------------------------------------------------------------
// Derive-request authorization (Phase 4 Stage A fix for Findings 1.1/2.1).
//
// The mTLS client certificate authenticates a *connection* ("you are one
// of the pinned peers"), not a *request* ("quorum_service actually issued
// this specific derive call"). Test C exploited exactly that gap: any
// holder of the shared client cert could derive any identity's key
// directly against the nodes. This HMAC binds every `DeriveRequest` to
// the one secret only `quorum_service` and the quorum nodes hold, plus a
// short expiry and a single-use nonce, which also closes Test D's replay
// gap: a captured, previously-valid request stops working the moment its
// nonce has been seen once or its window elapses.
//
// This is deliberately a shared symmetric key, not per-caller asymmetric
// signing: `quorum_service` is the only legitimate issuer of derive
// requests in this architecture (callers go through it, never straight to
// the nodes), so there is exactly one signer to authenticate, and HMAC
// keeps the node side simple. If a second legitimate issuer is ever
// added, this should move to per-issuer ed25519 signatures instead of a
// single shared secret.
// ---------------------------------------------------------------------

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A `DeriveRequest`'s authorization window is capped at this many
/// milliseconds from issuance, checked independently by the *node*
/// (not just trusted from the client) -- an issuer (even a
/// correctly-authenticated one) cannot hand out a long-lived or
/// unbounded-validity derive authorization.
pub const MAX_DERIVE_AUTH_WINDOW_MS: u64 = 30_000;

/// Validity window callers should request. Deliberately just under
/// [`MAX_DERIVE_AUTH_WINDOW_MS`] (T1-2): the restart guard
/// ([`derive_request_predates_restart`]) refuses requests expiring at or
/// before `process_start + MAX`, so a window of `MAX - 2s` means a freshly
/// restarted node refuses new requests for only ~2s instead of ~30s, while
/// still leaving 2s of clock-skew headroom under the node's own `MAX` check.
/// (Previously callers used 15s, which the guard would have refused for the
/// entire first 30s after every node start.)
/// Trade-off: the replay window a captured request stays valid for grows
/// from 15s to 28s; the single-use nonce still applies within it.
pub const DEFAULT_DERIVE_AUTH_VALIDITY_MS: u64 = MAX_DERIVE_AUTH_WINDOW_MS - 2_000;

pub fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

/// Restart-replay guard (roadmap T1-2 / TASK-009 / threat T-3).
///
/// A node's spent-nonce set lives in memory, so a restart forgets it. A
/// request captured before the restart could then be replayed inside its
/// own freshness window. Rather than persist nonces (new file format, a
/// file an attacker with disk access could truncate), a node remembers only
/// its own `process_start_unix_ms` and refuses any request whose
/// `expires_at_unix_ms` is at or before `process_start + MAX window`.
///
/// Why this is sufficient: at receipt the node enforces
/// `expires_at <= receipt_time + MAX`, so any request the node accepted
/// before crashing has `expires_at <= crash_time + MAX <= process_start +
/// MAX`, and is therefore refused here. Cost: for the first
/// [`MAX_DERIVE_AUTH_WINDOW_MS`] after start, requests with a shorter
/// window than the maximum are refused (fail closed).
///
/// Assumption (NEEDS_HUMAN_REVIEW): the node's wall clock does not step
/// backwards across a restart. Inputs are explicit so the clock is injectable.
pub fn derive_request_predates_restart(
    process_start_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> bool {
    expires_at_unix_ms <= process_start_unix_ms.saturating_add(MAX_DERIVE_AUTH_WINDOW_MS)
}

/// Computes the MAC binding `identity` + `expires_at_unix_ms` + `nonce` +
/// `transport_public_key` under `service_auth_key`. Any of the four
/// inputs changing (a different identity, a tampered expiry, a
/// replayed-but-edited nonce, or -- Finding 2.3's fix -- a swapped-in
/// transport key) invalidates the MAC. The transport key is included so
/// that a party sitting on the service-to-node hop can't redirect a
/// legitimately-authorized derive's sealed output to a transport key of
/// their own; mTLS already makes that hop hard to sit on, but binding it
/// here means that property doesn't rest on mTLS alone.
pub fn sign_derive_auth(
    service_auth_key: &[u8],
    identity: &str,
    expires_at_unix_ms: u64,
    nonce: &[u8; 16],
    transport_public_key: &quorum_vetseal::TransportPublicKey,
) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(service_auth_key).expect("HMAC accepts a key of any length");
    mac.update(identity.as_bytes());
    mac.update(&expires_at_unix_ms.to_be_bytes());
    mac.update(nonce);
    mac.update(&transport_public_key.to_bytes());
    let computed = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&computed);
    out
}

/// Verifies a MAC produced by [`sign_derive_auth`]. Constant-time via
/// `Mac::verify_slice` -- callers must NOT replace this with a `==`
/// comparison on the raw bytes.
pub fn verify_derive_auth(
    service_auth_key: &[u8],
    identity: &str,
    expires_at_unix_ms: u64,
    nonce: &[u8; 16],
    transport_public_key: &quorum_vetseal::TransportPublicKey,
    mac_to_check: &[u8; 32],
) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(service_auth_key) else {
        return false;
    };
    mac.update(identity.as_bytes());
    mac.update(&expires_at_unix_ms.to_be_bytes());
    mac.update(nonce);
    mac.update(&transport_public_key.to_bytes());
    mac.verify_slice(mac_to_check).is_ok()
}

/// Gap 3 (step 1): the per-node derive-authorization key.
///
/// `quorum_service` holds a MASTER secret; node `i` is provisioned ONLY with
/// `derive_node_auth_key(master, i)`. HKDF-SHA256 (RFC 5869) is one-way, so a
/// node's key (leaked from that node's config, memory or backup) lets an
/// attacker forge requests to THAT node only, which is fewer than the t+1
/// partials needed to derive anything. (Before this change every node held the
/// master itself: one stolen node key forged requests to all of them.)
///
/// The master must be at least this long (the service refuses to start with a
/// shorter one).
pub const MIN_AUTH_MASTER_BYTES: usize = 32;

const NODE_AUTH_SALT: &[u8] = b"ciphersettle/derive-auth/v1";

pub fn derive_node_auth_key(master: &[u8], node_id: usize) -> [u8; 32] {
    let mut info = Vec::with_capacity(16 + 8);
    info.extend_from_slice(b"node-auth-key");
    info.extend_from_slice(&(node_id as u64).to_be_bytes());
    hkdf_sha256_32(NODE_AUTH_SALT, master, &info)
}

/// HKDF-SHA256 (RFC 5869) producing exactly 32 bytes (a single expand block,
/// `T(1) = HMAC(PRK, info || 0x01)`). Checked against RFC 5869 test case 1.
pub fn hkdf_sha256_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC(salt, IKM). HMAC accepts a key of any length, so
    // these constructors cannot fail; the fallbacks keep this panic-free.
    let prk = match HmacSha256::new_from_slice(salt) {
        Ok(mut m) => {
            m.update(ikm);
            m.finalize().into_bytes()
        }
        Err(_) => return [0u8; 32],
    };
    match HmacSha256::new_from_slice(&prk) {
        Ok(mut m) => {
            m.update(info);
            m.update(&[1u8]);
            let t1 = m.finalize().into_bytes();
            let mut out = [0u8; 32];
            out.copy_from_slice(&t1);
            out
        }
        Err(_) => [0u8; 32],
    }
}

/// Builds a freshly-signed, freshly-nonced `DeriveRequest`, valid for
/// `validity_window_ms` from now (capped by the caller against
/// [`MAX_DERIVE_AUTH_WINDOW_MS`] indirectly, since the node enforces that
/// cap independently regardless of what the client asks for). Takes the
/// true end caller's `transport_public_key` so nodes seal their partials
/// against it rather than returning them in the clear (Finding 2.3).
pub fn build_derive_request(
    service_auth_key: &[u8],
    identity: &str,
    validity_window_ms: u64,
    transport_public_key: quorum_vetseal::TransportPublicKey,
) -> Message {
    use rand::Rng;
    let expires_at_unix_ms = now_unix_ms() + validity_window_ms;
    let nonce: [u8; 16] = rand::thread_rng().gen();
    let mac = sign_derive_auth(
        service_auth_key,
        identity,
        expires_at_unix_ms,
        &nonce,
        &transport_public_key,
    );
    Message::DeriveRequest {
        identity: identity.to_string(),
        expires_at_unix_ms,
        nonce,
        mac,
        transport_public_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    /// Runs a full N=5, T=2 DKG purely in-process (no networking -- this is
    /// exactly what quorum_node's network loop will do, minus the network)
    /// and returns each node's finalized (SecretKeyShare, PublicKeySet).
    fn run_dkg(n: usize, t: usize) -> Vec<(SecretKeyShare, PublicKeySet)> {
        let mut rng = thread_rng();
        let mut sessions = Vec::new();
        let mut commitments = Vec::new();
        for id in 0..n {
            let (session, commitment) = DkgSession::new(id, n, t, &mut rng);
            sessions.push(session);
            commitments.push(commitment);
        }
        // Broadcast phase: every node receives every commitment.
        for session in sessions.iter_mut() {
            for (dealer_id, commitment) in commitments.iter().enumerate() {
                session
                    .receive_commitment(dealer_id, commitment.clone())
                    .expect("honest commitment must be accepted");
            }
        }
        // Point-to-point phase: dealer i sends node j its share.
        let all_shares: Vec<Vec<[u8; 32]>> = (0..n)
            .map(|dealer_id| {
                (0..n)
                    .map(|peer_id| sessions[dealer_id].share_for(peer_id))
                    .collect()
            })
            .collect();
        for (peer_id, session) in sessions.iter_mut().enumerate() {
            for (dealer_id, dealer_shares) in all_shares.iter().enumerate() {
                session
                    .receive_share(dealer_id, dealer_shares[peer_id])
                    .expect("honest share must verify");
            }
        }
        sessions
            .into_iter()
            .map(|s| s.finalize().expect("DKG should be ready"))
            .collect()
    }

    #[test]
    fn honest_dkg_finalizes_and_derives_consistently() {
        let results = run_dkg(5, 2);
        let group_pks = results[0].1.clone();
        for (share, pks) in &results {
            assert!(pks.public_key() == group_pks.public_key());
            let _ = share; // each node's share differs; only the group key must match
        }

        let identity = "inv-test-001";
        let subset_a = [0, 1, 2];
        let subset_b = [2, 3, 4];

        let combine_subset = |subset: &[usize]| {
            let shares: BTreeMap<usize, SignatureShare> = subset
                .iter()
                .map(|&i| {
                    let partial = sign_partial(&results[i].0, identity);
                    assert!(verify_partial(&group_pks, i, identity, &partial));
                    (i, partial)
                })
                .collect();
            combine(&group_pks, &shares).unwrap()
        };

        let derived_a = combine_subset(&subset_a);
        let derived_b = combine_subset(&subset_b);
        assert_eq!(derived_a.to_bytes(), derived_b.to_bytes());
        assert!(verify_combined(&group_pks, identity, &derived_a));
    }

    #[test]
    fn tampered_share_is_reported_as_a_complaint_not_a_panic() {
        let mut rng = thread_rng();
        let (n, t) = (5, 2);
        let mut sessions = Vec::new();
        let mut commitments = Vec::new();
        for id in 0..n {
            let (session, commitment) = DkgSession::new(id, n, t, &mut rng);
            sessions.push(session);
            commitments.push(commitment);
        }
        for session in sessions.iter_mut() {
            for (dealer_id, commitment) in commitments.iter().enumerate() {
                session
                    .receive_commitment(dealer_id, commitment.clone())
                    .expect("honest commitment must be accepted");
            }
        }

        // Node 0 receives a correct share from dealer 1, but we flip a byte
        // in transit -- simulating either corruption or a malicious dealer.
        let mut tampered = sessions[1].share_for(0);
        tampered[0] ^= 0xFF;

        let result = sessions[0].receive_share(1, tampered);
        assert!(
            result.is_err(),
            "a tampered share must not be silently accepted"
        );
        let complaint = result.unwrap_err();
        assert_eq!(complaint.accuser, 0);
        assert_eq!(complaint.accused_dealer, 1);
        assert!(!sessions[0].outstanding_complaints().is_empty());
        assert!(!sessions[0].is_ready());
    }

    /// C-1 (NEEDS_HUMAN_CRYPTO_REVIEW): after DKG the group threshold is t.
    /// NIZK integration: an honest node's proof verifies against the GROUP's
    /// public key share, and every way of misattributing it fails.
    #[test]
    fn sealed_partial_proof_verifies_only_for_the_right_node_identity_and_recipient() {
        let mut rng = thread_rng();
        let dkg = run_dkg(5, 2);
        let recipient = quorum_vetseal::TransportSecretKey::random(&mut rng).public_key();
        let other_recipient = quorum_vetseal::TransportSecretKey::random(&mut rng).public_key();
        let (share2, group) = &dkg[2];

        let (sealed, proof) =
            seal_partial_with_proof(share2, "inv-1", &recipient, &mut rng).unwrap();
        assert!(verify_sealed_partial(
            group, 2, "inv-1", &recipient, &sealed, &proof
        ));
        // Claimed to be a different node: the group's key share for that node differs.
        assert!(!verify_sealed_partial(
            group, 3, "inv-1", &recipient, &sealed, &proof
        ));
        // Different identity / different recipient than the proof was made for.
        assert!(!verify_sealed_partial(
            group, 2, "inv-2", &recipient, &sealed, &proof
        ));
        assert!(!verify_sealed_partial(
            group,
            2,
            "inv-1",
            &other_recipient,
            &sealed,
            &proof
        ));
        // A proof from a different node's share does not verify for node 2.
        let (_, proof_of_3) =
            seal_partial_with_proof(&dkg[3].0, "inv-1", &recipient, &mut rng).unwrap();
        assert!(!verify_sealed_partial(
            group,
            2,
            "inv-1",
            &recipient,
            &sealed,
            &proof_of_3
        ));
    }

    #[test]
    fn a_valid_proof_for_an_invented_scalar_is_rejected_against_the_group_key() {
        let mut rng = thread_rng();
        let dkg = run_dkg(5, 2);
        let group = &dkg[0].1;
        let recipient = quorum_vetseal::TransportSecretKey::random(&mut rng).public_key();
        // The strong adversary: sound proof, but for a scalar that is nobody's DKG share.
        let mut fake_sk = [7u8; 32];
        fake_sk[31] = 0;
        let h = hash_identity_to_g2_for_test(b"inv-1");
        let (sealed, _pk, proof) =
            quorum_vetseal::nizk::seal_share_with_proof(&fake_sk, &h, &recipient, &mut rng)
                .unwrap();
        for node in 0..5 {
            assert!(!verify_sealed_partial(
                group, node, "inv-1", &recipient, &sealed, &proof
            ));
        }
    }

    #[test]
    fn group_threshold_equals_t_after_dkg() {
        for (n, t) in [(5usize, 2usize), (3, 1), (7, 3)] {
            let results = run_dkg(n, t);
            for (_, pks) in &results {
                assert_eq!(pks.threshold(), t);
            }
        }
    }

    /// C-1: a dealer whose commitment has the wrong number of coefficients
    /// is refused with a Complaint at receipt (no panic later).
    #[test]
    fn wrong_degree_dealer_is_rejected_with_a_complaint() {
        let mut rng = thread_rng();
        let (n, t) = (5, 2);
        let (mut victim, _own) = DkgSession::new(0, n, t, &mut rng);
        for bad_degree in [0usize, 1, 3, 4] {
            let bad = Poly::random(bad_degree, &mut rng).commitment();
            let res = victim.receive_commitment(1, bad);
            let c = res.expect_err("wrong-degree commitment must be rejected");
            assert_eq!(c.accused_dealer, 1);
        }
        assert!(!victim.is_ready());
        // Out-of-range dealer ids are rejected too.
        let ok_len = Poly::random(t, &mut rng).commitment();
        assert!(victim.receive_commitment(n, ok_len).is_err());
    }

    /// Fewer than t+1 partials must be an error, not a wrong key.
    #[test]
    fn combine_below_threshold_errors() {
        let results = run_dkg(5, 2);
        let pks = results[0].1.clone();
        let shares: BTreeMap<usize, SignatureShare> = [0usize, 1]
            .iter()
            .map(|&i| (i, sign_partial(&results[i].0, "inv-x")))
            .collect();
        assert!(combine(&pks, &shares).is_err());
    }

    /// A garbage (well-formed but wrong) partial fails verify_partial and
    /// poisons a combine that includes it.
    #[test]
    fn garbage_partial_fails_verification() {
        let results = run_dkg(5, 2);
        let pks = results[0].1.clone();
        let garbage = SignatureShare::random_for_test(&mut thread_rng());
        assert!(!verify_partial(&pks, 2, "inv-g", &garbage));
        let mut shares: BTreeMap<usize, SignatureShare> = [0usize, 1]
            .iter()
            .map(|&i| (i, sign_partial(&results[i].0, "inv-g")))
            .collect();
        shares.insert(2, garbage);
        let sig = combine(&pks, &shares).unwrap();
        assert!(!verify_combined(&pks, "inv-g", &sig));
    }

    /// A signature for one identity must not verify for another.
    #[test]
    fn signature_is_bound_to_identity() {
        let results = run_dkg(5, 2);
        let pks = results[0].1.clone();
        let shares: BTreeMap<usize, SignatureShare> = [0usize, 1, 2]
            .iter()
            .map(|&i| (i, sign_partial(&results[i].0, "inv-a")))
            .collect();
        let sig = combine(&pks, &shares).unwrap();
        assert!(verify_combined(&pks, "inv-a", &sig));
        assert!(!verify_combined(&pks, "inv-b", &sig));
    }

    #[test]
    fn commitment_and_pubkeyset_serde_round_trip() {
        let results = run_dkg(5, 2);
        let pks = &results[0].1;
        let json = serde_json::to_vec(pks).unwrap();
        let back: PublicKeySet = serde_json::from_slice(&json).unwrap();
        assert!(back == *pks);
        let c = Poly::random(2, &mut thread_rng()).commitment();
        let cj = serde_json::to_vec(&c).unwrap();
        let cb: Commitment = serde_json::from_slice(&cj).unwrap();
        assert!(cb == c);
    }

    /// Malformed commitment encodings are errors, never panics.
    #[test]
    fn malformed_commitment_decoding_is_an_error() {
        assert!(Commitment::from_bytes(&[]).is_err());
        assert!(Commitment::from_bytes(&[0u8; 47]).is_err());
        assert!(Commitment::from_bytes(&[0xFFu8; 48]).is_err()); // not a valid point
        let too_many = vec![0xC0u8; 48 * (bls::MAX_COMMITMENT_POINTS + 1)];
        assert!(Commitment::from_bytes(&too_many).is_err());
        assert!(serde_json::from_str::<Commitment>("\"!!not base64!!\"").is_err());
        assert!(serde_json::from_str::<Commitment>("\"\"").is_err());
    }

    #[test]
    fn non_canonical_share_bytes_are_a_complaint() {
        let mut rng = thread_rng();
        let (mut s, c) = DkgSession::new(0, 5, 2, &mut rng);
        s.receive_commitment(0, c).unwrap();
        assert!(s.receive_share(0, [0xFF; 32]).is_err());
    }

    #[test]
    fn finalize_fails_cleanly_if_not_all_shares_received() {
        let mut rng = thread_rng();
        let (session, _commitment) = DkgSession::new(0, 5, 2, &mut rng);
        // No commitments or shares fed in at all.
        assert!(!session.is_ready());
        assert!(session.finalize().is_err());
    }

    /// T1-2: simulates the full crash/restart timeline with an injected
    /// clock. Every request a node could have accepted before crashing must
    /// be refused after restart; a request issued after the guard period
    /// must be accepted.
    #[test]
    fn restart_guard_refuses_every_request_a_prior_process_could_have_accepted() {
        let crash_time = 1_000_000u64;
        let restart_time = crash_time + 1; // earliest possible restart
                                           // The most generous request the old process would have accepted:
                                           // issued right at the crash with the maximum allowed window.
        let latest_prior_expiry = crash_time + MAX_DERIVE_AUTH_WINDOW_MS;
        assert!(derive_request_predates_restart(
            restart_time,
            latest_prior_expiry
        ));
        // Any earlier-issued / shorter-window request is refused too.
        for expiry in [
            0,
            1,
            crash_time,
            crash_time + 15_000,
            latest_prior_expiry - 1,
        ] {
            assert!(
                derive_request_predates_restart(restart_time, expiry),
                "expiry {expiry}"
            );
        }
    }

    #[test]
    fn restart_guard_accepts_requests_issued_after_the_guard_period() {
        let start = 1_000_000u64;
        // Boundary: exactly start + MAX is still refused (<=), one ms later is accepted.
        assert!(derive_request_predates_restart(
            start,
            start + MAX_DERIVE_AUTH_WINDOW_MS
        ));
        assert!(!derive_request_predates_restart(
            start,
            start + MAX_DERIVE_AUTH_WINDOW_MS + 1
        ));
    }

    #[test]
    fn restart_guard_does_not_overflow_near_u64_max() {
        // Must not panic on overflow. (An earlier draft asserted `x || true`,
        // which can never fail; these are real assertions.)
        assert!(derive_request_predates_restart(u64::MAX, 0));
        assert!(derive_request_predates_restart(u64::MAX, u64::MAX));
        assert!(!derive_request_predates_restart(0, u64::MAX));
    }

    /// Pins the exact fail-closed window: a default-validity request issued
    /// at `start + d` is refused iff `d <= MAX - DEFAULT` (= 2 000 ms), and is
    /// monotone (once accepted, every later issue time is accepted too).
    #[test]
    fn restart_guard_refusal_window_is_exactly_max_minus_default_validity() {
        let start = 1_000_000u64;
        let window = MAX_DERIVE_AUTH_WINDOW_MS - DEFAULT_DERIVE_AUTH_VALIDITY_MS;
        assert_eq!(window, 2_000);
        let mut accepted_seen = false;
        for d in 0..=(window + 500) {
            let refused =
                derive_request_predates_restart(start, start + d + DEFAULT_DERIVE_AUTH_VALIDITY_MS);
            assert_eq!(refused, d <= window, "d = {d}");
            if !refused {
                accepted_seen = true;
            }
            assert!(
                !(accepted_seen && refused),
                "guard must be monotone in issue time"
            );
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 Appendix A.1 (Test Case 1): the first 32 bytes of the OKM.
    #[test]
    fn hkdf_sha256_matches_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256_32(&salt, &ikm, &info);
        assert_eq!(
            okm.to_vec(),
            unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn node_auth_keys_are_distinct_deterministic_and_not_the_master() {
        let master = [7u8; 32];
        let k: Vec<[u8; 32]> = (0..5).map(|i| derive_node_auth_key(&master, i)).collect();
        for i in 0..5 {
            assert_eq!(k[i], derive_node_auth_key(&master, i), "deterministic");
            assert_ne!(k[i].to_vec(), master.to_vec(), "must not equal the master");
            for j in (i + 1)..5 {
                assert_ne!(k[i], k[j], "nodes {i} and {j} must have different keys");
            }
        }
        // A different master gives different keys.
        assert_ne!(k[0], derive_node_auth_key(&[8u8; 32], 0));
    }

    #[test]
    fn derive_auth_round_trips_and_rejects_tampering() {
        let key = b"a fake service_auth_key, 32B+";
        let nonce = [7u8; 16];
        let tpk = quorum_vetseal::TransportSecretKey::random(&mut thread_rng()).public_key();
        let other_tpk = quorum_vetseal::TransportSecretKey::random(&mut thread_rng()).public_key();
        let mac = sign_derive_auth(key, "inv-1", 1_000, &nonce, &tpk);
        assert!(verify_derive_auth(key, "inv-1", 1_000, &nonce, &tpk, &mac));

        assert!(!verify_derive_auth(
            b"a different key entirely!!",
            "inv-1",
            1_000,
            &nonce,
            &tpk,
            &mac
        ));
        assert!(!verify_derive_auth(key, "inv-2", 1_000, &nonce, &tpk, &mac));
        assert!(!verify_derive_auth(key, "inv-1", 1_001, &nonce, &tpk, &mac));
        assert!(!verify_derive_auth(
            key, "inv-1", 1_000, &[8u8; 16], &tpk, &mac
        ));
        assert!(
            !verify_derive_auth(key, "inv-1", 1_000, &nonce, &other_tpk, &mac),
            "swapping in a different transport public key must invalidate the MAC"
        );
    }

    #[test]
    fn build_derive_request_produces_a_self_consistent_message() {
        let key = b"another fake service_auth_key32";
        let tpk = quorum_vetseal::TransportSecretKey::random(&mut thread_rng()).public_key();
        let msg = build_derive_request(key, "inv-2026-000042", 15_000, tpk);
        match msg {
            Message::DeriveRequest {
                identity,
                expires_at_unix_ms,
                nonce,
                mac,
                transport_public_key,
            } => {
                assert_eq!(identity, "inv-2026-000042");
                assert!(
                    expires_at_unix_ms > now_unix_ms(),
                    "expiry should be in the future"
                );
                assert!(verify_derive_auth(
                    key,
                    &identity,
                    expires_at_unix_ms,
                    &nonce,
                    &transport_public_key,
                    &mac
                ));
            }
            other => panic!("expected DeriveRequest, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------
// Wire message types. `quorum_node` serializes these (serde_json, one per
// line) over its mTLS-authenticated TCP streams. No transport code lives
// here -- just the shapes both ends need to agree on.
// ---------------------------------------------------------------------

// Boxing the larger variants here would shrink this enum's stack footprint,
// but `Message` is the node-to-node wire protocol's central type -- exactly
// the kind of quorum_core change the audit remediation roadmap says needs
// a dedicated cryptography-literate review and a full adversarial-suite
// pass before merge, not a lint-driven edit bundled into hygiene work.
// Tracked as known, low-severity (performance-only, not correctness) style
// debt.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Broadcast: "here is my dealer commitment."
    DkgCommitment { from: usize, commitment: Commitment },
    /// Point-to-point only, sent exactly once from `from` to `to`: "here is
    /// your private share of my polynomial." Never relay this to a third
    /// party.
    DkgShare {
        from: usize,
        to: usize,
        share: [u8; 32],
    },
    /// Broadcast: "dealer `against`'s share to me failed verification."
    DkgComplaint {
        from: usize,
        against: usize,
        reason: String,
    },
    /// Broadcast: "I have finalized my DKG share and am ready to serve
    /// derive requests."
    DkgReady { from: usize },
    /// Client -> node: "give me your partial derivation for this
    /// identity." `ciphersettle_core::resolve_access` (invoice-level
    /// authorization: is THIS caller allowed THIS invoice) still lives at
    /// the Phase 3 service layer, not here -- that's product policy, not
    /// this crate's job. What DOES live here, after Phase 4 Test C found
    /// that the node protocol had no authorization boundary of its own at
    /// all: proof that the request was actually issued by
    /// `quorum_service` (holder of `service_auth_key`), not just by
    /// anyone holding a pinned mTLS cert. `expires_at_unix_ms` and
    /// `nonce` together bound the authorization to a short window and
    /// make it single-use (Test D's replay gap) -- see
    /// `sign_derive_auth`/`verify_derive_auth`.
    DeriveRequest {
        identity: String,
        expires_at_unix_ms: u64,
        nonce: [u8; 16],
        mac: [u8; 32],
        /// Phase 4 Stage F / Finding 2.3 fix: the true end caller's
        /// transport public key (generated and held locally by that
        /// caller -- never by `quorum_service` or any node). The node
        /// seals its partial under this key instead of returning it in
        /// the clear, so a compromised or merely curious broker sitting
        /// between the node and the caller (in this architecture, that's
        /// `quorum_service` itself) never sees a usable key. Bound into
        /// `mac` alongside identity/expiry/nonce so a man-in-the-middle
        /// on the (already-mTLS-protected) service-to-node hop can't
        /// swap in a transport key of their own choosing.
        transport_public_key: quorum_vetseal::TransportPublicKey,
    },
    /// Node -> client: the requester's own partial, sealed under the
    /// `transport_public_key` from the matching `DeriveRequest` --
    /// nothing in this message is ever a usable plaintext signature
    /// share. See `quorum_vetseal` for what "sealed" means here and why.
    DerivePartial {
        from: usize,
        sealed_share: quorum_vetseal::SealedShare,
        /// NIZK that `sealed_share` encrypts this node's genuine partial
        /// for the requested identity (see `verify_sealed_partial`).
        /// Required: a node that omits it fails to decode and is treated
        /// like any other malformed responder.
        proof: quorum_vetseal::nizk::EncryptionProof,
    },
    /// Node -> client: "I won't/can't serve that request."
    DeriveReject { from: usize, reason: String },

    // ---- Phase 2: audit log ----
    /// Proposer (typically the derive-requesting client) -> a
    /// participating node: "please co-sign and append this entry." The
    /// entry's `seq`/`prev_hash` reflect what the proposer believes the
    /// log's current tip is; the receiving node independently re-derives
    /// and checks this against its OWN local tip before signing anything
    /// -- it does not trust the proposer's claim.
    AppendAuditEntry { entry: quorum_audit::AuditEntry },
    /// Node -> proposer: "I appended it and here's my signature."
    AuditEntrySigned { node_id: usize, signature: Vec<u8> },
    /// Node -> proposer: "I won't append that."
    AuditAppendRejected { node_id: usize, reason: String },
    /// Proposer -> every OTHER node (including ones that didn't
    /// participate in the derive, once reachable): "here is the entry,
    /// now co-signed by the participating nodes -- append your own copy."
    /// This is the actual replication step ("replicate the log across all
    /// quorum nodes, not just the operator's").
    ReplicateAuditEntry { entry: quorum_audit::AuditEntry },
    /// Node -> proposer (F-19): "this exact entry is now DURABLE in my audit
    /// log file (written, fsynced, renamed)". Sent only after persistence
    /// succeeded, or if the identical entry was already durable here. A
    /// proposer must not report an entry as committed until it holds at least
    /// `t + 1` of these. Additive wire change: a node that does not know this
    /// message simply never sends it (the proposer then reports NotDurable).
    AuditEntryCommitted {
        node_id: usize,
        seq: u64,
        entry_hash: [u8; 32],
    },
    /// Anyone -> a node: "give me your log" (optionally filtered), for
    /// reads (mirrors `get_audit_log`'s metadata-only shape) and for
    /// reconciliation (an external reconciler fetches every node's full
    /// log and compares).
    GetAuditLog { invoice_id: Option<String> },
    /// Node -> requester: the requested entries, from THIS node's local
    /// replica -- which is exactly why comparing this response across
    /// multiple nodes is what reconciliation means.
    AuditLogEntries {
        entries: Vec<quorum_audit::AuditEntry>,
    },
}
