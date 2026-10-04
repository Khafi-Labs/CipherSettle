//! Phase 0 PoC, rebuilt on `quorum_core` (blstrs only): single-process
//! simulation of a threshold DKG plus an identity-based derive-and-decrypt
//! round trip. Throwaway demo, not production code.
//! NEEDS_HUMAN_CRYPTO_REVIEW (inherits quorum_core's status).

use quorum_core::{
    combine, sign_partial, verify_combined, verify_partial, DkgSession, PublicKeySet,
    SecretKeyShare, Signature, SignatureShare,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const N: usize = 5;
const T: usize = 2;

fn main() {
    println!(
        "=== CipherSettle Phase 0 PoC: {}-of-{} threshold BLS DKG + derive (blstrs) ===\n",
        T + 1,
        N
    );
    let mut rng = rand::thread_rng();

    // DKG: every node deals a degree-T polynomial; everyone verifies every share.
    let mut sessions = Vec::with_capacity(N);
    let mut commitments = Vec::with_capacity(N);
    for id in 0..N {
        let (s, c) = DkgSession::new(id, N, T, &mut rng);
        sessions.push(s);
        commitments.push(c);
    }
    println!("[DKG] {N} nodes each dealt a degree-{T} polynomial (Feldman VSS).");
    for session in sessions.iter_mut() {
        for (dealer, c) in commitments.iter().enumerate() {
            session
                .receive_commitment(dealer, c.clone())
                .expect("honest commitment");
        }
    }
    let all_shares: Vec<Vec<[u8; 32]>> = (0..N)
        .map(|d| (0..N).map(|p| sessions[d].share_for(p)).collect())
        .collect();
    for (peer, session) in sessions.iter_mut().enumerate() {
        for (dealer, shares) in all_shares.iter().enumerate() {
            session
                .receive_share(dealer, shares[peer])
                .unwrap_or_else(|c| panic!("dealer {dealer} -> node {peer}: {}", c.reason));
        }
    }
    println!("[DKG] All {N}x{N} shares verified against their dealers' public commitments.");
    let results: Vec<(SecretKeyShare, PublicKeySet)> = sessions
        .into_iter()
        .map(|s| s.finalize().expect("DKG must finalize"))
        .collect();
    let group_pks = results[0].1.clone();
    assert!(results
        .iter()
        .all(|(_, p)| p.public_key() == group_pks.public_key()));
    assert_eq!(group_pks.threshold(), T);
    println!("[DKG] Every node derived the identical group public key; no party computed the group secret.\n");

    let invoice_id = "inv-2026-000042";
    println!("[DERIVE] Deriving a key for {invoice_id:?} using nodes [0, 1, 2]...");
    let a = derive(&results, &group_pks, invoice_id, &[0, 1, 2]);
    println!("[DERIVE] Re-deriving with a DIFFERENT subset [1, 3, 4]...");
    let b = derive(&results, &group_pks, invoice_id, &[1, 3, 4]);
    assert_eq!(
        a.to_bytes(),
        b.to_bytes(),
        "derived key must not depend on the responding subset"
    );
    println!("[DERIVE] Identical key from both subsets (k-of-n liveness confirmed).\n");

    let bad = SignatureShare::random_for_test(&mut rng);
    let rejected = !verify_partial(&group_pks, 4, invoice_id, &bad);
    println!("[ADVERSARIAL] A garbage partial \"from\" node 4 is rejected by per-share verification: {rejected}\n");
    assert!(rejected);

    let plaintext = b"invoice amount: 48,500.00; counterparty: Example Bank N.A.";
    let key = symmetric_key_from_derived(&a);
    let ct = xor_encrypt(&key, plaintext);
    let recovered = xor_encrypt(&key, &ct);
    assert_eq!(recovered, plaintext);
    println!(
        "[ROUND TRIP] Encrypted and decrypted {} bytes with the quorum-derived key.",
        plaintext.len()
    );
    println!("\n=== PoC complete: DKG -> derive (twice) -> reject-bad-partial -> round trip, all passed. ===");
}

fn derive(
    results: &[(SecretKeyShare, PublicKeySet)],
    pks: &PublicKeySet,
    identity: &str,
    subset: &[usize],
) -> Signature {
    assert!(subset.len() > T, "need at least {} nodes", T + 1);
    let mut shares: BTreeMap<usize, SignatureShare> = BTreeMap::new();
    for &i in subset {
        let partial = sign_partial(&results[i].0, identity);
        assert!(
            verify_partial(pks, i, identity, &partial),
            "node {i}'s partial failed verification"
        );
        shares.insert(i, partial);
    }
    let sig = combine(pks, &shares).expect("combine");
    assert!(
        verify_combined(pks, identity, &sig),
        "combined key failed verification"
    );
    sig
}

fn symmetric_key_from_derived(sig: &Signature) -> [u8; 32] {
    let out = Sha256::digest(sig.to_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn xor_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}
