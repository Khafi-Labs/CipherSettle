# CipherSettle: Technical Security Assessment

**Status:** Technical security assessment. **Independent cryptographic peer review is pending** — see §6 for the specific verification scope. Items marked `NEEDS_HUMAN_CRYPTO_REVIEW` in the source are unresolved.

**Nothing here is a security guarantee.** This is a self-assessment, not an independent audit. The most important limitation is that the reviewers of this document are the same team that designed and implemented the system being assessed, which is structurally unable to catch classes of errors it does not already know to look for. A qualified third party is required for that; see `CipherSettle_Audit_Remediation_Roadmap.md` § Phase 5.

## 1. System summary and trust model

- 5 nodes, threshold t=2 (need t+1=3). Feldman-VSS DKG on BLS12-381 (`quorum_core::bls`, blstrs only).
- Derive: the service asks nodes for partial signatures on `identity`; each node returns its partial
  **ElGamal-sealed in G2** to the caller's transport key, with a NIZK (`quorum_vetseal::nizk`) that the
  ciphertext encrypts `H(identity)^s` for the `s` behind that node's public key share. The client checks the
  proof against the group Feldman commitment, combines homomorphically, decrypts, and verifies the final BLS signature.
- Audit log: hash chain, ed25519 co-signatures, two-phase commit (vote, then replicate with > t signatures).
- Assumed adversary: up to t compromised nodes; network attacker; a holder of a pinned mTLS certificate.
  NOT modelled: a compromised majority, side channels, host compromise, malicious database.

## 2. Findings from this pass

| ID | Severity (assessed) | Status | Summary |
|---|---|---|---|
| R-1 | Medium | **Fixed in source, unverified build** | `ReplicateAuditEntry` merged/persisted every attached signature once the count gate passed, and did not check the entry hash matched the stored entry. A pinned peer could replay a genuine committed entry with a garbage signature for node k and overwrite k's stored valid co-signature (log evidence degraded below t+1 valid sigs). Fix: only signatures that verify over the entry hash are stored; hash must equal the stored entry's. |
| R-2 | High (protocol safety) | **Open, hazard pinned by a test** | Vote TTL (5 s) lets a node grant a second, different entry at the same seq. If proposer A is slower than the TTL, A and B can both gather 3 votes (overlap on one node) and two conflicting entries are each "committed". Client per-request timeout is 3 s and there are up to 8 attempts, so a >5 s round is reachable. Options: bound total proposer round time below the TTL; or hold the vote until a commit/higher seq is observed and resolve stuck votes by an explicit view change. Restart also drops votes (memory-only). Test: `vote_slot_tests::ttl_expiry_can_split_quorums_documented_hazard`. |
| R-3 | Medium | Open, **not verified by test** | `handle_message` has no peer identity: `PinnedCertVerifier` only checks "cert is in the allow-list", not *which* peer. The `from` field of `DkgCommitment`/`DkgShare` is therefore unauthenticated and `receive_commitment` overwrites. Any pinned cert holder (including the service's client cert, which is pinned on nodes) can impersonate a dealer during the DKG window, at minimum causing a permanent complaint/DoS. Fix idea: bind `from` to the cert fingerprint of the connection. |
| R-4 | High (operational) | Open | The epoch guard binds the **scheme string**, not the **group public key**. Nodes do not persist shares, so a full-quorum restart produces a new DKG and a new group key with the same scheme string; every existing invoice ciphertext (encrypted to the old key) becomes unrecoverable and the guard says nothing. Fix idea: store a fingerprint of the group public key in `crypto_meta`, refuse on mismatch. Also: a single restarted node can never rejoin (peers push DKG only at their own startup). |
| R-5 | Low | Open | `acknowledge_pre_cutover_data: true` is a persistent config flag; leaving it set makes an unstamped database with invoices start silently after the marker is lost. It should be one-shot (stamp then require removal). |
| R-6 | Low/Operational | Open | `DEFAULT_DERIVE_AUTH_VALIDITY_MS` = MAX - 2 s leaves only **2 s of tolerated clock skew** (a client clock ahead by > 2 s is rejected as "window exceeds maximum"). And the restart guard refuses a default-validity request for the first 2 s after node start. Both are pinned by `restart_guard_refusal_window_is_exactly_max_minus_default_validity`. |
| R-7 | Low | Open | Nonce set is pruned with an O(n) `retain` on every request under a lock; bounded only by the rate of MAC-valid requests (needs `service_auth_key`). Not exploitable without the key. |

## 3. Invariants and where each is (or is not) tested

1. Feldman: accepted share satisfies `g^share == C(x_i)` for the dealer's own commitment. Tested in `quorum_core`.
2. Dealer degree is exactly t (`commitment.len() == t+1`); wrong degree rejected at receipt (C-1). Tested.
3. Final share matches the group commitment at own index (`finalize`). Tested.
4. Every derive share is verified against the **group-derived** `pk_share(node_id)`, never node-supplied. Tested (Test M1/M2, core tests).
5. Proof bound to (ciphertext, pk_share, identity hash, recipient key). New: bit-flip and replay sweeps (**written but not yet run**).
6. At most one entry hash per seq per node within the TTL. Tested exhaustively (**written but not yet run**); **breaks after TTL (R-2)**.
7. Only signatures that verify over the entry hash are stored. R-1 fix; **no test yet exercises the node handler** (needs a live-node adversarial test: replay a committed entry with a garbage signature, assert stored signatures unchanged).
8. No request accepted by a previous process is served after restart, given a non-stepping wall clock. Tested (Test L, unit sweep).
9. A database with a mismatched epoch marker is never served, no override. Tested (Test N, matrix).

## 4. Attack surface

- Node mTLS listener (pinned certs; cert identity not bound to message `from`: R-3).
- Derive path: MAC + expiry + single-use nonce + restart guard; then seal + prove.
- Audit path: `AppendAuditEntry` (vote), `ReplicateAuditEntry` (commit; R-1), `GetAuditLog`.
- Service HTTP API (rate limiting, API keys, TLS off-loopback enforced). `tls_serve` uses `with_no_client_auth`.
- Client-side combine/verify (trusted caller code).
- Persistent state: Postgres (invoices, `crypto_meta`), node audit-log JSON files (unauthenticated on disk).

## 5. The ignored advisories: what the source can and cannot show

**Limitation:** the advisory texts were not available to the reviewer at the time of this assessment (the advisory database was unreachable). The table below is therefore derived from repository source and general knowledge of these crates rather than from the advisories themselves. Each claim is tagged by how it was established, and any claim marked *unverified* should be treated as a hypothesis to be checked, not a conclusion. `deny.toml` is the authoritative record of which advisories are ignored and under what conditions they are removed.

| Advisory group | Justification | Basis for the claim | Verdict |
|---|---|---|---|
| `postgres-protocol` / `tokio-postgres` (RUSTSEC-2026-0178/0179/0180) | **RESOLVED in Gap 7 (executed):** unpinned to `postgres-protocol 0.6.12` / `tokio-postgres 0.7.18`; `cargo audit` with no ignores no longer reports them. The ignores were removed from `deny.toml`. | n/a | n/a |
| `time 0.3.36` (RUSTSEC-2026-0009) | Only test tooling | *Verified in source:* no `time::`/`chrono` usage in `src`; the dependency graph shows `time` only under `rcgen` in `quorum_adversarial` and `quorum_orchestrator`. Not in the production node/service/client. *Unverified:* the advisory text was not read, so it cannot be confirmed that the exposed parse path is not reached during certificate generation. | Plausible; low risk. Confirm the advisory's trigger condition. |
| `rustls-webpki 0.101.7` (0098, 0099, 0104) | Custom pinned verifiers never reach name-constraint or CRL code | *Verified in source:* every `ClientConfig`/`ServerConfig` builder in the tree uses `with_custom_certificate_verifier`, a custom `with_client_cert_verifier`, or `with_no_client_auth`; none uses `WebPkiVerifier` or a root store. *Unverified (from general knowledge, not confirmed against source):* rustls 0.21's default TLS signature-check helpers parse the peer certificate with webpki but do not build a chain or apply name constraints/CRLs. | Likely sound (name-constraint checks and CRL parsing are in path-building, which pinned verifiers skip). **Confirm against the rustls 0.21 source.** The cleaner fix is a migration to rustls 0.23. |
| Stale ed25519 ignore | n/a | The crate is no longer in the dependency tree; the ignore has been removed. | Resolved |

## 6. Cryptographer checklist (exactly what to verify)

**A. `quorum_core/src/bls.rs`**
1. Hash-to-curve: `G2Projective::hash_to_curve(msg, SIG_DST, &[])` implements RFC 9380 `BLS12381G2_XMD:SHA-256_SSWU_RO_` with this DST; DST choice and length.
2. Scheme layout: pubkeys in G1, signatures in G2; verification equation `e(pk, H(m)) = e(g1, sig)` (`pairing_eq`), including identity-point handling of `pk` and `sig`.
3. Evaluation points `x = node_id + 1`; group secret at 0; Lagrange at zero (`lagrange_at_zero`) with duplicate-point rejection.
4. Feldman check `g^s == C(x_i)`; **completeness of complaint handling**: complaints only mark the session not-ready (no dispute resolution, no disqualification). Is "fail-stop on any bad dealer" acceptable for your liveness needs?
5. **Rushing / adaptive adversary in Pedersen-style DKG**: this is plain Feldman with a summed commitment; the known key-bias attack (Gennaro et al.) applies. Is the bias tolerable for BLS threshold signing here? (Note the DKG is also not authenticated: R-3.)
6. Scalar encodings: **two conventions coexist** (`scalar_to_bytes` is big-endian for DKG wire; `secret_scalar_bytes_for_test`/vetseal use little-endian `to_repr`). One bug from this already occurred. Confirm every boundary.
7. `Commitment::from_bytes`: relies on `G1Affine::from_compressed` performing on-curve and **subgroup** checks. Confirm for blstrs 0.7.1 (vs an `_unchecked` variant).
8. `SecretKeyShare` zeroing is best-effort assignment (not `zeroize`, no volatile guarantee).

**B. `quorum_vetseal` ElGamal and `nizk.rs`**
1. Statement: Okamoto-style proof of knowledge of `(s, r)` over `pk_share = g1^s`, `C1 = g2^r`, `C2 = recip^r * H^s`, three equations, one challenge. Check soundness/special soundness and honest-verifier ZK; whether **cross-group witness reuse (G1 and G2 with the same scalar)** is sound as written.
2. Fiat-Shamir transcript: contents (`PROOF_DST`, pk_share, recipient, H, C1, C2, R1..R3), fixed-width so no length prefixes, and **absence of any node id / session / request nonce**: is replay of a proof across requests for the same identity/recipient acceptable? (Ciphertext is fresh per request, so probably yes: confirm.)
3. `hash_to_scalar`: SHA-256 rejection sampling over 32-byte little-endian reprs (~50% acceptance); challenge is a full-width scalar; confirm no bias or malleability.
4. Verifier accepts `recipient` = identity point (ciphertext then equals the plaintext share): harmless to the caller who chose it, but confirm nothing relies on a non-degenerate recipient. Also `pk_share`-identity/`s = 0` edge.
5. **ElGamal is malleable by construction** (needed for homomorphic combine). Confirm there is no decryption-oracle exposure (final `verify_combined` is the only check).
6. `combine_sealed_shares`: index-to-x mapping consistent with `bls.rs` (`index_to_x` vs `point_of`); duplicate detection.
7. Binding gap (documented in `nizk.rs`): correctness depends on the caller deriving `pk_share` from the group commitment, which `verify_sealed_partial` does. Confirm no other caller uses `verify_sealed_share` directly.

**C. Restart guard (`derive_request_predates_restart`)**
1. Argument: any request accepted before a crash has `expires_at <= crash_time + MAX <= process_start + MAX`. Holds only if the wall clock never steps backwards across a restart (NTP step, VM restore): is that assumption acceptable, or use a persisted high-water mark?
2. 2 s skew tolerance and start-up refusal window (R-6).

**D. Epoch scheme (`decide_crypto_epoch`)**
1. Sufficiency: scheme string only (R-4). Recommend binding the group public key fingerprint.
2. One-shot acknowledgement (R-5).

**E. Audit two-phase commit (not crypto, but safety-critical)**
1. R-2 TTL split-quorum; R-1 fix review; is n=5, t=2, quorum 3 enough given two-proposer overlap only needs one shared voter after expiry?

## 7. Tests added in this pass

- `quorum_audit::vote_slot_tests` (5): **deterministic replacement for probabilistic Test E**. Enumerates all 2^5 delivery orders: exactly one winner with 5 reachable nodes; 2/2 split with 4 reachable recovers after TTL and never double-commits; commit clears slot; clock-going-backwards does not panic; TTL hazard pinned.
- `quorum_vetseal::nizk` (10): seed x node honest sweep; every byte flip of the proof and of the ciphertext is rejected; cross-identity and cross-node replay fails; degenerate blobs never verify or panic.
- `quorum_core`: restart-guard refusal window pinned and monotone.
- `quorum_service::db::epoch_tests`: exhaustive decision matrix.

Test E (live 5-node race) is kept as an end-to-end smoke test; it is no longer the evidence for the property. The deterministic test has no concurrency by design.

**Known reliability issue, un-reconciled:** Test E was separately observed to be flaky under load — 3 passes out of 5 back-to-back runs. It therefore should not be relied on as a hard gate until it has been re-run many times under controlled artificial load in a target environment and the discrepancy resolved. See `CipherSettle_Audit_Remediation_Roadmap.md` §4.

## 8. Not done / recommended next

1. Live adversarial test for R-1 (replay committed entry with garbage sig).
2. Decide R-2 (bound round time or view change), R-3 (bind `from` to cert), R-4 (group-key fingerprint), R-5.
3. Re-run `cargo deny check` in CI; consider lifting the 1.75 pin and moving to rustls 0.23.
4. A real fuzz harness (`cargo-fuzz`) for message decoding and `EncryptionProof::from_bytes`.
5. **Cryptographer review of section 6 — the single most important outstanding item.**
