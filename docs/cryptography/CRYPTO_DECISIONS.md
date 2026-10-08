# CipherSettle — Cryptographic Decision Records

This document maintains the architectural decision records (ADRs) for the cryptographic and security designs within the CipherSettle protocol.

**Evidence labels (Gap 17, session 25, read line by line against the code at commit 766c1a4).** **READ** = the cited code was read in that pass and matches. **EXECUTED** = a recorded test/probe demonstrates it (see `docs/PRODUCTION_READINESS.md`, `agent_memory/SECURITY_FINDINGS.md`). **UNVERIFIED** = not checked. This pass checks that the code does what each record SAYS; it does not judge the cryptography. **No independent cryptographer has reviewed any record below** (`NEEDS_HUMAN_CRYPTO_REVIEW`), and nothing here is a claim that the system is secure, audited or production-ready.

---

## CRYPTO-001 — Feldman VSS for DKG, with `Complaint` instead of panic

**STATUS:** `IMPLEMENTED_AND_TESTED`

**COMPONENT:** `quorum_core` (DKG session state machine)

**CONTEXT:** Phase 0's PoC (`quorum_poc`) used `assert!`/panic on a bad share. This is unacceptable in a long-running node process — a single malicious dealer could crash a live node.

**DECISION:** Represent a verification failure as a `Complaint` value returned from `DkgSession::receive_share`, not a panic. The complaining node simply never reaches `is_ready()`/finalizes.

**RATIONALE:** Fail-safe (blocks that node, doesn't crash it) without requiring the full dispute-resolution protocol to exist yet.

**SECURITY PROPERTY:** A single malicious dealer cannot crash an honest node's process. It CAN permanently stall any node it successfully lies to, since there is no exclusion/continue mechanism — this is a known, documented limitation, not a claimed fix for GJKR-style dispute resolution.

**ALTERNATIVES:** Full GJKR-style commit-then-reveal dispute resolution (A11) — explicitly deferred, tracked as `NOT_IMPLEMENTED`.

**IMPLEMENTATION:** `quorum_core::DkgSession::receive_share` / `Complaint` type.

**KNOWN LIMITATIONS:** No dispute resolution protocol is fully implemented for continued operation upon exclusion. READ (`quorum_core/src/bls.rs` `receive_share` returns `Result<(), Complaint>`). Still open (`SECURITY_REVIEW.md` R-3): the `from` field of DKG messages is not bound to the connection's certificate and `receive_commitment` overwrites a stored commitment for that dealer id, so any pinned-certificate holder can impersonate a dealer during the DKG window (`quorum_node/src/main.rs` `DkgCommitment` arm; `bls.rs` `commitments.insert`).

---

## CRYPTO-002 — Boneh-Franklin threshold BLS derive over `threshold_crypto`

**STATUS:** `SUPERSEDED_BY_V3` (Replaced by `blstrs` cutover; maintained for historical context)

**COMPONENT:** `quorum_core` (`sign_partial`, `verify_partial`, `verify_combined`)

**CONTEXT:** vetKD's actual model is "derive, don't decrypt" — a per-identity private key derived via threshold BLS, matching Boneh-Franklin IBE's `sk_id = s · H(id)` construction. The initial implementation utilized `threshold_crypto`.

**DECISION:** Use `threshold_crypto`'s BLS12-381 implementation directly rather than hand-rolling pairing arithmetic.

**RATIONALE:** Using an existing library's implementation rather than hand-rolling pairing arithmetic reduces the surface area for subtle correctness errors. However, `threshold_crypto` became unmaintained, triggering a high-priority remediation (A6) to move to `blst`/`blstrs`.

**SECURITY PROPERTY:** Below-threshold combination is refused. (In the current `blstrs` implementation this is `quorum_core::combine`, which requires at least `t + 1` shares; see CRYPTO-003.) 

**KNOWN LIMITATIONS:** Unmaintained dependency chain (`ff`/`pairing`/`group` 0.x), leading to the `blstrs` migration.

---

## CRYPTO-003 — `blstrs` migration (A6)

**STATUS:** `IMPLEMENTED_AND_INTEGRATED`

**COMPONENT:** `quorum_core`, `quorum_vetseal`

**CONTEXT:** A6 (High severity) — migrate off the unmaintained `threshold_crypto`/`ff`/`pairing`/`group` 0.x chain to `blst`/`blstrs`, the actively-maintained pairing library used across Ethereum/Filecoin.

**DECISION:** Fully transition `quorum_core` and `quorum_vetseal` to utilize `blstrs` directly for all cryptographic pairings and evaluations.

**RATIONALE:** "A subtly wrong migration here is worse than the unmaintained dependency it replaces." By directly using well-supported ecosystem primitives, the system eliminates the highest risk maintenance liability.

**SECURITY PROPERTY:** Relies on `blstrs::G2Projective::hash_to_curve` (RFC 9380). Validates that the curve/group assignment (secrets+commitments in G1, signatures in G2) preserves correct evaluation without structural mismatches.

**IMPLEMENTATION:** Built into production `quorum_core` and `quorum_vetseal`.

---

## CRYPTO-004 — Fiat-Shamir NIZK for sealed-share correctness

**STATUS:** `IMPLEMENTED_AND_INTEGRATED`

**COMPONENT:** `quorum_vetseal::nizk`

**CONTEXT:** A node's contribution should be independently verifiable *before* aggregation, not only checked after final combine+decrypt. Without this, a dishonest node's ciphertext is only caught after the caller decrypts, which is one step later than necessary in the pipeline.

**DECISION:** A Fiat-Shamir'd generalized-Schnorr (Chaum-Pedersen-style) NIZK proving a `SealedShare` encrypts the same secret-share exponent as a stated public key share, without revealing the share or the ElGamal randomness.

**RATIONALE:** Closes the "detect invalid cryptographic contributions before aggregation" success criterion.

**SECURITY PROPERTY:** A node sealing a share for the wrong identity is caught by `verify_sealed_share` before combine. 

**ASSUMPTIONS:** The Fiat-Shamir challenge is derived using SHA-256 with rejection sampling over 32-byte little-endian scalar representations, producing a full-width uniform scalar. This is sound under the random-oracle model. `blstrs::Scalar` exposes no hash-to-field routine in version 0.7.1, which is why the derivation is implemented here rather than delegated to the library.

**IMPLEMENTATION:** `quorum_vetseal::nizk`, wired into the live protocol: `quorum_node` emits a proof for every partial it sends (`quorum_core::seal_partial_with_proof`), and `quorum_client` verifies each node's proof before combining (`quorum_core::verify_sealed_partial`).

**KNOWN LIMITATIONS:** The service can be configured to skip the proof check (`insecure_skip_share_proofs`, test-only; since session 26 the service refuses it unless `CIPHERSETTLE_ALLOW_INSECURE_TEST_FLAGS` carries an explicit acknowledgement: F-28, unit-tested). Does **not** bind a `pk_share` to a node index by itself — the caller must independently confirm the presented `PublicKeyShare` matches `PublicKeySet::public_key_share(node_id)` from the DKG's own public commitment. The live path satisfies this: `verify_sealed_partial` re-derives the expected public key share from the group's own Feldman commitment rather than accepting the node's value. The proof system itself has **not** been reviewed by a qualified cryptographer — see `SECURITY_REVIEW.md` §6.B.

---

## CRYPTO-005 — ElGamal-over-G2 transport-key sealing, live-wired

**STATUS:** `IMPLEMENTED_AND_TESTED`

**COMPONENT:** `quorum_vetseal` (`encrypt_share`, `decrypt_share`, `combine_sealed_shares`, `TransportSecretKey`/`TransportPublicKey`, `SealedShare`/`SealedDerivedKey`).

**CONTEXT:** Finding 2.3: the derived key was returned unwrapped, protected only by the mTLS channel — not vetKD's actual security property of a transport-key-sealed result no intermediary can read.

**DECISION:** Seal each node's partial under the caller-supplied transport public key at the node, before it ever leaves the node; combine sealed shares without decrypting anywhere except at the true end caller, who holds the matching transport secret key.

**RATIONALE:** Sealing removes the *plaintext* share before it leaves the node, so the pre-combine check that used to run on plaintext (`verify_partial`) no longer has anything plaintext to check. That check was subsequently restored in its cryptographic form by CRYPTO-004's NIZK: the broker verifies a proof of correct encryption before combining. What remains deferred to the caller is verification of the *combine output*, via the final `verify()` in `open_sealed_derived_key` — both checks are required, and the NIZK does not replace the final one.

**SECURITY PROPERTY:** No node, broker, or backend process (including `quorum_service` itself) is ever structurally able to hold a plaintext derived key or an unsealed partial share meant for someone else. `quorum_service::derive_invoice_key` never constructs or references a `TransportSecretKey`.

**ASSUMPTIONS:** mTLS between service and nodes still matters for availability/integrity of the exchange even though confidentiality of the final key no longer depends on it; `sign_derive_auth`'s inclusion of `transport_public_key` in the MAC prevents a man-in-the-middle on the service-to-node hop from redirecting a sealed result to a transport key of their own.

**IMPLEMENTATION:** `quorum_vetseal::encrypt_share`/`combine_sealed_shares`; integrated across `quorum_node`, `quorum_client`, and `quorum_service`.

---

## CRYPTO-006 — HMAC-based derive authorization with expiry + single-use nonce

**STATUS:** `IMPLEMENTED_AND_TESTED`

**COMPONENT:** `quorum_core::sign_derive_auth`/`verify_derive_auth`/`build_derive_request`; `quorum_node`'s `DeriveRequest` handler.

**CONTEXT:** Finding 1.1 (CRITICAL: any holder of the shared mTLS client cert could derive any invoice's key with zero node-level authorization) and Finding 2.1 (HIGH: no anti-replay/freshness binding on derive requests).

**DECISION:** Bind every `DeriveRequest` to `identity`, an expiry (`expires_at_unix_ms`, capped node-side at `MAX_DERIVE_AUTH_WINDOW_MS = 30_000`), a single-use 16-byte `nonce`, and the caller's `transport_public_key`, all under an HMAC-SHA256 MAC. **Current key model (Gap 3 step 1, EXECUTED by adversarial group S):** the service holds a MASTER secret and each node `i` is configured with only `derive_node_auth_key(master, i)` (HKDF-SHA256, `quorum_core/src/lib.rs`); the service signs each request with the target node's derived key (one request per node). The first version of this record described one key shared by all nodes. Nodes verify the MAC (constant-time), reject expired or over-long-window requests, and track used nonces to reject replays.

**RATIONALE:** Addresses Findings 1.1 and 2.1 via a lightweight symmetric authentication token mechanism bound to the specific authorization parameters.

**SECURITY PROPERTY:** A party holding only the mTLS client certificate, without also holding a node's derived key, cannot construct a valid `DeriveRequest` for that node. A leaked derived key authorizes requests to THAT node only (below the `t+1` partials needed). A captured, valid `DeriveRequest` cannot be replayed after its expiry or after first use. Binding `transport_public_key` into the MAC prevents a party on the service-to-node hop from redirecting a sealed result to a transport key of their own.

**ASSUMPTIONS:** The service-held MASTER secret remains a single point of compromise: whoever holds it can authorize derivations on every node (THREAT_MODEL T-4). Removing that needs protocol-level change (Gap 3 step 2) which is `NEEDS_HUMAN_CRYPTO_REVIEW` and NOT done. No key rotation or versioning exists. The doc comment on `NodeConfig::service_auth_key_b64` was corrected in session 26 (F-29).

**IMPLEMENTATION:** `quorum_core::{sign_derive_auth, verify_derive_auth, build_derive_request, MAX_DERIVE_AUTH_WINDOW_MS}`; integrated into `quorum_node`.

---

## CRYPTO-007 — DKG dealer commitments of mismatched degree are rejected at receipt

**STATUS:** `IMPLEMENTED_AND_TESTED`

**COMPONENT:** `quorum_core::DkgSession::receive_commitment`

**CONTEXT:** The protocol folds commitments from each dealer into a joint aggregate public polynomial commitment. Plain addition of coefficient vectors implicitly zero-pads the shorter operand, so a commitment whose degree does not match the agreed threshold `t` would otherwise be silently accepted into the group's public commitment.

**DECISION:** `receive_commitment` returns `Result<(), Complaint>` and rejects any commitment whose length is not exactly `t + 1`, or whose dealer id is out of range. Commitments are additionally bounded by `MAX_COMMITMENT_POINTS` (256) at parse time, so an oversized commitment cannot cause unbounded allocation before it is rejected.

**SECURITY PROPERTY:** "A dealer that broadcasts a lower-degree or higher-degree polynomial commitment than the DKG's agreed threshold `t` is rejected, not silently accepted into the group's public commitment."

**RATIONALE:** Rejecting at receipt rather than asserting in `finalize` means a bad dealer never contaminates the aggregate, and the failure is attributable to a specific dealer rather than surfacing as an unexplained finalization failure.

**KNOWN LIMITATIONS:** This is a structural check only. It does not perform Feldman share verification — that happens when a receiver checks an individual share against the dealer's published commitment, and produces a `Complaint`. There is still no protocol for the quorum to exclude a confirmed-bad dealer and continue.

---

## CRYPTO-008 — Analysis of `quorum_vetseal`'s Construction 

**STATUS:** `SELF_REVIEWED_ONLY` (the label was `VERIFIED_BY_REVIEW`; no independent cryptographer was involved, so that label overstated it)

**COMPONENT:** `quorum_vetseal`

**FINDING:** `quorum_vetseal` is plain exponential ElGamal directly over BLS12-381 G2, *not* an ECDH-derived key wrapping a symmetric AEAD. The "message" encrypted is the BLS signature share/derived key *as a curve point itself* (`M = C2 - secret·C1`), which is why this works without an AEAD: integrity comes from the threshold verification rejecting any decrypted point that isn't the genuine result.

**SECURITY PROPERTY:** Malleability is inherent to plain ElGamal but is a non-issue here because: (a) only the originating node ever constructs `SealedShare`s from a genuine, freshly-verified partial, (b) `combine_sealed_shares` is a fixed, non-adversarial-input linear operation over already-produced ciphertexts, and (c) any resulting garbage is caught by the `verify_combined` check the caller is required to run.

**REVIEWER NOTE:** This record was written before the NIZK was added. The NIZK (CRYPTO-004) now gives an independent pre-combine check on each sealed share, which strengthens (a) further. The ElGamal malleability and absence of an AEAD remain, and remain accepted by design — see CRYPTO-005's stated tradeoff and `SECURITY_REVIEW.md` §6B for what a qualified cryptographer should examine here.

---

## CRYPTO-009 — Degree-mismatch liveness implications (historical)

**STATUS:** `RESOLVED_BY_CRYPTO_007`

**CONTEXT:** Assessing the impact of a dealer submitting a commitment whose degree differs from the expected threshold `t`.

**FINDING (as originally assessed, before the CRYPTO-007 fix):**
- **Higher-degree dealer (`> t`)**: the commitment would have been silently accepted, raising the group's effective threshold to the highest degree contributed. A single malicious dealer dealing at degree `n-1` would convert a 3-of-5 system into a 5-of-5 system without erroring — silent liveness loss.
- **Lower-degree dealer (`< t`)**: no effect on the aggregate degree, provided at least one honest dealer contributes a degree-`t` polynomial.

**RESOLUTION:** Both cases are now rejected at receipt by the length check described in CRYPTO-007, so neither the degree-inflation scenario nor the silent-padding scenario is reachable. `finalize` no longer needs a defensive `threshold() == t` assertion for this specific failure mode, though the aggregate threshold is still computed from the folded commitments.

**REMAINING CONCERN (availability, not degree inflation):** a dealer that submits a *correctly-shaped but dishonest* degree-`t` commitment is caught later, when individual shares fail Feldman verification and produce `Complaint`s. The complaining node never finalizes, but there is no mechanism to exclude the dealer and let the quorum continue. That is a separate gap, tracked as finding A11 in `CipherSettle_Audit_Remediation_Roadmap.md`.
