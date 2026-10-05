# CipherSettle Threat Model

**Version:** 1.0
**Status:** self-assessment. No independent cryptographic peer review has been performed; see `SECURITY_REVIEW.md` §6 for the outstanding verification scope.

## Assets
| Asset | Where | Notes |
|---|---|---|
| Per-invoice derived key | derived by quorum, sealed to caller's transport key (`quorum_vetseal`) | `quorum_service` never holds a `TransportSecretKey` |
| Node key shares | `quorum_node` | 3-of-5 threshold, Feldman DKG |
| `service_auth_key` (shared HMAC key) | `quorum_service`, all nodes | Compromise lets an attacker authorize any invoice |
| Invoice commitments | `ciphersettle_core::commitment`, Postgres | Salted, versioned SHA-256; service never sees plaintext |
| Audit log | `quorum_audit`, `quorum_notary` | Tamper-evident, majority reconciliation |
| Nonce store | in-memory in each node | Lost on restart; see T-3 |

## Actors
Malicious node, malicious/compromised `quorum_service`, malicious client, network attacker, insider, malicious DKG dealer. 

## Trust boundaries
1. client <-> `quorum_service` (HTTP, TLS terminates at service; adversarial test group K covers TLS termination and loopback enforcement)
2. `quorum_service` <-> nodes (mutual TLS + per-node HMAC derive auth)
3. nodes <-> `quorum_notary` / audit (mutual TLS)
4. service <-> Postgres
5. system <-> any external authority: **NONE exists in code** — the `VerificationAttestation` object is not built

## Attack paths

| ID | Path | Status | Mitigations / Evidence |
|---|---|---|---|
| T-1 | Node-level authorization bypass | Mitigated | HMAC derive auth bound to identity + expiry + nonce + transport key; evidence via adversarial test group C |
| T-2 | Replay of a derive request | Mitigated | Rejected within a 30 s window; evidence via adversarial test group D |
| T-3 | Replay after node restart | Mitigated with caveat | A restart guard refuses any request accepted by a previous process, given a non-stepping wall clock; evidence via test group L. **Caveat:** the guard is time-based, so it does not defend against a wall clock that steps backwards, and the in-memory nonce store is lost on restart. |
| T-4 | Compromised service or shared HMAC key authorizes any invoice | **Open / Accepted Risk** | Trust boundary by design of the current auth model; requires an operational decision, or resolution of the `VerificationAttestation` gap (see below) |
| T-5 | Malicious DKG dealer, wrong degree | Mitigated | Commitments of the wrong degree are rejected at receipt (`receive_commitment` returns `Result`; commitment length must equal `t+1`) |
| T-5b | Malicious DKG dealer, valid degree but dishonest share | **Open** | Detected as a `Complaint` and the complaining node never finalizes; there is no protocol to exclude a confirmed-bad dealer and continue. Availability impact only. |
| T-6 | Concurrent audit-log writers lose a write, or split a quorum | **Open** | Partial fix: only signatures that verify over the entry hash are stored (R-1). **The vote-TTL split-quorum hazard (R-2) is still open** — a proposer slower than the TTL can obtain overlapping votes and produce two conflicting "committed" entries. See `SECURITY_REVIEW.md`. |
| T-7 | Unsealed share or plaintext visible on node->service bytes | Mitigated | Verified in source: shares are sealed to the caller's transport key before leaving the node |
| T-8 | mTLS misconfiguration / cert handling | Mitigated | Certificate pinning is exact-DER-equality; adversarial test groups F and K cover certificate constraints and TLS enforcement |
| T-9 | Malformed/oversized input, parser DoS, network-reachable panics | Mitigated / Open | Line-length bounding exists (`bounded_line_reader.rs`); **fuzzing is not complete** |
| T-10 | Below-threshold / threshold compromise beyond PoC | Open | Requires formal analysis |
| T-11 | Vetseal design | **Open** | ElGamal over G2 has no AEAD, and is malleable by design (required for homomorphic combine — see CRYPTO-008). The NIZK is now implemented and wired into `DerivePartial`, but has not been reviewed by a human cryptographer. |
| T-12 | Supply chain (dependencies, secrets) | Partially mitigated | `cargo audit` and `cargo deny` run in the `supply-chain` job of `.github/workflows/ci.yml` (never yet run on GitHub; executed locally). **Three advisories remain knowingly accepted** (all `rustls-webpki 0.101.7`) with documented justifications in `deny.toml`. No SBOM is generated. Secrets can now be supplied from permission-checked files (Gap 9 slice) but are not KMS-backed and cannot be rotated online (finding A2). |

## The load-bearing architectural gap

T-4 above is the sharpest version of a gap that runs through the whole design: no `VerificationAttestation` from any external authority is checked anywhere in the system today. Authorization rests entirely on a shared HMAC secret between `quorum_service` and the nodes. Until an externally-signed attestation object exists and is independently verified by each node, any claim that access is conditioned on a regulator's verified result is aspirational rather than implemented. This is tracked as §6a of `CipherSettle_Audit_Remediation_Roadmap.md`.
