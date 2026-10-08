# CipherSettle — System Architecture

## System Overview

CipherSettle is a Rust Cargo workspace of 11 members implementing an off-chain, vetKD-inspired threshold key-derivation system, plus a Postgres-backed REST product API layered on top, plus an adversarial test harness. Phases were built incrementally (0 → 4); each phase's crates still exist and still work together via `quorum_orchestrator`.

*Note on External Trust Dependencies:* Egypt's Financial Regulatory Authority (FRA) under Decision No. 51 of 2026 is the authoritative body for double-financing and validity checks. CipherSettle complements, not replaces, FRA's role. It consumes no FRA output today — see the `VerificationAttestation` gap in `README.md` and `SECURITY_REVIEW.md`.

## Repository Structure

```
/ (workspace root)
├── Cargo.toml                  workspace member list (11 members)
├── Cargo.lock
├── rust-toolchain.toml         pins rustc 1.97
├── deny.toml                   cargo-deny policy
├── ci/check_pin_policy.sh      fails build on undocumented `=` pins
├── README.md                   canonical current framing + scope correction
├── SECURITY.md                 vulnerability disclosure policy
├── SECURITY_REVIEW.md          current technical security assessment
├── PHASE1_README.md … PHASE4_README.md   one doc per phase (historical record)
├── CipherSettle_Audit_Remediation_Roadmap.md   A1-A15 findings + remediation plan
├── CONTRIBUTING.md              build, test, and crypto-review requirements
├── docs/
│   ├── FINANCIAL_CONTEXT.md    commercial case: actors, lifecycle, use cases
│   ├── PRODUCTION_READINESS.md engineering / integration / procedure layers
│   ├── GLOSSARY.md             plain-language term definitions
│   ├── ARCHITECTURE.md         this file
│   ├── cryptography/CRYPTO_DECISIONS.md
│   └── security/THREAT_MODEL.md
├── src/
│   ├── ciphersettle_core/      dependency-free access-control + commitment + merkle logic
│   ├── quorum_poc/             Phase 0 in-process PoC (no networking)
│   ├── quorum_core/            Phase 1 transport-agnostic DKG/derive state machine
│   ├── quorum_node/            Phase 1 real mTLS node binary
│   ├── quorum_orchestrator/    test harness / demo driver (all phases)
│   ├── quorum_audit/           Phase 2 transport-agnostic hash-chained audit log
│   ├── quorum_notary/          Phase 2 external notarization service
│   ├── quorum_client/          Phase 3 shared mTLS client/broker logic
│   ├── quorum_service/         Phase 3 product REST API (Postgres-backed)
│   ├── quorum_adversarial/     Phase 4 adversarial test suite (binary, not `cargo test`)
│   └── quorum_vetseal/         verifiable-encryption sealing crate (blstrs only) + nizk.rs proof module
```

## Crate Dependency Map

Workspace-internal, non-dev dependencies. This block is compared against `cargo metadata` by `ci/check_docs_claims.sh` (C10), so it cannot drift silently. (`quorum_vetseal` has `quorum_core` as a dev-dependency only.) Process-level relationships are not dependencies: `quorum_orchestrator` and `quorum_adversarial` additionally SPAWN `quorum_node`, `quorum_notary` and `quorum_service` as real OS processes.

```deps
ciphersettle_core:
quorum_adversarial: ciphersettle_core, quorum_audit, quorum_client, quorum_core, quorum_vetseal
quorum_audit:
quorum_client: quorum_audit, quorum_core, quorum_vetseal
quorum_core: quorum_audit, quorum_vetseal
quorum_node: quorum_audit, quorum_core, quorum_vetseal
quorum_notary: quorum_audit, quorum_core
quorum_orchestrator: ciphersettle_core, quorum_audit, quorum_client, quorum_core, quorum_vetseal
quorum_poc: quorum_core
quorum_service: ciphersettle_core, quorum_audit, quorum_client, quorum_core, quorum_vetseal
quorum_vetseal:
```

**Key Architectural Detail:** `quorum_vetseal` is a dependency of `quorum_core`, `quorum_node`, `quorum_client`, `quorum_service` (and the orchestrator and adversarial harness) — i.e., it sits *underneath* the core protocol crate, not bolted on afterward. This is required because sealing is wired into the real `DeriveRequest` flow.

## Crate Responsibilities

- **`ciphersettle_core`** — dependency-free decision logic: access control (`resolve_access`), rate limiting (`check_rate_limit`), payload-size checks (`check_payload_size`), nullifier/idempotency (`check_nullifier`), audit-action naming (`audit_action_for`), the invoice commitment scheme (`commitment` module), and an append-only Merkle Mountain Range log (`merkle` module, publicly re-exported from `lib.rs` as `MerkleLog`/`MerkleProof`/`Side`/`MERKLE_VERSION`). Zero networking, zero IC dependency.
- **`quorum_poc`** — Phase 0, single-process, in-memory DKG + derive simulation. No networking. Superseded by Phase 1.
- **`quorum_core`** — transport-agnostic DKG (Feldman VSS with `Complaint` on bad shares) + Boneh-Franklin threshold BLS derive + the `Message` wire enum + `config` module + the HMAC-based derive-authorization functions (`sign_derive_auth`/`verify_derive_auth`/`build_derive_request`), the per-node key derivation (`derive_node_auth_key`, HKDF-SHA256 from a master secret), and `secret_files` (secrets loaded from permission-checked files) and the `quorum_vetseal` type wiring in `Message::DeriveRequest`/`DerivePartial`. Zero networking, zero product logic.
- **`quorum_node`** — the standalone node binary. Owns mTLS (cert-pinned, no CA), drives a `quorum_core::DkgSession`, serves derive requests, persists an audit log replica (`audit_store`: an atomic fsynced snapshot plus an append-only checksummed journal, `<log>.journal`, one fsynced write per append, compacted into a new snapshot past 4 MiB; a damaged log or journal is fatal at start, an incomplete final journal frame is truncated; format and policy in `quorum_audit::journal`, F-20), persists its key share envelope-encrypted (`share_store`, pilot tier), acknowledges an audit entry only after it is durable (`AuditEntryCommitted`), handles audit wire messages. Contains `bounded_line_reader` and `handle_message`'s `DeriveRequest` arm, which performs: authorization window check → HMAC MAC verification (`verify_derive_auth`, against the node's OWN derived key) → single-use nonce check → restart guard → sign partial → self-verify (a `debug_assert!`, so DEBUG BUILDS ONLY; release builds rely on the client-side proof check, finding F-22) → seal + prove (`seal_partial_with_proof`) → respond with `Message::DerivePartial { sealed_share, proof, .. }`.
- **`quorum_orchestrator`** — spawns real `quorum_node` OS processes, drives DKG, simulates a 2-of-5 outage, brokers a derive + round-trip decrypt, drives the Phase 2 audit-log tamper/reconciliation demo, and (Phase 3) exercises the live `quorum_service` REST surface end to end.
- **`quorum_audit`** — hash-chained, multi-signed audit log. `AuditLog::try_append` refuses non-tip-extending appends; `AuditLog::diverges_from` / `majority_reference` do reconciliation; `NotarizationReceipt` is the external-anchor shape.
- **`quorum_notary`** — standalone binary, independent identity, signs and stores a receipt for each root hash a client submits (`NotarizeRequest`). It does not schedule anything itself: the orchestrator or another client decides when to ask.
- **`quorum_client`** — shared mTLS client logic used by both `quorum_orchestrator` and `quorum_service`: `build_connector`/`send_request`/`send_fire_and_forget`, `collect_sealed_derived_key` + `open_sealed_derived_key` (the split demanded by vetseal sealing), `propose_audit_entry` (typed `ProposeError`; waits for t+1 durable acknowledgements; `propose_and_cosign_and_replicate` is its string-error wrapper), `fetch_majority_tip`.
- **`quorum_service`** — the product REST API. Postgres-backed via `deadpool-postgres`. Calls `ciphersettle_core`'s decision functions unchanged. `derive_invoice_key`'s handler requires a caller-supplied `transport_public_key_b64`, brokers a sealed derive via `quorum_client`, and returns only `sealed_derived_key_b64` + `used_node_ids` — it never holds a `TransportSecretKey`. TLS-terminates its own HTTP listener, refusing plaintext off-loopback. Also: versioned schema migrations (`migrations.rs`, `quorum_service migrate`), a transactional audit outbox with a background drainer (F-14), and the operational endpoints `/healthz`, `/readyz` (quorum reachability) and `/metrics` (admin-only).
- **`quorum_adversarial`** — a binary that spins up real quorums and attacks them: **82 checks in the default run across its groups (A–G, I–N, P, Q, R, S, T, W, Z; group H adds 2 and needs root)** covering (among others) malicious partials (A), below-threshold combine (B), node-level authorization bypass (C), replay (D), concurrent audit races (E), majority-tip reconciliation (I), mTLS penetration (F), HTTP penetration (G), sealed-share retry (J), TLS termination (K), restart-replay (L), the NIZK gate (M), the cutover guard (N), and a real `iptables` network partition (H).
- **`quorum_vetseal`** — ElGamal-over-G2 sealing of BLS shares/signatures under a caller-generated transport public key, on `blstrs` directly (raw 96-byte G2 points; no dependency on `quorum_core` types).

## Runtime Components

Real OS processes in a full end-to-end run: 5× `quorum_node`, 1× `quorum_notary`, 1× `quorum_service`, orchestrated by `quorum_orchestrator` (for the demo) or by `quorum_adversarial` (for attacks). All node-to-node and client-to-node traffic is mutual TLS with certificate pinning (no CA). `quorum_service`'s own external HTTP API is separately TLS-terminated (optional cert config; refuses plaintext off-loopback when configured without one).

## Data Flow

`register_invoice` → Postgres row + nullifier check (`ciphersettle_core::check_nullifier`) → `grant_settlement_access` → `derive_invoice_key` (caller supplies a transport public key; service brokers a k-of-n sealed derive against the live quorum via `quorum_client::collect_sealed_derived_key`; caller decrypts client-side via `open_sealed_derived_key`, never sending the transport secret key to the service) → `mark_settled` → `prune_ciphertext` (gated on a retention window). Every state-changing step is logged through `quorum_audit`'s hash-chained log: mutating handlers write an `audit_outbox` row in the SAME database transaction as the state change and a background drainer delivers it via `quorum_client::propose_audit_entry` (at-least-once; the API answers 202 'committed, audit pending' if delivery is delayed), while `derive_invoice_key` appends its audit record BEFORE deriving and denies the key (503) if the append fails (fail-closed).

## Invoice Lifecycle

See `PHASE3_README.md`'s numbered walkthrough (register → duplicate rejected → unauthorized derive rejected → grant → derive as issuer/bank → regulator registration + derive → settle → prune before/after retention window → full audit-log readback). This flow is handled in `quorum_service/src/main.rs`.

## Key Derivation Flow

1. Caller generates a `TransportSecretKey` locally (never transmitted) and derives its `TransportPublicKey`.
2. Caller calls `quorum_service`'s `derive_invoice_key` with `transport_public_key_b64` (+ optional `tried_subsets` for retry).
3. `quorum_service` authenticates the caller, checks rate limits, fetches the invoice, and calls `quorum_client::collect_sealed_derived_key` with freshly built, HMAC-signed, nonce'd, time-boxed `DeriveRequest`s, ONE PER NODE, each signed with that node's derived key (`quorum_core::build_derive_request`, `derive_node_auth_key`).
4. Each `quorum_node` checks the authorization window, verifies the HMAC MAC against its own configured derived key (`service_auth_key_b64` in the node config holds the per-node key, not the master), checks the nonce hasn't been used, signs its partial, self-verifies it at runtime and refuses to derive if the check fails (F-22, fixed session 24), then seals it under the caller's transport public key together with a NIZK proof of correct encryption (`quorum_core::seal_partial_with_proof`), and returns `Message::DerivePartial { sealed_share, proof, .. }`.
5. `quorum_client` **verifies each node's proof before combining** (`quorum_core::verify_sealed_partial`, deriving the expected public key share from the group's own Feldman commitment rather than trusting the node), then combines sealed shares (`quorum_vetseal::combine_sealed_shares`) without ever decrypting — `quorum_service` returns the still-sealed `SealedDerivedKey` + `used_node_ids` over HTTP.
6. The true caller decrypts locally via `quorum_client::open_sealed_derived_key`, which also performs the final `verify()` against the DKG's public key — this is where a bad node in the combined subset is caught (triggering a retry with an updated `tried_subsets` list).

## DKG Flow

Feldman VSS: each of `n` nodes deals a random degree-`t` polynomial, publishes a commitment, sends point shares to every other node. A receiving node that gets a share inconsistent with its dealer's published commitment returns a `Complaint` (does not panic) and never reaches `is_ready()`/finalizes. There is no protocol for the quorum to exclude a confirmed-cheating dealer and continue (`NOT_IMPLEMENTED`).

## Threshold Model

The live deployment shape used throughout the orchestrator/adversarial code is `n = 5`, `t = 2` (i.e. `want = t + 1 = 3`), a 3-of-5 quorum. `quorum_core`'s DKG/derive logic itself is general over `(n, t)`.

## Identity Model

- **mTLS identity** — per-node self-signed, pinned certificate; proves "you're talking to node N over the network."
- **Audit-signing identity** — a separate per-node ed25519 keypair.
- **Service-to-node authorization** — a per-node HMAC key derived (HKDF-SHA256) from one master secret that only `quorum_service` holds; each node's config contains only its own derived key, so compromising one node does not let an attacker authorize derivations against the others. Requests are bound with expiry+nonce+transport-key. It is still a service-held-secret trust model: a compromised SERVICE can authorize anything, and nothing here is independently verifiable by an external authority (Gap 3 step 2 and the `VerificationAttestation` gap).
- **HTTP API caller identity** — a pre-provisioned API-key → caller_id table in Postgres (not self-service signup).

## mTLS Architecture

Certificate-pinned (exact cert bytes), not hostname- or CA-based. `ServerName` is currently a hardcoded placeholder since pinning doesn't need hostname validation.

## Node Architecture

Single Tokio async process per node; `Shared` state behind a `tokio::sync::Mutex` covering DKG/derive state, plus a separate used-nonce tracking map (`used_derive_nonces`) for replay protection, an audit-log replica persisted as snapshot + append-only journal (`audit_store`) and, in the pilot tier, an envelope-encrypted share file (`share_store`) so a restart resumes the same group key instead of re-running DKG.

## Orchestrator

`quorum_orchestrator` is both the demo driver and the reference implementation other client logic (`quorum_client`) was extracted from. It performs cert generation, config writing, process spawning/killing, and acts as the mTLS client for demo purposes.

## REST API

`quorum_service`, axum 0.7-based, HTTP/1.1-only by deliberate choice. It exposes a REST subset of the method surface of the project's earlier Internet Computer canister prototype (that crate has since been deleted as superseded dead code; see roadmap finding A14): 9 of its 11 methods are implemented. `get_vetkd_public_key` and `get_encrypted_invoice` are not exposed. `get_merkle_proof` is an addition that did not exist in the earlier design.

## Database

Postgres via `deadpool-postgres` (a real connection pool). Schema is managed by ordered, SHA-256-checksummed migrations (`quorum_service/src/migrations.rs`), applied in one transaction under an advisory lock at startup or via `quorum_service migrate <db_url>`; a database newer than the binary, or an edited already-applied migration, is refused. Migration 1 is the original idempotent blob, so legacy databases are adopted without data changes. Tables: `invoices`, `nullifiers`, `regulators`, `derive_call_times`, `crypto_meta`, `audit_outbox`, `audit_failures`, `schema_migrations`. There are no down-migrations (rollback = restore a backup; see `deploy/README.md`). 

## Audit System

Distinguishes "stale replica" (length mismatch) from "tampered replica" (hash mismatch at a matched sequence number) during reconciliation. A proposal is acknowledged only after at least t+1 nodes confirm a durable (fsynced) commit; each node's copy survives SIGKILL (power-loss behaviour has NOT been rehearsed).

## Notary

`quorum_notary` is a genuinely separate process/identity providing external, independently-verifiable notarization receipts. A receipt is appended as one fsynced line (file and directory) BEFORE it is recorded or returned; if the write fails the notary returns no receipt (F-23, fixed session 24). The append is durable but not a rewrite-atomic file: a torn final line from a power cut is skipped on reload, not repaired, and power loss itself was not tested.

## Adversarial Testing

See `quorum_adversarial` for tests against malicious partials, below-threshold combine, node-level bypass, replay, concurrent audit races, majority-tip reconciliation, mTLS pentest, HTTP pentest, sealed-share retry, TLS termination, and a real network partition.

## Vetseal

ElGamal-over-G2 sealing of BLS shares/signatures under a caller-generated transport public key. The `nizk` module's proof of correct encryption is **wired into the live protocol**: `quorum_node` produces it on every partial (`seal_partial_with_proof`) and `quorum_client` verifies it against the group's Feldman commitment before combining (`verify_sealed_partial`). The proof system itself remains unreviewed by a cryptographer — see `SECURITY_REVIEW.md` §6.B.

## Invoice Commitment

`ciphersettle_core::commitment::InvoiceCommitment` — salted, hiding, binding hash over `(reference, issuer, debtor, amount, currency, dates)`, explicit versioned binary encoding. Field list explicitly provisional pending real Tax Authority e-invoice identifier integration.

## Trust Boundaries

- A holder of the one shared mTLS client certificate that `quorum_service` uses could theoretically reach nodes directly, but the HMAC/nonce/expiry checks enforce authorization.
- 5 quorum nodes are not necessarily 5 independent trust domains — confirming genuine trust-domain independence across the 5 quorum nodes is required.
- `quorum_service` is trusted to compute Merkle roots correctly if `merkle.rs` is ever used for authorization.

## Threat Model

A malicious minority of quorum nodes (up to the threshold), a party that can reach quorum nodes directly, a party that can observe/replay wire traffic, a party that controls the infrastructure operator but not a quorum majority. **Not yet modeled/defended:** a party that can forge an external authority's attestation, a colluding majority of quorum nodes.

## Current Architectural Gaps

- `VerificationAttestation` (the actual oracle-problem fix)
- DKG resharing/rotation
- DKG dispute resolution
- Everything tracked in `docs/PRODUCTION_READINESS.md` (KMS/HSM, deployment, backups, rotation, monitoring depth, legal and audit items)

## Earlier Designs

The original Internet Computer canister prototype (`ci-cdk` 0.17.x) was superseded by the Phases 1–4 architecture above and has been **deleted** rather than archived: it was never a workspace member, it did not compile on this project's pinned toolchain (`ic-cdk` 0.17 required a newer rustc than this project's pin of the time), and none of the security properties or test evidence claimed anywhere in this repository ever applied to it. Its decision logic survives unchanged in `ciphersettle_core`, which is what `quorum_service` calls. See roadmap finding A14.
