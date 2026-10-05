# Phase 1 — Core Crypto Service (mTLS quorum node + orchestrator)

Implements the Phase 1 exit criteria of the project's original phased roadmap (that roadmap document is not part of this repository; its criteria are quoted verbatim below):

> "3+ physically/organizationally separate test nodes ... completing DKG
> and derive calls over real mTLS, with one node killed mid-test to
> confirm k-of-n liveness works as designed."

## Crates

- **`quorum_core`** — transport-agnostic DKG state machine (Feldman VSS,
  now with `Complaint` instead of a panic on a bad share) + the
  Boneh-Franklin-style derive protocol + the wire `Message` enum +
  `config` module. Zero networking, zero product logic — same design
  principle as `ciphersettle_core`, applied to the crypto core.
- **`quorum_node`** — the actual standalone, independently-testable node
  binary. Owns mTLS (certificate-pinned, no CA — see `src/quorum_node/src/tls.rs`),
  drives a `quorum_core::DkgSession` from real network messages, and
  serves derive requests once finalized. `cargo run -p quorum_node --
  <config.json>`.
- **`quorum_orchestrator`** — the test harness that plays the roadmap's
  "provisioned out-of-band before DKG" role: generates identities, writes
  configs, spawns 5 real `quorum_node` **OS processes**, waits for DKG,
  **kills 2 of them**, then acts as the mTLS client for a 3-of-5 derive +
  round-trip decrypt. `cargo run -p quorum_orchestrator`.

## Run it

```bash
cargo build -p quorum_node -p quorum_orchestrator
cargo run -p quorum_orchestrator
```

No arguments needed — the orchestrator does everything: cert generation,
config writing, process spawning, the simulated outage, and the derive
round trip, then tears down any surviving node processes on exit.

## What's real here (vs. the Phase 0 PoC)

| | Phase 0 (`quorum_poc`) | Phase 1 (this) |
|---|---|---|
| Nodes | in-process structs | separate OS processes |
| Transport | function calls | TCP + mutual TLS |
| Bad share handling | `panic!` | `Complaint` (logged, blocks finalize) |
| Node identity | none | self-signed cert per node, pinned |
| Liveness test | re-derive from a different in-memory subset | `SIGKILL` 2 of 5 real processes, derive from the 3 survivors |
| Group public key | computed, asserted equal in-process | independently computed per node, **published** to a file, cross-checked by the orchestrator |

## What's still open (see also each crate's own doc comments)

Straight from the roadmap's own Phase 1 bullets, in the order it lists
them:

- **DKG resharing/rotation** — not implemented. A node's cert and share
  are fixed for its whole process lifetime. This is explicitly called out
  in the roadmap as needing to be designed *before* real data flows,
  precisely because retrofitting it later is harder.
- **Dispute resolution** — a `Complaint` is logged and blocks that node
  from ever finalizing, but there's no protocol for the quorum to
  collectively exclude a confirmed-cheating dealer and continue without
  them (Pedersen/GJKR-style). Right now one bad actor can permanently
  stall the node(s) they lied to.
- **gRPC/REST** — the roadmap suggests this for Phase 3's service layer;
  this Phase 1 crypto service uses a minimal newline-delimited-JSON wire
  protocol instead, which is enough to prove the mTLS + DKG + derive
  mechanics but isn't the eventual client-facing API shape.
- **HSM/enclave sealing** of each node's share — currently held in plain
  process memory (`quorum_core::SecretKeyShare`, whose scalar is overwritten
  with zero on drop -- best effort, no `mlock`, no guarantee against copies
  the compiler made; see roadmap T3-2).
- **Real access control on derive requests** — implemented in Phase 3, at
  the node rather than in this phase. Every `DeriveRequest` is HMAC-signed
  with the shared `service_auth_key` over the caller identity, the
  request's transport public key, and a short expiry, and is replay-checked
  against an in-memory nonce set (`quorum_core::sign_derive_auth` /
  `verify_derive_auth` / `build_derive_request`; see
  `docs/security/THREAT_MODEL.md` T-1, T-2, T-3). What is *still* missing is
  authorization conditioned on an independently verifiable attestation from
  an external authority — that is T-4 in the threat model and the
  `VerificationAttestation` gap in `SECURITY_REVIEW.md`, and it is the
  load-bearing gap in the whole design, not a Phase 1 leftover.

## A note on the "separate processes" vs "separate machines" gap

The roadmap's own exit criteria say "different machines, ideally different
operators if you can rope in early partners." This harness runs 5
processes on one host bound to different loopback ports — a real,
labeled simplification, not a claim of having tested cross-host mTLS,
firewall traversal, or clock-skew-sensitive certificate validity windows.
Moving this to actual separate hosts should be close to a non-event given
the transport is already genuine TCP + mTLS rather than in-process calls
— the main things to re-verify at that point are DNS/hostname handling in
`ServerName` (currently a hardcoded placeholder, since pinning is by exact
cert bytes rather than hostname) and firewall rules for the listen ports.
