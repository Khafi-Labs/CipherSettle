# Phase 3 — Service Layer (the product REST API)

Implements the Phase 3 exit criteria of the project's original phased roadmap (that roadmap document is not part of this repository; its criteria are quoted verbatim below):

> "End-to-end flow — register → grant → derive (via quorum) → settle →
> prune — running against real Postgres-backed nodes, API surface
> matching the method set of the project's earlier Internet Computer
> canister prototype."

## New crates

- **`quorum_client`** (new library, extracted from `quorum_orchestrator`)
  — shared mTLS client logic: `build_connector`, `send_request`,
  `send_fire_and_forget` (see "performance fix" below),
  `derive_from_quorum` (broker a k-of-n derive), and
  `propose_and_cosign_and_replicate` (the full audit-append flow).
  `quorum_orchestrator` was refactored to use this too, rather than
  keeping its own duplicate copy — re-verified against the full Phase 1+2
  demo after the refactor with no behavior change.
- **`quorum_service`** (new binary) — the actual product API. A REST
  service, backed by Postgres, that implements a REST **subset** of the
  method set of the project's earlier Internet Computer canister
  prototype (that crate has since been deleted as superseded dead code —
  see finding A14 of `CipherSettle_Audit_Remediation_Roadmap.md`): 9 of
  its 11 methods are exposed here; `get_vetkd_public_key` and
  `get_encrypted_invoice` are not, and `get_merkle_proof` is an addition
  that did not exist in the earlier design.
  It calls `ciphersettle_core`'s decision functions
  (`resolve_access`, `check_rate_limit`, `check_payload_size`,
  `check_nullifier`, `audit_action_for`) **unchanged**. Derive calls are
  brokered against the live quorum via `quorum_client`; every
  state-changing action is logged through the Phase 2 audit log via the
  same client.

## Run it

The full three-phase demo (DKG → outage → derive/round-trip → audit
log/notarization/tamper/reconciliation → the Phase 3 product API) is one
command, but needs a real Postgres instance and the `quorum_service`
binary built first:

```bash
# one-time setup
sudo apt-get install postgresql
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'ciphersettle_dev';"
sudo -u postgres psql -c "CREATE DATABASE ciphersettle_phase3;"

cargo build -p quorum_node -p quorum_notary -p quorum_orchestrator -p quorum_service
cargo run -p quorum_orchestrator
```

Runs in about 9 seconds end to end (all three phases) and tears down
every process (5 nodes, notary, service) on exit. The demo re-uses the
same Postgres database across runs but generates a fresh timestamped
`invoice_id` each time, so re-running doesn't collide on uniqueness
constraints.

## What the Phase 3 section of the demo actually exercises

Against the **still-live** 3-of-5 quorum from Phase 1/2 (not a fresh one):

1. `register_invoice` → 201, then a duplicate → 409 (nullifier +
   invoice_id uniqueness, via `ciphersettle_core::check_nullifier`)
2. An unrelated caller tries `derive_invoice_key` before any access is
   granted → 403 (`ciphersettle_core::resolve_access` denying it)
3. `grant_settlement_access` (issuer → bank) → 200
4. `derive_invoice_key` as the issuer → 200, a real derived key from the
   live quorum; same as the bank → 200
5. `register_regulator` (admin-only) → 200, then the regulator can derive
   too regardless of issuer/bank relationship → 200 (and a non-admin
   trying to register a regulator → 403)
6. `mark_settled` (by the bank) → 200
7. `prune_ciphertext` before the retention window elapses → 409; after it
   elapses, by a completely unrelated caller (matching the original
   canister's "callable by anyone, gated by eligibility, not identity"
   design) → 200; pruning again → 409
8. `get_audit_log` → the full 7-action lifecycle in order:
   `invoice_registered`, `settlement_access_granted`,
   `key_derived_issuer`, `key_derived_bank`, `disclosure_request`,
   `invoice_settled`, `ciphertext_pruned`

That last list is worth pausing on: every one of those action strings
came from `ciphersettle_core::audit_action_for` — the exact same decision
function the earlier canister prototype called — run against a Postgres row
instead of a stable-memory map, logged through a hash-chained,
multi-node-co-signed entry instead of an in-canister `Vec`, for a key
that came from a real 3-of-5 threshold BLS quorum instead of vetKD.
That's the actual point of this phase.

## A performance bug the demo itself surfaced (and the fix)

The first working end-to-end run took over a minute and printed a wall of
`unexpected end of file` errors from every node. Cause: `quorum_client`'s
generic `send_request` always waits for a response line, but
`ReplicateAuditEntry` is fire-and-forget (nodes never reply to it) — so
every replication call sat for the full 3-second timeout, on every node,
for every audit event, and the node-side connection looked like an abrupt
disconnect once the client gave up. Fixed by adding
`send_fire_and_forget`, which writes the message and returns immediately
without waiting to read anything back. The full three-phase demo now
finishes in about 9 seconds with clean logs. Worth calling out because
it's exactly the kind of thing that's invisible in a single-node unit
test and only shows up once you're actually running the real protocol
end to end — which is the point of building these demos rather than only
trusting the pure-logic test suite.

## Named gaps

| Area | What's real | What's still open |
|---|---|---|
| Decision logic | `ciphersettle_core`'s functions called unchanged for every gated action | — |
| Storage | Real Postgres, a real transaction for the register-invoice check-and-insert | Closed for pooling: `deadpool-postgres` provides a real connection pool, verified by `tests/db_pool_concurrency.rs`. Remaining work is schema migration tooling (schema is created idempotently at startup, not via versioned migrations) |
| Identity/principal | A pre-provisioned API-key → caller_id table (the roadmap's "real API-key/subscription layer," not self-service signup) | No key rotation/expiry, no per-key rate limits independent of caller_id. API keys are hashed at rest and compared in constant time (finding A15) |
| Derive | Brokered against the live quorum via `quorum_client::collect_sealed_derived_key`; each partial is ElGamal-sealed to the caller's transport key before it leaves the node, and the caller decrypts client-side | The pre-combine verification gap that was open when this file was first written is closed: every sealed partial now carries a NIZK proof, verified against the group's own Feldman commitment *before* aggregation (`quorum_core::verify_sealed_partial`), and adversarial group M exercises that gate end-to-end against a live quorum over real mTLS. What remains is that no independent human cryptographer has reviewed the NIZK or the ElGamal-over-G2 construction, which has no AEAD (malleability is accepted by design — see CRYPTO-008); the outstanding review scope is listed in `SECURITY_REVIEW.md` §6 |
| Audit logging | Every state-changing action logged through the real Phase 2 hash-chained, co-signed log | The vote-TTL split-quorum hazard (finding R-2) is open: a proposer slower than the TTL can obtain overlapping votes and produce two conflicting "committed" entries. Running more than one `quorum_service` replica concurrently is therefore not recommended until R-2 is resolved |
| Transport | Real mTLS from the service to the quorum + notary | Closed for the HTTP API: `quorum_service` terminates TLS itself (`tls_serve.rs`) and refuses plaintext off-loopback. Both behaviours are exercised by adversarial test group K. What remains is choosing a real certificate authority and deployment certificate, which is operational rather than a code gap |
| Rate limiting | `ciphersettle_core::check_rate_limit` enforced per caller via a real Postgres-backed call-history table | Still per-caller only — mitigated by requiring a provisioned API key at all, but nothing stops one admin from provisioning many keys for one operator |

## Field-name note worth knowing about (not a bug)

`ciphersettle_core::RateLimitPolicy::window_nanos` is named for the IC's
nanosecond clock, since that's what the original canister always fed it.
This service is off the IC and uses milliseconds throughout. The function
itself is unit-agnostic — it just compares `u64` timestamps — so reusing
it unchanged is correct as long as every timestamp passed in is
consistently milliseconds, which they are here. `db.rs` has a comment at
the exact call site; worth remembering if you're reading the code cold.
