# Production readiness — the three layers

Approval for a system like this depends on **three independent things** being
true at once:

1. **The code** must be sound and hardened.
2. **The integration design** must connect to the systems it is supposed to
   complement, without creating a second, competing source of truth.
3. **The procedure** must satisfy the regulator's licensing, outsourcing, and
   sandboxing expectations.

Passing the first does not substitute for the second or the third. A
cryptographically sound system with no verified link to the regulator's own
systems is commercially useless; a well-integrated system built on un-reviewed
primitives is a liability. This document tracks all three.

> **Framing, stated once and held to throughout:** CipherSettle is a
> **security and access-control layer for infrastructure that already
> exists**. It is a safeguard around a factoring workflow, not a replacement
> for it, and not a competitor to the systems operated by the Ministry of
> Finance or the Financial Regulatory Authority. It is intended to be
> compatible with, and subordinate to, those systems. Nothing below changes
> that.

**Status convention:** ✅ done and evidenced · ◐ partially done, residual
listed · ❌ open, not started. Everything marked ✅ is verifiable in the code
or in a test; the pointer is given so a reviewer does not have to take this
document's word for it.

---

## Layer 1 — Engineering: what has to change in this codebase

### Already done — and commonly mistaken for outstanding work

These four items appear on most external review lists as open. They are
implemented and tested. Listing them as outstanding would misrepresent the
system's maturity in both directions.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1.1 | **Replace the unmaintained BLS dependency.** `threshold_crypto` (poanetwork) is abandoned and must be replaced by `blstrs`/`blst`. | ✅ **Done** | `threshold_crypto` and its `ff`/`pairing` chain are absent from `Cargo.lock`; `blstrs` is the only BLS implementation. Recorded as CRYPTO-002 and finding A6 in `CipherSettle_Audit_Remediation_Roadmap.md` |
| 1.2 | **Multi-round retry protocol.** The service must be able to say "exclude node *k*, try again" rather than failing wholesale, so the system degrades gracefully under partial failure. | ✅ **Done** | `collect_sealed_derived_key` takes `tried_subsets` and returns `used_node_ids`; `CollectSealedError::SubsetsExhausted` is the distinct terminal state; the caller drives the collect → attempt → retry conversation via `DeriveReq.tried_subsets` in `quorum_service` (finding A12). Adversarial group L/M exercise it |
| 1.3 | **TLS-terminate the HTTP API** rather than binding plaintext to loopback and hoping. | ✅ **Done** | `quorum_service`'s `tls_serve.rs` terminates TLS itself *and* refuses plaintext off-loopback (`refuse_plaintext_off_loopback`, called before binding). Adversarial group K covers both behaviours (finding A5) |
| 1.4 | **Real Postgres connection pool** instead of a single client behind a mutex. | ✅ **Done** | `deadpool_postgres::Pool` in `quorum_service`'s `AppState`, exercised by `tests/db_pool_concurrency.rs` (finding A10) |
| 1.5 | **Dependency scanning.** `cargo audit` + `cargo deny` in CI. | ◐ Done, with accepted exceptions | the `supply-chain` job in `.github/workflows/ci.yml` runs both on every push and daily, and derives the audit ignore list from `deny.toml` so the two cannot drift. **Three advisories (all `rustls-webpki 0.101.7`) are knowingly accepted after Gap 7 (was seven)**, each with a written justification *and a removal condition*. The four postgres-protocol / tokio-postgres / time ignores were removed by upgrading (cargo audit with no ignores now reports only the three rustls-webpki IDs) |

### Open — genuinely blocking

| # | Item | Why it blocks production | Cost |
|---|---|---|---|
| 1.6 | **Independent cryptographic peer review.** | The single largest gap. Everything in layers 1 and 2 was designed, built, and adversarially tested by the same process. "the adversarial suite passes" is evidence of care, not proof of soundness — a passing suite authored by the same party that wrote the code cannot be. `SECURITY_REVIEW.md` §6 is the exact checklist a reviewer should work through | External; cannot be done in-house |
| 1.7 | **DKG resharing and key rotation.** | A node's share is fixed for its process lifetime. Any membership change, any suspected compromise, and any full restart currently requires a new DKG — and **a full restart produces a new group key, making previously-issued ciphertexts unrecoverable**. **Gap 1 (restart persistence) is now implemented for the pilot tier** (row 1.14); resharing/replacement (Gap 2) is still absent, so a node that loses disk AND backup is lost for good. Not viable for a live regulated system | Large protocol change |
| 1.8 | **DKG dispute resolution.** | A `Complaint` is detected and the complaining node refuses to finalize, but there is no protocol for the quorum to *exclude* a confirmed-bad dealer and continue. One dishonest dealer can permanently stall the nodes it lied to. Availability impact, not confidentiality | Medium |
| 1.9 | **Toolchain unpinning.** | ✅ Done (Gap 7, executed): `rust-toolchain.toml` is 1.97; the `zeroize`/`zeroize_derive`/`postgres-protocol`/`base64ct` exact pins and the `ed25519-dalek =2.1.1` exact pin are removed and `Cargo.lock` regenerated for those crates (`zeroize 1.9.0`, `postgres-protocol 0.6.12`, `tokio-postgres 0.7.18`, `base64ct 1.8.3`, `time 0.3.55`). Evidence: fmt, `clippy -D warnings`, 126 unit/integration tests (DB markers `ran`), adversarial 39/39, `cargo audit`, `cargo deny check` all pass | Remaining: rustls 0.21 → 0.23 (removes the last 3 ignores) |
| 1.10 | **HSM / hardware protection of node shares.** | Shares are held in plain process memory, zeroized on drop on a best-effort basis with no `mlock` and no guarantee against compiler-made copies | Deployment + protocol work |
| 1.11 | **Vote-TTL split-quorum hazard** (`SECURITY_REVIEW.md` R-2). | A proposer slower than the vote TTL can obtain overlapping votes and produce two conflicting "committed" entries. Blocks running more than one `quorum_service` replica concurrently | Medium |
| 1.13 | **Audit failure semantics (F-13/F-14).** | ◐ Implemented, EXECUTED tests (adversarial group Z, Y); NOT cryptographer-reviewed. In `quorum_service`: audit events for state changes go through a transactional outbox (`audit_outbox`, inserted atomically with the change), appends are serialized by one in-process lock (single proposer, never held with a DB connection), delivery failure returns HTTP **202** `{state_change: committed, audit: pending, outbox_id}` (not 500) and a background drainer retries with backoff; derive-key stays audit-first and fail-closed (**503** + `audit_failures` row). The client returns a typed `ProposeError` (`Contention` / `QuorumUnavailable`). Retry budget and vote TTL were NOT widened. | Delivery is at-least-once (a crash between audit append and `done` can duplicate one entry); one service replica only (already required by 1.11); the raw multi-proposer protocol hazard (Tests E/X/Y) and R-2 are unchanged and still need the owner's B/D decision |
| 1.14 | **Audit-log persistence atomicity (Gap 13 / F-01).** | ✅ Implemented, EXECUTED: atomic+fsync writes for the audit log, group pubkey and ready marker; damaged log refuses to start; adversarial group Q (SIGKILL mid-burst x3 rounds, corrupt/truncated/tampered files) 12/12 repeated runs, 9 unit tests incl. crash injection at every write stage. | SIGKILL only, no power-loss rehearsal; acknowledged-before-durable gap F-19 is open; O(n) rewrite per append (F-20) |
| 1.20 | **Durable key-share persistence (Gap 1).** | ◐ Implemented for the PILOT tier, EXECUTED tests; NOT cryptographer-reviewed (`NEEDS_HUMAN_CRYPTO_REVIEW`). `quorum_node::share_store`: one AES-256-GCM envelope-encrypted file per node (`ring`), AAD binds version/node id/n/t/crypto epoch/group-key fingerprint, KEK via `KekProvider` (`FileKek`: 0600 file outside the share dir, one per node), atomic never-overwrite create (temp, fsync, hard-link, fsync dir). Boot modes: share present => load+verify+resume, never DKG; none + `init_ceremony=true` => DKG, persist BEFORE ready; every other combination (missing/corrupt/wrong KEK/wrong node/wrong group/pin mismatch/ceremony over existing share/no `persistence` section without `allow_ephemeral_share`) is a fatal startup error. Evidence: adversarial group P failed 1/8 before the fix (`evidence/test_p_before_fix_session07.log`), 9/9 after; 17 share-store unit tests + 2 mutation checks; full regression `evidence/regression_summary_session07.txt` (143 tests, 54/54 adversarial). | No KMS/HSM `KekProvider` is implemented (interface only): a root attacker on a node reads KEK and share, so this tier is NOT for real data (Gap 10/HSM open). Backup/restore unit-tested, never rehearsed with operators; KEK escrow/splitting undecided. No crash-injection test (Gap 13). Partial ceremony recovery = wipe all nodes. Orchestrator does not yet emit persistent configs. Audit-log/pubkey/ready files still use non-atomic writes (F-01) |
| 1.15 | **Per-node derive-auth keys (Gap 3 step 1).** | ◐ EXECUTED: HKDF-SHA256 per-node keys (RFC 5869 vector unit-tested); test S1 failed before, passes after; 154 tests + 62/62 adversarial + orchestrator e2e. Evidence: `evidence/test_s_before_fix_session12.log`, `evidence/regression_summary_session12_step1.txt`. | Service master is still a single point of compromise (Gap 3 step 2, `NEEDS_HUMAN_CRYPTO_REVIEW`, design only). No online rotation/key versioning. |
| 1.16 | **Schema migrations, images, backup/restore rehearsal (Gap 10, slice 1).** | ◐ EXECUTED: versioned/checksummed/transactional migrations (8 DB tests, written first and failing; mutation-checked: removing the advisory lock fails m6 3/3, removing the checksum check fails m5), `quorum_service migrate` subcommand, Postgres backup->restore rehearsal with digest comparison and a negative check (`evidence/rehearsal_session17/`), Dockerfile + static policy check (rejects a bad fixture). | Container images NEVER built or scanned (no daemon/registry here; CI job `container-image` never run); no digest pinning; no deployment manifest (compose/k8s) for a 5-node topology; no down-migrations; node-tier backup/restore never rehearsed by an operator; no PITR; restore time measured only on toy data. Gap 10 stays OPEN. |
| 1.17 | **Secrets from files (Gap 9, slice 1).** | ◐ EXECUTED: `quorum_core::secret_files` (7 unit tests written first and failing; mutation-checked: removing the permission check fails 2, removing the one-source rule fails 1); wired into node, service and notary config loading; adversarial group T (3 checks: service refuses a world-readable secret file, node refuses inline+file, no secret in stderr); group Z now runs the real service with its derive-auth master and API key from 0600 files. | Read once at start: NO online rotation, NO certificate rotation, no secret-manager client, secrets still in process memory, `cert_der_b64`/pins still inline. Orchestrator still emits inline-secret configs. Gap 9 stays OPEN. |
| 1.18 | **Metrics, alerts, runbook (Gap 11, slice 2).** | ◐ EXECUTED: admin-only `/metrics` (audit outbox rows by status, oldest unfinished age, invoices, audit failures); tests written first (404 before); Z7a sees a pending audit during a forced failure, Z7b 401/403, Z7c gauges equal SQL after drain and no secret in output; 2 renderer unit tests; mutation-checked (removing the admin check turns Z7b red). | `deploy/alerts.yml` and `docs/RUNBOOK_audit_backlog.md` are UNVERIFIED (never loaded in Prometheus/promtool, never used in a drill). No request-latency/error counters, no structured/JSON logging, no log shipping, `/readyz` now checks quorum REACHABILITY (see 1.19) but not that nodes hold shares. Gap 11 stays OPEN. |
| 1.19 | **`/readyz` reflects quorum reachability (Gap 11, slice 3).** | ✅ EXECUTED: `/readyz` is 200 only if Postgres answers AND >= t+1 (3 of 5) nodes answer a filtered read over the pinned mTLS channel; 503 `quorum unavailable` otherwise (no node or address in the body); result cached 1 s so the unauthenticated endpoint cannot fan out TLS handshakes per request. Z8b failed before (200 with 2 of 5 nodes up), passes after; Z8a guards against over-eager 503; mutation-checked (`threshold` instead of `threshold+1` turns Z8b red). | Reachability, NOT readiness: a node still in DKG or without a share also answers; a half-open or slow node can still pass a 1 s probe; probes are not authenticated as 'this is the genuine node set' beyond cert pinning. |
| 1.12 | **Complete fuzzing (T-9, Gap 8).** | ◐ Stable seeded driver EXECUTED (`quorum_adversarial --only W`: 7 parsers, 100k inputs each, 0 panics; mutation-checked) and 7 libFuzzer targets in `fuzz/` that type-check. **Open:** no coverage-guided run has been executed (needs nightly + cargo-fuzz; `.github/workflows/fuzz.yml` is unexercised); node line-reader and `handle_message` not fuzzed. Evidence: `agent_memory/evidence/gap8_*` | Run `fuzz.yml` for >=1 h/target; fuzz the node state machine |
| 1.21 | **Panic-free hot paths (Gap 8 / F-21).** | ✅ Implemented, EXECUTED: deny lints (`unwrap/expect/panic/unreachable/todo/unimplemented`) on 8 production crates, workspace clippy `-D warnings` clean; bad config exits 1 with a message, no backtrace. Real defects fixed: malformed `ciphertext_b64` dropped the connection (Z4/Z5), HKDF all-zero fallback, `bag_peaks` empty panic. 156 unit tests, 71/71 adversarial expected in CI. Not covered: indexing/arithmetic panics (lint not enabled). | Consider `clippy::indexing_slicing` |
| 1.22 | **Health endpoints (Gap 11, first slice only).** | ◐ `GET /healthz` (liveness) and `GET /readyz` (DB checkout + `SELECT 1`, fixed 503 body) on `quorum_service`, unauthenticated, no secrets. Adversarial Z6 failed before (404), passes after (EXECUTED, `evidence/test_z6_*_session16.log`). | NOT done: structured logging (`tracing`), metrics, alerts, runbooks, drill. No quorum-liveness (`t+1` nodes) in `/readyz`. The 503 path is not tested. Gap 11 stays OPEN. |
| 1.23 | **Documentation reconciled with the code (Gap 17).** | ◐ EXECUTED: `ci/check_docs_claims.sh` (C1-C10, C10 = ARCHITECTURE crate-dependency block vs `cargo metadata`) verifies unique readiness row ids, that every backticked repo path in the maintained docs exists, that no doc names a Rust version other than the pin, that adversarial counts match what CI asserts, that nobody is told to set an env var nothing reads, that the accepted-advisory count equals `deny.toml`, that documented id ranges match, that every HTTP route is documented (and vice versa), and that every `cargo -p` names a real package. Session 22 also did a CLAIM-BY-CLAIM read of README.md and fixed 7 stale claims (see notes) and ran group H for the first time (2/2 with real iptables); run in CI and in `run_local_regression.sh`, with a self-test (`check_docs_claims_selftest.sh`) proving every check class can fail. It FOUND 9 real drifts on first run (`evidence/test_docs_claims_before_fix_session21.log`), among them a non-existent `security.yml` described as running audit/deny/SBOM, an SBOM that is not generated, and `seven` accepted advisories where three remain; all fixed. | The checker cannot judge whether PROSE is true. The README was read claim by claim; ARCHITECTURE was read line by line in session 23 (about 15 stale claims fixed; the two findings it surfaced, F-22 and F-23, were then fixed test-first in session 24); FINANCIAL_CONTEXT, THREAT_MODEL, CRYPTO_DECISIONS, CONTRIBUTING and PHASE1-3 READMEs were only checked mechanically, NOT read line by line (ARCHITECTURE excepted). Dated records (agent_memory, SECURITY_REVIEW.md, the roadmap, PHASE READMEs' original counts) are intentionally not rewritten. Gap 17 stays OPEN. |

### The honest summary of layer 1

The protocol mechanisms an external reviewer most often flags as missing are
present. What is missing is **assurance and operational lifecycle**: an
independent opinion (1.6), and the machinery to change a live membership
without destroying historical data (1.7). Those two are what block a
regulated deployment, and they are not the same problem.

---

## Layer 2 — Integration design: what has to change to satisfy Decision 51

CipherSettle today is generic invoice-confidentiality infrastructure. Mapping
it onto the specific obligations of Decision 51 requires **built integration
points**, not merely architecture that could accommodate them. Each item
below is unbuilt.

### 2.1 A verification hook into the FRA / Ministry of Finance / e-Finance systems

The system needs to be **triggered by and reconciled against** the actual
external unified-system check, rather than running an independent,
self-contained determination of its own. Two sources of truth for "is this
invoice already financed?" is precisely the failure mode to avoid.

This is the concrete form of the `VerificationAttestation` gap
(`SECURITY_REVIEW.md`, roadmap §6a): today a derive request is authorized by
a shared HMAC secret between the service and the nodes, and no external
signature is checked anywhere.

**A design constraint that must survive this integration.** Once CipherSettle
consumes the regulator's verified result, it is *carrying and enforcing* that
determination — it is still not making one. The distinction has to stay
visible in code and in the API surface:

- `ciphersettle_core::check_nullifier` and the 409 response
  (`"nullifier already registered (replay/idempotency check — not a
  double-financing determination)"`) must keep their current wording.
- The Verifiable Creditor / regulator determination must be *referenced* (by
  identifier, by receipt), never re-derived from the invoice bytes.
- If the external check is unavailable, the correct behaviour is to **fail
  closed** — deny the grant — not to fall back to a local judgement.

Whether FRA or e-Finance exposes an API or a signed receipt a third party
could consume is **unconfirmed**. This is the single largest unknown in the
project, and it is an unknown about an external system, not about this code.

### 2.2 Movable Collateral Registry gating as an enforced precondition

Decision 51 requires Movable Collateral Registry registration under
Law 115/2015 in every agreement. That has to become an **actual API check**:
no decryption grant is issued until registration is confirmed — enforced in
the code path, not left to contractual language between the parties.

The same fail-closed rule as 2.1 applies: no confirmation, no grant.

*(The legal characterization in this section is taken from the project's
integration requirements and has not been reviewed by counsel — see layer 3.)*

### 2.3 A defined regulator-access interface, co-designed with FRA

At minimum: read-only audit visibility. Possibly: an invoice-specific
decryption capability for dispute resolution. Either way this has to be
**designed with FRA, not decided unilaterally and presented as a fait
accompli**. Note that the `Regulator` role and `disclosure_request` action
string already exist in `ciphersettle_core`, so supervisory accesses are
logged as first-class events rather than smuggled in as ordinary reads.

### 2.4 Node operator separation and governance

The threshold's security property depends on node independence. In the target
deployment the node operators must be genuinely separate from the service
operator and from each other. That is an organizational design (operator
agreements, membership-change process, separation of duties between
protocol operation and regulation) with no code in this repository to express
it.

### 2.5 Arabic-language technical and audit documentation

The log and any regulator-facing reporting need to be usable by FRA's
supervisory staff, not only readable by the engineers. This includes: the
audit-log action vocabulary, the API surface, the operational runbook, and
this documentation set.

---

## Layer 3 — Procedure: what has to happen to obtain approval

### 3.1 Enter through FRA's existing fintech / non-bank technology channels

Not as a novel submission. FRA operates a FinTech legislation track and has
been actively building electronic infrastructure — the e-finance
partnership itself is evidence of openness to electronic infrastructure. The
realistic entry point is a **sandbox or pilot request through that structure**,
not a cold regulatory filing.

### 3.2 Engage Egyptian financial-regulatory counsel *before* submission

Two specific questions need a qualified Egyptian financial-regulatory
lawyer's sign-off:

1. **How is a third-party cryptographic infrastructure provider, sitting
   inside a regulated factoring workflow, treated under FRA's licensing and
   outsourcing rules?** Does this role require its own license, or does it
   fall under an existing one? This is the question that most determines the
   shape of the submission, and it is not answerable by engineers.
2. **How must the Law 115/2015 collateral-registration link be worded
   contractually** for the integration in 2.2 to have the intended effect?

### 3.3 Sequence the independent audit *before* sandbox engagement

Findings from the independent security review (1.6) should **exist** before
FRA sandbox engagement begins, not be promised as something that will happen
during it. Submitting with "we will be audited later" is materially weaker
than submitting with audit results in hand — even when those results contain
open findings, which they will.

### 3.4 Pick one pilot partner and one narrow invoice class

A single partner company and one bounded class of invoices, so the regulator
is evaluating an observable deployment rather than a hypothetical
sector-wide rollout. This also bounds the blast radius of everything in
layer 1 that remains open — which is how a pilot is run responsibly against an
incomplete system.

### 3.5 Assemble the documentation package in Arabic

Consequent on 2.5 and a precondition for the supervisory staff who would
otherwise have to read English-language cryptographic design documents to
evaluate a filing.

---

## Why approval needs all three

The three layers fail independently:

| If only this is done | What still blocks it |
|---|---|
| Code is hardened and reviewed | Nothing consumes the regulator's verified result (2.1); registry gating is contractual rather than enforced (2.2); the role may need a license nobody has applied for (3.2) |
| Integration is complete | The primitives under it are unreviewed (1.6); a membership change still destroys historical ciphertexts (1.7) |
| Procedure is complete | The filing describes a system whose crypto no independent party has examined (1.6), and whose access control rests on a shared secret rather than on the regulator's signature (2.1) |

The shortest honest summary: **sound cryptography is necessary and nowhere
near sufficient.** It is one of three axes, and the one this repository can
most directly evidence.

---

## Explicitly preserved: the non-claims

None of layers 1–3 changes what this project claims. Restated so they are not
lost in a long document:

- **CipherSettle does not determine invoice validity and does not detect or
  prevent double financing.** It consumes an external authority's
  determination (2.1) and enforces it; it does not produce one. Determination
  stays with the regulator's systems.
- **It does not move money.** Settlement is recorded as a state transition;
  funds move on licensed banking rails.
- **It is not a payments processor, not a factoring platform, and not a
  regulator.** It is a security and access-control layer for infrastructure
  that already exists.
- **It is a research prototype** with no independent cryptographic peer
  review. See `SECURITY_REVIEW.md` §6 for what such a reviewer should check.

---

**Related documents:** `README.md` (scope and non-claims) ·
`docs/FINANCIAL_CONTEXT.md` (the commercial case and use cases) ·
`SECURITY_REVIEW.md` (current technical assessment) ·
`docs/security/THREAT_MODEL.md` (attack paths) ·
`CipherSettle_Audit_Remediation_Roadmap.md` (findings A1–A15, §6a) ·
`docs/GLOSSARY.md` (terms)