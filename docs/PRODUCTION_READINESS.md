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
| 1.5 | **Dependency scanning.** `cargo audit` + `cargo deny` in CI. | ◐ Done, with accepted exceptions | `.github/workflows/security.yml` runs both daily and derives the audit ignore list from `deny.toml` so the two cannot drift. **Seven advisories are knowingly accepted**, each with a written justification *and a removal condition*. Two are reachable only from a malicious/compromised Postgres server; one only through test tooling |

### Open — genuinely blocking

| # | Item | Why it blocks production | Cost |
|---|---|---|---|
| 1.6 | **Independent cryptographic peer review.** | The single largest gap. Everything in layers 1 and 2 was designed, built, and adversarially tested by the same process. "41/41 adversarial checks pass" is evidence of care, not proof of soundness — a passing suite authored by the same party that wrote the code cannot be. `SECURITY_REVIEW.md` §6 is the exact checklist a reviewer should work through | External; cannot be done in-house |
| 1.7 | **DKG resharing and key rotation.** | A node's share is fixed for its process lifetime. Any membership change, any suspected compromise, and any full restart currently requires a new DKG — and **a full restart produces a new group key, making previously-issued ciphertexts unrecoverable**. Not viable for a live regulated system | Large protocol change |
| 1.8 | **DKG dispute resolution.** | A `Complaint` is detected and the complaining node refuses to finalize, but there is no protocol for the quorum to *exclude* a confirmed-bad dealer and continue. One dishonest dealer can permanently stall the nodes it lied to. Availability impact, not confidentiality | Medium |
| 1.9 | **Toolchain unpinning.** | `rust-toolchain.toml` holds 1.75.0 and several crates carry exact pins (`zeroize =1.5.7`, `postgres-protocol =0.6.6`, `base64ct =1.6.0`) that are no longer forced by anything — the dependency chain that required them is gone. Until these lift, the accepted-advisory list in 1.5 cannot shrink and the build is stuck behind a compiler no current dependency wants (finding A3) | Small, but needs a full suite run per step |
| 1.10 | **HSM / hardware protection of node shares.** | Shares are held in plain process memory, zeroized on drop on a best-effort basis with no `mlock` and no guarantee against compiler-made copies | Deployment + protocol work |
| 1.11 | **Vote-TTL split-quorum hazard** (`SECURITY_REVIEW.md` R-2). | A proposer slower than the vote TTL can obtain overlapping votes and produce two conflicting "committed" entries. Blocks running more than one `quorum_service` replica concurrently | Medium |
| 1.12 | **Complete fuzzing.** | Line-length bounding exists; the parsers are not fuzzed to exhaustion (T-9) | Ongoing |

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