# Financial context — what this system does in an invoice-financing workflow

This document is for reviewers who need to answer "what is this actually for
in a financial context?" without reading the cryptographic sources first. It
describes the commercial problem, the actors, the invoice lifecycle as
actually implemented, the use cases the design supports, and — just as
importantly — the use cases it does **not** support. Every claim here is
traceable to code; §12 maps each one to the file, symbol, or test that backs
it.

It does not repeat the security posture. That is `SECURITY_REVIEW.md`,
`docs/security/THREAT_MODEL.md`, and `CipherSettle_Audit_Remediation_Roadmap.md`.
Where a limitation is material to a commercial decision it is repeated here
and marked explicitly rather than left for the reader to discover.

> **Status: research prototype.** Nothing in this repository is deployed,
> audited for compliance, or cleared for handling real financing. §10 and §11
> list what would have to change first.

---

## 1. The commercial problem

In invoice financing — discounting, factoring, reverse factoring — a supplier
has issued an invoice to a buyer, and a bank or factor wants to advance
against it before the buyer pays. To underwrite the advance, the financier
needs to read the invoice's terms: the amount, the goods, the delivery
milestones, the payment date, the credit terms.

Those terms are exactly what the supplier considers commercially sensitive.
The price reveals margin. The quantity and cadence reveal production
planning. The identity of the buyer and the payment terms reveal the supply
relationship itself. Handing a financier a copy is often acceptable. Handing
them a copy **and** handing the platform operator, the hosting provider, and
the database administrator a copy is usually not — yet that is the normal
consequence of conventional data-room and file-sharing designs, because in
those designs the operator must be able to read what it stores.

CipherSettle targets that specific, narrow gap: **how a financier gets
read access to one invoice, for as long as the arrangement lasts, without any
infrastructure operator acquiring the ability to read every invoice.** It is
not a replacement for a factoring platform, a payments rail, or a regulator's
own systems. It is a confidentiality and evidence layer that could sit
alongside such a platform.

## 2. The guarantee, stated precisely

Three properties, which are easy to conflate and are worth separating:

| # | Property | Meaning | Status |
|---|---|---|---|
| 1 | **Per-invoice, revocable access** | The issuer grants a named financier access to one invoice and can withdraw it | Implemented (`grant_settlement_access` / `revoke_settlement_access`) |
| 2 | **No standing master key** | No party — including the operator — holds a key capable of decrypting all invoices | Implemented and demonstrated: the derived key exists only as a `(t+1)`-of-`n` threshold, and each node's partial is sealed to the caller's transport key |
| 3 | **Tamper-evident access history** | Every access event is recorded in a log that a single party cannot rewrite, and is externally notarized | Implemented, with one open hazard (the vote-TTL split-quorum risk, `SECURITY_REVIEW.md` R-2) |

Two confidentiality claims must also be kept apart, because they have
different strength:

- **From the infrastructure operator** — strong, and demonstrated. The
  `quorum_service` process stores ciphertext and a commitment, never
  plaintext; it never holds a transport secret key; and even the quorum nodes
  only ever hold sealed shares. Operating the infrastructure does not confer
  the ability to read it.
- **From other participants** — weaker, and this is the prototype's central
  open gap. Authorization is decided inside this system, against a shared HMAC
  secret between the service and the nodes. There is **no** signature from an
  external authority — the FRA, e-Finance, or anyone else — that a node
  verifies. So today the system proves *who within the platform* accessed
  what; it does not yet prove *that an external authority had approved* it.
  This is the `VerificationAttestation` gap (`SECURITY_REVIEW.md`,
  roadmap §6a), and it is the single most important thing to understand about
  the system's present maturity.

One more thing a financier should be clear about: **confidentiality from the
operator is not confidentiality from the parties.** The issuer and the
granted financier are entitled to read the invoice; that is the point. A
regulator granted access under the platform's policy can read it too, and
that access is itself logged (`disclosure_request`). CipherSettle reduces the
number of parties who legitimately hold plaintext; it does not reduce the
number entitled to it.

## 3. Actors

| Actor | What the design gives them | What it does not |
|---|---|---|
| **Issuer (supplier)** | Registers an encrypted invoice; grants and revokes a financier's access | Cannot see who else holds access beyond what the audit log reveals |
| **Financier (bank / factor)** | Derives the invoice key on demand and decrypts locally, without the ciphertext or key ever being at rest in plaintext anywhere | Cannot derive without an issuer-granted access record; cannot derive without the quorum's threshold |
| **Second lender / syndicate member** | Same as any financier, if separately granted | Sees nothing about invoices it was not granted |
| **Platform / service operator** | Hosts the API, the database, and the quorum nodes | **Cannot read invoice contents.** This is the central claim |
| **Node operators** (distinct from the above, in the target deployment) | Run the threshold nodes | An individual node cannot reconstruct any invoice key; ≤ 2 of 5 nodes together cannot either |
| **External auditor / supervisor** | Can be granted the `Regulator` role, with every such grant logged as `disclosure_request` | Not yet able to act on an externally signed approval — see §2 |

## 4. The invoice lifecycle as implemented

Every state-changing action below is written to the audit log *before* its
effect is observable to the caller, through a hash-chained, multi-node
co-signed entry that a separate notary process then anchors.

| Step | Endpoint (`quorum_service`) | Authorized caller | Audit action string | Financial meaning |
|---|---|---|---|---|
| Register | `POST /invoices` | Any provisioned API-key holder | `invoice_registered` | Supplier deposits an encrypted invoice plus a salted commitment binding its contents. Re-submission of the same invoice or nullifier is refused with 409 (a replay/idempotency guard — **not** a double-financing determination) |
| Grant | `POST /invoices/:id/grant` | Issuer only | `settlement_access_granted` | Supplier nominates the financier for this invoice |
| Revoke | `POST /invoices/:id/revoke` | Issuer only | `settlement_access_revoked` | Arrangement falls through, or the supplier withdraws access, without waiting for settlement |
| Derive | `POST /invoices/:id/derive-key` | Issuer, granted financier, or regulator | `key_derived_issuer` / `key_derived_bank` / `disclosure_request` | The financier obtains the sealed derived key and decrypts locally |
| Settle | `POST /invoices/:id/settle` | Issuer or granted financier | `invoice_settled` | Records that the receivable was settled. **Money does not move here** — this is a terminal-state marker for retention and pruning eligibility |
| Prune | `POST /invoices/:id/prune` | Anyone, gated by eligibility | `ciphertext_pruned` | Ciphertext may be deleted once settled **and** past the retention window. The audit log is never pruned |
| Regulator | `POST /regulators`, `DELETE /regulators/:id` | Admin only | — | Grants or removes the supervisory role |
| Inspect | `GET /audit-log`, `GET /invoices/:id/merkle-proof` | Provisioned caller | — | The compliance artifact: who did what, in order, and a Merkle inclusion proof that a given invoice's commitment is in the log |

Two honest qualifications on that table:

- **Access is revocable, not time-boxed.** There is no expiry field on a
  grant in the current data model: access persists until the issuer revokes it
  or the invoice is marked settled. Time-boxing is a natural next step (the
  derive-request HMAC already carries a short expiry, so the mechanism exists)
  but it is **not implemented** at the access-grant level.
- **Granularity is whole-invoice.** A financier who is entitled to an invoice
  can decrypt it entirely. There is no field-level or partial disclosure. For
  a lender who only needs, say, the amount and date, the practical options
  today are to receive a separately encrypted minimal document, or to accept
  full access. Selective disclosure is not implemented.

## 5. Why threshold key derivation, rather than a master key

The conventional alternatives, and what changes with each:

| Approach | Who can read everything | If that party is compromised |
|---|---|---|
| Shared password / link | The platform operator, the host, every admin, every DB reader | Everything leaks at once; the key must be rotated everywhere |
| Platform-held master key (or KMS escrow) | The platform operator, by construction | Everything leaks; rotation is required; there is always a standing master key to subpoena, compel, or lose |
| Encrypted database with keys in a secrets manager | The platform operator, by construction | Same, one layer down |
| **Threshold derivation (this system)** | **Nobody, as a standing capability** | A single node, or any two of five, yields no invoice key and no information about one |

The specific properties that matter for a financing arrangement:

1. **No standing master key exists.** There is no secret whose disclosure
   compromises every invoice. There is nothing to escrow, subpoena, lose, or
   forget to rotate, because there is no such key to hold.
2. **Operating the infrastructure is separated from reading the data.** The
   operator's business model and their capability are decoupled. That is the
   distinction a factor's information-security reviewer is actually asking
   about when they ask "who at your vendor can read our borrowers' invoices?"
3. **Claims are verifiable, not trusted.** Because a `t+1`-of-`n` share is
   required, and each sealed share carries a non-interactive zero-knowledge
   proof binding it to that node's own DKG share, no single node can
   contribute a forged partial that survives aggregation. A dishonest node is
   excluded and identified, not believed.
4. **Revocation is immediate and independent of settlement.** The issuer's
   `revoke` call is effective at once, with no dependency on the financier
   cooperating or on an invoice reaching a terminal state.

What this rests on, stated just as plainly: the standard Byzantine threshold
assumption. A **colluding threshold** (three of five nodes) could agree on
anything. The system is designed so that operating fewer than a threshold of
honest nodes is insufficient — not so that a hostile majority is harmless.
§10 lists the residual risks.

## 6. Financial use cases this design supports

Each row is a real arrangement; the second column is what CipherSettle
contributes to it. None of these requires the system to move money, decide
credit, or verify an invoice's authenticity.

| Use case | What CipherSettle contributes |
|---|---|
| **Single-lender invoice discounting** | The factor reads the invoice through a revocable per-invoice grant; the platform and its host never hold a copy in plaintext |
| **Syndicated / club financing** | Each participating lender is granted separately, and each access is separately recorded, so the financing arrangement and the disclosure history are both reconstructable |
| **Reverse factoring (supply chain finance)** | The buyer — who is not the invoice's issuer — needs to see supplier invoices to confirm payables. Grants work for a nominated bank, and a regulator role exists for supervisory visibility; fine-grained confirmation fields are not modelled (see §4) |
| **Dynamic discounting / early payment** | A supplier offers an early-payment discount; the buyer's finance team needs the invoice without the supplier re-issuing documents into a second channel. Revocation covers the case where the buyer declines |
| **Trade finance** (documentary credit underlying documents, receivables forfaiting) | The document set stays confidential between the parties entitled to it, with a per-document access history rather than a shared drive |
| **Portfolio credit assessment** | A factor assessing many invoices needs access to those invoices and not to the rest of a supplier's book. Grants are per-invoice, so the blast radius of a portfolio review is bounded by what was actually granted |
| **Post-transaction dispute investigation** | When a party disputes what was disclosed and when, the co-signed, notarized log is evidence that does not depend on trusting the operator's own records |
| **Supervisory access** | A supervisor can be granted the regulator role for specific invoices. Crucially, *that access is itself logged and co-signed* — the supervisory disclosure is as auditable as any other |

## 7. What this system explicitly does not do

Stated plainly, because over-claiming is the fastest way to lose a
regulator's trust:

- **It does not move money.** Settlement is recorded as a state transition;
  the money moves on licensed banking rails outside this system. It is
  infrastructure software, not a payments processor.
- **It does not detect or prevent double financing.** It refuses to register
  the same invoice or nullifier twice through this system — a replay and
  idempotency guard. That is not a determination that a receivable has been
  financed elsewhere, and the API error string says so explicitly. Invoice
  validity and double-financing detection are the domain of the Egyptian
  Financial Regulatory Authority's own systems (e-Finance), not this project.
- **It does not verify that an invoice is genuine**, that a buyer owes the
  amount, or that goods were delivered. It commits to the bytes it was given,
  not to their truth.
- **It does not make credit decisions**, perform KYC/AML, or establish
  identity. Identities are pre-provisioned API keys; there is no self-service
  onboarding and no key rotation or expiry for them.
- **It is not a general-purpose confidential-computing platform.** It handles
  one asset — invoice-term decryption keys — and one workflow.
- **It has not been assessed for compliance** with any financial-oversight or
  data-protection regime. See §10 and §11.

## 8. Where it sits relative to an existing factoring platform

As an insert, not a replacement. The realistic integration shape is:

```
issuer ──encrypts invoice locally──▶ ciphertext + commitment
                                        │
                                        ▼
                        ┌───────────────────────────────┐
                        │  CipherSettle quorum + service │  ← the operator adds
                        │  (no plaintext, ever)          │     nothing to the
                        └───────────────────────────────┘     invoice data it hosts
                                        │  sealed derived key (opaque)
                                        ▼
                                  financier decrypts locally ──▶ plaintext invoice
```

The factoring platform keeps its workflow, its ledger, and its relationship
with the borrower. CipherSettle replaces the "shared drive / data room /
master key" step with a revocable, provable, per-invoice grant. Nothing in
this repository is a data model for a factoring book, a limit system, or a
collections process.

An FRA-regulated environment adds one important constraint that this design
currently does **not** meet: an independent regulator's systems remain
authoritative, and this project has no verified way to consume their results.
`README.md` §"The VerificationAttestation gap" is explicit that whether the FRA
or e-Finance exposes an API or signed receipt a third party could consume is
unconfirmed. Until it does, this project cannot honestly claim that access is
conditioned on a regulator's verified result.

## 9. Economic and operational implications

What changes for the parties, in practice:

- **The number of parties holding plaintext drops** from "everyone with
  storage or admin access" to "the issuer, the currently-granted financier,
  and any regulator who has been granted access."
- **A breach of the platform's own infrastructure yields ciphertext,
  commitments, and audit metadata** — not invoice terms. That is a materially
  different notification and remediation posture, and the single most valuable
  practical property of the design.
- **Key-escalation requests become structurally impossible to satisfy.** "Can
  your support team decrypt this for us?" has no answer other than "no one
  can, and that is the design" — a good property for data-minimization
  commitments, and a real operational constraint when a genuine dispute
  requires access.
- **Revocation is immediate**, independent of settlement and of the
  counterparty's cooperation.
- **Operational cost is non-trivial.** A deployment needs multiple
  independently-operated nodes, mutual-TLS certificate lifecycle management, a
  Postgres instance, and — not yet implemented — DKG resharing and key
  rotation. It also needs an operator-separation governance model (Phase 5 in
  `README.md`), which is an organizational question, not a code question.
- **Availability is a quorum property.** A derivation needs a reachable
  `t+1` of `n` nodes. Node failure is tolerated; a correlated failure across a
  threshold is not.

## 10. Questions a supervisor, risk committee, or lender is likely to ask

| Question | Honest current answer |
|---|---|
| Can any one party read every invoice? | No. There is no standing key; reading one invoice needs a `t+1`-of-`n` threshold, and each partial is sealed to the end caller's transport key |
| Can the operator read invoices? | No, by construction — verified in source and by adversarial tests, not merely asserted |
| Can the operator quietly change or delete the access history? | No single party can. The log is hash-chained, co-signed by the nodes, reconciled by majority vote, and anchored by a separate notary identity. Residual risk: a colluding majority of reporting nodes, and the open vote-TTL split-quorum hazard (R-2) |
| Is there key escrow? | No |
| What happens if one node is compromised? | It learns nothing about any invoice key on its own, and a forged partial is rejected and the node identified by the NIZK gate. Two compromised nodes are still below the 3-of-5 threshold |
| What if three nodes collude? | They meet the threshold. This is the fundamental assumption of the construction, not a defect, and the reason external notarization exists as a check that does not depend on the quorum's honesty |
| What if a node's share leaks permanently? | It is fixed for the process lifetime; **rotation and resharing are not implemented**. This is a genuine commercial blocker for long-lived production use |
| What happens on a full restart? | A full-quorum restart runs a new DKG and produces a **new group key**, which makes previously-issued ciphertexts unrecoverable. Also unimplemented, also commercial-blocking |
| Is the cryptography reviewed? | No independent peer review has been performed. `SECURITY_REVIEW.md` §6 lists exactly what a reviewer should examine. This is the largest gap in the assurance case |
| Is the system compliant with data-protection or cybersecurity requirements? | No assessment has been performed. Legal, data-protection and compliance questions require qualified Egyptian counsel |
| How long is data retained? | Ciphertext is prunable once the invoice is settled and past the retention window; the audit log is append-only and never pruned. Both policies are configurable |
| What is the availability/recovery story? | A derivation needs a reachable threshold of nodes. Backup and disaster recovery of node state and the Postgres instance are not designed in this repository |

## 11. What would have to be true before this could carry real financing

Broken out by layer in `docs/PRODUCTION_READINESS.md` — engineering,
integration design, and procedure — because approval depends on all three,
not on the cryptography alone. Summarised here in the order that blocks:

1. **Independent cryptographic peer review** of `quorum_core::bls` and
   `quorum_vetseal::nizk`, against the checklist in `SECURITY_REVIEW.md` §6.
   Nothing below matters if the primitives are wrong.
2. **DKG resharing and key rotation.** A node joining or leaving, a node
   suspected of compromise, and a restart must not require re-issuing every
   invoice's key. Until this exists, node lifecycle management is a genuine
   operational hazard rather than a routine task.
3. **`VerificationAttestation`.** Nodes must independently verify a
   signed result from an external authority, rather than trusting a shared HMAC
   secret. This is what would make "access is conditioned on a regulator's
   verified result" a claim rather than an aspiration — and it depends on an
   external system exposing something consumable, which is unconfirmed.
4. **Governance and operator separation.** Who runs the nodes, on what
   independence, under what agreement, and how membership changes are agreed.
5. **Legal and compliance work** — data protection, records retention,
   outsourcing/operational-resilience expectations, and the licensing question
   of whether operating such an infrastructure is itself a regulated activity.
   Requires qualified Egyptian counsel; none has been engaged.
6. **Hardware protection of node shares** (HSM or equivalent). Shares are held
   in plain process memory today, zeroized on drop on a best-effort basis.
7. **Resolving the vote-TTL split-quorum hazard** (R-2) before more than one
   service replica is deployed.
8. **An integration layer** to a real platform: a ledger, identity, and a
   production key-management and certificate story.
9. **A formal operational runbook** — node provisioning, DKG ceremonies,
   monitoring, and incident response.

Two layers sit outside this repository entirely and are not code work at all:
the **integration design** (a verification hook into the regulator's own
systems, Movable Collateral Registry gating, a co-designed regulator-access
interface, Arabic-language documentation — `docs/PRODUCTION_READINESS.md`
layer 2) and the **procedure** (entering through an existing fintech/sandbox
channel, engaging Egyptian financial-regulatory counsel before filing, having
audit findings in hand beforehand, one pilot partner and one narrow invoice
class — layer 3).

## 12. Where each claim in this document is verifiable

A reviewer who wants to check any statement above against code:

| Claim | Where to look |
|---|---|
| The service stores ciphertext, never plaintext invoice terms | `src/quorum_service/src/main.rs` (`register_invoice`), `src/quorum_service/src/db.rs` |
| The service holds no transport secret key | `docs/security/THREAT_MODEL.md` §Assets; verified in source per `src/quorum_vetseal/INTEGRATION.md` §5 |
| A key needs a threshold of nodes and no single node can reconstruct it | `src/quorum_core/src/bls.rs`; `src/quorum_poc/README.md` (Phase 0 PoC) |
| Bad shares and wrong-degree commitments are rejected | `src/quorum_core/src/bls.rs` (`receive_commitment`) |
| A forged partial is excluded before aggregation | `src/quorum_core/src/bls.rs` (`verify_sealed_partial`), `src/quorum_vetseal/src/nizk.rs`, adversarial group M |
| Every action is logged before its effect is observable | `src/quorum_service/src/main.rs` (`log_audit_event` call order) |
| One party cannot rewrite the log | `src/quorum_audit/src/lib.rs` (`try_append`, `majority_reference`, `diverges_from`) |
| The log is anchored outside the quorum's control | `src/quorum_notary/`, `NotarizationReceipt` in `src/quorum_audit/src/lib.rs` |
| Access control is policy-gated per invoice | `src/ciphersettle_core/src/lib.rs` (`resolve_access`, `grant_settlement_access`, `revoke_settlement_access`) |
| Revocation is immediate and independent of settlement | `src/ciphersettle_core/src/lib.rs` (`revoke_settlement_access`) |
| The nullifier check is not a double-financing determination | `src/ciphersettle_core/src/lib.rs`, and the 409 message string in `src/quorum_service/src/main.rs` |
| Ciphertext is prunable after settlement; the audit log is not | `src/ciphersettle_core/src/lib.rs` (`is_eligible_for_ciphertext_pruning`) |
| No standing master key exists | Structural: `quorum_core`'s key is a distributed share; `docs/ARCHITECTURE.md` §key-derivation flow |
| The known open risks | `SECURITY_REVIEW.md` (R-1…R-7), `docs/security/THREAT_MODEL.md` (T-1…T-12), `CipherSettle_Audit_Remediation_Roadmap.md` (A1–A15, §6a) |

---

**Related documents:** `README.md` (scope and non-claims) ·
`docs/ARCHITECTURE.md` (structure and data flow) ·
`SECURITY_REVIEW.md` (current technical security assessment) ·
`docs/security/THREAT_MODEL.md` (attack paths) ·
`docs/cryptography/CRYPTO_DECISIONS.md` (design decision records) ·
`CipherSettle_Audit_Remediation_Roadmap.md` (findings and remediation status)