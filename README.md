# CipherSettle

A from-scratch, standalone reconstruction of vetKeys-style confidential key derivation for invoice financing: a small quorum of independent nodes derives per-invoice decryption keys via threshold cryptography, so that **no single server, operator, or node is ever a point of total trust** for who can read a given invoice's terms. This repo builds and tests the entire protocol outside the Internet Computer, phase by phase, allowing each mechanism to be independently verified before deployment.

> **Status: research prototype, not production software.** Independent cryptographic peer review has not yet been performed. Several findings remain open, including one architectural gap (§ "The VerificationAttestation gap" below) that is load-bearing for the system's central claim. This is stated up front, deliberately, rather than in a footnote — see `SECURITY_REVIEW.md`, `docs/security/THREAT_MODEL.md`, and `CipherSettle_Audit_Remediation_Roadmap.md` for the full picture.

> **Attribution.** The threshold key-derivation model CipherSettle reconstructs is the design published by DFINITY as "vetKeys". CipherSettle is an independent, from-scratch reimplementation of that published design. It is not affiliated with, endorsed by, sponsored by, or contractually related to DFINITY or the Internet Computer, and no comparative claim against that product is intended or implied. Where this document or its code comments reference vetKeys or the Internet Computer, it is as a public design reference.

## What this project claims — and deliberately does not

The scope and operational boundaries of CipherSettle have been specifically defined to complement existing regulatory frameworks. See `CipherSettle_Audit_Remediation_Roadmap.md` §6a for the detailed architectural context.

**CipherSettle does not claim to prevent double financing or verify invoice validity.** Egypt's Financial Regulatory Authority (FRA) operates its own digital factoring system with e-Finance, performing both of those functions authoritatively. A project outside the regulator claiming to execute the same role would be redundant and would represent a false claim of regulatory authority. Nothing in this codebase should be described as detecting, preventing, or adjudicating double financing — that is the FRA's domain, not this system's.

**What this project actually does:**
- **Protects confidential invoice data from any single infrastructure operator.** Not from the factoring company that already legitimately holds the data — that is a different threat model — but from whoever operates the servers this system depends on, ensuring that operating the infrastructure does not imply the ability to read every invoice on it.
- **Conditions access on a verifiable official result, not a self-asserted one** — subject to the availability of external attestations (see "VerificationAttestation gap" below).
- **Produces tamper-evident evidence of what happened and when** — recording who requested access, when, and whether the quorum granted it, auditable after the fact without requiring implicit trust in the operator.

**The VerificationAttestation gap:** `quorum_core::verify_derive_auth` authorizes key derivations today against a shared HMAC secret between `quorum_service` and every node. There is no per-invoice signed attestation from the FRA, from e-Finance, or from any other external authority checked anywhere in this system yet. Every claim this project makes regarding "access conditioned on the regulator's verified result" is aspirational until a `VerificationAttestation` object, signed by a real external source, exists and is independently checked by each node — not merely asserted by `quorum_service`. Whether the FRA or e-Finance exposes an API or a signed receipt a third party could consume remains unconfirmed. This is the primary load-bearing assumption under the architecture, and it remains unverified.

**On naming:** `ciphersettle_core::check_nullifier` and `quorum_service`'s nullifier conflict message refer to an anti-replay / idempotency guard — the same invoice cannot be registered twice through this system. That mechanism is legitimate and within scope. It is deliberately **not** a double-financing determination, and the API error string says so explicitly: `"nullifier already registered (replay/idempotency check — not a double-financing determination)"`.

## What has to change before this carries real financing

Approval depends on **three independent things** being true at once — the code, the integration design, and the procedure. Sound cryptography is necessary and nowhere near sufficient. Full breakdown in `docs/PRODUCTION_READINESS.md`; the current state:

**Layer 1 — engineering.** Four items that external reviews routinely flag as outstanding are already built and should not be re-listed: the unmaintained `threshold_crypto` dependency is replaced by `blstrs` (A6), the multi-round collect → attempt → retry protocol exists (`tried_subsets` / `used_node_ids`, A12), the HTTP API terminates TLS and refuses plaintext off-loopback (A5), and Postgres uses a real `deadpool-postgres` pool rather than a mutex-guarded client (A10). What is genuinely open: **independent cryptographic peer review** (the largest gap — everything here was written and adversarially tested by the same process), **DKG resharing and key rotation**, **DKG dispute resolution**, toolchain unpinning, HSM protection of node shares, the vote-TTL split-quorum hazard (R-2), and complete fuzzing.

**Layer 2 — integration design.** Nothing here is built. A verification hook into the FRA / Ministry of Finance / e-Finance systems so access is gated on the regulator's actual result rather than a shared HMAC secret — the `VerificationAttestation` gap; Movable Collateral Registry registration under Law 115/2015 as an enforced API precondition rather than contractual language; a regulator-access interface co-designed with FRA; node-operator separation and governance; Arabic-language technical and audit documentation.

**Layer 3 — procedure.** Enter through FRA's existing fintech / non-bank technology channels rather than a cold submission; engage Egyptian financial-regulatory counsel *before* filing, specifically on whether a third-party cryptographic infrastructure provider inside a regulated factoring workflow needs its own license; have the independent audit findings in hand before sandbox engagement rather than promising them during it; pick one pilot partner and one narrow invoice class.

**What stays true through all of it:** CipherSettle is a **security and access-control layer for infrastructure that already exists** — a safeguard, not a replacement. It complements and is subordinate to the systems operated by the Ministry of Finance and the Financial Regulatory Authority. Even once it consumes an external authority's verified result, it enforces that determination rather than making one: invoice-validity and double-financing determinations stay with the regulator.

## The problem this solves

Confidential invoice financing requires a specific, narrow guarantee: an issuer registers an invoice's encrypted terms and can grant a bank/financier access to decrypt it — revocable, per-invoice, with no standing master key anywhere — and every one of those access events must be **provably recorded**, provable without having to trust whoever operates the servers. Improper implementation risks leaking commercially sensitive terms to backend operators, or losing the ability to prove historical access controls to an auditor.

CipherSettle addresses this using identity-based threshold key derivation, where a `T+1`-of-`N` quorum of nodes jointly derives a key for a specific invoice identity, and no individual node (or coalition below the threshold) ever sees or reconstructs the underlying secret. This repository implements that model as ordinary Rust processes communicating over mutual TLS. Every property (DKG correctness, k-of-n liveness, tamper-evident history, actual confidentiality of a derived key in transit) is demonstrated via runnable tests. It deliberately never touches money movement itself — fund custody stays on licensed banking rails; this is infrastructure software, not a payments processor, nor a regulator.

**`docs/FINANCIAL_CONTEXT.md` is the document to read if you want the commercial case**: the actors and what each of them gains, the invoice lifecycle mapped to actual endpoints, the financial use cases this supports (discounting, syndicated lending, reverse factoring, dynamic discounting, trade finance, portfolio assessment, dispute investigation, supervisory access) — and the ones it does not. It closes with the questions a supervisor or lender is likely to ask, each with an honest current answer, and a claim-to-code map so any statement can be checked against source.

## How it works, phase by phase

| Phase | What it adds | Crate(s) | Doc |
|---|---|---|---|
| 0 | DKG (Feldman VSS) + threshold BLS derive + k-of-n liveness + round-trip decrypt, all in-process | `quorum_poc` | `src/quorum_poc/README.md` |
| 1 | The same protocol over real mutual TLS between separate OS processes; a live kill-2-of-5 liveness test | `quorum_core`, `quorum_node`, `quorum_orchestrator` | `PHASE1_README.md` |
| 2 | Tamper-evident, multi-signed, hash-chained audit log + an independent external notary process | `quorum_audit`, `quorum_notary` | `PHASE2_README.md` |
| 3 | The actual product REST API (Postgres-backed) | `quorum_client`, `quorum_service` | `PHASE3_README.md` |
| 4 | 41 adversarial checks across 14 test groups (A–N) run against a real live quorum (malicious nodes, replay, threshold-bypass, mTLS and HTTP penetration tests, restart replay, network partition) | `quorum_adversarial` | `PHASE4_README.md` |
| — | Verifiable-encryption sealing: a derived key is never plaintext to any node, broker, or backend process — only the true end caller holding a locally-generated transport key can decrypt it. Each node's sealed partial carries a NIZK proof, verified against the group's own commitment before aggregation | `quorum_vetseal` | `src/quorum_vetseal/INTEGRATION.md`, `docs/cryptography/CRYPTO_DECISIONS.md` |
| 5 | Pilot & governance: operator agreements, membership-change process, protocol-operator/regulator separation, legal-track questions | — (organizational, not code) | Pending regulatory clarity |
| 6a | Post-audit design review: repositioning away from double-financing-prevention claims; adds a salted, hiding, binding invoice-commitment scheme | `ciphersettle_core::commitment`, `ciphersettle_core::merkle` | `CipherSettle_Audit_Remediation_Roadmap.md` §6a |

Reading order for understanding the cryptography: `quorum_poc` → `quorum_core` → `quorum_vetseal`. Reading order for the product surface: `ciphersettle_core` → `quorum_service` → `PHASE3_README.md`. Reading order for the security posture: `SECURITY_REVIEW.md` → `docs/security/THREAT_MODEL.md` → `CipherSettle_Audit_Remediation_Roadmap.md`.

## How to use it

Everything below assumes **rustc/cargo 1.97**, which `rust-toolchain.toml` pins declaratively (`channel = "1.97"`, tracking 1.97.x). The sandbox-era exact-version pins (`zeroize`, `postgres-protocol`, `base64ct`) were lifted in Gap 7; the remaining exact pins, if any, are checked by `ci/check_pin_policy.sh`, which requires an explanatory comment above each.

Continuous integration runs on every push and pull request: `.github/workflows/ci.yml` builds, lints (`clippy -D warnings`), and tests the workspace against the pinned toolchain and a real Postgres 16 service container, and enforces that any exact-version pin carries an explanatory comment. `.github/workflows/security.yml` runs `cargo audit`, `cargo deny` against `deny.toml`, and emits a CycloneDX SBOM on release tags.

**Phase 0 — see the core protocol work, no setup needed:**
```bash
cargo run -p quorum_poc
```

**Phase 1 — real mTLS nodes, real process kill:**
```bash
cargo build -p quorum_node -p quorum_orchestrator
cargo run -p quorum_orchestrator
```

**Phase 2 — adds the audit log + notary to the same run:**
```bash
cargo build -p quorum_node -p quorum_notary -p quorum_orchestrator
cargo run -p quorum_orchestrator
```

**Phase 3 — the full product API, needs Postgres:**
```bash
sudo apt-get install postgresql
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'ciphersettle_dev';"
sudo -u postgres psql -c "CREATE DATABASE ciphersettle_phase3;"
cargo build -p quorum_node -p quorum_notary -p quorum_service -p quorum_orchestrator
cargo run -p quorum_orchestrator   # drives Phases 1-3 end to end, one command
```

**Phase 4 — adversarial test suite (needs its own database + root for one test's `iptables` rules):**
```bash
sudo -u postgres psql -c "CREATE DATABASE ciphersettle_adversarial;"
cargo build -p quorum_node -p quorum_service -p quorum_adversarial
cargo run -p quorum_adversarial
```

**`quorum_vetseal` — the sealing crate:**
ElGamal sealing and NIZK proofs are wired into `DerivePartial` within `quorum_node`. Standalone unit tests can be run via:
```bash
cargo test -p quorum_vetseal
```

A single adversarial group can be run in isolation with `--only`, e.g. `cargo run -p quorum_adversarial -- --only M` for the NIZK proof gate.

**`ciphersettle_core::commitment` — the invoice-commitment scheme, standalone unit tests:**
```bash
cargo test -p ciphersettle_core
```

**Everything at once**, if you have Postgres running and root available:
```bash
cargo build --workspace
cargo run -p quorum_orchestrator && cargo run -p quorum_adversarial
```

The workspace has 11 members and nothing else; every command above operates only within them.

## What's real vs. still open

Every phase document contains a detailed status of its components. The current overall system status:

**Implemented and exercised against real infrastructure** (mTLS between real OS processes, a real Postgres 16 database — not mocked at the protocol level):

- Feldman VSS DKG, threshold BLS derive, and k-of-n liveness.
- Hash-chained, multi-signed audit log with external notarization by a separate process and identity.
- The adversarial suite: 41 checks across 14 groups (A–N) covering malicious partials, below-threshold combine, node-level authorization bypass, replay, restart replay, concurrent audit races, majority-tip reconciliation, mTLS penetration, HTTP penetration, sealed-share retry, TLS termination, the NIZK proof gate, the cutover guard, and a real network partition.
- Transport-key sealing and NIZK proofs (`quorum_vetseal`), wired into `DerivePartial` in `quorum_node` and verified by `quorum_client` against the group's own commitment before aggregation.
- Node-level derive authorization: HMAC over identity, expiry, single-use nonce and transport key, plus a restart guard — closing the earlier finding that any holder of the shared client certificate could derive any invoice's key.
- The invoice-commitment scheme (`ciphersettle_core::commitment`) and the append-only Merkle log (`ciphersettle_core::merkle`).

**Explicitly not yet claimed:**

- **Independent cryptographic peer review has not been performed.** The `bls.rs` and `nizk.rs` code paths this project most depends on have not been reviewed by a qualified cryptographer. `SECURITY_REVIEW.md` §6 lists exactly what such a reviewer should check. This is the largest gap in the assurance case.
- **The `VerificationAttestation` object and node-side independent verification** is not built. Until it exists, the system's central claim — access conditioned on an externally verified regulatory result — is aspirational rather than implemented.
- **The network-partition test (group H) has not been observed passing in a controlled run.** The test code is present and exercises a real partition, but `iptables` was unavailable in the environment where the suite was last verified, so that specific check is reported as unconfirmed rather than demonstrated. See `CipherSettle_Audit_Remediation_Roadmap.md` (finding A12).
- **The sealing layer is adversarially tested only at its proof gate.** Group M of the adversarial suite does exercise the NIZK gate end-to-end against a live quorum over real mTLS — including a discriminating control (M2) showing the same adversary poisons the combine when the gate is off. What is *not* covered end-to-end is a broader sweep of the ElGamal sealing layer itself: only its unit tests in `quorum_vetseal` exercise combine/decrypt edge cases.
- **DKG resharing and key rotation are not implemented** — a node's share is fixed for its process lifetime, which blocks any operational membership-change process. A full-quorum restart currently produces a new group key, making previously-issued ciphertexts unrecoverable.
- **Dispute resolution for a cheating DKG dealer is detected but not resolved.** There is no protocol for the quorum to exclude a confirmed-bad dealer and continue.
- **Seven known security advisories are knowingly accepted**, each with a written justification and a removal condition in `deny.toml`. Two are reachable only from a malicious or compromised Postgres server; one is reachable only through test tooling.
- Governance, legal questions, and regulatory compliance — including Egypt's Personal Data Protection Law No. 151 of 2020 and FRA cybersecurity requirements — remain open and require qualified Egyptian counsel. No compliance assessment has been performed.
- **Market validation:** field research with factoring companies and platform operators is required to confirm data-hosting practices and external audit requirements.

## Documentation

| Document | What it covers |
|---|---|
| `docs/FINANCIAL_CONTEXT.md` | **Start here for the business case:** the invoice-financing problem, the actors, the lifecycle as implemented, supported and unsupported use cases, and what a supervisor or lender would ask |
| `docs/PRODUCTION_READINESS.md` | The three layers — engineering, integration design, procedure — with per-item status and why approval needs all three |
| `docs/GLOSSARY.md` | Plain-language definitions for every term used across the docs, from factoring to zero-knowledge proofs |
| `SECURITY_REVIEW.md` | Technical security assessment: findings R-1…R-7, tested invariants, accepted advisories, and a cryptographic peer-review checklist |
| `docs/ARCHITECTURE.md` | Crate structure, dependency map, data flow, key-derivation flow, identity and mTLS design |
| `docs/security/THREAT_MODEL.md` | Assets, actors, trust boundaries, and the attack-path table (T-1…T-12) |
| `docs/cryptography/CRYPTO_DECISIONS.md` | Design decision records CRYPTO-001…CRYPTO-009 for each cryptographic mechanism |
| `CipherSettle_Audit_Remediation_Roadmap.md` | Findings A1–A15 and their remediation status, plus the §6a architectural repositioning |
| `PHASE1_README.md` … `PHASE4_README.md` | Per-phase what-it-builds and how-to-run. Point-in-time records: their "still open" sections are annotated with what has since been closed |
| `src/quorum_vetseal/INTEGRATION.md` | Sealing/NIZK design and how it was plumbed into the protocol |
| `SECURITY.md` | How to report a vulnerability privately |
| `CONTRIBUTING.md` | Build, test, and cryptographic review requirements |

**If you are reviewing this project, start with `SECURITY_REVIEW.md` and §6a of the remediation roadmap.** The phase documents record how the system was built and are kept for that reason; they are not the current security posture, and several items they list as open have since been closed.

## Layout

```
.github/workflows/       ci.yml (build/clippy/test) and security.yml (audit/deny/SBOM)
ci/                      check_pin_policy.sh -- fails the build on undocumented version pins
docs/
  ARCHITECTURE.md
  FINANCIAL_CONTEXT.md      -- the business case: actors, lifecycle, use cases
  PRODUCTION_READINESS.md   -- engineering / integration / procedure, by layer
  GLOSSARY.md               -- plain-language terms, finance through crypto
  cryptography/CRYPTO_DECISIONS.md
  security/THREAT_MODEL.md
src/
  ciphersettle_core/     access-control, lifecycle, invoice-commitment, and Merkle-log logic (no workspace deps)
  quorum_poc/            Phase 0
  quorum_core/           Phase 1 -- transport-agnostic DKG/derive state machine
  quorum_node/           Phase 1 -- real mTLS node binary
  quorum_orchestrator/   Phase 1/2/3 test harness / demo driver
  quorum_audit/          Phase 2 -- transport-agnostic audit log
  quorum_notary/         Phase 2 -- external notarization service
  quorum_client/         Phase 3 -- shared mTLS client/broker logic
  quorum_service/        Phase 3 -- the product REST API
  quorum_adversarial/    Phase 4 -- adversarial test suite
  quorum_vetseal/        verifiable-encryption sealing crate
```

## License

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text. Each workspace crate declares `license = "Apache-2.0"` in its manifest.
