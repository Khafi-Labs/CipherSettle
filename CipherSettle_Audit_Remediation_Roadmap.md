# CipherSettle — Audit Remediation Roadmap
### A phased implementation plan to resolve every finding in the September 2026 Independent Engineering & Security Audit, and prepare the platform for FRA submission

---

## 0. Purpose and reading guide

This roadmap takes the 15 findings (A1–A15) from *CipherSettle — Independent Engineering & Security Audit* and turns each into a concrete, sequenced engineering plan: what the optimal fix is, why that fix and not a cheaper one, and what "done" looks like.

It is organized around one governing constraint the audit already stated plainly: **items A1 and A6 gate everything else.** No amount of polish on A8–A15 makes the system presentable to a regulator if the threshold-cryptography stack is unmaintained and no independent auditor has ever looked at the code. The phases below are ordered so that the highest-leverage, most blocking work happens first, and so that later phases inherit a stable foundation instead of being built on pins and workarounds that Phase 1 is about to rip out anyway.

Each finding entry uses the same shape:
- **Problem** (one line, from the audit)
- **Optimal solution** — the fix this roadmap commits to, and why it beats the alternatives
- **Implementation plan** — concrete steps
- **Definition of done**
- **Owner role** (engineering role, not a named person)

---

## 1. Governing principles for this roadmap

1. **Fix root causes, not symptoms.** A3's pinned dependencies and A9's missing CI are both downstream of A6's unmaintained crypto stack and the toolchain wall it forces. Migrating A6 first makes A3 and much of A9 nearly free.
2. **No cryptographic code ships without a cryptography-literate reviewer.** Every change touching `quorum_core`, `quorum_vetseal`, `quorum_audit`, or `quorum_node`'s cryptographic paths gets a human reviewer qualified to sign off on the mathematics, and passes the adversarial suite before merge — the same standard the project already held itself to when it found and fixed its own Critical/High findings pre-audit.
3. **Every phase ends with the adversarial suite still fully green.** Regression of existing guarantees is treated as a launch-blocking bug in the roadmap itself, not an acceptable cost of progress.
4. **Disclosure discipline continues.** The audit itself models something regulators reward: naming what's broken before being asked. Every phase closes with an updated, dated open-items list — never a silent one.
5. **A1 (third-party audit) is commissioned early, not scheduled last.** A firm needs lead time to scope and staff the engagement; running the RFP process in parallel with Phases 1–2 means the audit can start the moment the crypto-stack migration (Phase 1) is done, instead of adding its own serial delay.

### A note on method

Some items in this roadmap are well-specified, mechanical, and low-ambiguity (CI wiring, dependency re-resolution, bulk `zeroize` wrapping, API migrations across enumerated call sites). Others are not: verifying the mathematical equivalence of two pairing implementations, designing a resharing protocol's correctness properties, DKG dispute-resolution edge cases, and any final sign-off that a cryptographic invariant still holds after a change. Those are reserved for a reviewer with cryptographic training. The distinction is not about tooling — it is about where judgment is required, and where a second pair of eyes does not substitute for it.

---

## 2. Phase overview

| Phase | Theme | Primary findings closed | Gate to next phase |
|---|---|---|---|
| **0** | Stop the bleeding — toolchain & CI foundation | A9 (steps 1–4 shipped; step 5 resolved — Apache-2.0 chosen), groundwork for A3 | CI green on current code |
| **1** | Cryptographic foundation migration | A6, A3, A4, A9 (complete) | Full adversarial suite passes on `blstrs` + current Rust + `ed25519-dalek` 2.x |
| **2** | Secrets, transport, and key lifecycle | A2, A5, A7, A8 | All secrets zeroized and KMS-backed; mTLS+HTTPS everywhere; resharing/rotation designed and implemented |
| **3** | Protocol resilience & recovery | A11, A12, A13 ✅ | DKG dispute resolution and multi-round retry pass new adversarial cases; framed wire protocol enforced. A13 done; A11/A12 open. |
| **4** | Hygiene, hardening, and housekeeping | A10, A14, A15 | Connection pooling live; dead code archived; API-key auth hardened |
| **5** | Independent audit engagement | A1 | Signed engagement letter with accredited firm; audit kickoff |
| **6** | Remediate audit findings & pilot readiness | Whatever Phase 5 turns up | Firm's sign-off letter or documented, Authority-accepted residual-risk list |

Phases 0–4 are primarily internal engineering work and can run on a compressed timeline with disciplined execution. Phase 5's calendar length is controlled by the external firm, not by CipherSettle's own team, and should be started in parallel with Phase 2, not queued after Phase 4.

---

## 3. Findings, in remediation order

### Phase 0 — Toolchain & CI foundation

#### A9 — No CI, no dependency scanning, no SBOM, no license file *(Medium)* — ✅ Resolved
**Optimal solution:** Stand up CI before touching the crypto stack, so every subsequent migration in Phases 1–4 is protected by an automated gate from day one instead of retrofitted at the end.

**Implementation plan:**
1. ~~Add a CI workflow...~~ Done: `.github/workflows/ci.yml`. Runs `cargo build --workspace --locked --all-targets`, `cargo clippy --workspace --locked --all-targets -- -D warnings`, `cargo test --workspace --locked`, and `cargo fmt --check`, against a real Postgres 16 service container (needed for `quorum_service/tests/db_pool_concurrency.rs`, A10's integration test). The workflow installs the exact toolchain from `rust-toolchain.toml` rather than `stable`, so CI cannot silently pass against a newer compiler than a real clone builds with. Also folded in A3's step 4 as a CI step: `ci/check_pin_policy.sh` fails the build if any exact-version dependency pin lacks an explanatory comment above it. Running it against the repo as it stood caught **4 real, pre-existing gaps** (`quorum_client`, `quorum_adversarial`, `quorum_notary`, `quorum_orchestrator` all had undocumented `zeroize`/`postgres-protocol` pins) — fixed by adding the same comment convention already used elsewhere in the repo; the script now passes clean.
2. ~~Add a second, schedule-triggered job (daily) running `cargo audit`...~~ Done: `.github/workflows/security.yml`, daily cron plus on every `Cargo.toml`/`Cargo.lock` change. The advisory ignore list is **derived from `deny.toml` at run time** rather than duplicated, so the audit job and the `cargo-deny` job cannot drift apart and report different answers about the same lockfile. Seven advisories are knowingly accepted (RUSTSEC-2026-0178/-0179/-0180, -0009, -0098, -0099, -0104); each carries a written justification and a removal condition in `deny.toml`. Anything else fails the build. This job installs its tooling under `stable` rather than the workspace's 1.75 pin, precisely so the check itself is not blocked by the same toolchain wall the project code is subject to.
3. ~~Add `cargo deny`...~~ Done: `deny.toml` (license allowlist, `sources` locked to crates.io only, `bans.multiple-versions = "warn"` — deliberately not `deny`, since this workspace knowingly carries multiple generations of `sha2`/`base64`/`rand` side by side from the A6 migration; re-tighten to `deny` once the remaining duplicates are understood). Wired into `security.yml` via `EmbarkStudios/cargo-deny-action`.
4. ~~Generate an SBOM via `cargo cyclonedx`...~~ Done: `security.yml`'s `sbom` job, gated to `refs/tags/v*` (an SBOM is a release artifact, not a per-commit one) via `cargo-cyclonedx`, uploaded as a build artifact.
5. ~~Add a `LICENSE` file...~~ Done: the project is licensed under Apache-2.0. The `LICENSE` file is present at the repository root, `README.md` links to it, and all eleven workspace-member `Cargo.toml` manifests declare `license = "Apache-2.0"` (which also makes `deny.toml`'s `private.ignore` exemption unnecessary to rely on). *This was a business/legal decision rather than an engineering one, and was made deliberately rather than left to default copyright terms, under which nothing would have been licensed at all.*

**Verification status.** Items 1–4 were written against a development environment matching `rust-toolchain.toml`, in which the commands CI runs were executed directly and 43/43 tests passed including the pool-concurrency test genuinely exercising a live database. The workflows themselves have been authored to run in GitHub Actions but should be confirmed on the first real CI run; items 2–4 in particular have not yet been observed executing end-to-end against the live advisory database.

**Definition of done:** A commit that reintroduces a hard version pin behind a known CVE, or that fails `clippy`, fails CI automatically. **Met** — with the caveat above regarding first-run confirmation.

**Owner:** Platform/DevOps engineer.

---

### Phase 1 — Cryptographic foundation migration

#### A6 — Unmaintained threshold-cryptography stack *(High — highest leverage item after A1)*
**Optimal solution:** Migrate `threshold_crypto`/`ff`/`pairing`/`group` 0.x to `blst`/`blstrs`, the actively maintained, widely-audited pairing library used across the Ethereum and Filecoin ecosystems for exactly this class of BLS threshold-signature work.

**Implementation plan:**
1. Spike: reimplement the DKG and threshold-signing/decryption primitives from `quorum_vetseal`/`quorum_core` against `blstrs`'s API in an isolated branch, with the existing unit tests as the correctness oracle before touching the live quorum code.
2. Re-derive and re-verify every cryptographic invariant the current implementation relies on (curve choice, pairing direction, hash-to-curve method) against `blstrs`'s equivalents — these are not always drop-in identical, and a mismatch here is exactly the kind of error that must not slip through.
3. Cut over `quorum_core`, `quorum_vetseal`, `quorum_node`, and `quorum_service` to the new primitives behind a feature flag; run the full adversarial suite against both implementations in parallel during the transition window.
4. Remove the old dependency tree entirely once cutover is verified; this is also expected to remove the `edition2024` toolchain wall that forced A3's pins in the first place.
5. Document the migration and the correctness argument in a short design note — this is precisely the kind of artifact a third-party auditor (Phase 5) will want to review first.

**Reviewer requirement:** verifying the actual mathematical equivalence of the two curve/pairing implementations requires a human with cryptographic training to sign off before merge. A subtly wrong migration here is worse than the unmaintained dependency it replaces.

**Definition of done:** Full adversarial suite passes exclusively against `blstrs`; old crates removed from `Cargo.lock`.

**Owner:** Cryptography-literate senior engineer.

#### A3 — Two dependencies behind patched DoS CVEs *(High)*
**Optimal solution:** Once A6's toolchain wall is gone, delete every hard `=x.y.z` pin across all eleven `Cargo.toml` files and re-resolve against current, patched versions rather than bumping only the two flagged crates — a targeted bump without removing the pinning *policy* just recreates this finding at the next advisory.

**Implementation plan:**
1. Confirm current stable Rust builds the post-A6 workspace.
2. Remove all exact pins; run `cargo update` to re-resolve.
3. Bump `postgres-protocol` to ≥0.6.12 and `tokio-postgres` to ≥0.7.18 explicitly, confirming the resolved graph reflects it.
4. Add a CI check (from A9) that fails the build if any `Cargo.toml` reintroduces an `=` pin without an accompanying, dated comment explaining why.
5. Run `cargo audit` clean as the exit criterion.

**Definition of done:** `cargo audit` reports zero advisories against the resolved lockfile; CI enforces no un-commented exact pins going forward.

**Owner:** Platform engineer.

#### A4 — `ed25519-dalek` 1.x end-of-life *(High)* — ✅ Mechanical migration done; invariant re-verification still needs a human sign-off
**Optimal solution:** Migrate to `ed25519-dalek` 2.x across all five call sites identified in the audit (`quorum_node`, `quorum_notary`, `quorum_audit`, `quorum_orchestrator`, `quorum_adversarial`).

**Implementation plan:**
1. ~~Replace the combined-byte `Keypair` type with the 2.x `SigningKey`/`VerifyingKey` split at each of the five call sites.~~ Done, and this surfaced more than a pure API-surface change:
   - **Pinned to 2.1.1, not the latest 2.2.0** — checked the crates.io index directly rather than assuming: 2.2.0 bumped its own declared MSRV to rustc 1.81 (above this workspace's 1.75), while 2.1.1 still declares 1.60.
   - **`SigningKey::to_bytes()` is 32 bytes (the seed only), not 1.x's 64-byte secret‖public blob.** This is a real wire-format change to `audit_keypair_b64` everywhere it's written and read (`quorum_orchestrator`/`quorum_adversarial` as writers, `quorum_node`/`quorum_notary` as readers) — updated consistently across all four, with an explicit, informative panic if a config is ever found carrying the old 64-byte format instead of silently misreading it.
   - **`Signature::from_bytes` changed from fallible (1.x) to infallible over a fixed-size `&[u8; 64]` (2.x)** — the wrong-length case (malformed/truncated data, not a cryptographic failure) now has to be handled explicitly via `try_into()` before calling it; done in both of `quorum_audit`'s verification functions, same observable behavior (reject cleanly) via a different mechanism.
   - **A real, non-obvious dependency conflict**: `ed25519-dalek` 2.x needs `zeroize >= 1.5`, but this workspace already pinned `zeroize = "=1.3.0"` everywhere for the *old* `threshold_crypto` chain — two conflicting exact pins of the same crate can't coexist. Checked whether the old chain would tolerate a newer `zeroize` before assuming a messier fix was needed: bumping the shared pin to `1.5.7` works for both, and the resulting `curve25519-dalek` 3.2.1→3.2.0 "downgrade" this triggered was checked against that project's actual diff (a `zeroize`-constraint relaxation and CI changes only, no cryptographic code changed) rather than accepted on faith.
   - **A separate RNG-version split**: three of the five crates (`quorum_orchestrator`, `quorum_adversarial`, and transitively via `quorum_vetseal`/`quorum_core`) call into the old `threshold_crypto`-era code with `rand` 0.7's `Rng` trait in the same function scope as new `ed25519-dalek` 2.x calls needing `rand` 0.8's *unrelated, semver-incompatible* `Rng` trait. Both are now explicit, separately-named dependencies (`rand` and `rand08 = { package = "rand", version = "0.8" }`) rather than one silently shadowing the other. `quorum_node` and `quorum_notary` needed neither bump — they only ever load a key from config (`from_bytes`), never generate one.
   - **Verified against live processes, not just unit tests**: ran a real `quorum_orchestrator` demo end to end, then wrote a standalone harness that loaded a live node's actual on-disk config and actual on-disk audit log, derived the `VerifyingKey` from the real seed, and confirmed the real signature a live process wrote verifies correctly — and that a wrong key correctly does not.
   - `quorum_audit`'s full test suite (17 tests, including forgery-rejection) and the whole workspace's build/clippy/test suite all pass with no other regressions.
2. Update serialization/deserialization of stored keypairs (this touches A2's secrets-at-rest work — sequence these together, see Phase 2). **Done for the wire-format change itself** (see above); A2's own zeroization-on-drop and KMS/Vault work is still separately open.
3. **Not done, and not closable by inspection:** re-run the `sign_entry_hash` call-site audit to confirm the "no attacker-influenced public key" invariant still holds post-migration. The mechanical migration preserves the same call shape at every site, which is suggestive but is exactly the kind of "looks right" that isn't the same claim as "a reviewer re-derived the invariant" — that's the one piece of A4 explicitly reserved for cryptographic review, and it still is.
4. **Not done.** A regression test asserting that invariant is a natural adversarial-suite addition but depends on step 3's re-verification defining precisely what to assert.

**Definition of done:** No `ed25519-dalek = "1"` requirement remains anywhere in the workspace (**met** — confirmed via `cargo tree`); new regression test passes (**not met** — blocked on step 3).

**Owner:** Backend engineer (mechanical migration — done), cryptography reviewer sign-off (steps 3–4 — still open).

---

### Phase 2 — Secrets, transport, and key lifecycle

#### A2 — Secret material stored as plaintext bytes, `zeroize` never invoked *(High)*
**Optimal solution:** Two-part fix — (a) a real secrets-management layer for keys at rest, (b) actually wire up the `zeroize` dependency already sitting unused in every crate.

**Implementation plan:**
1. **At rest:** introduce a KMS/Vault-backed secrets layer. Recommend a cloud KMS (AWS KMS, GCP KMS, or Azure Key Vault, matched to the eventual hosting environment) for TLS keys and the service auth key, with HashiCorp Vault as the self-hosted alternative if the Authority requires on-premises key custody. Define a documented node-provisioning process: new node joins the quorum by requesting a short-lived credential from the operator, not by receiving a JSON file over email or scp.
2. **In memory:** wrap every secret byte buffer — TLS private keys, ed25519 keypairs, `service_auth_key`, and threshold key shares — in `zeroize`'s `Zeroizing<T>` or `#[derive(ZeroizeOnDrop)]`. This is a mechanical, per-type change across `quorum_core::config`, `quorum_vetseal`, and the node/service crates.
3. Update `NodeConfig` loading to fetch secrets from the KMS/Vault layer at startup rather than reading them directly from a plaintext JSON file; the JSON file becomes references/handles, not the secrets themselves.
4. Add a CI/lint check (or a documented code-review checklist item) flagging any new `Vec<u8>` or `String` field in a struct that historically held secret material, to prevent regression.

**Reviewer requirement:** the KMS/Vault integration and provisioning-process design need architecture decisions (which cloud, which access model) before implementation.

**Definition of done:** No secret byte buffer traceable in a `grep` for `String`/`Vec<u8>` in the relevant structs without a zeroizing wrapper; `NodeConfig` on disk contains no live secret material; documented provisioning runbook exists.

**Owner:** Platform/security engineer.

#### A5 — HTTP API has no TLS termination *(High)* — ✅ Fixed
**Optimal solution:** Terminate TLS at the service itself using the project's existing `rustls` dependency (already present and patched, per the audit's appendix), rather than mandating an external proxy — this keeps the security property inside the deployable artifact instead of depending on every operator configuring a reverse proxy correctly.

**Implementation plan:**
1. ~~Extend `quorum_service`'s HTTP listener to bind with `rustls`-backed TLS...~~ Done, with a real detour along the way: the obvious approach (`axum-server`'s `tls-rustls` feature) doesn't work in this workspace -- its latest release (0.6.0) is API-incompatible with the newer `hyper-util` this workspace's `axum` 0.7.9 already resolves to. Confirmed by actually trying it, not assumed. Fell back to axum's own documented "low-level rustls" pattern instead (`src/quorum_service/src/tls_serve.rs`: `hyper::server::conn::http1` + `hyper_util`'s `TokioIo` + `tokio_rustls::TlsAcceptor`), which is materially the same amount of code `axum-server` would have been. Deliberately HTTP/1.1-only -- this API doesn't need HTTP/2, and enabling it pulls in `h2` → `indexmap 2.3+` → `hashbrown 0.15+`, which hits the same edition2024/rustc-1.75 wall A6 exists to remove; skipping the feature was simpler than adding another pin. **Certificates**: per the note on A2 below, its KMS/Vault-backed provisioning layer doesn't exist yet, so `tls_cert_der_b64`/`tls_key_der_b64` are config-supplied DER bytes for now, the same pattern this config already uses for the mTLS node identity -- swapping the source of those bytes for a KMS/Vault call later is a config-loading change, not a `tls_serve.rs` change.
2. ~~Retain the option to run behind an operator-controlled proxy...~~ Unchanged by this fix: `tls_cert_der_b64`/`tls_key_der_b64` are optional and, when absent, `quorum_service` still binds plaintext -- an operator that wants their own edge TLS can still terminate it there and point this service's plaintext listener at loopback only, which is exactly what step 3's loopback check permits.
3. ~~Update the binding to allow configurable interfaces...with TLS as a non-optional precondition...~~ Done: `tls_serve::refuse_plaintext_off_loopback`, called immediately after config parsing (moved there deliberately -- an earlier draft checked it right before binding, after Postgres connect and schema init, which would have made a misconfigured deployment fail for a confusing reason if Postgres also happened to be unreachable; fail-fast on the service's own config first). Verified at the actual process level, not just by reading the code: a deliberately-broken config (non-loopback + unreachable DB + nonexistent pubkey file) is refused in under 5ms, confirming it never touches any of those other resources.

**Definition of done:** `quorum_service` refuses to bind to a non-loopback interface without valid TLS configuration; adversarial suite gains a test asserting plaintext HTTP is rejected off-loopback. **Met**: new `quorum_adversarial` Test K (K1-K3c) runs against the live `quorum_service` binary, not a unit test in isolation -- K1 confirms the process exits and the port never becomes connectable when misconfigured off-loopback without TLS; K2 confirms plaintext loopback still works unchanged (backward compatible with every other test in this suite); K3a-c confirm a real TLS handshake completes when TLS is configured, that the connection actually carries a genuine HTTP response, and that a plaintext request against the same port does NOT get served in the clear. All 5 checks pass against live processes. Full `quorum_adversarial` suite re-run afterward: A-D, F, G, I, J, K, H2 all still pass; H1 was not exercisable in the verification environment for the unrelated, pre-existing reason noted under A12 (`iptables` unavailable, so the network-partition simulation cannot take effect regardless of any code); **E was observed flaky under that environment's load (3/5 pass on repeated isolated runs)** -- confirmed via direct repeated measurement rather than assumed, and not caused by this change (A5's diff never touches `quorum_audit`, `quorum_orchestrator`, or `quorum_notary`, which is everything Test E exercises).

**Owner:** Backend engineer.

#### A7 — No key resharing or rotation *(High)*
**Optimal solution:** Design and implement a proactive secret-sharing (PSS) style resharing protocol, allowing the quorum to redistribute shares among a new or changed node set without reconstructing the master secret at any single point — this is the standard cryptographic answer to "operators change over the system's lifetime," and it composes naturally with A6's `blstrs` migration (several maintained threshold libraries in that ecosystem have reference resharing implementations worth evaluating rather than building the primitive from scratch).

**Implementation plan:**
1. Specify the resharing protocol: trigger conditions (planned rotation, suspected compromise, operator turnover), the multi-round handshake among current and incoming nodes, and how the DKG dispute-detection machinery from A11 plugs in so a dishonest participant can't stall a resharing round either.
2. Prototype against the post-A6 `blstrs`-based primitives; write a dedicated adversarial test group (given its own letter rather than folded into an existing group) proving old shares are provably invalidated after a reshare and a minority of old+new shares cannot reconstruct the secret.
3. Add an operational runbook: how an operator actually triggers and executes a rotation in production, including the provisioning flow from A2.

**Reviewer requirement:** protocol specification and the correctness-critical resharing math need cryptographic design review before implementation.

**Definition of done:** New adversarial test group passes, demonstrating share rotation without secret reconstruction and without an availability gap during the reshare window.

**Owner:** Cryptography-literate senior engineer.

#### A8 — Single shared symmetric `service_auth_key` *(Medium)*
**Optimal solution:** Replace the shared HMAC secret with an asymmetric scheme: `quorum_service` signs each `DeriveRequest` with its own private key; every node verifies against `quorum_service`'s single public key. This directly removes the "one leaked secret compromises every node" blast radius the audit flagged, and is a much smaller change than A7 or A6.

**Implementation plan:**
1. Generate a `quorum_service` signing keypair (ed25519, consistent with A4's migration), stored via the A2 secrets layer.
2. Replace the HMAC construction in the request-signing/verification path with a signature construction; distribute the public key to nodes via the same provisioning process as their TLS material.
3. Update the adversarial suite's existing auth-bypass test cases to target the new scheme.

**Definition of done:** No shared symmetric secret remains for request authentication; a compromised node can no longer forge requests to peers.

**Owner:** Backend engineer.

---

### Phase 3 — Protocol resilience & recovery

#### A11 — DKG dispute detection without resolution *(Medium)*
**Optimal solution:** Implement the standard verifiable-secret-sharing complaint/resolution flow: a node that receives a bad share broadcasts a complaint; the accused dealer must reveal the disputed share value on the public channel for cross-verification; if the reveal is provably wrong, the dealer is excluded and the DKG proceeds with the remaining honest set (subject to still meeting the threshold).

**Implementation plan:**
1. Extend `quorum_core`'s DKG state machine with complaint and reveal message types and the associated broadcast round.
2. Define the exclusion and threshold-recount logic: what happens if too many dealers are excluded to still meet the threshold (this must fail closed, not silently reduce the security threshold).
3. Add adversarial test cases with a deliberately dishonest dealer, verifying the round completes with the honest subset and the dishonest party is excluded rather than able to stall indefinitely.

**Definition of done:** New adversarial tests demonstrate DKG completion despite one dishonest dealer, and correct fail-closed behavior when exclusions would drop below threshold.

**Owner:** Cryptography-literate engineer.

#### A12 — No multi-round sealed-share retry protocol *(Medium)* — ✅ Fixed, with a correction to the finding's own framing
**Optimal solution:** Build the multi-round retry protocol into `quorum_service` itself (not just the test harness), so a bad node's ciphertext discovered post-combine triggers an automatic retry against a different node subset rather than requiring the caller to retry manually.

**A correction, not just an implementation, was needed first:** this finding's "optimal solution" text was written for an architecture where `quorum_service` combines *and decrypts*, so it can discover a bad node itself. That's no longer how this codebase works -- Finding 2.3's fix (already shipped, see `quorum_vetseal`) means `quorum_service` only ever handles *sealed* shares and never holds a `TransportSecretKey`, so it structurally cannot tell a bad result from a good one. Only the true caller, who holds the transport secret key, can. This isn't a new problem A12 introduces; the code's own pre-existing doc comments on `derive_from_quorum` already said as much ("a multi-round collect/attempt-open/retry-excluding conversation between it and the true caller, since only the caller can tell a subset failed"). The fix below is the best achievable version of this finding's actual intent given that hard constraint: `quorum_service` still owns and formalizes the entire retry *state machine* (which subsets to try, in what order, when to give up), and the caller's role is reduced to the smallest thing physically necessary -- decrypt, check, and if it fails, echo back which subset was used. That's not literally "zero caller-side logic," but it's the floor, not a shortcut.

**Implementation plan:**
1. ~~Formalize the retry state machine...~~ Done, with one real correction along the way. The first version tracked `excluded_node_ids` and permanently excluded every node in a failed subset. Checking the actual numbers before shipping it: this project's real deployment is 3-of-5 (`want = threshold + 1 = 3`, `n = 5`), and excluding a full 3-node subset leaves only 2 nodes -- **never enough to retry again, ever, after a single failure, regardless of which node was actually bad.** That would have made the "retry protocol" strictly worse than no protocol for the shape this project actually runs. Redesigned to a genuine combination search: the caller accumulates `tried_subsets` (every subset a previous round returned that failed verification) and `quorum_client::collect_sealed_derived_key` picks the first untried `want`-sized combination of currently-reachable nodes -- mirroring `derive_from_quorum`'s already-correct in-process `combinations()` logic instead of reinventing something weaker. `CollectSealedError` distinguishes "transient, not enough nodes responded" from "terminal, every combination already failed" (mapped to HTTP 500 vs 409 respectively in `quorum_service`), satisfying the "clear terminal failure mode" requirement.
2. ~~Port the logic already proven in the in-process test harness into `quorum_service`'s live request-handling path.~~ Done: `DeriveReq`/`DeriveResp` in `quorum_service` gained `tried_subsets` (request) and `used_node_ids` (response); the `/invoices/{id}/derive-key` handler wires straight through to the corrected `collect_sealed_derived_key`.
3. ~~Add adversarial tests simulating a bad node landing in the first subset tried, confirming automatic recovery without caller intervention.~~ Done: `quorum_adversarial`'s new Test J runs against a **live `quorum_service` process** and a genuinely malicious node (reusing Test A's `spawn_garbage_adversary`, not a mock). J1 confirms the bad node actually lands in round 1's subset (so the test proves something); J2 confirms round 1 correctly fails client-side verification; J3 confirms the first retry picks a different subset; J4 loops retries until recovery or the 9-round bound, and confirms recovery happens within it; J5 confirms that with every subset reported as tried, the service returns a clean 409, not a fabricated success or a 500. **Caught a second real bug by actually running this, not just writing it**: the first version of J4 asserted recovery specifically on the *second* attempt. It failed -- because a single bad node is present in 6 of the 10 possible 3-node subsets (not 4, as an earlier draft of the doc comment above incorrectly claimed), a naive lexicographic search can and did hit a second bad subset before finding a clean one. Fixed the test to loop until recovery or exhaustion (which is what's actually guaranteed) rather than asserting a specific round; one real run took 6 retries before recovering, still comfortably inside the 9-round worst-case bound.

**Known limitation, documented rather than hidden:** the combination search is correctness-safe (recovery within the retry cap is guaranteed for any single bad node) but not latency-optimal -- it doesn't yet use the information "this subset failed" to deprioritize the nodes it contained on the next attempt, so worst case is several full rounds of contacting every node before landing on a clean subset. A smarter selection heuristic is a real, worthwhile follow-up, not a mechanical fix, so it wasn't done here.

**Definition of done:** A live `quorum_service` request survives a bad-node-in-first-subset scenario ~~without caller-side retry logic~~ (revised per the correction above: with the minimum caller-side logic the sealed-share architecture makes physically unavoidable -- decrypt, check, retry); new adversarial test passes. **Met**, all 5 of Test J's checks pass against live processes; full `quorum_adversarial` suite still passes A-G and I. Test H1 was not exercisable in the verification environment for an unrelated, pre-existing reason -- `iptables` was unavailable there, so its network-partition simulation could not take effect regardless of any code, and not something this change touched.

**Owner:** Backend engineer.

#### A13 — Unbounded wire-protocol message length *(Low–Medium)* — ✅ Fixed
**Optimal solution:** Replace the unbounded `BufReader::lines()` reader with a length-bounded frame reader that closes the connection if a peer exceeds a configured maximum line length.

**Implementation plan:**
1. ~~Introduce a max-line-length constant (configurable, conservative default).~~ Done: `quorum_node::bounded_line_reader::MAX_WIRE_LINE_BYTES` (8 MiB — sized generously above any realistic legitimate message, since individual DKG/derive messages are a few KB and the only message type that grows with usage is audit-log bulk transfers).
2. ~~Wrap the existing reader with a bounded variant; on overflow, log and close the connection rather than continuing to buffer.~~ Done: `BoundedLineReader` (`src/quorum_node/src/bounded_line_reader.rs`) replaces `BufReader::lines()` in `handle_inbound`. It scans only the not-yet-checked suffix of its buffer on each new chunk (an earlier draft re-scanned the whole buffer every time, an accidental O(n²) CPU cost under exactly this attack — caught and fixed by timing the test suite, not by inspection). Exceeding the cap returns an `Err`, which `handle_inbound`'s existing `?`-propagation and its caller's logging already turn into "log and drop the connection" with no code changes needed there.
3. ~~Add an adversarial test sending an oversized, unterminated line and asserting bounded memory growth and connection closure.~~ Done at two levels: unit tests in `bounded_line_reader`'s own test module (including one asserting the buffer never grows far past the cap, not just that an error is eventually returned), and `quorum_adversarial`'s Test F gained F3/F3b — a *validly-pinned* peer (this finding's actual threat model: a compromised participant, not an anonymous attacker) streams 8.5 MiB with no terminator against a live `quorum_node` process; F3 confirms the connection is closed, F3b confirms the node stays alive and keeps serving other connections afterward, not just that the bad connection dies.

**Where AI helps:** This is a small, well-scoped, low-risk change well suited to AI-assisted implementation with standard review.

**Definition of done:** New adversarial test passes; memory use under an oversized-line attack is bounded and connection is dropped. **Met** — this added test group L (L1–L4), bringing `quorum_adversarial` to 41 checks across 14 groups (A–N).

---

### Phase 4 — Hygiene, hardening, and housekeeping

#### A10 — `Mutex<Client>` instead of a real Postgres connection pool *(Medium)* — ✅ Fixed (predates this remediation engagement)
**Optimal solution:** Replace with `deadpool-postgres` or `bb8-postgres` (both standard, actively maintained pooling crates for `tokio-postgres`), sized appropriately for expected concurrent load.

**Implementation plan:**
1. Introduce the pool at `quorum_service` startup, replacing the single `Mutex<Client>`.
2. Update all call sites in `quorum_service::db` to acquire a pooled connection per operation.
3. Load-test to confirm the pool removes the serialization bottleneck the single mutex imposed, and tune pool size against realistic concurrent request volume.

**Reviewer requirement:** the final concurrency behaviour under load needs review.

**Definition of done:** No `Mutex<Client>` remains; load test shows concurrent request handling without serialized DB access as the bottleneck.

**Owner:** Backend engineer.

#### A14 — Orphaned `ciphersettle_backend` (dead IC canister code) *(Low)* — ✅ Fixed; escalated from "archive" to "delete"
**Optimal solution (as originally planned):** Move to a clearly labeled `legacy/` or `archive/` directory with a README explaining it was superseded by Phases 1–4, rather than deleting outright — preserving history for anyone who wants to see the earlier design direction.

**Why the plan changed:** the crate was first archived, then **deleted** as part of preparing this repository for publication. Three factors, each independently sufficient: it could not build on any toolchain this project uses (`ic-cdk` 0.17 requires rustc 1.78+, above the pinned 1.75) and therefore could never be compiled or tested by a reviewer; carrying `ic-cdk`/`ic-stable-structures` in the tree added a second, unrelated cryptographic and runtime dependency stack to a repository whose central claim is a specific, reviewable protocol; and a reviewer skimming the repository is more likely to be confused than enlightened by an early IC-based prototype that no longer represents the design. Its decision logic was never lost — it survives in `ciphersettle_core`, which `quorum_service` calls.

**Implementation plan:**
1. ~~Remove it from the active `Cargo.toml` workspace members list so it no longer affects builds or CI.~~ Done.
2. ~~Archive it under `legacy/` with an unambiguous README.~~ Done, then superseded by deletion.
3. Delete the crate and its README outright. Done. `docs/ARCHITECTURE.md` §"Earlier Designs" records what it was and why it is gone, so the fact of the earlier design is still documented.

**Definition of done:** No reference to a canister implementation remains in the workspace, in build inputs, or in any document presented as describing the current system. **Met.**

**Owner:** Any engineer.

#### A15 — API-key comparison not constant-time; keys stored in plaintext in `AppState` *(Low)* — ✅ Fixed (predates this remediation engagement)
**Optimal solution:** Hash stored API keys (rather than keeping raw values in `AppState`) and compare using a constant-time check; treat this as the seed of a proper API-key/OAuth layer if the number of integrators is expected to grow.

**Implementation plan:**
1. Store a salted hash (e.g., via `argon2` or a keyed HMAC) of each API key rather than the raw value.
2. Replace the `HashMap` lookup/compare with a constant-time comparison (`subtle` crate) against the hash of the presented key.
3. If integrator count is expected to grow past a handful (business decision — flag for product input), scope a follow-on OAuth2/client-credentials migration as a separate, non-blocking workstream.

**Reviewer requirement:** the OAuth migration (if pursued) needs architecture input before implementation.

**Definition of done:** No plaintext API key stored in memory beyond the request that presents it; comparison uses a constant-time primitive.

**Owner:** Backend engineer.

---

### Phase 5 — Independent third-party audit

#### A1 — No independent third-party cryptographic/security audit *(Critical, blocking)*
**Optimal solution:** This cannot be resolved with more internal engineering, by design — it requires commissioning a named, accredited third-party cryptography and security firm, and this roadmap treats it as a parallel track, not a final step.

**Implementation plan:**
1. **Start the RFP process during Phase 1**, not after Phase 4. Candidate firms should have demonstrated experience with threshold/BLS cryptography specifically, not only general application security — the audit's own findings show this project's risk is concentrated in the cryptographic core, not primarily the web-app layer.
2. Scope the engagement explicitly to cover what this internal audit disclosed it did *not* cover (Section 6 of the audit): formal verification / security-reduction review of the threshold BLS construction and the verifiable-encryption sealing scheme, fuzzing of the wire protocol/HTTP boundary/Postgres interaction layer, and — separately, likely a different specialty — a penetration test once a deployment target exists.
3. Provide the firm with the existing adversarial reproducer suite as a starting point rather than only a design document.
4. Target engagement kickoff for immediately after Phase 1 completes (the crypto stack the firm reviews should be the `blstrs`-based one, not the soon-to-be-replaced `threshold_crypto` one — reviewing code about to be thrown away wastes the engagement's budget).
5. Build in calendar slack for Phase 6 (remediation of whatever the firm finds) before committing to an FRA submission date.

**Note:** this finding is explicitly the one item on the list that is not resolvable by better internal engineering. Selecting the firm, negotiating scope, and the audit itself are outside the project's control.

**Definition of done:** Signed engagement letter with an accredited firm; audit kicked off against the post-Phase-1–4 codebase.

**Owner:** Engineering leadership + legal/compliance (external-facing, not an individual contributor task).

---

### Phase 6 — Remediate third-party findings & pilot readiness

By definition, the content of this phase depends on what the Phase 5 firm finds. Reserve calendar time and engineering capacity rather than scheduling specific fixes now. Exit criteria for this phase — and for the roadmap as a whole — are:

- The third-party firm's sign-off letter, **or**
- A documented, Authority-accepted list of residual risks the Authority has knowingly agreed to accept for a supervised pilot (a synthetic-data sandbox pilot under close supervision does not require every item above to be closed, but production deployment with real invoices and real money does).

---

## 4. Consolidated timeline (indicative, not calendar-committed)

| Phase | Depends on | Can run in parallel with |
|---|---|---|
| 0 — CI foundation | — | Nothing (do first, it's fast) |
| 1 — Crypto migration (A6, A3, A4) | Phase 0 | Phase 5 RFP process (start the paperwork now) |
| 2 — Secrets/transport/rotation (A2, A5, A7, A8) | Phase 1 | — |
| 3 — Protocol resilience (A11, A12, A13) | Phase 1 (A11/A12 benefit from stable crypto primitives) | Phase 2 |
| 4 — Hygiene (A10, A14, A15) | Phase 0 only | Phases 1–3 (no dependency — can run anytime, good filler work) |
| 5 — Third-party audit engagement | Phase 1 complete (review target should be stable) | Phases 2–4 |
| 6 — Remediate findings, pilot readiness | Phase 5 results | — |

Phase 4's items have no technical dependency on Phases 1–3 and can be parallelized by a second engineer track from day one — there is no reason A14 (archiving dead code) or A15 (API-key hashing) waits on the cryptographic migration.

**Flagged during implementation, not itself a numbered finding:** `quorum_adversarial`'s Test E ("concurrent audit proposers both succeed with no lost write", the adversarial-suite proof that Finding 1.2's retry-on-collision fix works) was observed to be genuinely flaky under load while verifying an unrelated change (A5) — 3 passes out of 5 back-to-back runs, confirmed by direct repeated measurement, not assumed from a single failure. The A5 diff never touches `quorum_audit`, `quorum_orchestrator`, or `quorum_notary` (everything Test E exercises), so this predates A5 rather than being caused by it. Worth a look: either the retry-on-collision logic itself has a real timing-dependent gap under contention, or the test's own timing assumptions (how concurrently it fires the two proposers) are too tight for a loaded machine. Not triaged further here since it's outside A5's scope, but it shouldn't sit unflagged in a suite everyone otherwise treats as a hard gate. **It should be re-run repeatedly under artificial CPU/memory load in a controlled environment before being relied on as evidence, and it should not be presented as a hard gate until it is.**

---

## 5. Definition of "fully prepared for implementation"

The project can accurately describe itself as launch-ready for a **supervised pilot** (under the sandbox-pilot option in the regulatory proposal) when:

- Phases 0–4 are complete and the adversarial suite — expanded with every new test case described above — passes in full.
- The Phase 5 engagement has either delivered a sign-off letter, or produced a residual-risk list the Authority has explicitly, knowingly accepted for pilot scope.
- The updated open-items list (this roadmap's living counterpart to the audit's Section 2 table) is dated and current, not stale.

The project should **not** describe itself as ready for **production deployment with real invoices, real counterparties, or real money** until Phase 6 is closed and the third-party firm's findings are fully remediated — this mirrors exactly what the independent audit already committed to, and this roadmap changes none of that judgment, only operationalizes it.

---

## 6a. Post-audit design review: repositioning away from double-financing prevention

After this roadmap's A1–A15 findings were largely worked through, a separate design review reconsidered what this project's actual value proposition should be, given that Egypt's FRA operates its own digital factoring system with e-Finance, providing invoice inquiry, prior-financing checks, and invoice freezing. *(This is characterised here as publicly-reported context, not as a citation of any specific regulatory instrument; the project's claims should be re-checked against the Authority's own published materials before any formal submission.)* The review's conclusion, which this project now follows:

**CipherSettle should not claim to prevent double financing or verify invoice validity — the FRA now does both authoritatively, and duplicating that function is redundant at best and a false claim of regulatory authority at worst.** Its actual value is narrower and complementary: protecting confidential invoice data from any single infrastructure operator (not from the factoring company that already legitimately holds the data — that's a different adversary the project's own documentation had not previously stated explicitly), conditioning access on a verifiable official result rather than a self-asserted one, and producing tamper-evident evidence of what happened and why.

This reframing surfaced two findings worth recording precisely because they're **not yet resolved, and can't be resolved by engineering work alone**:

- **The oracle problem is not hypothetical — it's the current architecture.** Checked directly against the code: `quorum_core::verify_derive_auth` currently authorizes a key derivation against exactly one thing, a shared HMAC secret between `quorum_service` and every node. There is no per-invoice signed attestation from any external authority checked anywhere in this system today. Every claim this project could make about "access conditioned on the FRA's verified result" is aspirational until an `VerificationAttestation`-shaped object, signed by a real external source, exists and is independently checked by each node — not merely asserted by `quorum_service`.
- **Whether FRA/e-Finance exposes any API or signed receipt a third party can consume is unconfirmed.** Searched for a public announcement of one and found none. This is the load-bearing assumption under the entire redesign, and it's unverified in both directions — not "probably yes," not "probably no."

Also flagged, not yet acted on: language auditing this project's own documentation for overreach (e.g. "cryptographically enforce," which overstates what a threshold quorum checking a signed attestation actually guarantees), and confirming genuine trust-domain independence across the 5 quorum nodes (5 servers under one administrator's control are not 5 independent parties from a security standpoint, regardless of the threshold math).

### What's been built against this reframing

- **`ciphersettle_core::commitment`** (new): a salted, hiding hash commitment over invoice content (reference, issuer, debtor, amount, currency, dates), with domain separation, an explicit versioned binary encoding (deliberately not JCS/RFC 8785 canonical JSON, which has known cross-implementation pitfalls), and 7 tests covering binding, hiding, tamper-detection field-by-field, and version rejection. This closes a gap that existed nowhere in the project before this review: there was no invoice-commitment scheme of *any* strength, not merely a weak one. The field list is explicitly provisional pending confirmation of what a real Tax Authority e-invoice identifier integration would need.

### What's still open, and why it isn't engineering work

- **The `VerificationAttestation` object and node-side independent verification of it** — the single most important remaining piece, and explicitly scoped as the next step, not yet built.
- **Confirming FRA/e-Finance's actual API/signature surface** — requires a real relationship with that system's operators, not something resolvable from inside this codebase.
- **Customer validation** — the design review's own strongest recommendation was to interview several real factoring companies or platform operators before building further, to learn who hosts their data today, who can see it, and whether the FRA or auditors have actually asked them for proof of pre-financing inquiry. That determines whether this is a product with real demand or, in the review's own words, "just a good crypto project." Outside what this engineering process can determine on its own.
- **Legal review** (Personal Data Protection Law No. 151 of 2020, FRA cybersecurity requirements) — needs qualified Egyptian counsel.

---

## 6. Review and sign-off requirements, summarized

**Items that need cryptographic peer review before merge** — anything touching `quorum_core`, `quorum_vetseal`, `quorum_audit`, or `quorum_node`'s cryptographic paths. Specifically: verifying the mathematical equivalence of the old and new pairing implementations during the `blstrs` migration (A6); designing the resharing/rotation protocol's correctness properties (A8); DKG dispute-resolution game-theoretic edge cases (A11); and any final sign-off that a cryptographic invariant the audit relies on still holds after a change (A4 step 3).

**Items that need standard code review and the adversarial suite** — CI/SBOM tooling, dependency-pin removal and re-resolution, `zeroize` wrapping across known struct types, mechanical API migrations across enumerated call sites, connection-pool refactors, dead-code archival, API-key hashing and constant-time comparison, wire-protocol length bounding, and test scaffolding once the invariant being tested has been specified.

**Items outside engineering control entirely:** selecting and scoping the third-party audit firm (A1), and everything listed in §5.

The distinction is not about how the work gets done. It is about where judgment is required and where a second pair of eyes does not substitute for a qualified reviewer. See also `CONTRIBUTING.md`, which makes the peer-review requirement a merge condition.
