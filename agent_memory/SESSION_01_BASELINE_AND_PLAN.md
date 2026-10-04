# Session 01: baseline and Gap 6 plan

## Environment (EXECUTED)
rustc/cargo 1.75.0 (Ubuntu apt; rustup blocked by sandbox network), clippy 0.1.75, rustfmt 1.7.0, PostgreSQL 16.15, 1 vCPU.
Not available: cargo-audit, cargo-deny (need newer Rust than 1.75; sandbox cannot reach static.rust-lang.org). No `.git` directory in the archive.

## Baseline
- `cargo build --workspace --locked --all-targets`: OK, 0 warnings, 183 s cold.
- `cargo test --workspace --locked` with CIPHERSETTLE_TEST_DB_REQUIRED=1: 126 passed / 0 failed / 0 ignored
  (core 54+4, audit 16, quorum_core 19, node 6, service 11+2 DB, vetseal 14). DB tests confirmed `ran`, not skipped.
- `cargo fmt --check`: clean. `cargo clippy --all-targets -D warnings`: clean. `ci/check_pin_policy.sh`: OK.
- Adversarial (`--only A,B,C,D,M,L,E,I,F,G,J,K,N`): 35/35 PASS once DB `ciphersettle_adversarial` exists. Test H (needs iptables) not run.
- Test E x10 idle: 10/10 pass.
Logs: `agent_memory/evidence/`.

## Not yet done from FIRST STEPS
Full read of README, THREAT_MODEL, CRYPTO_DECISIONS, PRODUCTION_READINESS, SECURITY_REVIEW is NOT complete; only the Gap List, prompt, CONTRIBUTING (part), and targeted code were read.

## Plan: Gap 6 (CI)
Files to add/touch: `.github/workflows/ci.yml`, `.github/workflows/flake-hunt.yml` (manual: Test E x100 under CPU stress), `ci/setup_test_db.sh` (creates both DBs from one source of truth), `CONTRIBUTING.md` (fix env var, DB steps), `deny.toml` (workflow reference), adversarial DSNs read from env.
CI jobs: (1) build+test on pinned 1.75.0 with Postgres service and DB_REQUIRED=1; (2) clippy -D warnings + fmt + pin policy; (3) adversarial suite excl. H; (4) cargo audit + cargo deny on current stable (separate job); (5) negative job: point tests at an unreachable DB and assert CI step FAILS.
Tests/evidence: negative DB job (fails before the fix = no CI exists; passes after); Test E loop with per-failure logs.
Test E root cause approach: run under `stress` load at 2..5 concurrent proposers, capture which of a_ok/b_ok/both_actions_present fails and retry count; inspect `MAX_PROPOSE_ATTEMPTS`, vote-slot TTL, and refetch timing. Hypothesis only (UNVERIFIED): retry budget or TTL is too tight under CPU starvation.
Risks: pinned 1.75 vs deny/audit needing stable; 1 vCPU CI runners may amplify flakiness (that is useful signal, not a reason to retry-mask).
Needs human: GitHub remote + runners for the "20 consecutive green runs" criterion; `git init`/branch policy since the archive has no history.

---
# Session 02: required reading complete; pre-change DB-required experiment (no code changed yet)

## Reading status
Now read in full: README, SECURITY_REVIEW, THREAT_MODEL, CRYPTO_DECISIONS, PRODUCTION_READINESS, deny.toml, ci/check_pin_policy.sh, roadmap A9 and the Test E note.
Still absent from the archive: AGENTS.md, BLSTRS_MIGRATION.md (asked owner in session 01).

## CORRECTION to session 01 / F-07
The zip contains NO dotfiles at all (no .git, .github, .gitignore: `unzip -l` EXECUTED). So `.github/workflows/{ci,security}.yml`, which README, roadmap A9, THREAT_MODEL T-12, PRODUCTION_READINESS 1.5, deny.toml and CONTRIBUTING all say exist, were most likely STRIPPED FROM THE ARCHIVE, not never written. I cannot tell which. Consequence: whatever I write must be diffed against upstream's real files if they exist. Statements "CI does not exist" are withdrawn; the correct statement is "no CI in the archive I was given".

## Pre-change experiment (EXECUTED, unmodified code, `cargo test -p quorum_service --test db_pool_concurrency`)
(An earlier S3/S4 attempt was INVALID: Postgres had died when the sandbox restarted. Caught by checking `pg_lsclusters`; rerun after restart.)
- S1 REQUIRED=1, DB unreachable: exit 101, `DB_REQUIRED_BUT_UNREACHABLE` (guard works).
- S2 REQUIRED unset, DB unreachable: exit 0, tests `skipped` (by design).
- S3 CONTRIBUTING.md recipe (`TEST_DATABASE_URL`) with a HEALTHY DB: exit 0 "ok", both tests `skipped`. CONFIRMED ISSUE: no code reads TEST_DATABASE_URL; the test falls back to postgres:postgres@localhost.
- S3b same + REQUIRED=1: exit 101 (guard catches it).
- S4 CIPHERSETTLE_TEST_DB_URL + REQUIRED=1, DB up: exit 0, markers `ran`.

## Confirmed issues to fix (scope of this change, nothing more)
1. Documented DB setup silently skips (S3). Fix docs + add `ci/assert_db_tests_ran.sh` which fails unless every outcome marker is `ran`, independent of env vars.
2. No CI in the archive: add ci.yml (build/test/lint/adversarial/supply-chain) + a negative job proving a broken DB FAILS.
3. Test E flake not reproduced idle (10/10): add a reproducible stress harness and run it; no Rust changes unless a root cause is demonstrated.
Out of scope now: hard-coded DSNs in quorum_adversarial (F-06), Test H, any crypto/protocol change.

## Session 02: changes made for Gap 6 (STATUS: NOT CLOSED)
Files added: `.github/workflows/ci.yml`, `.github/workflows/flake-hunt.yml`, `ci/setup_test_db.sh`, `ci/assert_db_tests_ran.sh`, `ci/check_ci_fails_on_broken_db.sh`, `ci/audit_ignores.sh`, `ci/stress_test_e.sh`. Edited: `CONTRIBUTING.md` (DB setup block only). No Rust source changed.

### Evidence per change (EXECUTED locally unless stated)
| Change | Evidence |
|---|---|
| CONTRIBUTING wrong env var | Before: S3 green+skipped. After: new recipe => markers `ran`; old recipe now caught by `assert_db_tests_ran.sh` (exit 1). |
| `assert_db_tests_ran.sh` | Exit 1 on old-recipe skip; exit 0 when both markers `ran`; exit 1 when no markers. |
| `check_ci_fails_on_broken_db.sh` (negative test) | 5/5 expectations hold: REQUIRED=1 => rc 101 + DB_REQUIRED_BUT_UNREACHABLE; assert fails; REQUIRED unset => rc 0 (the hazard) but assert fails. MUTATION: with assert stubbed to `exit 0`, the negative test reports `NEGATIVE TEST FAILED`; script restored, sha256 verified identical. |
| `setup_test_db.sh` | `exists:` path and `created:` path (dropped ciphersettle_adversarial, recreated); idempotent on rerun. |
| `audit_ignores.sh` | Emits exactly the 7 IDs in deny.toml; ignores IDs mentioned only in comments. |
| ci.yml lint/test steps | pin policy OK; fmt clean; clippy -D warnings clean; build ok; `cargo test --workspace --locked` 126 passed 0 failed; DB markers `ran`. |
| ci.yml adversarial step | Same command: exit 0, `39/39 checks passed as expected.`, ci.yml's grep matches. Group H excluded (no iptables). |
| YAML | Both workflows parse (PyYAML); jobs/triggers listed. This is syntax only. |
| Action pins | SHAs from `git ls-remote` tags (checkout v4.3.1, cache v4.3.0, upload-artifact v4.6.2). NOT independently verified against GitHub UI. |

### Test E stress campaign (no retries; harness `ci/stress_test_e.sh`)
| Campaign | Load | Result |
|---|---|---|
| idle (session 01, ad hoc) | none | 10/10 pass, ~3.3 s/run |
| loaded | stress-ng 4 cpu + 1 vm | 100/100 pass, mean 4.0 s |
| heavy | stress-ng 16 cpu + 2 vm, loadavg ~11 on 1 vCPU | 100/100 pass, mean 6.1 s, max 6.6 s |
(An earlier loaded launch was killed by the sandbox after 4 runs and discarded; not a failure.)
Interpretation: the reported 2/4 and 3/5 failures are NOT reproduced in 210 runs. Rule of three: the failure rate here is likely < ~3% at 95% confidence, vs the earlier 40-50%. This does NOT show the flake is fixed or explained: root cause unknown. The harness cannot vary proposer count (Test E hardcodes 2); the prompt asks for >2 proposers, which needs a test change not made here. Hypothesis still open (UNVERIFIED): R-2 vote-TTL (5 s) vs 3 s client timeout x 8 attempts under a slower or higher-latency environment than this sandbox.

### Gap 6 "closed when" checklist
| Condition | Status |
|---|---|
| CI workflows exist, run build/test w/ Postgres, DB_REQUIRED=1, clippy -D warnings, fmt, audit, deny | WRITTEN; steps executed locally; workflows NEVER RUN on GitHub; audit/deny NOT executed anywhere (toolchain/network). UNVERIFIED |
| Deliberately broken DB makes CI fail, not skip | Demonstrated locally (negative test + mutation). The CI job is unrun. |
| Test E run 100+ times under load, root cause fixed | 210 runs, 0 failures; NO root cause; >2 proposers untested. OPEN |
| CI green on 20 consecutive runs | NOT DONE: needs a GitHub remote. OPEN |
Verdict: Gap 6 is NOT closed.

---
# Session 03: Test E root-cause investigation
Change (test-only, additive: 106 lines added, 0 changed): `quorum_adversarial` gets opt-in group `X` (`--only X --proposers N`). Never runs in the default run or CI (verified: `--only E` prints no Test X; default run still `39/39`). `ci/stress_test_e.sh` takes `PROPOSERS=N`; `flake-hunt.yml` gets a `proposers` input (YAML parses). Test E's own assertions are untouched.
Regression check after the change (EXECUTED): fmt clean, clippy -D warnings clean, workspace build ok, `cargo test` 126 passed/0 failed, DB markers `ran`, adversarial default `39/39`, ci.yml grep matches. (Postgres had died again between turns; the first rerun showed 19/23 from skipped DB groups and was redone after restart.)
Hypothesis tested: "with >=3 proposers a vote split deadlocks all proposers". Initial prediction of FREQUENT failure was WRONG (N=3: 0/10 idle). Rare but real: 6 failures in 140 probe runs, all with the identical `ok=0 entries_in_log=0` signature; mechanism confirmed in node logs. Findings F-13, F-14, F-15; design note awaiting human decision.
Gap 6 status: STILL NOT CLOSED (unchanged blockers: no GitHub runs, audit/deny never executed, Test E 2-proposer root cause not reproduced).

---
# Session 04: supply-chain tools executed; Gap 7 feasibility (no repo source changed)
Unblocked via apt: Rust 1.91.1 (alongside 1.75; separate CARGO_HOME/target dirs so the pinned baseline is untouched), `cargo-audit 0.22.2`, `cargo-deny 0.20.2` (built with `cargo install --locked`).
EXECUTED results on the unmodified tree:
- `cargo audit $(ci/audit_ignores.sh)`: exit 0 (1289 advisories, 187 crates).
- `cargo audit` with NO ignores: exit 1, exactly the 7 documented advisories (F-17).
- `cargo deny check`: exit 0: advisories ok, bans ok, licenses ok, sources ok (non-fatal warnings: 5 duplicate-crate versions, 4 unused license allowances).
- Rust 1.91.1, unmodified Cargo.lock: `cargo build/test --workspace --locked` ok, 126 passed/0 failed, DB markers `ran`, 0 compiler warnings; adversarial `39/39`.
- Clippy 1.91.1: 15 lints, `-D warnings` fails (F-16). The Gap List's merkle.rs:347 lint is not among them (F-04 revised).
Changed: `ci.yml` supply-chain job now pins `cargo-audit 0.22.2` / `cargo-deny 0.20.2` (the versions run above).
Gap 6 checklist update: audit/deny steps are now EXECUTED LOCALLY (still never run on GitHub). Remaining blockers unchanged: GitHub runs (20 green), Test E 2-proposer root cause. F-13/F-14 remain OPEN pending owner decisions (not answered).
Gap 7 readiness: the toolchain bump looks low-risk (no lockfile churn needed to build/test on 1.91). Remaining Gap 7 work: change rust-toolchain.toml, fix the 15 lints atomically with it, decide on unpinning zeroize/postgres-protocol/base64ct (which is what removes the 4 postgres/time ignores), then rerun everything.

---
# Session 05: Gap 7 (toolchain + dependency hygiene)
Recovered state: the session-04 `gap6_changes_2.tar.gz` overlay on the original zip (the Gap 7 edits made at the end of session 04 were NOT in any archive, so they were redone). `git init` baseline taken first.
Toolchain: the sandbox's rustup stable is **1.97.0** (not 1.91), so `rust-toolchain.toml` now pins `1.97`, the version actually executed. Rust 1.91 is therefore not what is verified.

## Changes (EXECUTED on rustc/clippy 1.97.0)
1. Toolchain 1.75.0 -> 1.97; the 15 session-04 clippy lints fixed (map_or -> is_none_or/is_some_and, is_multiple_of, slice::from_ref, doc-list continuation, 6 added `wait()` after early-return `kill()` in quorum_adversarial). Two of those lints were in my own session-03 group-X code. On 1.97 clippy reports 0 lints with those fixes.
2. Pins removed: `zeroize`, `zeroize_derive`, `postgres-protocol`, `base64ct` (none were used directly by source; they were pure transitive pins), and `ed25519-dalek =2.1.1` relaxed to `2.1.1` (caret). Lock changes: zeroize 1.9.0, postgres-protocol 0.6.12, tokio-postgres 0.7.18, postgres-types 0.2.14, base64ct 1.8.3, time 0.3.55 (+ their transitive bumps: md-5 0.11, phf 0.13, whoami 2, deranged, num-conv).
3. `deny.toml`: removed the 4 ignores that the above fixes (0178, 0179, 0180, RUSTSEC-2026-0009). 3 remain (rustls-webpki 0098/0099/0104; fix needs rustls 0.21 -> 0.23, NOT done, touches the custom TLS verifiers, so it is its own change).
4. Docs reconciled: README, CONTRIBUTING, ARCHITECTURE, PRODUCTION_READINESS 1.5/1.9, SECURITY_REVIEW, quorum_poc README, stale comments in Cargo.toml / check_pin_policy.sh.

## Evidence (after all changes)
fmt clean; `ci/check_pin_policy.sh` OK; `clippy --workspace --locked --all-targets -D warnings` exit 0; build exit 0, 0 warnings; `cargo test --workspace --locked` 126 passed / 0 failed with CIPHERSETTLE_TEST_DB_REQUIRED=1, DB markers `ran`; adversarial (A-G,I-N) `39/39 checks passed as expected.`
`cargo audit` (0.22.2) with no ignores: exit 1, exactly the 3 rustls-webpki IDs. With `ci/audit_ignores.sh`: exit 0. `cargo deny check` (0.20.2): advisories/bans/licenses/sources ok (duplicate-crate warnings only).
NOT verified: tests on 1.91 or on any version other than 1.97; the workflows on GitHub; Test H (iptables). The lock bumps touched crypto-adjacent crates (zeroize 1.5.7->1.9.0, base64ct 1.6.0->1.8.3; ed25519-dalek stays 2.1.1 in the lock) so the NEEDS_HUMAN_CRYPTO_REVIEW list should be re-checked against the new lock; the test suites pass, which is not a review.

## Gap 7 "closed when" check
`cargo audit`, `cargo deny`, `clippy -D warnings` pass on stable "with no unexplained suppressions": met with 3 EXPLAINED suppressions (rustls-webpki). Strictly: Gap 7 is closed except the rustls migration, which is needed to reach zero ignores. Not claimed as fully closed.
Gap 6 unchanged: still needs GitHub runs (20 green) and a 2-proposer Test E root cause. F-13 / F-14 still await owner decisions.

---
# Session 06: F-13 / F-14 fix (tests first)
Owner decisions: see DESIGN_NOTE (delegated: outbox for mutations, derive audit-first, no retry/TTL widening, serialized in-process proposer).

## Failing first (EXECUTED, unfixed code): `--only Z` => 1/6 pass
Z2a HTTP 500 after the invoice committed; Z2b invoice row exists with no outbox/audit record; Z2c nothing ever audited; Z1b/Z3 failed (no outbox table). Log: evidence/test_z_before_fix_session06.log. Z1a (8 concurrent registrations) passed pre-fix: the natural race is rare, so Z2 forces the failure deterministically.

## Changes
- quorum_client: `ProposeError {Contention, QuorumUnavailable, NotConfigured}` + `propose_audit_entry`; `propose_and_cosign_and_replicate` kept as a string wrapper. Same protocol, same 8-attempt budget, TTL untouched.
- quorum_service: `audit_outbox` (atomic with every state change: single-statement CTEs, or inside the register tx), `audit_failures`, in-process `audit_lock` (never held with a DB connection/tx), inline delivery + background drainer with backoff, 202 `audit: pending` instead of 500-after-commit, derive stays audit-first (503 + audit_failures row on failure).
- quorum_adversarial: group Y3 (typed error), group Z (service-level, 6 checks, part of the default/CI run). ci.yml: group list + `45/45`.

## Evidence after fix (EXECUTED, rustc 1.97)
fmt/pin policy OK; clippy -D warnings exit 0; build 0 warnings; `cargo test --workspace` 126 passed / 0 failed, DB markers `ran`; adversarial A-G,I-N + Z: `45/45`; `--only Y,Z`: 9/9; Z x30 idle: 30/30; Z x15 under load (8 busy loops on 2 vCPU, loadavg up to 9): 15/15. Logs in evidence/.

## Honest limits
- Not tested end-to-end: the derive-key 503 / `audit_failures` path (code READ only); the stale-claim re-delivery after a crash; outbox behaviour with multiple service replicas (unsupported).
- Delivery is at-least-once: a crash between the audit append and `done` can duplicate one entry.
- The underlying protocol hazard is NOT removed: Tests E/X (raw concurrent proposers) and R-2 are unchanged; the fix avoids it inside one service process. The 2-proposer Test E root cause (F-15) is still unexplained.
- Behaviour change for API clients: state-changing endpoints may now answer 202 (change committed, audit queued) where they previously answered 500. Clients must NOT retry on 202.
- Existing `expect()` in fetch_majority_tip and similar remain (Gap 8).

---
# Session 07/08: Gap 1 (share persistence) completed and verified
Failing first (EXECUTED): `--only P` => 1/8 on the unmodified node (`evidence/test_p_before_fix_session07.log`).
Fix: `quorum_node::share_store` + boot modes + `SharePersistenceConfig`/`allow_ephemeral_share` in `quorum_core::config`; `SecretKeyShare::export_for_sealed_storage`/`restore_verified`, `PublicKeySet::fingerprint_sha256`; deps `ring`, `zeroize` on quorum_node (lockfile: 2 edges, 0 new packages).
Session 08 corrections: clippy had failed on three lints in my own test code (clone on Copy; two needless range loops), fixed with no behaviour change. ci.yml now runs group P and expects 54/54 (was inconsistent).
Evidence (EXECUTED, rustc 1.91.1): fmt OK, pin policy OK, clippy -D warnings exit 0, build 0 warnings, `cargo test --workspace` 143 passed / 0 failed, DB markers `ran`, adversarial A-G,I-N,P,Z `54/54`; group P x5: 5/5 (9/9 each). Logs in evidence/.
Not verified: rustc 1.97 (pinned) not available here; cargo audit/deny not rerun for the new edges (ring/zeroize already in tree); crash-injection; KMS/HSM; operator rehearsal.
Gap 1 status: implemented for pilot tier with executed evidence; real-data tier NOT met (needs KMS/HSM KekProvider, crypto review). Human review of the design note decisions D1-D10 is still required.

---
# Session 10: environment reset; tree rebuilt from uploads (NOTHING compiled or run)
Sandbox had no Rust/Postgres and blocked the Ubuntu mirrors (403 host_not_allowed), so no build, test or lint ran this session.
Rebuilt base -> gap6_2 -> gap7 -> f13_f14 -> gap1 overlays and inspected statically (READ). The gap1 overlay carries Gap 1 wiring, group P (P1-P9, P8 now a KEK-needle scan) and `ci.yml` expecting 54/54, plus evidence logs from an earlier session (rustc 1.91.1: clippy 0, 143 unit tests, 54/54 adversarial, P 9/9 x5). I did NOT re-run them. This supersedes my earlier report that Gap 1's clippy/regression were unfinished: those logs show them finished, but they are unverified by me.
Docs corrected: design note and F-18 no longer call P8 a weak log-marker check.
OPEN: (1) `rust-toolchain.toml` says 1.97 but all Gap 1 evidence is on 1.91.1; pick one and rerun. (2) Gap 13 (F-01) is NOT in this tree: node still uses `let _ = std::fs::write` for the audit log, pubkey and ready files. (3) A Gap 13 attempt from another session had Q1 failing on both old and new node binaries (appended=6, every node held 5). Hypothesis, UNVERIFIED: replication is fire-and-forget (quorum_client lib.rs ~932-935), and the test kills nodes immediately after the last append, so the 6th entry was never processed; the test should poll until all nodes report 6 before killing.

---
# Session 11: uploads integrated and verified on 1.97; Gap 13 (F-01) done
Integration: the uploaded `gap1_integrated_uncompiled` tree was diffed against my own HEAD (F-13/F-14): identical except Gap 1 files, so it was adopted as a commit. Verified (EXECUTED, rustc 1.97.0, the pinned toolchain; closes session-10 OPEN item 1): fmt OK, pin policy OK, clippy -D warnings 0, build 0 warnings, 143 tests passed, DB markers `ran`, adversarial `54/54`; group P x8 stability run.
Gap 13: failing first = `audit_store` unit tests 7/9 failing on a faithful port of the old behaviour; process-level `--only Q` on the OLD node 2/6 (Q3 caught a 0-byte audit log left by SIGKILL; Q4-Q6 node started with an empty log). Fix: `quorum_node::audit_store` + wiring (persist-then-swap, fatal on damaged log, atomic pubkey/ready). Results: see regression summary below. New findings F-19 (ack before durable), F-20.
Results (EXECUTED, rustc 1.97.0): fmt OK; pin policy OK; clippy -D warnings 0; build 0 warnings; `cargo test --workspace` 152 passed / 0 failed (143 + 9 audit_store), DB markers `ran`; adversarial A-G,I-N,P,Q,Z `60/60`; Q x12: 12/12; P x8 (on 1.97): 8/8. ci.yml expects 60/60 and runs group Q. NOT re-run this session: cargo audit/deny (no dependency change), Test H, crash tests other than SIGKILL.
Gap 13 status: implemented for SIGKILL; not rehearsed for power loss; F-19 open.

---
# Session 12: F-19 (acknowledged => durable) fixed
Failing first: `--only R` on the previous build: 0 durable holders per acknowledged round. Fix: `Message::AuditEntryCommitted`, node ack after durable persist (also for an already-present identical entry), client waits for t+1 acks, new `ProposeError::NotDurable`. After (EXECUTED, rustc 1.97): fmt/pin OK; clippy 0; build 0 warnings; 152 tests; adversarial `61/61` (adds R); R x3 runs all rounds 5/5 holders. ci.yml expects 61/61.

## Session 12 (continuation) — Gap 3 step 1: per-node derive-auth keys
- EXECUTED: test S1 written first and failed before the fix (`evidence/test_s_before_fix_session12.log`): a key taken from one node authorized derivation on other nodes.
- Fix: `quorum_core::derive_node_auth_key(master, node_id)` (HKDF-SHA256, RFC 5869 test vector unit-tested). Each node is configured with its own derived key; the client builds one request per node. Nodes never hold the master.
- EXECUTED (rustc 1.97): fmt, pin policy, clippy -D warnings, build (0 warnings), 154 tests (DB markers `ran`), adversarial 62/62, orchestrator end-to-end rc=0. Summary: `evidence/regression_summary_session12_step1.txt`.
- Operator note: provision the master to the service only; run `quorum_node derive-auth-key <master_b64> <node_id>` to obtain each node's key. Master must be >= 32 bytes (service refuses to start otherwise). LIMITATION: no online rotation or key versioning.
- LIMITATION (not closed): a compromised SERVICE holds the master and can still authorize any derivation. That is Gap 3 step 2 (signed per-request authorization). Design note written; NEEDS_HUMAN_CRYPTO_REVIEW; not implemented.
- Next per work order: Gap 8 (panic-free lints + fuzz targets), tests first.

# Session 13/14: Gap 8 (panic-free lints + parser fuzzing)
- State recovery: the sandbox was reset twice and the uncommitted Gap 8 work of session 13 was lost the first time. Session 14 rebuilt the repo (baseline zip + 7 delta archives in order, then the session-13 edits replayed from the transcript) and COMMITTED + bundled it (`ciphersettle_repo.bundle`) before doing anything else. Sessions 9-10 are not covered by any archive.
- Tests first: Z4 added and shown failing on unfixed code (`evidence/test_z4_before_fix_session14.log`, status 0), then the fixes. Z5 (112 hostile bodies x 7 POST routes) and fuzz group W (7 bodies) added; BOTH harnesses mutation-checked (see SECURITY_FINDINGS Gap 8). Group W initially passed a seeded bug -> structure-aware JSON mutation added.
- Evidence: `evidence/gap8_regression_summary_session14*.txt`, `gap8_adversarial_*`, `gap8_w_100k_session14.log`.
- Toolchain caveat: rustc 1.91.1 (distro), not the pinned 1.97; rerun CI on the pin.
- NOT closed: coverage-guided fuzz hours (needs nightly), node state-machine fuzzing, indexing/arithmetic panic lints. Next: run `fuzz.yml` in CI; then Gap 2 (needs human cryptographer), Gap 4/5 (infrastructure), per work order.

# Session 15: verification preparation for Gaps 6, 8, 13 (no gap closed)
- The sandbox was reset again; the previous session's uncommitted prep work was lost. Rebuilt from the last bundle (ed54d0c) and the surviving VERIFICATION_RUNBOOK.md/corpus_tests.rs, committed immediately.
- Added: `ci/assert_toolchain_pinned.sh` (wired into every pinned CI install), `ci/assert_fuzz_ran.sh` + `check_fuzz_assert.sh` (gate self-tested on synthetic logs), `ci/check_fuzz_setup.sh`, `ci/run_local_regression.sh`; hardened `fuzz.yml` (pipefail, 3600 s default, gate job, crash artifacts, corpus cache); `ci.yml` pipefail, DB-required check, no-[FAIL] check; 60-file committed fuzz corpus + replay tests; 3 unit regressions; `quorum_node audit-powerloss-{workload,verify}` for the Gap 13 power-loss rehearsal.
- EXECUTED on rustc 1.91.1 (NOT the pin 1.97): fmt, clippy -D warnings, build, 168 unit tests (DB markers ran), adversarial 71/71, broken-DB negative test, fuzz setup/gate checks. The ONLY failing step is `toolchain_pinned`, which fails by design on 1.91.
- NOT EXECUTED: anything on GitHub, rustc 1.97, nightly/libFuzzer, real power-cut rehearsal, cargo audit/deny this session. Mutation checks and the orchestrator e2e from the lost session were not repeated.
- Gap statuses unchanged: 8 partial, 6 partial, 13 SIGKILL-only.

# Session 16: Gap 11 first slice (health endpoints). No gap closed.
- Z6 written first and FAILED (404) with the routes removed, then PASSED (`evidence/test_z6_*_session16.log`). Expected adversarial count is now 72/72 (ci.yml, run_local_regression.sh, runbook updated).
- Gap 11 remains OPEN: no tracing, metrics, alerts, runbooks or drill. `/readyz` does not check node quorum liveness; the 503 path is untested.
- Gaps still needing people/infrastructure: 2, 3 step 2, 4/5 (crypto review), 9, 10, 12, 15, 16. Gap 17 not reconciled (grep found no obvious stale 'not integrated' wording; needs a manual read).

# Session 17: independent verification of the uploaded bundle (a1f6f57) on the PINNED toolchain
- Adopted `ciphersettle_repo.bundle` (HEAD a1f6f57: Gap 8, fuzz prep, Gap 11 health slice) as the baseline. My own uncommitted session-13 Gap 8 work duplicated commit 021862b and was discarded (kept as a patch outside the repo).
- EXECUTED on rustc 1.97.0 (the pin; the earlier sessions 14-16 ran 1.91.1): ci/run_local_regression.sh ALL STEPS PASSED: toolchain pinned, pin policy, fuzz setup/gate, fmt, clippy -D warnings, fuzz crate typecheck, build, 168 unit tests (DB markers ran), broken-DB negative test, adversarial 72/72 (incl. W, Z4-Z6). Plus cargo audit, cargo deny, orchestrator e2e (all pass). Evidence: `evidence/verification_session17_*`.
- This closes caveat (e) of the Gap 8 findings (1.91.1-only results) and the "cargo audit/deny / orchestrator e2e not run" caveats from sessions 14-16. Still OPEN: GitHub Actions runs (20 green), nightly libFuzzer hours, power-loss rehearsal, Test E flake campaign.

# Session 17 (continued): Gap 10 slice 1 — migrations, backup/restore rehearsal, image policy
- Tests first: `tests/migrations.rs` (8 DB tests) written before the module existed; first run = compile failure (`evidence/test_migrations_before_fix_session17.log`); the Dockerfile policy script was shown rejecting a bad fixture and failing with no Dockerfile (`evidence/test_dockerfile_policy_before_fix_session17.log`).
- Implemented: `src/quorum_service/src/migrations.rs` (ordered, SHA-256-checksummed, one transaction under an advisory lock; refuses newer-than-binary and edited-after-applied; legacy DBs adopted as v1; failed migration rolls back fully), `quorum_service migrate <db_url>`, `ci/backup_restore_rehearsal.sh` (+ evidence), `Dockerfile`, `.dockerignore`, `ci/check_dockerfile.sh`, `deploy/README.md`, CI steps (policy, rehearsal, `container-image` job).
- Mutation checks (EXECUTED): advisory lock removed -> m6 fails 3/3; checksum check disabled -> m5 fails. Real legacy adoption observed: the pre-existing adversarial DB (legacy schema) now has `schema_migrations` v1 after the suite ran.
- Two things my own change tripped, fixed WITHOUT weakening the gates: the repo's "no `|| true`" CI-script gate (cleanup now warns instead of swallowing), and a clippy `needless_borrows` in the new test.
- EXECUTED on rustc 1.97.0: ALL regression steps pass (176 unit tests, adversarial 72/72): `evidence/regression_summary_session17_gap10_slice1.txt`.
- NOT verified: Docker images were never built or scanned (no daemon/registry reachable); CI `container-image` job never run; no 5-node deployment manifest; node-tier backup/restore never rehearsed on a second host; no PITR. Gap 10 stays OPEN.

# Session 18: Gap 9 slice 1 — secrets from files
- Tests first: 7 unit tests in `quorum_core/src/secret_files.rs` written before the function existed (`evidence/test_secret_files_before_fix_session18.log`: compile failure), then implemented. Mutation-checked: permission check off -> 2 fail; one-source rule off -> 1 fails.
- Wired into node, service and notary (`quorum_core::secret_files::load_config`; notary gained a `quorum_core` dependency, Cargo.lock +1 edge; `fuzz/Cargo.lock` +1 edge). New adversarial group T (3 checks) and group Z now boots the real service with master + API key from 0600 files. Suite count is now 75/75 (ci.yml, run_local_regression.sh, runbook updated).
- EXECUTED on rustc 1.97.0: unit tests 183 pass / 0 fail, adversarial 75/75, all other regression steps pass (`evidence/regression_summary_session18_gap9_slice1.txt`).
- NOT done (Gap 9 stays OPEN): certificate rotation, online secret rotation, secret-manager client, orchestrator still writes inline-secret configs, secrets remain in process memory.
- Operator docs: `deploy/README.md` "Secrets from files". Note for operators: Kubernetes secret mounts default to 0644 and will be REFUSED until `defaultMode: 0400`.
