# Contributing to CipherSettle

Thank you for your interest in contributing to CipherSettle. This document
provides guidelines and instructions for contributing to this cryptographic
protocol project.

**Current status:** research prototype, not production software. Independent
cryptographic peer review has not yet been performed. Please read `README.md`
§ "What's real vs. still open" and `SECURITY_REVIEW.md` before proposing
changes — they describe what this project does not yet claim to do.

## Project phases
CipherSettle is structured across multiple phases (Phases 0–4, plus Phase 6a's
commitment scheme). Please ensure contributions align with the current phase's
objectives and maintain the integrity of established phases.

## Prerequisites
To build and test CipherSettle, you will need the following:
- **Rustc/Cargo**: 1.97, as pinned by `rust-toolchain.toml`
- **PostgreSQL**: 16 (required for Phase 3+ functionality and for the
  `quorum_service` integration tests)
- **Linux with `iptables`**: required for the Phase 4 network-partition test
  (group H), which also needs root or `CAP_NET_ADMIN`

## Getting started & building
1. Clone the repository and navigate to the project root.
2. Build the workspace using the pinned toolchain:
   ```bash
   cargo build --workspace --locked
   ```

   `rust-toolchain.toml` pins the exact version so that CI cannot pass against
   a newer compiler than the one a real clone builds with. If you are on a
   newer toolchain, the workspace still pins — see `rust-toolchain.toml` for
   why.

3. For the tests that need a database, start Postgres and create the test
   databases with the shared script (idempotent; test-only credentials, never
   reuse them anywhere real):
   ```bash
   sudo apt-get install postgresql
   sudo pg_ctlcluster 16 main start
   sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'ciphersettle_dev';"
   bash ci/setup_test_db.sh        # creates ciphersettle_test and ciphersettle_adversarial
   export CIPHERSETTLE_TEST_DB_URL="postgres://postgres:ciphersettle_dev@127.0.0.1:5432/ciphersettle_test"
   export CIPHERSETTLE_TEST_DB_REQUIRED=1   # unreachable DB => test FAILS instead of skipping
   ```

   The variable the code reads is `CIPHERSETTLE_TEST_DB_URL`. (Earlier versions
   of this file said `TEST_DATABASE_URL`; nothing reads that, and following it
   produced a green run in which the database tests were silently skipped.)
   Without `CIPHERSETTLE_TEST_DB_REQUIRED=1`, `cargo test` reports a skipped DB
   test as `ok`. To check that they really ran, after `cargo test` run:
   ```bash
   bash ci/assert_db_tests_ran.sh   # fails unless every DB test marker says `ran`
   ```

## Testing requirements
All pull requests must pass the project's validation suite. Before submitting
a PR, ensure the following pass without errors:
```bash
cargo build --workspace --locked --all-targets
cargo test --workspace --locked
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo fmt --all -- --check
bash ci/check_pin_policy.sh
```

`bash ci/run_local_regression.sh <outdir>` runs all of the above plus the
docs-claims check and its self-test, the Dockerfile policy check, the fuzz-crate
type-check, the DB-tests-really-ran and broken-DB negative checks and the
default adversarial suite (82 checks, which must all pass). It does NOT run
GitHub Actions, `cargo audit`/`cargo deny`, fuzzing, the orchestrator end to
end, a power-loss rehearsal or the Test E flake campaign (its last lines say
so). Run `bash ci/check_docs_claims.sh` after touching any `.md` file: it
fails on stale paths, Rust versions, check counts, undocumented routes and a
wrong crate-dependency map. `.github/workflows/ci.yml` runs the same steps
and more; it has never yet run on GitHub. `cargo deny check`
enforces the policy in `deny.toml` (advisories, licenses, dependency sources);
`cargo-audit` and `cargo-deny` are installed with `cargo install --locked`
(CI pins `cargo-audit 0.22.2`, `cargo-deny 0.20.2`) and run in a separate job
from the workspace build.

## Code style
Production crate roots deny `clippy::unwrap_used`, `expect_used`, `panic`,
`unreachable`, `todo` and `unimplemented` outside tests (startup failures go
through `quorum_core::config::{fatal, or_fatal}`); do not add `#[allow]` to
get around them. Bug fixes and security changes are made test-first: add the
failing test, record the red output under `agent_memory/evidence/`, then fix.
Never weaken a check, add a retry to make a test pass, or mark a test ignored.
Please adhere to the standard Rust formatting guidelines. Ensure `cargo fmt`
has been run on all modified files. Documentation comments and clear rationale
for complex logic are required, especially for consensus and cryptographic
operations.

If you add an exact-version dependency pin (`=x.y.z`), add an explanatory
comment above it. `ci/check_pin_policy.sh` fails the build otherwise — see
finding A3 in `CipherSettle_Audit_Remediation_Roadmap.md` for why these pins
exist and when they can be removed.

## Pull requests and cryptographic review
When submitting a pull request, provide a clear description of the changes, the rationale behind them, and any related issues.

**CRITICAL: Cryptographic code review requirements.**
Any change touching the following core cryptographic and consensus modules
requires a dedicated cryptographic peer review by a qualified reviewer before
merging:
- `quorum_core` (DKG, threshold BLS, derive authorization)
- `quorum_vetseal` (ElGamal sealing, NIZK proofs)
- `quorum_audit` (hash-chained log, co-signatures, vote slots)
- `quorum_node` (the `DeriveRequest` handler, DKG message handling)
- `ciphersettle_core` (access control, invoice commitment, Merkle log)

Changes affecting authorization semantics, threshold configurations, key
lifecycles, or audit-log consensus fall under this requirement. Merely passing
CI does not satisfy it — see `SECURITY_REVIEW.md` §6 for the checklist a
qualified reviewer should work through.

## Security reporting

**Do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.** See [`SECURITY.md`](SECURITY.md) for the private
reporting channel and for the project's known open security items.