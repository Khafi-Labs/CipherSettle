# Verification runbook (Gaps 6, 8, 13)

Audience: an operator who has the repository, a GitHub repo with Actions enabled
and, for section 6, a disposable Linux VM or machine. Every command below is
meant to be copy-pasted. Nothing in here has been executed on GitHub; the
sections say exactly which parts were executed locally and which were not.

## 0. Ground rules (read first)

1. **A successful build is not sufficient to close a gap.** A gap closes only when
   its own "closed when" condition (quoted in sections 3, 5 and 6) is met, with
   the evidence attached. Green CI on its own closes nothing if the condition
   asks for more (20 consecutive runs, a one-hour fuzz run per target, ...).
2. **Only the pinned compiler counts.** `rust-toolchain.toml` pins `1.97`. A run
   on any other rustc (earlier authoring sessions only had 1.91.1; session 17 onward ran 1.97) is not evidence
   about the pinned build. `ci/assert_toolchain_pinned.sh` makes the mismatch a
   hard failure, and every CI job runs it.
3. **Status vocabulary** (use exactly these words in notes and PRs):
   `EXECUTED + PASSED`, `EXECUTED + FAILED`, `NOT EXECUTED`, `BLOCKED BY ENVIRONMENT`.
   An unexecuted check is never "passing".
4. Never mark a gap CLOSED in `agent_memory/SECURITY_FINDINGS.md` or
   `docs/PRODUCTION_READINESS.md` until section 8's checklist for that gap is
   fully ticked and the evidence files are committed.
5. Evidence that was produced on a different compiler or by an older commit does
   not carry over. Re-run after every change to the code or to the pin.

## 1. Get the exact tree

```bash
git clone ciphersettle_repo.bundle ciphersettle && cd ciphersettle   # or your own remote
git log --oneline | head -3
```

Caveat inherited from earlier sessions: the tree was reconstructed from a
baseline zip plus delta archives; sessions 9-10 are covered by no archive.
Compare against your real repository before trusting it. If the adversarial
suite reports a count other than `82/82`, diff against your repository first.

## 2. Full CI on Rust 1.97

### 2a. On GitHub (the authoritative run)

```bash
git push origin HEAD:main            # push triggers .github/workflows/ci.yml
gh run watch --exit-status           # or open the Actions tab
```

Jobs (all must be green): `lint` (pin assertion, dependency-pin policy, fmt,
clippy `-D warnings`, fuzz-setup consistency, fuzz-gate self-test, fuzz crate
type-check), `test` (DB required, unit tests incl. corpus replay, DB-ran
assertion), `adversarial` (suite must print exactly `82/82 checks passed as
expected.`, no `[FAIL]` line), `db-guard-negative` (a broken DB must FAIL CI),
`supply-chain` (`cargo audit`, `cargo deny check`).

Most likely first-run failures, because only 1.91 has ever been used:
newer clippy lints, `cargo fmt` differences, or an advisory published since the
last local run. Fix, push, re-run; do not weaken a check.

### 2b. Local equivalent (needs rustup, Postgres 16)

```bash
rustup toolchain install "$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)" --component clippy --component rustfmt
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'ciphersettle_dev'"     # test-only credential
bash ci/setup_test_db.sh
bash ci/run_local_regression.sh verification_out        # exit 0 only if ALL steps pass
cat verification_out/summary.txt
```

It runs the pin assertion, dependency-pin policy, fuzz setup checks, fmt,
clippy, fuzz crate type-check, build, all unit tests (DB required), the
DB-really-ran assertion, the broken-DB negative test and the adversarial suite
(must be exactly 82/82). It does not run: GitHub Actions, cargo audit/deny,
fuzzing, the orchestrator, power-loss or the Test E campaign. Extra local
checks:

```bash
cargo install cargo-audit --locked --version 0.22.2 && cargo install cargo-deny --locked --version 0.20.2
cargo audit $(bash ci/audit_ignores.sh) && cargo deny check
su postgres -c "psql -c 'CREATE DATABASE ciphersettle_phase3'"; cargo run --locked -p quorum_orchestrator   # must exit 0
```

## 3. All 7 fuzz targets for 3600 seconds each (Gap 8)

### 3a. On GitHub

```bash
gh workflow run fuzz.yml -f seconds=3600
gh run list --workflow fuzz.yml --limit 1
gh run watch --exit-status <run-id>
```

Seven matrix jobs run in parallel (`commitment_decode`, `signature_decode`,
`scalar_decode`, `invoice_commitment_decode`, `wire_message_json`,
`merkle_proof_json`, `audit_log_json`), each roughly 65-75 minutes (install +
build + 3600 s). Per job the workflow: validates the duration, installs nightly
and `cargo-fuzz 0.13.2`, restores the corpus cache, requires the committed
`seed-*` and `regress-*` files to exist, runs
`cargo +nightly fuzz run <target> -- -max_total_time=3600 -timeout=30 -rss_limit_mb=2048 -max_len=65536 -print_final_stats=1`
through `tee`, then runs `ci/assert_fuzz_ran.sh` (requires libFuzzer's final
`Done N runs in S second(s)` with `S >= 3600` and no failure marker), and
uploads `fuzz-log-<target>` always and `fuzz-crash-<target>` on failure. The
`fuzz-gate` job fails unless all seven succeeded.

What has and has not been verified about this workflow (honest status):

| Property | Status |
|---|---|
| YAML lints (`actionlint`), parses | EXECUTED + PASSED (authoring sandbox) |
| 7 names agree across bodies, targets, `[[bin]]`, matrix, corpus; each target calls its own body; workflow keeps pipefail, 3600 default, log gate, crash upload, gate job | EXECUTED + PASSED (`ci/check_fuzz_setup.sh`, plus 3 negative controls that make it fail) |
| The log gate rejects short runs, crashes, timeouts, OOM, missing `Done` line, empty log; accepts a clean full-length log | EXECUTED + PASSED on SYNTHETIC logs (`ci/check_fuzz_assert.sh`). Never seen a real libFuzzer log |
| The `fuzz/` crate type-checks | EXECUTED + PASSED on stable 1.91 (`cargo check`), NOT built with sanitizers or nightly |
| `cargo +nightly fuzz` builds and runs each target | NOT EXECUTED (BLOCKED BY ENVIRONMENT: the sandbox cannot reach static.rust-lang.org) |
| Runs for exactly 3600 s | NOT EXECUTED. libFuzzer stops once the budget is exceeded, so S is 3600 or a second or two more; the gate requires `S >= 3600` |
| A crash really fails the job and uploads artifacts | NOT EXECUTED on GitHub; logic covered by synthetic logs and `defaults.run.shell: bash` (pipefail). See 3c for a deliberate-crash drill |

### 3b. Local, one target (needs nightly)

```bash
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked --version 0.13.2
cd fuzz
cargo +nightly fuzz run merkle_proof_json -- -max_total_time=3600 -timeout=30 -rss_limit_mb=2048 -max_len=65536 -print_final_stats=1 2>&1 | tee ../fuzz-merkle_proof_json.log
cd .. && bash ci/assert_fuzz_ran.sh fuzz-merkle_proof_json.log 3600
```

Seven targets at one hour each is about 7 hours serially; run them in parallel
on separate machines or use the workflow.

### 3c. First-run drill (do this once, before trusting a green run)

Prove the pipeline can fail: on a scratch branch, add `panic!()` as the first line of
`merkle_proof_json` in `src/quorum_adversarial/src/fuzz_bodies.rs`, run the
workflow with `seconds=60`. Expected: that job fails within a minute or two,
`fuzz-crash-merkle_proof_json` contains a `crash-*` file, `fuzz-gate` is red.
Delete the branch. If any of that does not happen, the workflow is not safe to
rely on; fix it before the real run.

## 4. Full regression and adversarial suite

Covered by 2a/2b. The adversarial suite alone:

```bash
bash ci/setup_test_db.sh
cargo run --locked -p quorum_adversarial -- --only A,B,C,D,M,L,E,I,F,G,J,K,N,Z,P,Q,R,S,W | tee adversarial.log
grep -q '^82/82 checks passed as expected\.' adversarial.log && ! grep -q '^\[FAIL\]' adversarial.log && echo OK
```

Group H (real network partition) needs iptables and root, and is not in the CI
list. Group X is a probe that runs only when named. Group W is the stable
seeded fuzz driver (`--fuzz-iters N`, default 20000 per body); it is NOT
coverage-guided and does not replace section 3.

## 5. Database-required CI verification (Gap 6)

The guarantee: a DB test that cannot reach Postgres must FAIL, never skip.
Three independent layers, all exercised by CI:

1. `test` job sets `CIPHERSETTLE_TEST_DB_REQUIRED=1` and a step asserts it.
2. `ci/assert_db_tests_ran.sh` demands every DB test left an outcome marker
   `ran` (a skip is reported by cargo as a pass, so cargo's exit code is not trusted).
3. `db-guard-negative` job runs `ci/check_ci_fails_on_broken_db.sh`: with an
   unreachable DB, REQUIRED=1 must exit non-zero with `DB_REQUIRED_BUT_UNREACHABLE`,
   and with REQUIRED unset the marker check must still fail.

Local drill: `bash ci/check_ci_fails_on_broken_db.sh` must print
`RESULT: broken DB setup fails CI as required`. Real-CI drill (once): on a scratch
branch change `POSTGRES_PASSWORD` in the `test` job's service to a wrong value;
the `test` job must go red. Delete the branch.

Status: the script and the local drill are EXECUTED + PASSED (authoring sandbox; first run on the pinned 1.97 in session 17 onward).
The GitHub run is NOT EXECUTED.

## 6. Power-loss testing (Gap 13)

What exists: group Q (SIGKILL mid-burst, corrupt/truncated/tampered files) is
EXECUTED + PASSED and is why Gap 13 is "closed for SIGKILL only". It cannot
model a power cut (page cache and unflushed disk cache lost). This section adds
tooling to rehearse that. The tooling was exercised locally with `kill -9` only;
a power-loss rehearsal itself is NOT EXECUTED (needs a machine you can power
off).

Tools (in `quorum_node`, no cluster needed; they use the production
`audit_store` write path):

* `quorum_node audit-powerloss-workload <log> <ack> [max]`: append one entry,
  commit with one fsynced journal frame (`<log>.journal`; compaction uses atomic temp-file + fsync + rename + dir-fsync), THEN durably
  record the entry count in `<ack>`. Resumes from what is on disk.
* `quorum_node audit-powerloss-verify <log> [ack]`: exit 0 only if the log parses,
  its hash chain verifies, and it holds at least `<ack>` entries (acknowledged
  implies durable). Exit 1 otherwise.

Procedure (one cycle; use a dedicated test mount, never a machine you care about):

```bash
cargo build --release --locked -p quorum_node
D=/mnt/plt                       # ext4 or xfs, default mount options (NOT `sync`), not tmpfs
sudo mkdir -p $D && sudo chown "$USER" $D
nohup ./target/release/quorum_node audit-powerloss-workload $D/audit.json $D/ack >/dev/null 2>&1 &
sleep $((RANDOM % 56 + 5))       # cut power at a random moment
# CUT POWER NOW, with no clean shutdown. Best to worst:
#   (1) hardware: pull the plug / switched PDU            (2) hypervisor "power off" / "reset"
#   (3) echo b | sudo tee /proc/sysrq-trigger   (immediate reboot, no sync; loses page cache only)
# After the machine is back and $D is mounted:
./target/release/quorum_node audit-powerloss-verify $D/audit.json $D/ack | tee -a plt.log
echo "cycle=$N rc=$? $(uname -r) $(findmnt -no FSTYPE,OPTIONS $D) method=<1|2|3>" >> plt.log
```

The next cycle's workload resumes automatically (restart it after each verify).
Stale `audit.json.tmp.*` files left by a cut are removed by the loader.

Proposed pass criterion (an extension, NOT in the original gap list; confirm
with the project owner): at least 100 cuts, at least 20 of them by method (1) or
(2), across both ext4 and xfs, with every `verify` exiting 0 and zero cases of
an ack ahead of the disk. A single `FAIL` (damaged log or durability violation)
is a bug: keep `audit.json`, `ack` and `plt.log`, then treat it like a crash
(section 9).

Limits to state in any report: method (3) and many hypervisor power-offs do not
discard the disk's volatile write cache, so they can over-state durability;
this exercises the audit-log write primitive, not the whole node; it says
nothing about the share store (`share_store.rs`) or the pubkey/ready files'
use of the same primitive beyond reusing `write_atomic`.

## 7. Collecting logs and artifacts

```bash
gh run list --workflow ci.yml --limit 25 --json databaseId,conclusion,event,headSha,createdAt,url > ci_runs.json
gh run download <run-id> -D artifacts/ci-<run-id>        # adversarial-log
gh run list --workflow fuzz.yml --limit 3 --json databaseId,conclusion,url
gh run download <fuzz-run-id> -D artifacts/fuzz-<id>     # fuzz-log-<target> x7, fuzz-crash-<target> if any
cp -r verification_out agent_memory/evidence/verification_<date>_<rustc>   # section 2b output
```

Commit logs under `agent_memory/evidence/`, named with date and toolchain. Record
in each note which of the four status words applies.

## 8. Can Gap 6 / Gap 8 be marked CLOSED?

Both are currently **PARTIALLY CLOSED**. Mark CLOSED only when every box is
ticked, with the evidence linked next to the status.

**Gap 6 (CI) closed when** (from the gap list): CI is green on 20 consecutive
runs, and a deliberately broken DB setup makes CI fail rather than skip; plus
its fix text: Test E run at least 100 times under load with the flakiness root
cause fixed.

- [ ] `ci.yml` ran on GitHub on the pinned 1.97 and `toolchain pin` steps passed.
- [ ] 20 consecutive completed runs of `ci.yml` are all `success`
      (`gh run list --workflow ci.yml --limit 20`; interpret "consecutive" as:
      no failed run in the window and no "re-run failed jobs" counted; pushes
      and the daily schedule both count). Save `ci_runs.json`.
- [ ] The broken-DB drill in section 5 turned the `test` job red, and
      `db-guard-negative` is green in those 20 runs.
- [ ] `flake-hunt.yml` ran Test E at least 100 times under load
      (`gh workflow run flake-hunt.yml -f runs=100 -f stress_cpu=4 -f stress_vm=1`)
      with zero failures, OR the root cause of the earlier 2-proposer flake is
      identified and fixed with a test. The root cause was NOT reproduced so far
      (F-05), so a clean 100-run alone is weak evidence; say so in the note.
- [ ] `supply-chain` job green (cargo audit, cargo deny) with only the documented ignores.

**Gap 8 (panics and fuzzing) closed when** (from the gap list): the deny lints
pass, AND a fuzzing run of at least 1 hour per target finds no crash.

- [ ] Lints: `cargo clippy --workspace --locked --all-targets -- -D warnings`
      green on 1.97 in CI (lint job). (Local 1.91 result exists; not enough.)
- [ ] `fuzz.yml` ran with `seconds=3600` (or more), all 7 matrix jobs green,
      `fuzz-gate` green, and each `fuzz-log-<target>` shows
      `Done N runs in S second(s)` with `S >= 3600`; no `fuzz-crash-*` artifact.
- [ ] The section 3c drill showed a deliberate crash turning the job red.
- [ ] Any crash found along the way was added as a permanent regression (section 9)
      and the run repeated from scratch for the affected target.
- [ ] Not required by the criterion but still open and must stay listed as open:
      fuzzing the node line reader and `handle_message`; indexing/arithmetic panic lints.

If any box is unticked, the status stays PARTIALLY CLOSED. Do not edit the
status to CLOSED "pending" anything.

## 9. A fuzz run found a crash

1. The job is red and `fuzz-crash-<target>` holds `crash-*`, `timeout-*` or `oom-*`.
   Download it: `gh run download <id> -n fuzz-crash-<target> -D crash/`.
2. Reproduce locally on nightly:
   `cd fuzz && cargo +nightly fuzz run <target> ../crash/crash-<hash>` (exits non-zero).
   Minimise: `cargo +nightly fuzz tmin <target> ../crash/crash-<hash>`.
3. Add it as a permanent regression: copy the (minimised) bytes to
   `fuzz/corpus/<target>/regress-<short-description>.<bin|json>`.
4. Confirm it fails WITHOUT nightly: `cargo test -p quorum_adversarial corpus_`
   must FAIL on the unfixed code (it replays every committed file through the
   same body). If it does not fail, the crash depends on sanitizers or timing;
   investigate before fixing, and still keep the file.
5. Fix the cause in production code (no `unwrap`/`expect`/`panic`; return an error
   or reject the input). If the fix is protocol- or crypto-level, stop and get
   human cryptographer review.
6. Add a focused unit test next to the fixed code (see
   `fuzz/regression/README.md` for the pattern) and mutation-check it: revert the
   fix, see the test fail, restore.
7. Update the table in `fuzz/regression/README.md`, add a finding to
   `agent_memory/SECURITY_FINDINGS.md`, keep `corpus_contains_the_named_bug_regressions`
   in `src/quorum_adversarial/src/corpus_tests.rs` in sync if the file is a named bug pin.
8. Re-run section 2b, then re-run section 3 for that target from the start
   (a fixed crash resets the "no crash in one hour" evidence).

## 10. Authoring-sandbox evidence for this runbook

See `agent_memory/evidence/verification_prep_session15_summary.txt` and, for the pinned-toolchain run, `agent_memory/evidence/verification_session17_pin197_summary.txt` for the exact
per-check status (EXECUTED + PASSED / FAILED, NOT EXECUTED, BLOCKED BY ENVIRONMENT).
