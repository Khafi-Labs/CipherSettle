# Regression map: bug -> deterministic pin

Every bug found during Gap 8 is pinned by at least one check that runs WITHOUT
a nightly toolchain, plus (where the input is a byte string) a committed corpus
file that libFuzzer replays first. "Mutation-checked" means the pin was shown
to FAIL when the fix was reverted; anything not marked so has only been shown to pass.

| Bug | Deterministic pin | Corpus input(s) (`fuzz/corpus/...`) | Mutation-checked |
|---|---|---|---|
| **F-21** malformed `ciphertext_b64` panicked a service handler | `quorum_service` unit test `f21_regression_tests::regression_malformed_request_base64_is_an_error_not_a_panic` (helper). Handler level: adversarial **Z4**, **Z5** (live service + Postgres) | none (HTTP bodies are not a libFuzzer target) | Z4, Z5: yes. Unit test: yes |
| **HKDF all-zero fallback** | `quorum_core` tests `regression_hkdf_never_yields_the_all_zero_key_and_node_keys_differ`, `new_hmac_matches_new_from_slice_for_all_key_lengths`, `hkdf_sha256_matches_rfc5869_test_case_1` | none | per-node-key test: yes |
| **`bag_peaks` panicked on empty peaks** | `ciphersettle_core` test `bag_peaks_of_nothing_is_none_and_empty_peak_proof_is_rejected` | `merkle_proof_json/regress-empty-peaks*.json` | yes |
| **`MerkleProof::verify` panicked on out-of-range `peak_index`** | `ciphersettle_core` test `regression_out_of_range_peak_index_is_rejected_not_panicked`; `corpus_tests::corpus_replay_every_committed_input_runs_clean` | `merkle_proof_json/regress-peak-index-*.json` | yes (unit + corpus replay) |
| Structural attack classes (deep nesting, u64::MAX ids, wrong lengths, non-canonical scalars, off-curve points, too many points) | `corpus_tests::*` + adversarial group W | `wire_message_json/regress-deep-*`, `commitment_decode/regress-max-points-plus-one.bin`, `scalar_decode/regress-modulus-r-*.bin`, ... | not individually |

## Adding a crash found by a fuzz run

1. Download the `fuzz-crash-<target>` artifact (`crash-*`, `timeout-*`, `oom-*`).
2. Copy it to `fuzz/corpus/<target>/regress-<description>.<ext>` (exact bytes).
3. `cargo test -p quorum_adversarial corpus_` must FAIL (reproduces without nightly). If not, investigate before fixing.
4. Fix the cause; step 3 must now pass.
5. Add a row above and an entry to `agent_memory/SECURITY_FINDINGS.md`.
6. Commit the corpus file with the fix.
