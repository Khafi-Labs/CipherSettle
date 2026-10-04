# Fuzz targets (Gap 8 / T-9)

Seven targets, one per parser fed from the network, the DB or config:
`commitment_decode`, `signature_decode`, `scalar_decode`,
`invoice_commitment_decode`, `wire_message_json`, `merkle_proof_json`,
`audit_log_json`. Each is a one-line wrapper over a function in
`src/quorum_adversarial/src/fuzz_bodies.rs`.

Two ways to run the SAME bodies:

* Every push (stable, seeded, deterministic): `cargo run --locked -p
  quorum_adversarial -- --only W [--fuzz-iters N]`. Not coverage-guided; it
  mutates valid encodings (bytes and JSON structure) plus a structural corpus.
* Long coverage-guided runs (nightly + cargo-fuzz):
  `cargo install cargo-fuzz && cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=3600`

A crash writes `fuzz/artifacts/<target>/crash-*`; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-...`, add the
bytes as a regression case in `fuzz_smoke.rs::corpus()`, fix, and re-run.

Not covered here (needs a different harness): the node's line-reader
(`BoundedLineReader`, async, in a bin crate; has unit tests for the cap and for
non-UTF-8) and service HTTP bodies (covered by adversarial checks Z4/Z5 against
the live service instead).
