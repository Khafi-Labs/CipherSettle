//! Gap 8 / T-9: stable-Rust, seeded, deterministic driver for the shared fuzz
//! bodies in `fuzz_bodies.rs`. This is NOT coverage-guided fuzzing -- it is a
//! fast regression net (random bytes + mutations of VALID encodings + a fixed
//! corpus of structural attacks) that runs in CI on every push. Long
//! coverage-guided runs use the `fuzz/` crate (cargo-fuzz, nightly).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use base64::Engine;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

use crate::fuzz_bodies::ALL;

const DEFAULT_ITERS: usize = 20_000;
const SEED: u64 = 0xC1F4_E5E7_u64;
const SLOW_CALL: Duration = Duration::from_secs(2);

fn hex_prefix(b: &[u8]) -> String {
    b.iter()
        .take(48)
        .map(|x| format!("{x:02x}"))
        .collect::<String>()
}

/// Interesting replacement values for a JSON node (boundary integers, wrong
/// types, empty / oversized containers, hash-sized byte arrays).
fn interesting(rng: &mut StdRng) -> serde_json::Value {
    use serde_json::{json, Value};
    match rng.gen_range(0..14) {
        0 => json!(0),
        1 => json!(1),
        2 => json!(2),
        3 => json!(u64::MAX),
        4 => json!(i64::MIN),
        5 => json!(1e308),
        6 => Value::Null,
        7 => json!(true),
        8 => json!(""),
        9 => json!("A".repeat(rng.gen_range(1..300))),
        10 => json!([]),
        11 => json!({}),
        12 => Value::Array(
            (0..rng.gen_range(0..70))
                .map(|_| json!(rng.gen::<u8>()))
                .collect(),
        ),
        _ => json!(rng.gen_range(3..40u64)),
    }
}

/// Structure-aware mutation: replace / delete / duplicate a random node.
fn mutate_value(rng: &mut StdRng, v: &mut serde_json::Value, depth: usize) {
    use serde_json::Value;
    let descend = depth < 6 && rng.gen_bool(0.7);
    match v {
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let k = keys[rng.gen_range(0..keys.len())].clone();
            match rng.gen_range(0..6) {
                0 => {
                    map.remove(&k);
                }
                1 => {
                    let val = interesting(rng);
                    map.insert(k, val);
                }
                _ if descend => {
                    if let Some(child) = map.get_mut(&k) {
                        mutate_value(rng, child, depth + 1);
                    }
                }
                _ => {
                    let val = interesting(rng);
                    map.insert(k, val);
                }
            }
        }
        Value::Array(arr) if !arr.is_empty() => {
            let i = rng.gen_range(0..arr.len());
            match rng.gen_range(0..6) {
                0 => {
                    arr.remove(i);
                }
                1 => {
                    let dup = arr[i].clone();
                    arr.insert(i, dup);
                }
                2 => arr[i] = interesting(rng),
                _ if descend => mutate_value(rng, &mut arr[i], depth + 1),
                _ => arr[i] = interesting(rng),
            }
        }
        _ => *v = interesting(rng),
    }
}

fn mutate(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    // Half the time, if the seed is JSON, mutate its structure instead of its bytes.
    if rng.gen_bool(0.5) {
        if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(seed) {
            for _ in 0..rng.gen_range(1..=3) {
                mutate_value(rng, &mut val, 0);
            }
            if let Ok(out) = serde_json::to_vec(&val) {
                return out;
            }
        }
    }
    mutate_bytes(rng, seed)
}

fn mutate_bytes(rng: &mut StdRng, seed: &[u8]) -> Vec<u8> {
    const TOKENS: &[&[u8]] = &[
        b"18446744073709551615",
        b"99999999999999999999999",
        b"-1",
        b"null",
        b"[]",
        b"{}",
        b"\"\"",
        b"\\u0000",
        b"[[[[[[[[[[[[[[[[",
    ];
    let mut v = seed.to_vec();
    for _ in 0..rng.gen_range(1..=4) {
        match rng.gen_range(0..7) {
            0 if !v.is_empty() => {
                let i = rng.gen_range(0..v.len());
                v[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if !v.is_empty() => {
                let i = rng.gen_range(0..v.len());
                v[i] = rng.gen();
            }
            2 if !v.is_empty() => {
                let n = rng.gen_range(0..v.len());
                v.truncate(n);
            }
            3 => {
                let i = rng.gen_range(0..=v.len());
                let t = TOKENS[rng.gen_range(0..TOKENS.len())];
                v.splice(i..i, t.iter().copied());
            }
            4 if !v.is_empty() => {
                let a = rng.gen_range(0..v.len());
                let b = rng.gen_range(a..v.len());
                let chunk = v[a..b].to_vec();
                let i = rng.gen_range(0..=v.len());
                v.splice(i..i, chunk);
            }
            5 if !v.is_empty() => {
                let i = rng.gen_range(0..v.len());
                v.remove(i);
            }
            _ => {
                let i = rng.gen_range(0..=v.len());
                v.insert(i, rng.gen());
            }
        }
        if v.len() > 1 << 20 {
            v.truncate(1 << 20);
        }
    }
    v
}

/// Valid encodings (seeds) for each body, by name.
fn seeds(name: &str, rng: &mut StdRng) -> Vec<Vec<u8>> {
    use ciphersettle_core::MerkleLog;
    use quorum_audit::{AuditEvent, AuditLog};
    use quorum_core::{scalar_to_bytes, Commitment, DkgSession, Message, Poly, SignatureShare};
    let mut out: Vec<Vec<u8>> = Vec::new();
    match name {
        "commitment_decode" => {
            for t in [1usize, 2, 5] {
                out.push(Poly::random(t, rng).commitment().to_bytes());
            }
        }
        "signature_decode" => {
            for _ in 0..3 {
                out.push(SignatureShare::random_for_test(rng).to_bytes().to_vec());
            }
        }
        "scalar_decode" => {
            let p = Poly::random(2, rng);
            for x in 1..4u64 {
                out.push(scalar_to_bytes(&p.evaluate(x)).to_vec());
            }
        }
        "invoice_commitment_decode" => {
            for i in 0..3 {
                let b = crate::sample_commitment_b64(&format!("fz-{i}"));
                if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b) {
                    out.push(raw);
                }
            }
        }
        "wire_message_json" => {
            let (mut sess, commitment) = DkgSession::new(0, 3, 1, rng);
            let share = sess.share_for(1);
            let _ = &mut sess;
            let c: Commitment = commitment;
            for m in [
                Message::DkgCommitment {
                    from: 0,
                    commitment: c,
                },
                Message::DkgShare {
                    from: 0,
                    to: 1,
                    share,
                },
            ] {
                if let Ok(b) = serde_json::to_vec(&m) {
                    out.push(b);
                }
            }
            let mut root = [0u8; 32];
            rng.fill_bytes(&mut root);
            if let Ok(b) = serde_json::to_vec(&quorum_audit::wire::NotaryMessage::NotarizeRequest {
                root_hash: root,
            }) {
                out.push(b);
            }
        }
        "merkle_proof_json" => {
            let mut log = MerkleLog::new();
            for i in 0..6u8 {
                log.append(&[i; 8]);
            }
            for i in [0u64, 3, 5] {
                if let Some(Ok(b)) = log.prove(i).map(|p| serde_json::to_vec(&p)) {
                    out.push(b);
                }
            }
        }
        "audit_log_json" => {
            let mut log = AuditLog::default();
            for i in 0..4u64 {
                let e = log.propose_next(AuditEvent {
                    invoice_id: format!("inv-{i}"),
                    actor: "a".into(),
                    action: "invoice_registered".into(),
                    timestamp_unix_ms: i,
                });
                let _ = log.try_append(e);
            }
            if let Ok(b) = serde_json::to_vec(&log) {
                out.push(b);
            }
            if let Some(e) = log.entries.first() {
                if let Ok(b) = serde_json::to_vec(e) {
                    out.push(b);
                }
            }
        }
        _ => {}
    }
    out
}

/// Fixed structural-attack inputs applied to every body.
fn corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xff; 4096],
        b"{}".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"\"\"".to_vec(),
        br#"{"entries":[]}"#.to_vec(),
        br#"{"entries":[{"seq":18446744073709551615,"prev_hash":[],"entry_hash":[],"event":{},"signatures":{}}]}"#.to_vec(),
        br#"{"version":1,"leaf_count":18446744073709551615,"siblings":[],"peak_index":18446744073709551615,"peaks":[]}"#.to_vec(),
    ];
    // Deep nesting: must be rejected by the parser's recursion limit, not overflow the stack.
    c.push([b"[".repeat(200_000), b"]".repeat(200_000)].concat());
    c.push(
        [
            b"{\"a\":".repeat(100_000),
            b"1".to_vec(),
            b"}".repeat(100_000),
        ]
        .concat(),
    );
    c
}

pub struct Outcome {
    pub name: String,
    pub passed: bool,
    pub notes: String,
}

pub fn run(iters: Option<usize>) -> Vec<Outcome> {
    let iters = iters.unwrap_or(DEFAULT_ITERS);
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // panics are counted, not printed
    let mut results = Vec::new();

    for (i, (name, body)) in ALL.iter().enumerate() {
        let mut rng = StdRng::seed_from_u64(SEED ^ (i as u64));
        let seeds = seeds(name, &mut rng);
        let corpus = corpus();
        let mut panics = 0usize;
        let mut slow = 0usize;
        let mut first_bad: Option<String> = None;
        let mut max_call = Duration::ZERO;
        let mut calls = 0usize;
        let mut accepted_seeds = 0usize;

        let mut one = |input: &[u8]| {
            let t = Instant::now();
            let r = catch_unwind(AssertUnwindSafe(|| body(input)));
            let dt = t.elapsed();
            calls += 1;
            if dt > max_call {
                max_call = dt;
            }
            if r.is_err() {
                panics += 1;
                first_bad.get_or_insert_with(|| {
                    format!(
                        "panic on input len={} hex={}",
                        input.len(),
                        hex_prefix(input)
                    )
                });
            }
            if dt > SLOW_CALL {
                slow += 1;
                first_bad.get_or_insert_with(|| {
                    format!(
                        "slow call {dt:?} on input len={} hex={}",
                        input.len(),
                        hex_prefix(input)
                    )
                });
            }
        };

        for s in &seeds {
            one(s); // the valid encodings themselves must round-trip
            accepted_seeds += 1;
        }
        for c in &corpus {
            one(c);
        }
        for n in 0..iters {
            if n % 4 == 0 || seeds.is_empty() {
                let len = rng.gen_range(0..400);
                let mut buf = vec![0u8; len];
                rng.fill_bytes(&mut buf);
                one(&buf);
            } else {
                let s = &seeds[rng.gen_range(0..seeds.len())];
                let m = mutate(&mut rng, s);
                one(&m);
            }
        }

        let ok = panics == 0 && slow == 0 && !seeds.is_empty();
        results.push(Outcome {
            name: format!(
                "W{}: `{}` survives {} inputs (random + mutated valid seeds + structural corpus) with no panic, no slow call, canonical round-trip",
                i + 1,
                name,
                calls
            ),
            passed: ok,
            notes: format!(
                "seeds={accepted_seeds} panics={panics} slow={slow} max_call={max_call:?}{}",
                first_bad.map(|b| format!(" FIRST_BAD: {b}")).unwrap_or_default()
            ),
        });
    }
    std::panic::set_hook(prev_hook);
    results
}
