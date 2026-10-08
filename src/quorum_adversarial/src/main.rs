//! Phase 4 of the threshold-quorum roadmap: adversarial tests run against
//! the REAL system built in Phases 0-3 (`quorum_node`, `quorum_client`,
//! `quorum_service`), not a paper exercise. Every test below either (a)
//! confirms a defense actually holds under attack, or (b) concretely
//! reproduces a gap that was previously only a documented caveat --
//! turning "we think this might be a problem" into "here is a runnable
//! demonstration that it is."
//!
//! This is explicitly NOT a substitute for independent third-party
//! review -- it's the "adversarial tests" bullet of Phase 4, run by
//! the same process that built the system (see `SECURITY_REVIEW.md`
//! §6 for what an outside cryptographer still needs to check, and the
//! roadmap's Phase 5 for the audit engagement that would satisfy it).
//! That's a real limitation: this project's authors testing their own
//! system are structurally unable to catch classes of bugs they don't
//! already know to look for. Treat every "PASS" below as "this specific
//! attack, as implemented here, didn't work" -- not as a certification.
//!
//! Run: `cargo run -p quorum_adversarial` (needs a running Postgres for
//! the HTTP pen-test section; see PHASE3_README.md for setup).

use ed25519_dalek::SigningKey;
use quorum_audit::AuditEvent;
use quorum_core::config::{NodeConfig, PeerConfig};
use quorum_core::Message;
// Audit finding A4: rand 0.8's OsRng (the whole workspace is on rand 0.8
// now that threshold_crypto is gone).
use quorum_core::PublicKeySet;
use rand::rngs::OsRng as OsRng08;
use rustls::{Certificate, ServerName};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const N: usize = 5;
const T: usize = 2; // 3-of-5

struct GeneratedIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_identity() -> GeneratedIdentity {
    let cert = rcgen::generate_simple_self_signed(vec!["quorum-node".to_string()]).unwrap();
    GeneratedIdentity {
        cert_der: cert.serialize_der().unwrap(),
        key_der: cert.serialize_private_key_der(),
    }
}

fn generate_audit_keypair() -> SigningKey {
    let mut csprng = OsRng08 {};
    SigningKey::generate(&mut csprng)
}

fn generate_service_auth_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A stand-in `InvoiceCommitment`, computed the way a real caller would
/// (client-side, over the invoice's own plaintext fields, never sent to
/// this harness's `quorum_service` instance) -- see `commitment.rs`'s
/// module doc comment. `register_invoice` now requires this on every
/// request (Phase 6a wiring), so every test call needs one.
fn sample_commitment_b64(invoice_reference: &str) -> String {
    use ciphersettle_core::InvoiceFields;
    let fields = InvoiceFields {
        invoice_reference: invoice_reference.to_string(),
        issuer: "Adversarial Test Issuer".to_string(),
        debtor: "Adversarial Test Debtor".to_string(),
        amount_minor_units: 1_234_500,
        currency: "EGP".to_string(),
        issue_date: "2026-09-01".to_string(),
        due_date: "2026-12-01".to_string(),
    };
    let commitment = ciphersettle_core::InvoiceCommitment::compute(&fields, &mut OsRng08);
    b64(&commitment.to_bytes())
}

#[cfg(test)]
mod corpus_tests;
mod fuzz_bodies;
mod fuzz_smoke;

struct Report {
    results: Vec<(String, bool, String)>,
}

impl Report {
    fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }
    fn record(&mut self, name: &str, passed: bool, notes: impl Into<String>) {
        let notes = notes.into();
        println!("[{}] {name}: {notes}", if passed { "PASS" } else { "FAIL" });
        self.results.push((name.to_string(), passed, notes));
    }
    fn print_summary(&self) {
        println!("\n=== Phase 4 Adversarial Test Summary ===");
        let passed = self.results.iter().filter(|(_, p, _)| *p).count();
        for (name, p, notes) in &self.results {
            println!("  [{}] {name} -- {notes}", if *p { "PASS" } else { "FAIL" });
        }
        println!("{passed}/{} checks passed as expected.", self.results.len());
    }
}

fn locate_sibling_binary(name: &str) -> PathBuf {
    let mut exe = std::env::current_exe().unwrap();
    exe.pop();
    let candidate = exe.join(name);
    if candidate.exists() {
        return candidate;
    }
    panic!("could not find sibling binary `{name}`; build it first with `cargo build -p {name}`");
}

fn kill_all(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// A fully spun-up, DKG-complete quorum: 5 real node processes, their
/// identities, the group public key, and a client connector pinned to
/// trust all 5.
struct LiveQuorum {
    node_identities: Vec<GeneratedIdentity>,
    #[allow(dead_code)] // kept for tests that may want to sign as a node directly
    node_audit_keys: Vec<SigningKey>,
    addrs: Vec<String>,
    children: Vec<Child>,
    #[allow(dead_code)] // kept for tests that inspect on-disk state directly
    audit_log_files: Vec<PathBuf>,
    pubkey_files: Vec<PathBuf>,
    group_pks: PublicKeySet,
    client_identity: GeneratedIdentity,
    connector: TlsConnector,
    work_dir: PathBuf,
    /// The shared secret every node in this quorum was configured with,
    /// required to authorize a `DeriveRequest` (Phase 4 Stage A). Tests
    /// that want the legitimate path use this; Test C deliberately does
    /// NOT, to prove an attacker without it is now refused.
    service_auth_key: Vec<u8>,
}

async fn spin_up_quorum(work_dir_name: &str, base_port: u16) -> LiveQuorum {
    let work_dir = PathBuf::from(format!("/tmp/{work_dir_name}"));
    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir).unwrap();

    let node_identities: Vec<GeneratedIdentity> = (0..N).map(|_| generate_identity()).collect();
    let node_audit_keys: Vec<SigningKey> = (0..N).map(|_| generate_audit_keypair()).collect();
    let client_identity = generate_identity();
    let addrs: Vec<String> = (0..N)
        .map(|i| format!("127.0.0.1:{}", base_port + i as u16))
        .collect();
    let service_auth_key = generate_service_auth_key();

    let node_binary = locate_sibling_binary("quorum_node");
    let mut children = Vec::with_capacity(N);
    let mut ready_files = Vec::with_capacity(N);
    let mut pubkey_files = Vec::with_capacity(N);
    let mut audit_log_files = Vec::with_capacity(N);

    for id in 0..N {
        let peers: Vec<PeerConfig> = (0..N)
            .filter(|&j| j != id)
            .map(|j| PeerConfig {
                id: j,
                addr: addrs[j].clone(),
                cert_der_b64: b64(&node_identities[j].cert_der),
                audit_pubkey_b64: b64(&node_audit_keys[j].verifying_key().to_bytes()),
            })
            .collect();
        let ready_file = work_dir.join(format!("node{id}.ready"));
        let pubkey_file = work_dir.join(format!("node{id}.pubkey.json"));
        let audit_log_file = work_dir.join(format!("node{id}.audit_log.json"));
        let config = NodeConfig {
            node_id: id,
            listen_addr: addrs[id].clone(),
            n: N,
            t: T,
            cert_der_b64: b64(&node_identities[id].cert_der),
            key_der_b64: b64(&node_identities[id].key_der),
            audit_keypair_b64: b64(&node_audit_keys[id].to_bytes()),
            peers,
            client_cert_der_b64: b64(&client_identity.cert_der),
            ready_file: ready_file.to_string_lossy().to_string(),
            pubkey_file: pubkey_file.to_string_lossy().to_string(),
            audit_log_file: audit_log_file.to_string_lossy().to_string(),
            service_auth_key_b64: b64(&quorum_core::derive_node_auth_key(&service_auth_key, id)),
            persistence: None,
            allow_ephemeral_share: true, // throwaway test quorum
        };
        let config_path = work_dir.join(format!("node{id}.json"));
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let child = Command::new(&node_binary)
            .arg(&config_path)
            .spawn()
            .unwrap();
        children.push(child);
        ready_files.push(ready_file);
        pubkey_files.push(pubkey_file);
        audit_log_files.push(audit_log_file);
    }

    wait_for_ready(&ready_files, &mut children, Duration::from_secs(30)).await;
    // T1-2: nodes deliberately refuse new derive requests for
    // `MAX_DERIVE_AUTH_WINDOW_MS - DEFAULT_DERIVE_AUTH_VALIDITY_MS` after
    // process start (restart-replay guard). DKG can finish faster than that,
    // so wait it out; this changes timing only, no assertion.
    tokio::time::sleep(Duration::from_millis(
        quorum_core::MAX_DERIVE_AUTH_WINDOW_MS - quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS + 500,
    ))
    .await;

    let group_pks: PublicKeySet = {
        let raw = std::fs::read(&pubkey_files[0]).unwrap();
        serde_json::from_slice(&raw).unwrap()
    };

    let connector = quorum_client::build_connector(
        client_identity.cert_der.clone(),
        client_identity.key_der.clone(),
        node_identities.iter().map(|n| n.cert_der.clone()).collect(),
    )
    .expect("test TLS identity");

    LiveQuorum {
        node_identities,
        node_audit_keys,
        addrs,
        children,
        audit_log_files,
        pubkey_files,
        group_pks,
        client_identity,
        connector,
        work_dir,
        service_auth_key: service_auth_key.to_vec(),
    }
}

async fn wait_for_ready(ready_files: &[PathBuf], children: &mut [Child], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    for (id, f) in ready_files.iter().enumerate() {
        while !f.exists() {
            if Instant::now() > deadline {
                kill_all(children);
                panic!("timed out waiting for node {id} DKG");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

fn node_addr_list(q: &LiveQuorum, ids: &[usize]) -> Vec<(usize, String)> {
    ids.iter().map(|&id| (id, q.addrs[id].clone())).collect()
}

// =========================================================================
// TEST A: malicious minority node submitting bad partial derivations.
// =========================================================================
//
// After honest DKG completes, node 2 is killed and replaced with a fake
// process that REUSES node 2's real cert/key (so it passes the pinned-TLS
// check) but returns garbage on every DeriveRequest. We confirm:
//   (a) derive still succeeds using the 4 remaining honest nodes, and
//   (b) if too many nodes are malicious to leave a valid threshold, derive
//       correctly FAILS rather than silently returning a wrong key.
async fn test_a_malicious_minority(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_a", 9500).await;
    let identity = "inv-adversarial-a";

    // Sanity: honest derive works before we introduce any adversary.
    let honest_addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);
    let baseline = quorum_client::derive_from_quorum(
        &q.connector,
        &honest_addrs,
        &q.group_pks,
        identity,
        T,
        &q.service_auth_key,
    )
    .await;
    if baseline.is_err() {
        report.record(
            "A0: honest baseline derive",
            false,
            format!("baseline derive itself failed: {baseline:?}"),
        );
        kill_all(&mut q.children);
        return;
    }
    report.record(
        "A0: honest baseline derive",
        true,
        "5-of-5 honest nodes derive successfully before any attack",
    );

    // Replace node 2 with a malicious impersonator that reuses its cert.
    q.children[2].kill().unwrap();
    q.children[2].wait().ok();
    let adversary_addr = q.addrs[2].clone();
    spawn_garbage_adversary(&q, 2, adversary_addr.clone()).await;
    tokio::time::sleep(Duration::from_millis(200)).await; // let it bind

    let with_one_malicious = quorum_client::derive_from_quorum(
        &q.connector,
        &honest_addrs,
        &q.group_pks,
        identity,
        T,
        &q.service_auth_key,
    )
    .await;
    match with_one_malicious {
        Ok(sig) => {
            let ok = quorum_core::verify_combined(&q.group_pks, identity, &sig)
                && sig.to_bytes() == baseline.unwrap().to_bytes();
            report.record(
                "A1: 1-of-5 malicious (garbage partials)",
                ok,
                if ok {
                    "correctly ignored node 2's garbage partial and derived the SAME correct key from the 4 honest nodes"
                } else {
                    "derived a key but it doesn't match the honest baseline -- possible corruption, not just rejection"
                },
            );
        }
        Err(e) => report.record(
            "A1: 1-of-5 malicious (garbage partials)",
            false,
            format!("derive failed even though 4 honest nodes remained: {e}"),
        ),
    }

    // Now also take down nodes 3 and 4 (real outage, not malicious), so
    // only nodes 0, 1 are left alongside malicious node 2 -- i.e. only 2
    // genuinely honest respondents against a threshold requiring 3. This
    // must FAIL, not silently succeed with an under-threshold result.
    q.children[3].kill().unwrap();
    q.children[3].wait().ok();
    q.children[4].kill().unwrap();
    q.children[4].wait().ok();
    let under_threshold = quorum_client::derive_from_quorum(
        &q.connector,
        &honest_addrs,
        &q.group_pks,
        identity,
        T,
        &q.service_auth_key,
    )
    .await;
    report.record(
        "A2: below-threshold honest nodes correctly refuses",
        under_threshold.is_err(),
        match under_threshold {
            Err(e) => format!("correctly returned an error rather than a wrong key: {e}"),
            Ok(_) => "INCORRECTLY produced a derived key with only 2 honest respondents (need 3)"
                .to_string(),
        },
    );

    kill_all(&mut q.children);
}

/// Binds a fake mTLS "node" at `addr`, reusing the real node's cert/key so
/// it passes the pinned-certificate check, that answers every
/// `DeriveRequest` with a garbage `SignatureShare` -- sealed under the
/// request's own `transport_public_key`, exactly like a real node would,
/// so this test still exercises the real sealed wire protocol -- and
/// drops everything else. Runs until the process ends (spawned as a
/// detached tokio task).
async fn spawn_garbage_adversary(q: &LiveQuorum, node_id: usize, addr: String) {
    let cert_der = q.node_identities[node_id].cert_der.clone();
    let key_der = q.node_identities[node_id].key_der.clone();
    let client_cert = q.client_identity.cert_der.clone();
    tokio::spawn(async move {
        let server_config =
            quorum_client::build_server_config(cert_der, key_der, vec![client_cert])
                .expect("test TLS identity");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("adversary bind failed");
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let (read_half, mut write_half) = tokio::io::split(tls);
                let mut lines = BufReader::new(read_half).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Ok(Message::DeriveRequest {
                        identity,
                        transport_public_key,
                        ..
                    }) = serde_json::from_str::<Message>(&line)
                    {
                        // A random, syntactically-valid-but-wrong SignatureShare,
                        // sealed under the caller's real transport key -- this is
                        // what a genuinely malicious node (as opposed to one that
                        // simply refuses to answer) would send: it can't produce
                        // a plaintext share that verifies, but it can still speak
                        // the sealed wire format correctly, so the failure has to
                        // be caught after combine+decrypt, not at this hop.
                        //
                        // With the NIZK integrated this adversary is the STRONG
                        // one nizk.rs warns about: it invents its own scalar s'
                        // and produces a fully VALID proof for a share of s'.
                        // The proof is sound, but s' is not this node's DKG
                        // share, so it must fail against the group's public key
                        // share for this node -- caught before the combine.
                        let resp = {
                            let mut rng = rand::thread_rng();
                            let mut fake_sk = [0u8; quorum_vetseal::FR_BYTES];
                            rand::RngCore::fill_bytes(&mut rng, &mut fake_sk);
                            fake_sk[31] = 0; // little-endian: top byte 0 keeps it below the field modulus
                            let identity_hash =
                                quorum_core::hash_identity_to_g2_for_test(identity.as_bytes());
                            let (sealed_share, _pk, proof) =
                                quorum_vetseal::nizk::seal_share_with_proof(
                                    &fake_sk,
                                    &identity_hash,
                                    &transport_public_key,
                                    &mut rng,
                                )
                                .expect("sealing an invented share cannot fail");
                            Message::DerivePartial {
                                from: node_id,
                                sealed_share,
                                proof,
                            }
                        };
                        let mut out = serde_json::to_vec(&resp).unwrap();
                        out.push(b'\n');
                        let _ = write_half.write_all(&out).await;
                    }
                    // Anything else (DKG messages, audit messages): ignore.
                }
            });
        }
    });
}

// =========================================================================
// TEST B: below-threshold collusion cannot derive on its own.
// =========================================================================
async fn test_b_below_threshold_combine(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_b", 9510).await;
    let identity = "inv-adversarial-b";
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);

    // Collect T (not T+1) sealed shares directly (bypassing
    // derive_from_quorum's own threshold gate) to confirm combining
    // below-threshold sealed shares still can't produce a usable key.
    // There's no plaintext share left for quorum_core's own
    // combine to reject outright anymore (see quorum_vetseal's
    // module docs on this tradeoff) -- Lagrange-interpolating from only T
    // points evaluates the wrong polynomial, so the check now lives at
    // "does the decrypted result verify," not "did combine() error."
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let transport_pk = transport_sk.public_key();
    let mut sealed_shares: Vec<(usize, quorum_vetseal::SealedShare)> = Vec::new();
    for (id, addr) in addrs.iter().take(T) {
        let req = quorum_core::build_derive_request(
            &quorum_core::derive_node_auth_key(&q.service_auth_key, *id),
            identity,
            quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
            transport_pk,
        );
        if let Some(Message::DerivePartial { sealed_share, .. }) =
            quorum_client::send_request(&q.connector, addr, &req).await
        {
            sealed_shares.push((*id, sealed_share));
        }
    }
    report.record(
        "B0: collected exactly T sealed shares",
        sealed_shares.len() == T,
        format!(
            "collected {} (need exactly {T} for this test)",
            sealed_shares.len()
        ),
    );

    let produced_verifying_key = quorum_vetseal::combine_sealed_shares(&sealed_shares)
        .ok()
        .and_then(|combined| {
            quorum_core::Signature::from_bytes(&transport_sk.decrypt_combined(&combined)).ok()
        })
        .is_some_and(|sig| quorum_core::verify_combined(&q.group_pks, identity, &sig));
    report.record(
        "B1: T-of-N (below threshold) combine cannot produce a key that verifies",
        !produced_verifying_key,
        if produced_verifying_key {
            "INCORRECTLY produced a verifying signature from only T shares".to_string()
        } else {
            format!("combining only {T} sealed shares correctly failed to produce a key that verifies against the group public key")
        },
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST C (was CRITICAL, now re-run against the Stage A fix): node-level
// access-control bypass.
// =========================================================================
//
// quorum_service enforces ciphersettle_core::resolve_access before ever
// asking the quorum to derive anything. quorum_node itself still doesn't
// know about invoices, issuers, banks, or regulators -- that's still
// product policy, out of scope for this binary. What changed after Stage
// A: the pinned mTLS client cert is no longer sufficient *authorization*
// on its own. This test simulates an attacker who has that same shared
// client cert (the property the original finding exploited) but, unlike
// quorum_service, does NOT hold the separate `service_auth_key` -- they
// have to guess it. Confirms the guess is refused.
async fn test_c_node_level_bypass(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_c", 9520).await;
    let never_registered_id = "inv-NEVER-REGISTERED-ANYWHERE-12345";
    let addrs = node_addr_list(&q, &[0, 1, 2]);

    let attacker_guessed_key: [u8; 32] = {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    };
    let result = quorum_client::derive_from_quorum(
        &q.connector,
        &addrs,
        &q.group_pks,
        never_registered_id,
        T,
        &attacker_guessed_key,
    )
    .await;
    match result {
        Ok(sig) => {
            let verified = quorum_core::verify_combined(&q.group_pks, never_registered_id, &sig);
            report.record(
                "C: node-level bypass of quorum_service's access control",
                false,
                format!(
                    "STILL CRITICAL: derived a verified key (verify={verified}) for an invoice that was \
                     never registered through quorum_service, using only the pinned mTLS client cert -- the \
                     Stage A service_auth_key check did not actually block this."
                ),
            );
        }
        Err(e) => {
            report.record(
                "C: node-level bypass of quorum_service's access control",
                true,
                format!(
                    "bypass correctly BLOCKED: holding the shared mTLS client cert is no longer sufficient \
                     by itself -- every node refused the request for lacking a valid service_auth_key MAC \
                     (Stage A fix for Finding 1.1): {e}"
                ),
            );
        }
    }

    kill_all(&mut q.children);
}

// =========================================================================
// TEST D (re-run against the Stage A fix): replay of a captured, but
// legitimately-issued, derive request.
// =========================================================================
async fn test_d_replay(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_d", 9530).await;
    let identity = "inv-adversarial-d";
    let addr = q.addrs[0].clone();

    // A genuinely valid, correctly-signed request -- exactly what
    // quorum_service itself would send.
    let transport_pk =
        quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng()).public_key();
    let req = quorum_core::build_derive_request(
        &quorum_core::derive_node_auth_key(&q.service_auth_key, 0),
        identity,
        quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
        transport_pk,
    );
    let first = quorum_client::send_request(&q.connector, &addr, &req).await;
    // A brand-new TLS session, same exact message bytes -- simulating an
    // attacker who captured the request (e.g. from a compromised host
    // that had the client cert, or a proxy log) and resends it later.
    let replayed = quorum_client::send_request(&q.connector, &addr, &req).await;

    let first_served = matches!(first, Some(Message::DerivePartial { .. }));
    let replay_rejected = matches!(replayed, Some(Message::DeriveReject { .. }));
    let fixed = first_served && replay_rejected;
    report.record(
        "D: replayed derive request is rejected by single-use nonce tracking",
        fixed,
        if fixed {
            "confirmed FIXED: the first request was served normally; the byte-identical replay over a \
             fresh TLS connection was rejected because its nonce had already been recorded as used -- \
             Stage A closes Finding 2.1."
                .to_string()
        } else {
            format!(
                "unexpected: first_served={first_served} replay_rejected={replay_rejected} \
                 (first={first:?}, replayed={replayed:?})"
            )
        },
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST L: replay of a captured derive request across a node restart
// (roadmap T1-2 / TASK-009 / threat T-3).
// =========================================================================
//
// A node's spent-nonce set is memory-only, so a restart forgets it. The
// restart guard (`quorum_core::derive_request_predates_restart`) makes the
// node refuse any request a previous incarnation could have accepted.
//
// What this test can and cannot show (recorded honestly, see T1-2 notes):
// * The node does NOT persist its DKG share, and a restarted node never
//   re-runs DKG with its already-finished peers, so today a restarted node
//   stays in `NodeState::Dkg` and refuses every derive request anyway.
//   A replayed request is therefore rejected even WITHOUT the guard --
//   the "served after restart" exploit cannot occur in this build.
// * The guard is checked BEFORE the DKG-state check, so its refusal carries
//   the distinctive reason `RESTART_GUARD`. L3 asserts on that reason,
//   which is what makes this test discriminating: with the guard removed
//   the reply would say "DKG has not finalized" and L3 would fail.
// * The guard therefore matters once shares are persisted (future work);
//   this test pins its behaviour in a live process today.
async fn test_l_restart_replay(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_l", 9620).await;
    let identity = "inv-adversarial-l";
    let addr = q.addrs[0].clone();

    // A genuinely valid request, as quorum_service would send it.
    let transport_pk =
        quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng()).public_key();
    let req = quorum_core::build_derive_request(
        &quorum_core::derive_node_auth_key(&q.service_auth_key, 0),
        identity,
        quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
        transport_pk,
    );
    let first = quorum_client::send_request(&q.connector, &addr, &req).await;
    let first_served = matches!(first, Some(Message::DerivePartial { .. }));
    report.record(
        "L1: the captured request is served normally by the original node process (sanity check)",
        first_served,
        format!("first response: {first:?}"),
    );

    // Restart node 0 with the SAME config: same process-external state,
    // fresh process memory (empty nonce set).
    let _ = q.children[0].kill();
    let _ = q.children[0].wait();
    let node_binary = locate_sibling_binary("quorum_node");
    let config_path = q.work_dir.join("node0.json");
    let restart_at = Instant::now();
    q.children[0] = Command::new(&node_binary)
        .arg(&config_path)
        .spawn()
        .unwrap();

    // Replay the byte-identical request as soon as the restarted node
    // answers at all.
    let mut replayed = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        replayed = quorum_client::send_request(&q.connector, &addr, &req).await;
        if replayed.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let replay_served = matches!(replayed, Some(Message::DerivePartial { .. }));
    report.record(
        "L2: a request captured before the restart is NOT served after the restart",
        replayed.is_some() && !replay_served,
        format!("replay response: {replayed:?}"),
    );
    let guard_fired = match &replayed {
        Some(Message::DeriveReject { reason, .. }) => reason.contains("RESTART_GUARD"),
        _ => false,
    };
    report.record(
        "L3: the refusal comes from the restart guard (not merely from the node lacking a DKG share)",
        guard_fired,
        format!("replay response: {replayed:?}"),
    );

    // Control: once the guard period has passed, a FRESH request must not be
    // blocked by the guard. (The restarted node still has no DKG share, so
    // it is expected to refuse for that other reason -- recorded, not hidden.)
    let elapsed = restart_at.elapsed();
    let wait_total = Duration::from_millis(
        quorum_core::MAX_DERIVE_AUTH_WINDOW_MS - quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS
            + 1_000,
    );
    if elapsed < wait_total {
        tokio::time::sleep(wait_total - elapsed).await;
    }
    let transport_pk2 =
        quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng()).public_key();
    let fresh_req = quorum_core::build_derive_request(
        &quorum_core::derive_node_auth_key(&q.service_auth_key, 0),
        "inv-adversarial-l-fresh",
        quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
        transport_pk2,
    );
    let fresh = quorum_client::send_request(&q.connector, &addr, &fresh_req).await;
    let fresh_not_guard_blocked = match &fresh {
        Some(Message::DeriveReject { reason, .. }) => !reason.contains("RESTART_GUARD"),
        Some(_) => true,
        None => false,
    };
    report.record(
        "L4: after the guard period a fresh request is not refused by the guard",
        fresh_not_guard_blocked,
        format!("fresh response: {fresh:?} (a 'DKG has not finalized' refusal here is expected: nodes do not persist shares)"),
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST E (re-run against the Stage B fix): concurrent audit proposers.
// =========================================================================
//
// Two proposers race to append to the SAME log at the SAME moment (both
// starting from an empty log, both believing they're writing seq 0).
// Before Stage B, the losing proposer's event could vanish entirely: it
// got a bare `Err` with no retry, so unless the caller noticed and
// re-implemented recovery itself, that audit event was gone. Stage B adds
// a bounded retry-with-refetch loop inside
// `propose_and_cosign_and_replicate` itself: this test now expects BOTH
// proposers to succeed, each landing at a distinct sequence number, with
// BOTH events present somewhere in the final log -- not just checking
// `entries[0]`, which is exactly the check that made a perfectly healthy
// "I lost the race, retried, and landed at seq 1" outcome look like data
// loss in the original version of this test.
async fn test_e_concurrent_audit_race(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_e", 9540).await;
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);

    let event_a = AuditEvent {
        invoice_id: "inv-race".into(),
        actor: "proposer-a".into(),
        action: "action_a".into(),
        timestamp_unix_ms: 1,
    };
    let event_b = AuditEvent {
        invoice_id: "inv-race".into(),
        actor: "proposer-b".into(),
        action: "action_b".into(),
        timestamp_unix_ms: 2,
    };

    let connector_a = q.connector.clone();
    let connector_b = q.connector.clone();
    let addrs_a = addrs.clone();
    let addrs_b = addrs.clone();
    let (result_a, result_b) = tokio::join!(
        quorum_client::propose_and_cosign_and_replicate(&connector_a, &addrs_a, T, event_a),
        quorum_client::propose_and_cosign_and_replicate(&connector_b, &addrs_b, T, event_b),
    );

    let both_ok = result_a.is_ok() && result_b.is_ok();
    let log0 = quorum_client::fetch_full_log(&q.connector, &addrs[0].1)
        .await
        .unwrap();
    let actions: Vec<&str> = log0
        .entries
        .iter()
        .map(|e| e.event.action.as_str())
        .collect();
    let both_actions_present = actions.contains(&"action_a") && actions.contains(&"action_b");
    let chain_still_valid = log0.verify_chain().is_ok();
    let no_duplicate_seqs = {
        let mut seqs: Vec<u64> = log0.entries.iter().map(|e| e.seq).collect();
        let before = seqs.len();
        seqs.dedup();
        seqs.len() == before
    };

    let fixed = both_ok && both_actions_present && chain_still_valid && no_duplicate_seqs;
    report.record(
        "E: concurrent audit proposers both succeed with no lost write (Stage B retry)",
        fixed,
        if fixed {
            format!(
                "confirmed FIXED: both concurrent proposers received Ok, and both events are actually \
                 present in the final log ({actions:?}) with a valid, non-duplicated hash chain -- the \
                 losing proposer's retry-with-refetch absorbed the collision instead of silently dropping \
                 its event (Stage B closes Finding 1.2)."
            )
        } else {
            format!(
                "unexpected: a_ok={} b_ok={} both_actions_present={both_actions_present} \
                 chain_still_valid={chain_still_valid} no_duplicate_seqs={no_duplicate_seqs} actions={actions:?} \
                 -- investigate (result_a={result_a:?} could carry the last retry's error if it never \
                 recovered)",
                result_a.is_ok(), result_b.is_ok(),
            )
        },
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST X (opt-in, NOT part of the default run or CI): N concurrent proposers.
// =========================================================================
//
// Test E fixes the proposer count at 2. With n=5 nodes and a quorum of 3, two
// proposers can never deadlock (the vote split is 3/2, 4/1 or 5/0, so one
// always reaches quorum). With THREE OR MORE proposers a 2/2/1 split leaves
// nobody at quorum while every node holds its vote for up to
// `PENDING_AUDIT_VOTE_TTL` (5 s), and the client's retry budget
// (`MAX_PROPOSE_ATTEMPTS` = 8, ~0.5-0.8 s of total backoff) may be exhausted
// first. This group measures that: it asserts the SAME properties as Test E
// (every proposer Ok, every event present, valid chain, no duplicate seqs)
// for N proposers, and prints each proposer's outcome so a failure is
// diagnosable. It is a probe for a suspected liveness gap (see
// agent_memory/SECURITY_FINDINGS.md), so it is excluded from the default run:
// it runs only with `--only X` and takes the count from `--proposers N`.
async fn test_x_n_concurrent_proposers(report: &mut Report, proposers: usize) {
    let mut q = spin_up_quorum("adversarial_test_x", 9700).await;
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);

    let started = Instant::now();
    let mut handles = Vec::new();
    for i in 0..proposers {
        let connector = q.connector.clone();
        let addrs = addrs.clone();
        let event = AuditEvent {
            invoice_id: "inv-race-x".into(),
            actor: format!("proposer-{i}"),
            action: format!("action_{i}"),
            timestamp_unix_ms: 1 + i as u64,
        };
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let r =
                quorum_client::propose_and_cosign_and_replicate(&connector, &addrs, T, event).await;
            (r, t0.elapsed())
        }));
    }
    let mut outcomes: Vec<String> = Vec::new();
    let mut ok_count = 0usize;
    for (i, h) in handles.into_iter().enumerate() {
        match h.await {
            Ok((Ok(entry), d)) => {
                ok_count += 1;
                outcomes.push(format!("p{i}: OK seq={} in {}ms", entry.seq, d.as_millis()));
            }
            Ok((Err(e), d)) => {
                let short: String = e.chars().take(110).collect();
                outcomes.push(format!("p{i}: ERR in {}ms: {short}", d.as_millis()));
            }
            Err(e) => outcomes.push(format!("p{i}: task join error: {e}")),
        }
    }
    let total_ms = started.elapsed().as_millis();

    let log0 = quorum_client::fetch_full_log(&q.connector, &addrs[0].1).await;
    let (all_present, chain_ok, no_dup_seqs, n_entries) = match &log0 {
        Ok(log) => {
            let actions: Vec<&str> = log
                .entries
                .iter()
                .map(|e| e.event.action.as_str())
                .collect();
            let all_present =
                (0..proposers).all(|i| actions.contains(&format!("action_{i}").as_str()));
            let mut seqs: Vec<u64> = log.entries.iter().map(|e| e.seq).collect();
            let before = seqs.len();
            seqs.dedup();
            (
                all_present,
                log.verify_chain().is_ok(),
                seqs.len() == before,
                log.entries.len(),
            )
        }
        Err(_) => (false, false, false, 0),
    };

    let passed = ok_count == proposers && all_present && chain_ok && no_dup_seqs;
    report.record(
        &format!("X: {proposers} concurrent audit proposers all succeed with no lost write"),
        passed,
        format!(
            "proposers={proposers} ok={ok_count} entries_in_log={n_entries} all_present={all_present} \
             chain_ok={chain_ok} no_dup_seqs={no_dup_seqs} total={total_ms}ms | {}",
            outcomes.join(" ; ")
        ),
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST Y (opt-in, F-13): deterministic forced vote split.
// =========================================================================
//
// No timing luck: votes are cast by hand so the 2/2/1 split ALWAYS exists.
//   entry A -> nodes {0,1}, entry B -> nodes {2,3}, entry C -> node {4}
// No entry can reach quorum (3 of 5), and each node refuses any other entry at
// seq 0 until its pending vote commits or `PENDING_AUDIT_VOTE_TTL` (5 s)
// expires. A fresh proposer must therefore be unable to commit.
//
// This pins CURRENT behaviour (F-13): the operation ends with an explicit
// `Err`, nothing is committed anywhere, and only TTL expiry unblocks it. It
// does not assert a fix. When F-13 is fixed (design pending), the hazard
// check Y1 must change together with that design, not be deleted.
async fn test_y_forced_vote_split(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_y", 9750).await;
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);

    let empty = quorum_audit::AuditLog::default();
    let mk = |tag: &str| {
        empty.propose_next(AuditEvent {
            invoice_id: "inv-split".into(),
            actor: format!("proposer-{tag}"),
            action: format!("action_{tag}"),
            timestamp_unix_ms: 1,
        })
    };
    let plan: [(&str, &[usize]); 3] = [("A", &[0, 1]), ("B", &[2, 3]), ("C", &[4])];
    let mut votes_granted = 0usize;
    for (tag, nodes) in plan {
        let entry = mk(tag);
        for &n in nodes {
            let r = quorum_client::send_request(
                &q.connector,
                &addrs[n].1,
                &Message::AppendAuditEntry {
                    entry: entry.clone(),
                },
            )
            .await;
            if matches!(r, Some(Message::AuditEntrySigned { .. })) {
                votes_granted += 1;
            }
        }
    }
    let premise = votes_granted == 5;

    let t0 = Instant::now();
    let d_event = AuditEvent {
        invoice_id: "inv-split".into(),
        actor: "proposer-D".into(),
        action: "action_D".into(),
        timestamp_unix_ms: 2,
    };
    let r =
        quorum_client::propose_and_cosign_and_replicate(&q.connector, &addrs, T, d_event.clone())
            .await;
    let elapsed_ms = t0.elapsed().as_millis();
    let mut entries_anywhere = 0usize;
    for (_, a) in &addrs {
        if let Ok(log) = quorum_client::fetch_full_log(&q.connector, a).await {
            entries_anywhere += log.entries.len();
        }
    }
    let explicit_err = r.is_err();
    report.record(
        "Y1: forced 2/2/1 vote split -> proposer fails explicitly, nothing commits (F-13 hazard pinned)",
        premise && explicit_err && entries_anywhere == 0,
        format!(
            "votes_granted={votes_granted}/5 propose_err={explicit_err} entries_in_all_logs={entries_anywhere} \
             elapsed={elapsed_ms}ms err={}",
            r.err().unwrap_or_default().chars().take(120).collect::<String>()
        ),
    );

    // F-13: the same condition must be reported as a TYPED contention error
    // (not a bare string), distinguishable from an outage.
    let typed = quorum_client::propose_audit_entry(
        &q.connector,
        &addrs,
        T,
        AuditEvent {
            invoice_id: "inv-split".into(),
            actor: "proposer-E".into(),
            action: "action_E".into(),
            timestamp_unix_ms: 3,
        },
    )
    .await;
    report.record(
        "Y3: the stalled proposal is reported as a typed ProposeError::Contention (not an outage, not a bare string)",
        matches!(typed, Err(quorum_client::ProposeError::Contention { rejections, .. }) if rejections > 0),
        format!("{typed:?}"),
    );

    // Observation: how long until the stuck slots free themselves.
    tokio::time::sleep(Duration::from_millis(5_500)).await;
    let r2 =
        quorum_client::propose_and_cosign_and_replicate(&q.connector, &addrs, T, d_event).await;
    report.record(
        "Y2: after the 5 s vote TTL the same proposal succeeds (only TTL expiry unblocks the split)",
        r2.is_ok(),
        format!("ok={} err={:?}", r2.is_ok(), r2.as_ref().err()),
    );
    kill_all(&mut q.children);
}

// =========================================================================
// TEST Z (F-13 + F-14): service-level audit failure semantics.
// =========================================================================
//
// Owner invariants (session 06):
//  * F-14: a state change must never exist without EITHER a committed audit
//    entry OR a durable, observable pending-audit record created atomically
//    with it (transactional outbox). A failed audit append must not leave a
//    silent hole.
//  * F-13: when the audit quorum cannot make progress, the operation fails
//    EXPLICITLY (not a bare 500 after a committed change) and the work is not
//    lost; concurrent callers must not starve each other.
//
// Z2 forces the failure deterministically (hand-cast 2/2/1 vote split at seq 0,
// see Test Y), then registers an invoice through the real HTTP service.
// Z1 then fires K concurrent registrations and requires all to commit.
const Z_DB: &str =
    "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial";

async fn z_scalar_string(
    db: &tokio_postgres::Client,
    sql: &str,
    p: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Option<String>, String> {
    db.query_opt(sql, p)
        .await
        .map(|r| r.map(|row| row.get::<_, String>(0)))
        .map_err(|e| e.to_string())
}

/// Value of one Prometheus text-format sample line (`name{labels} value`).
fn z_metric(text: &str, series: &str) -> Option<f64> {
    text.lines()
        .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
        .and_then(|l| l[series.len()..].trim().parse::<f64>().ok())
}

async fn z_metrics(addr: &str, key: Option<&str>) -> (u16, String) {
    http_json(addr, "GET", "/metrics", key, None).await
}

async fn test_z_service_audit_semantics(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_z", 9800).await;
    let (db, conn) = match tokio_postgres::connect(Z_DB, tokio_postgres::NoTls).await {
        Ok(x) => x,
        Err(_) => {
            report.record(
                "Z: service audit semantics",
                false,
                "SKIPPED -- could not connect to Postgres (ciphersettle_adversarial)",
            );
            kill_all(&mut q.children);
            return;
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let service_binary = locate_sibling_binary("quorum_service");
    let service_addr = "127.0.0.1:9809".to_string();
    let key = "z-issuer-key";
    // Gap 9: the service gets its derive-auth master and API key from 0600
    // FILES (not inline config), through the real binary.
    let (master_file, apikey_file) = {
        use std::os::unix::fs::PermissionsExt;
        let m = q.work_dir.join("z_master.secret");
        let a = q.work_dir.join("z_apikey.secret");
        std::fs::write(&m, format!("{}\n", b64(&q.service_auth_key))).unwrap();
        std::fs::write(&a, format!("{key}\n")).unwrap();
        for f in [&m, &a] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (m, a)
    };
    let config = serde_json::json!({
        "listen_addr": service_addr, "db_url": Z_DB, "admin_caller_id": "z-admin",
        "api_keys": [{"key_file": apikey_file.to_string_lossy(), "caller_id": "z-issuer"}, {"key": "z-admin-key", "caller_id": "z-admin"}],
        "client_cert_der_b64": b64(&q.client_identity.cert_der),
        "client_key_der_b64": b64(&q.client_identity.key_der),
        "service_auth_key_file": master_file.to_string_lossy(),
        "quorum_nodes": (0..N).map(|i| serde_json::json!({
            "id": i, "addr": q.addrs[i], "cert_der_b64": b64(&q.node_identities[i].cert_der),
        })).collect::<Vec<_>>(),
        "notary_addr": null, "notary_cert_der_b64": null,
        "group_pubkey_file": q.pubkey_files[1].to_string_lossy(),
        "quorum_threshold": T, "max_ciphertext_bytes": 1024,
        "ciphertext_retention_ms": 999_999_999u64,
        "derive_rate_limit_max_calls": 10, "derive_rate_limit_window_ms": 60_000u64,
        "acknowledge_pre_cutover_data": true,
    });
    let config_path = q.work_dir.join("service.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut service_child = Command::new(&service_binary)
        .arg(&config_path)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(&service_addr).await.is_err() {
        if Instant::now() > deadline {
            report.record(
                "Z: service audit semantics",
                false,
                "quorum_service never started listening",
            );
            let _ = service_child.kill();
            let _ = service_child.wait();
            kill_all(&mut q.children);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);
    let post_invoice = |id: String| {
        let sa = service_addr.clone();
        async move {
            http_json(
                &sa,
                "POST",
                "/invoices",
                Some(key),
                Some(
                    &serde_json::json!({"invoice_id": id, "nullifier_hash": format!("z-null-{id}"),
                    "ciphertext_b64": b64(b"x"), "commitment_b64": sample_commitment_b64(&id)})
                    .to_string(),
                ),
            )
            .await
        }
    };

    // ---- Z2: forced audit failure --------------------------------------
    let empty = quorum_audit::AuditLog::default();
    let mut granted = 0usize;
    for (tag, nodes) in [("A", vec![0usize, 1]), ("B", vec![2, 3]), ("C", vec![4])] {
        let entry = empty.propose_next(AuditEvent {
            invoice_id: "z-split".into(),
            actor: format!("z-{tag}"),
            action: format!("z_action_{tag}"),
            timestamp_unix_ms: 1,
        });
        for n in nodes {
            let r = quorum_client::send_request(
                &q.connector,
                &addrs[n].1,
                &Message::AppendAuditEntry {
                    entry: entry.clone(),
                },
            )
            .await;
            if matches!(r, Some(Message::AuditEntrySigned { .. })) {
                granted += 1;
            }
        }
    }
    let inv2 = format!("z2-{run_id}");
    let (st2, body2) = post_invoice(inv2.clone()).await;
    let row_exists = db
        .query_opt("SELECT 1 FROM invoices WHERE invoice_id = $1", &[&inv2])
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);
    let outbox_status = z_scalar_string(
        &db,
        "SELECT status FROM audit_outbox WHERE invoice_id = $1 AND action = 'invoice_registered'",
        &[&inv2],
    )
    .await;
    report.record(
        "Z2a: audit append fails -> explicit 202 'committed, audit pending' (never a bare 500 after a committed change)",
        granted == 5 && st2 == 202 && body2.contains("pending"),
        format!("split_votes={granted}/5 http={st2} body={}", body2.chars().take(160).collect::<String>()),
    );
    let (mst, mbody) = z_metrics(&service_addr, Some("z-admin-key")).await;
    let pend = z_metric(&mbody, "ciphersettle_audit_outbox_rows{status=\"pending\"}");
    let age = z_metric(
        &mbody,
        "ciphersettle_audit_outbox_oldest_unfinished_age_seconds",
    );
    report.record(
        "Z7a: while an audit is pending, /metrics shows it (pending >= 1, oldest age > 0) so an alert can fire",
        mst == 200 && pend.is_some_and(|v| v >= 1.0) && age.is_some_and(|v| v > 0.0),
        format!("status={mst} pending={pend:?} oldest_age_s={age:?}"),
    );
    report.record(
        "Z2b: F-14 atomicity: the state change is NEVER present without a durable pending-audit (outbox) record",
        !row_exists || matches!(&outbox_status, Ok(Some(_))),
        format!("invoice_row_exists={row_exists} outbox_status={outbox_status:?}"),
    );
    // The outbox must drain on its own once the vote slots free (5 s TTL).
    let mut drained = false;
    let mut entries_for_inv = 0usize;
    let mut chain_ok = false;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(25) {
        let st = z_scalar_string(&db,
            "SELECT status FROM audit_outbox WHERE invoice_id = $1 AND action = 'invoice_registered'", &[&inv2]).await;
        if matches!(&st, Ok(Some(s)) if s == "done") {
            if let Ok(log) = quorum_client::fetch_full_log(&q.connector, &addrs[1].1).await {
                entries_for_inv = log
                    .entries
                    .iter()
                    .filter(|e| e.event.invoice_id == inv2)
                    .count();
                chain_ok = log.verify_chain().is_ok();
                drained = entries_for_inv >= 1;
                if drained {
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    report.record(
        "Z2c: the pending audit is committed automatically once progress is possible, exactly once, chain valid (no lost evidence)",
        drained && entries_for_inv == 1 && chain_ok,
        format!("drained={drained} entries_for_invoice={entries_for_inv} chain_ok={chain_ok} after={}ms", t0.elapsed().as_millis()),
    );

    // ---- Z1: K concurrent registrations through the live service -------
    const K: usize = 8;
    let mut hs = Vec::new();
    for i in 0..K {
        let id = format!("z1-{run_id}-{i}");
        hs.push(tokio::spawn({
            let f = post_invoice(id.clone());
            async move { (id, f.await) }
        }));
    }
    let mut ids = Vec::new();
    let mut statuses = Vec::new();
    for h in hs {
        if let Ok((id, (st, _))) = h.await {
            ids.push(id);
            statuses.push(st);
        }
    }
    let all_201 = statuses.len() == K && statuses.iter().all(|s| *s == 201);
    // Wait for any outbox rows to drain, then require every invoice audited once.
    let t1 = Instant::now();
    let mut per_invoice: Vec<usize> = vec![0; ids.len()];
    let mut pending_left = i64::MAX;
    while t1.elapsed() < Duration::from_secs(25) {
        pending_left = db
            .query_one(
                "SELECT count(*) FROM audit_outbox WHERE invoice_id LIKE $1 AND status <> 'done'",
                &[&format!("z1-{run_id}-%")],
            )
            .await
            .map(|r| r.get(0))
            .unwrap_or(i64::MAX);
        if let Ok(log) = quorum_client::fetch_full_log(&q.connector, &addrs[1].1).await {
            for (i, id) in ids.iter().enumerate() {
                per_invoice[i] = log
                    .entries
                    .iter()
                    .filter(|e| e.event.invoice_id == *id && e.event.action == "invoice_registered")
                    .count();
            }
        }
        if pending_left == 0 && per_invoice.iter().all(|c| *c == 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    report.record(
        "Z1a: 8 concurrent registrations through the live service all succeed with 201 (no caller starved by audit contention)",
        all_201,
        format!("statuses={statuses:?}"),
    );
    report.record(
        "Z1b: every one of the 8 is audited exactly once and nothing is left pending (no lost write, no duplicate)",
        pending_left == 0 && per_invoice.iter().all(|c| *c == 1),
        format!("pending_left={pending_left} per_invoice_counts={per_invoice:?}"),
    );
    let orphans: i64 = db.query_one(
        "SELECT count(*) FROM invoices i WHERE i.invoice_id LIKE $1 AND NOT EXISTS (SELECT 1 FROM audit_outbox o WHERE o.invoice_id = i.invoice_id AND o.action = 'invoice_registered')",
        &[&format!("z%-{run_id}%")]).await.map(|r| r.get(0)).unwrap_or(-1);
    report.record(
        "Z3: no invoice from this run exists without an outbox/audit record (F-14 invariant over the whole table)",
        orphans == 0,
        format!("invoices_without_outbox_record={orphans}"),
    );

    // ---- Z4 (Gap 8 / F-21): malformed request field must not panic a handler.
    let bad_id = format!("z4-bad-{run_id}");
    let (st_bad, body_bad) = http_json(
        &service_addr,
        "POST",
        "/invoices",
        Some(key),
        Some(
            &serde_json::json!({"invoice_id": bad_id, "nullifier_hash": format!("z-null-{bad_id}"),
            "ciphertext_b64": "!!! not base64 !!!", "commitment_b64": sample_commitment_b64(&bad_id)})
            .to_string(),
        ),
    )
    .await;
    let (st_ok, _) = post_invoice(format!("z4-ok-{run_id}")).await;
    report.record(
        "Z4: invalid base64 in ciphertext_b64 is a clean 400 (not a panicked handler) and the service keeps serving",
        st_bad == 400 && (st_ok == 201 || st_ok == 202),
        format!("bad_status={st_bad} body={body_bad:?} next_valid_status={st_ok}"),
    );

    // ---- Z7 (Gap 11): /metrics is admin-only and matches the database.
    let (st_noauth, _) = z_metrics(&service_addr, None).await;
    let (st_issuer, _) = z_metrics(&service_addr, Some(key)).await;
    report.record(
        "Z7b: /metrics requires authentication (401 without a key) and the admin (403 for a non-admin key)",
        st_noauth == 401 && st_issuer == 403,
        format!("no_key={st_noauth} issuer_key={st_issuer}"),
    );
    // Let the drainer finish everything, then compare gauges with SQL truth.
    let t0 = Instant::now();
    loop {
        let open: i64 = db
            .query_one(
                "SELECT count(*) FROM audit_outbox WHERE status <> 'done'",
                &[],
            )
            .await
            .map(|r| r.get(0))
            .unwrap_or(-1);
        if open == 0 || t0.elapsed() > Duration::from_secs(20) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let (_, m) = z_metrics(&service_addr, Some("z-admin-key")).await;
    let sql_done: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_outbox WHERE status = 'done'",
            &[],
        )
        .await
        .map(|r| r.get(0))
        .unwrap_or(-1);
    let sql_inv: i64 = db
        .query_one("SELECT count(*) FROM invoices", &[])
        .await
        .map(|r| r.get(0))
        .unwrap_or(-1);
    let sql_fail: i64 = db
        .query_one("SELECT count(*) FROM audit_failures", &[])
        .await
        .map(|r| r.get(0))
        .unwrap_or(-1);
    let g_done = z_metric(&m, "ciphersettle_audit_outbox_rows{status=\"done\"}");
    let g_pend = z_metric(&m, "ciphersettle_audit_outbox_rows{status=\"pending\"}");
    let g_inv = z_metric(&m, "ciphersettle_invoices_total");
    let g_fail = z_metric(&m, "ciphersettle_audit_failures_total");
    let g_age = z_metric(
        &m,
        "ciphersettle_audit_outbox_oldest_unfinished_age_seconds",
    );
    let leaks = [
        "z-issuer-key",
        "z-admin-key",
        "postgres://",
        "ciphersettle_dev",
        "api_key",
    ]
    .iter()
    .any(|s| m.contains(s));
    report.record(
        "Z7c: /metrics gauges equal the database (done/invoices/failures), nothing pending after drain, age 0, and no secret appears in the output",
        g_done == Some(sql_done as f64) && g_pend == Some(0.0) && g_inv == Some(sql_inv as f64)
            && g_fail == Some(sql_fail as f64) && g_age == Some(0.0) && !leaks,
        format!("done={g_done:?}/{sql_done} pending={g_pend:?} invoices={g_inv:?}/{sql_inv} failures={g_fail:?}/{sql_fail} age={g_age:?} leaks={leaks}"),
    );

    // ---- Z5 (Gap 8 / T-9): malformed-body sweep over every POST route. No
    // response may be a 5xx or a dropped connection (status 0); the service
    // must still serve a valid request afterwards.
    let sweep_id = format!("z4-ok-{run_id}");
    let routes = [
        "/invoices".to_string(),
        format!("/invoices/{sweep_id}/grant"),
        format!("/invoices/{sweep_id}/revoke"),
        format!("/invoices/{sweep_id}/settle"),
        format!("/invoices/{sweep_id}/prune"),
        format!("/invoices/{sweep_id}/derive-key"),
        "/regulators".to_string(),
    ];
    let bodies: Vec<String> = vec![
        String::new(),
        "{}".into(),
        "[]".into(),
        "null".into(),
        "\"x\"".into(),
        "{\"a\":".into(),
        "\u{0}".into(),
        "{\"invoice_id\":1,\"nullifier_hash\":null,\"ciphertext_b64\":[],\"commitment_b64\":{}}".into(),
        "{\"invoice_id\":\"x\",\"nullifier_hash\":\"y\",\"ciphertext_b64\":\"\",\"commitment_b64\":\"\"}".into(),
        "{\"bank\":18446744073709551616,\"principal\":-1}".into(),
        "{\"transport_public_key_b64\":\"!!!\"}".into(),
        "{\"transport_public_key_b64\":\"AAAA\",\"used_node_ids\":[18446744073709551615,-1,null]}".into(),
        format!("{{\"bank\":\"{}\",\"principal\":\"{}\"}}", "A".repeat(1 << 20), "B".repeat(1 << 16)),
        format!("{}{}", "[".repeat(5000), "]".repeat(5000)),
        "\u{feff}{\"bank\":\"x\"}".into(),
        "{\"invoice_id\":\"z5-b64\",\"nullifier_hash\":\"n\",\"ciphertext_b64\":\"!!!\",\"commitment_b64\":\"!!!\"}".into(),
    ];
    let mut sweep_bad: Vec<String> = Vec::new();
    let mut sweep_n = 0usize;
    for r in &routes {
        for b in &bodies {
            sweep_n += 1;
            let (st, _) = http_json(&service_addr, "POST", r, Some(key), Some(b)).await;
            if st == 0 || st >= 500 {
                sweep_bad.push(format!("{r} body_len={} -> {st}", b.len()));
            }
        }
    }
    // ---- Z6 (Gap 11): unauthenticated health endpoints exist and leak nothing.
    let (st_h, body_h) = http_json(&service_addr, "GET", "/healthz", None, None).await;
    let (st_r, body_r) = http_json(&service_addr, "GET", "/readyz", None, None).await;
    let leak = [key, "postgres", "password", "ciphersettle_dev"]
        .iter()
        .any(|w| body_h.contains(w) || body_r.contains(w));
    report.record(
        "Z6: /healthz and /readyz answer 200 without credentials and expose no secret or DB detail",
        st_h == 200 && st_r == 200 && !leak,
        format!("healthz={st_h} {body_h:?} readyz={st_r} {body_r:?} leak={leak}"),
    );
    let (st_after, _) = post_invoice(format!("z5-after-{run_id}")).await;
    report.record(
        "Z5: 112 malformed/hostile JSON bodies across all 7 POST routes never cause a 5xx or dropped connection, and the service still serves afterwards",
        sweep_bad.is_empty() && sweep_n == 112 && (st_after == 201 || st_after == 202),
        format!("requests={sweep_n} bad={sweep_bad:?} next_valid_status={st_after}"),
    );

    // ---- Z8 (Gap 11): /readyz reflects quorum reachability (needs t+1 = 3 of 5 nodes).
    // The result is cached ~1 s inside the service, so wait past it after each change.
    let readyz = || async {
        tokio::time::sleep(Duration::from_millis(1600)).await;
        http_json(&service_addr, "GET", "/readyz", None, None).await
    };
    let (r_all, _) = readyz().await;
    for i in [3usize, 4] {
        let _ = q.children[i].kill();
        let _ = q.children[i].wait();
    }
    let (r_three, _) = readyz().await;
    report.record(
        "Z8a: /readyz stays 200 while exactly t+1 = 3 of 5 nodes are reachable",
        r_all == 200 && r_three == 200,
        format!("all_up={r_all} three_up={r_three}"),
    );
    let _ = q.children[2].kill();
    let _ = q.children[2].wait();
    let (r_two, body_two) = readyz().await;
    let (h_two, _) = http_json(&service_addr, "GET", "/healthz", None, None).await;
    let leak2 = ["127.0.0.1", "98", "node", "postgres", "password"]
        .iter()
        .any(|w| body_two.contains(w));
    report.record(
        "Z8b: /readyz turns 503 when fewer than 3 nodes are reachable (the service cannot release keys), /healthz stays 200, and the body names no node or address",
        r_two == 503 && h_two == 200 && !leak2,
        format!("two_up_readyz={r_two} body={body_two:?} healthz={h_two} leak={leak2}"),
    );

    let _ = service_child.kill();
    let _ = service_child.wait();
    kill_all(&mut q.children);
}

// =========================================================================
// TEST T (Gap 9 slice): secrets loaded from files; unsafe sources refused.
// =========================================================================
//  T1  service: a secret file readable by group/other => refuses to start
//  T2  node: the same secret given inline AND by file => refuses to start
//  T3  neither refusal prints the secret value
// (The happy path is exercised by group Z, whose service gets its derive-auth
// master and API key from 0600 files.)
fn t_run_refusal(
    binary: &str,
    config: &serde_json::Value,
    dir: &std::path::Path,
    name: &str,
) -> (Option<i32>, String) {
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec(config).unwrap_or_default()).unwrap();
    match Command::new(locate_sibling_binary(binary))
        .arg(&path)
        .output()
    {
        Ok(o) => (
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        ),
        Err(e) => (None, format!("spawn failed: {e}")),
    }
}

async fn test_t_secret_files(report: &mut Report) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("adversarial_t_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = "T-SECRET-VALUE-0123456789";
    let loose = dir.join("loose.secret");
    std::fs::write(&loose, secret).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let tight = dir.join("tight.secret");
    std::fs::write(&tight, secret).unwrap();
    std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (code1, err1) = t_run_refusal(
        "quorum_service",
        &serde_json::json!({"service_auth_key_file": loose.to_string_lossy()}),
        &dir,
        "svc_loose",
    );
    report.record(
        "T1: service refuses a group/other-readable secret file (exit 1, says why)",
        code1 == Some(1) && err1.contains("permissions"),
        format!("exit={code1:?} stderr={err1:?}"),
    );
    let (code2, err2) = t_run_refusal(
        "quorum_node",
        &serde_json::json!({
            "service_auth_key_b64": "aW5saW5l",
            "service_auth_key_file": tight.to_string_lossy()
        }),
        &dir,
        "node_both",
    );
    report.record(
        "T2: node refuses a secret given both inline and by file (exit 1, says why)",
        code2 == Some(1) && err2.contains("both"),
        format!("exit={code2:?} stderr={err2:?}"),
    );
    report.record(
        "T3: refusals never print the secret value",
        !err1.contains(secret) && !err2.contains(secret),
        "stderr of T1/T2 checked for the secret string".to_string(),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// =========================================================================
// TEST Q (Gap 13 / F-01): audit-log durability across kill -9 and corruption.
// =========================================================================
//
// Closed-when for Gap 13: killing the process at random points during writes
// never leaves a corrupt or truncated log; a damaged log is never silently
// replaced by an empty one.
//  Q1  all 5 nodes hold 6 committed entries, SIGKILL all: every node's file
//      parses, its hash chain verifies, and it still holds the 6 entries.
//  Q2  after restarting from those files a new append lands as entry 7.
//  Q3  3 rounds of SIGKILL in the middle of a burst of appends: after every
//      kill every node's file parses and verifies (any length), and the
//      cluster restarts.
//  Q4-Q6  a corrupt / truncated / tampered log file => the node REFUSES to
//      start (non-zero exit, no ready file) instead of starting empty.
// NOTE (not asserted, see SECURITY_FINDINGS F-19): propose returns Ok after a
// fire-and-forget replicate, so an acknowledged entry is not guaranteed to be
// durable on any node at the instant of a kill. Q1 therefore polls until all
// nodes hold the entries before killing.
fn q_read_log(nodes: &PNodes, id: usize) -> Result<quorum_audit::AuditLog, String> {
    // F-20: the node persists snapshot + append-only journal; read both.
    quorum_audit::journal::load_log(&nodes.path("audit_log.json", id)).map_err(|e| format!("{e}"))
}

async fn test_q_audit_log_durability(report: &mut Report) {
    let work = PathBuf::from("/tmp/adversarial_test_q");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let base_port = 9940u16;
    let nodes = PNodes {
        work: work.clone(),
        ids: (0..N).map(|_| generate_identity()).collect(),
        audit: (0..N).map(|_| generate_audit_keypair()).collect(),
        client: generate_identity(),
        addrs: (0..N)
            .map(|i| format!("127.0.0.1:{}", base_port + i as u16))
            .collect(),
        auth_key: generate_service_auth_key(),
    };
    for id in 0..N {
        nodes.write_kek(id);
    }
    let ready: Vec<PathBuf> = (0..N).map(|i| nodes.path("ready", i)).collect();
    let connector = quorum_client::build_connector(
        nodes.client.cert_der.clone(),
        nodes.client.key_der.clone(),
        nodes.ids.iter().map(|n| n.cert_der.clone()).collect(),
    )
    .expect("test TLS identity");
    let addrs: Vec<(usize, String)> = nodes.addrs.iter().cloned().enumerate().collect();
    let ev = |tag: &str, i: usize| AuditEvent {
        invoice_id: format!("q-{tag}-{i}"),
        actor: "q".into(),
        action: format!("q_action_{tag}_{i}"),
        timestamp_unix_ms: 1 + i as u64,
    };

    let mut children: Vec<Child> = (0..N).map(|i| nodes.spawn(i, true)).collect();
    wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;

    // ---- Q1: committed entries survive SIGKILL of every node ----
    let mut appended = 0usize;
    for i in 0..6 {
        if quorum_client::propose_audit_entry(&connector, &addrs, T, ev("a", i))
            .await
            .is_ok()
        {
            appended += 1;
        }
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10)
        && !(0..N).all(|i| {
            q_read_log(&nodes, i)
                .map(|l| l.entries.len() >= appended)
                .unwrap_or(false)
        })
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    kill_all(&mut children); // SIGKILL + wait
    let after_kill: Vec<Result<usize, String>> = (0..N)
        .map(|i| q_read_log(&nodes, i).map(|l| l.entries.len()))
        .collect();
    report.record(
        "Q1: after SIGKILL of every node, each audit-log file parses, its hash chain verifies, and it holds all committed entries",
        appended == 6 && after_kill.iter().all(|r| matches!(r, Ok(n) if *n == appended)),
        format!("appended={appended} per_node={after_kill:?}"),
    );

    // ---- Q2: restart from the files; the log continues ----
    for i in 0..N {
        nodes.clear_outputs(i);
    }
    let mut children: Vec<Child> = (0..N).map(|i| nodes.spawn(i, false)).collect();
    wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;
    let tip_before = quorum_client::fetch_majority_tip(&connector, &addrs).await;
    let next = quorum_client::propose_audit_entry(&connector, &addrs, T, ev("b", 0)).await;
    report.record(
        "Q2: after restarting from the persisted files the majority tip is intact and a new entry lands at seq 6",
        matches!(&tip_before, Ok(l) if l.entries.len() == 6)
            && matches!(&next, Ok(e) if e.seq == 6),
        format!(
            "tip_len={:?} next={:?}",
            tip_before.as_ref().map(|l| l.entries.len()).map_err(|e| e.clone()),
            next.as_ref().map(|e| e.seq).map_err(|e| e.to_string())
        ),
    );

    // ---- Q3: SIGKILL in the middle of a burst, 3 rounds ----
    let mut q3_ok = true;
    let mut q3_notes: Vec<String> = Vec::new();
    for round in 0..3usize {
        let burst = {
            let connector = connector.clone();
            let addrs = addrs.clone();
            tokio::spawn(async move {
                let mut ok = 0usize;
                for i in 0..200 {
                    let e = AuditEvent {
                        invoice_id: format!("q-burst-{round}-{i}"),
                        actor: "q".into(),
                        action: "burst".into(),
                        timestamp_unix_ms: 1 + i as u64,
                    };
                    if quorum_client::propose_audit_entry(&connector, &addrs, T, e)
                        .await
                        .is_ok()
                    {
                        ok += 1;
                    }
                }
                ok
            })
        };
        let delay = 150
            + (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0)
                % 600);
        tokio::time::sleep(Duration::from_millis(delay)).await;
        kill_all(&mut children);
        burst.abort();
        let lens: Vec<Result<usize, String>> = (0..N)
            .map(|i| q_read_log(&nodes, i).map(|l| l.entries.len()))
            .collect();
        let intact = lens.iter().all(|r| r.is_ok());
        q3_ok &= intact;
        q3_notes.push(format!(
            "round {round}: killed after {delay}ms lens={lens:?}"
        ));
        for i in 0..N {
            nodes.clear_outputs(i);
        }
        children = (0..N).map(|i| nodes.spawn(i, false)).collect();
        wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;
    }
    report.record(
        "Q3: 3 rounds of SIGKILL in the middle of an append burst never leave a corrupt or truncated audit log, and the cluster restarts every time",
        q3_ok,
        q3_notes.join(" | "),
    );
    kill_all(&mut children);

    // ---- Q4-Q6: damaged log => refuse to start, never start empty ----
    // F-20: node 1's state may live partly in the journal; materialise the full log
    // as one snapshot file (the damaged-snapshot cases below then apply to it).
    let valid = quorum_audit::journal::load_log(&nodes.path("audit_log.json", 1))
        .ok()
        .and_then(|l| serde_json::to_vec_pretty(&l).ok())
        .unwrap_or_default();
    // Frames for node 1's entries, captured BEFORE Q5 overwrites node 1's files.
    let full_log = quorum_audit::journal::load_log(&nodes.path("audit_log.json", 1)).ok();
    let frames: Vec<Vec<u8>> = full_log
        .as_ref()
        .map(|l| {
            l.entries
                .iter()
                .filter_map(|e| {
                    quorum_audit::journal::encode_frame(&quorum_audit::journal::Record::Append {
                        entry: e.clone(),
                    })
                    .ok()
                })
                .collect()
        })
        .unwrap_or_default();
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&valid).unwrap_or(serde_json::Value::Null);
    if let Some(a) = tampered["entries"][1]["event"].get_mut("action") {
        *a = serde_json::Value::String("tampered".into());
    }
    let cases: Vec<(&str, usize, Vec<u8>, &str)> = vec![
        (
            "Q4: a garbage audit-log file",
            0,
            b"not json at all".to_vec(),
            "Q4",
        ),
        (
            "Q5: a truncated audit-log file",
            1,
            valid[..valid.len() / 2].to_vec(),
            "Q5",
        ),
        (
            "Q6: an audit log whose hash chain was tampered with",
            2,
            serde_json::to_vec(&tampered).unwrap_or_default(),
            "Q6",
        ),
    ];
    for (name, id, bytes, _) in cases {
        nodes.clear_outputs(id);
        std::fs::write(nodes.path("audit_log.json", id), &bytes).unwrap();
        let _ = std::fs::remove_file(quorum_audit::journal::journal_path(
            &nodes.path("audit_log.json", id),
        ));
        let mut child = nodes.spawn(id, false);
        let (refused, why) = p_exits_nonzero(&mut child, Duration::from_secs(15)).await;
        let started = nodes.path("ready", id).exists();
        let logtxt = std::fs::read_to_string(nodes.path("log", id)).unwrap_or_default();
        let msg_ok = logtxt.contains("audit log");
        report.record(
            &format!("{name} makes the node refuse to start (non-zero exit, no ready file) instead of silently starting with an empty log"),
            refused && !started && msg_ok,
            format!("exit_nonzero={refused} ({why}) ready_file_written={started} error_mentions_audit_log={msg_ok}"),
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    // ---- Q7/Q8 (F-20): the append-only journal on the real node ----
    let have_frames = frames.len() >= 2;
    // Q7: one flipped bit inside the FIRST frame of a journal that has later frames.
    {
        let id = 3usize;
        nodes.clear_outputs(id);
        let snap = nodes.path("audit_log.json", id);
        let _ = std::fs::remove_file(&snap);
        let mut jr: Vec<u8> = frames.iter().flatten().copied().collect();
        if let Some(b) = jr.get_mut(12) {
            *b ^= 0x01;
        }
        std::fs::write(quorum_audit::journal::journal_path(&snap), &jr).unwrap();
        let mut child = nodes.spawn(id, false);
        let (refused, why) = p_exits_nonzero(&mut child, Duration::from_secs(15)).await;
        let started = nodes.path("ready", id).exists();
        let logtxt = std::fs::read_to_string(nodes.path("log", id)).unwrap_or_default();
        let unchanged = std::fs::read(quorum_audit::journal::journal_path(&snap))
            .ok()
            .as_deref()
            == Some(jr.as_slice());
        report.record(
            "Q7: a damaged frame in the audit-log JOURNAL makes the node refuse to start and leaves the journal untouched",
            have_frames && refused && !started && logtxt.contains("audit log") && unchanged,
            format!("frames={} exit_nonzero={refused} ({why}) ready_file_written={started} journal_unchanged={unchanged}", frames.len()),
        );
        let _ = child.kill();
        let _ = child.wait();
    }
    // Q8: an INCOMPLETE final frame (a write that was never acknowledged) is cut
    // off at startup; the acknowledged entries before it survive.
    {
        let id = 4usize;
        nodes.clear_outputs(id);
        let snap = nodes.path("audit_log.json", id);
        let _ = std::fs::remove_file(&snap);
        let good: Vec<u8> = frames.iter().flatten().copied().collect();
        let mut jr = good.clone();
        if let Some(first) = frames.first() {
            jr.extend_from_slice(&first[..first.len() / 2]);
        }
        let jp = quorum_audit::journal::journal_path(&snap);
        std::fs::write(&jp, &jr).unwrap();
        let mut child = nodes.spawn(id, false);
        let (exited_nonzero, why) = p_exits_nonzero(&mut child, Duration::from_secs(8)).await;
        let truncated = std::fs::metadata(&jp).map(|m| m.len() as usize).ok() == Some(good.len());
        let logtxt = std::fs::read_to_string(nodes.path("log", id)).unwrap_or_default();
        report.record(
            "Q8: an incomplete final audit-log journal frame is truncated at startup and the node does NOT refuse to start",
            have_frames && !exited_nonzero && truncated && !logtxt.contains("corrupt audit log"),
            format!("frames={} exited_nonzero={exited_nonzero} ({why}) journal_truncated_to_last_good_frame={truncated}", frames.len()),
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}

// =========================================================================
// TEST R (F-19): an acknowledged audit entry is durable on >= t+1 nodes.
// =========================================================================
//
// `propose_audit_entry` used to return Ok after FIRE-AND-FORGET replication,
// so an entry the caller (and the service's outbox) treated as recorded could
// exist on no disk if the cluster died right after. Each round: restart the
// cluster, append one entry, and the INSTANT the call returns Ok, SIGKILL all
// nodes. The entry must then be in at least t+1 = 3 node files.
async fn test_r_ack_implies_durable(report: &mut Report) {
    let work = PathBuf::from("/tmp/adversarial_test_r");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let base_port = 9960u16;
    let nodes = PNodes {
        work: work.clone(),
        ids: (0..N).map(|_| generate_identity()).collect(),
        audit: (0..N).map(|_| generate_audit_keypair()).collect(),
        client: generate_identity(),
        addrs: (0..N)
            .map(|i| format!("127.0.0.1:{}", base_port + i as u16))
            .collect(),
        auth_key: generate_service_auth_key(),
    };
    for id in 0..N {
        nodes.write_kek(id);
    }
    let ready: Vec<PathBuf> = (0..N).map(|i| nodes.path("ready", i)).collect();
    let connector = quorum_client::build_connector(
        nodes.client.cert_der.clone(),
        nodes.client.key_der.clone(),
        nodes.ids.iter().map(|n| n.cert_der.clone()).collect(),
    )
    .expect("test TLS identity");
    let addrs: Vec<(usize, String)> = nodes.addrs.iter().cloned().enumerate().collect();
    let mut children: Vec<Child> = (0..N).map(|i| nodes.spawn(i, true)).collect();
    wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;

    const ROUNDS: usize = 8;
    let mut worst = usize::MAX;
    let mut per_round: Vec<String> = Vec::new();
    let mut acked_rounds = 0usize;
    for round in 0..ROUNDS {
        let r = quorum_client::propose_audit_entry(
            &connector,
            &addrs,
            T,
            AuditEvent {
                invoice_id: format!("r-{round}"),
                actor: "r".into(),
                action: "r_action".into(),
                timestamp_unix_ms: 1 + round as u64,
            },
        )
        .await;
        kill_all(&mut children); // immediately after the acknowledgement
        if let Ok(entry) = r {
            acked_rounds += 1;
            let holders = (0..N)
                .filter(|&i| {
                    q_read_log(&nodes, i)
                        .map(|l| l.entries.iter().any(|e| e.entry_hash == entry.entry_hash))
                        .unwrap_or(false)
                })
                .count();
            worst = worst.min(holders);
            per_round.push(format!("r{round}:{holders}"));
        } else {
            per_round.push(format!("r{round}:ERR"));
        }
        for i in 0..N {
            nodes.clear_outputs(i);
        }
        children = (0..N).map(|i| nodes.spawn(i, false)).collect();
        wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;
    }
    report.record(
        "R: after propose returns Ok and every node is SIGKILLed immediately, the entry is on disk on at least t+1 nodes (every round)",
        acked_rounds == ROUNDS && worst > T,
        format!("acked_rounds={acked_rounds}/{ROUNDS} min_durable_holders={worst} (need >= {}) [{}]", T + 1, per_round.join(" ")),
    );
    kill_all(&mut children);
}

// =========================================================================
// TEST S (Gap 3, step 1): one node's leaked auth key must not reach the others.
// =========================================================================
//
// Every node used to hold the SAME derive-authorization secret, so stealing it
// from any one node (config, backup, memory) let an attacker forge a request
// that ALL nodes accepted: a full key derivation without the service. Now node
// i is provisioned only with HKDF(master, i). The attacker below holds node 0's
// REAL key and sends a validly MAC'd request to all 5 nodes. At most node 0
// may answer, which is below the t+1 = 3 partials needed to derive anything.
async fn test_s_leaked_node_key_is_contained(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_s", 9830).await;
    let leaked_node0_key = quorum_core::derive_node_auth_key(&q.service_auth_key, 0);
    let attacker_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let attacker_pk = attacker_sk.public_key();
    // The restart guard refuses requests that predate the node's start window;
    // wait it out so a refusal here can only come from the MAC check.
    tokio::time::sleep(Duration::from_millis(
        quorum_core::MAX_DERIVE_AUTH_WINDOW_MS - quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS + 500,
    ))
    .await;
    let req = quorum_core::build_derive_request(
        &leaked_node0_key,
        "inv-never-registered-anywhere",
        quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
        attacker_pk,
    );
    let mut answered: Vec<usize> = Vec::new();
    for i in 0..N {
        if let Some(Message::DerivePartial { .. }) =
            quorum_client::send_request(&q.connector, &q.addrs[i], &req).await
        {
            answered.push(i);
        }
    }
    report.record(
        "S1: a request forged with ONE node's leaked key is accepted by that node only (fewer than t+1 partials, no derivation possible)",
        answered == vec![0] && answered.len() <= T,
        format!("nodes that served the forged request: {answered:?} (need {} to derive)", T + 1),
    );
    kill_all(&mut q.children);
}

// =========================================================================
// TEST I: audit-log tip read no longer trusts a single hardcoded node.
// =========================================================================
//
// Reproduces Finding 2.2 directly: propose two entries normally so all 5
// nodes are caught up, then kill node_addrs[0]'s process outright (not
// just partition it -- fully offline) and propose a third entry. Under
// the pre-Stage-F code, `try_propose_once` read the tip exclusively from
// `node_addrs[0]`; with that node dead, `fetch_full_log` against it would
// fail every single time, `propose_and_cosign_and_replicate`'s retry loop
// would burn all `MAX_PROPOSE_ATTEMPTS` retrying an unreachable node, and
// the whole operation would return `Err` -- despite the other 4 nodes (an
// easy majority) being healthy, reachable, and perfectly able to serve a
// correct tip and co-sign the entry themselves. Stage F's
// `fetch_majority_tip` reads from every node and only needs a majority to
// respond with a valid, chain-verified log, so this should now succeed
// immediately, using nodes 1-4, with node 0 correctly excluded.
async fn test_i_majority_tip_read(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_i", 9600).await;
    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);

    let event1 = AuditEvent {
        invoice_id: "inv-tip".into(),
        actor: "setup".into(),
        action: "action_1".into(),
        timestamp_unix_ms: 1,
    };
    let event2 = AuditEvent {
        invoice_id: "inv-tip".into(),
        actor: "setup".into(),
        action: "action_2".into(),
        timestamp_unix_ms: 2,
    };
    quorum_client::propose_and_cosign_and_replicate(&q.connector, &addrs, T, event1)
        .await
        .expect("setup propose 1 should succeed with a full healthy quorum");
    quorum_client::propose_and_cosign_and_replicate(&q.connector, &addrs, T, event2)
        .await
        .expect("setup propose 2 should succeed with a full healthy quorum");

    // node_addrs[0] specifically -- the node the pre-fix code hardcoded
    // its tip read to -- is now killed outright.
    q.children[0].kill().unwrap();
    let _ = q.children[0].wait();
    tokio::time::sleep(Duration::from_millis(300)).await; // let the OS finish tearing the socket down

    let event3 = AuditEvent {
        invoice_id: "inv-tip".into(),
        actor: "proposer".into(),
        action: "action_3".into(),
        timestamp_unix_ms: 3,
    };
    let start = Instant::now();
    let result =
        quorum_client::propose_and_cosign_and_replicate(&q.connector, &addrs, T, event3).await;
    let elapsed = start.elapsed();

    let succeeded = result.is_ok();
    let landed_at_seq_2 = matches!(&result, Ok(entry) if entry.seq == 2);
    // A generous ceiling: the pre-fix code would have spent 8 retries all
    // failing against the dead node 0 (its own backoff formula alone sums
    // to hundreds of ms before even counting connection-timeout waits per
    // attempt) and still returned Err. The fixed code should succeed on
    // its first attempt against a plain majority of live nodes -- well
    // under a couple of seconds even accounting for CI slowness.
    let was_fast = elapsed < Duration::from_secs(5);

    let fixed = succeeded && landed_at_seq_2 && was_fast;
    report.record(
        "I: audit-log tip read tolerates node_addrs[0] being offline (Stage F fix)",
        fixed,
        if fixed {
            format!(
                "confirmed FIXED: with node_addrs[0] killed outright, the propose still succeeded in \
                 {elapsed:?} and landed at the correct seq 2, using fetch_majority_tip's read from nodes \
                 1-4 -- the previous hardcoded dependency on node_addrs[0] specifically is gone \
                 (Stage F closes Finding 2.2)."
            )
        } else {
            format!(
                "unexpected: succeeded={succeeded} landed_at_seq_2={landed_at_seq_2} elapsed={elapsed:?} \
                 result={result:?} -- investigate"
            )
        },
    );

    kill_all(&mut q.children);
}

// =========================================================================
// TEST F: mTLS penetration test -- no client cert, and a non-pinned cert.
// =========================================================================
async fn test_f_mtls_pentest(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_f", 9550).await;
    let addr = q.addrs[0].clone();
    let server_name = ServerName::try_from("quorum-node").unwrap();

    // F1: no client certificate at all.
    struct AcceptAnyServer;
    impl rustls::client::ServerCertVerifier for AcceptAnyServer {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
    let no_client_auth_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth();
    let connector_no_auth = TlsConnector::from(Arc::new(no_client_auth_config));
    let stream = TcpStream::connect(&addr).await.unwrap();
    let rejected = match connector_no_auth.connect(server_name.clone(), stream).await {
        Err(_) => true,
        Ok(mut tls) => !probe_survives(&mut tls).await,
    };
    report.record(
        "F1: connection with NO client certificate is rejected",
        rejected,
        if rejected {
            "correctly rejected (either at handshake, or via a fatal alert on the first subsequent I/O -- TLS 1.3 can accept a client's Finished optimistically before the server's rejection alert arrives, so both are checked)".to_string()
        } else {
            "INCORRECTLY accepted a connection with no client certificate at all, AND a real request/response round-trip succeeded over it".to_string()
        },
    );

    // F2: a valid, well-formed TLS client cert that is simply NOT in the
    // node's pinned allow-list (a completely unrelated freshly-generated
    // identity).
    let stranger = generate_identity();
    let connector_stranger = quorum_client::build_connector(
        stranger.cert_der.clone(),
        stranger.key_der.clone(),
        vec![q.node_identities[0].cert_der.clone()], // trusts the real server cert
    )
    .expect("test TLS identity");
    let stream2 = TcpStream::connect(&addr).await.unwrap();
    let rejected2 = match connector_stranger.connect(server_name, stream2).await {
        Err(_) => true,
        Ok(mut tls) => !probe_survives(&mut tls).await,
    };
    report.record(
        "F2: connection with a non-pinned client certificate is rejected",
        rejected2,
        if rejected2 {
            "correctly rejected (handshake or first-I/O fatal alert)".to_string()
        } else {
            "INCORRECTLY accepted a connection from an unpinned, unrelated certificate, AND a real request/response round-trip succeeded over it".to_string()
        },
    );

    // F3: audit finding A13. Unlike F1/F2, this uses a VALID, pinned
    // client certificate -- exactly the "authenticated peer that is
    // compromised, buggy, or simply malicious" threat model the finding
    // describes, not an unauthenticated attacker. It streams an
    // unterminated line well past
    // `quorum_node::bounded_line_reader::MAX_WIRE_LINE_BYTES` (8 MiB) and
    // checks two things: the node closes the connection instead of
    // buffering it without bound, and the node is still alive and
    // serving other, well-behaved connections afterward.
    {
        let legit_peer_id = 1; // any id other than 0 (the listener under test), already pinned by it
        let build_legit_connector = || {
            quorum_client::build_connector(
                q.node_identities[legit_peer_id].cert_der.clone(),
                q.node_identities[legit_peer_id].key_der.clone(),
                vec![q.node_identities[0].cert_der.clone()],
            )
            .expect("test TLS identity")
        };

        let stream3 = TcpStream::connect(&addr).await.unwrap();
        let mut tls3 = build_legit_connector()
            .connect(ServerName::try_from("quorum-node").unwrap(), stream3)
            .await
            .expect("a validly-pinned certificate must complete the TLS handshake");

        let chunk = vec![b'a'; 64 * 1024];
        let total_to_send = 8 * 1024 * 1024 + (8 * chunk.len()); // past the 8 MiB cap
        let mut sent = 0usize;
        let mut write_failed = false;
        while sent < total_to_send {
            if tls3.write_all(&chunk).await.is_err() {
                write_failed = true;
                break;
            }
            sent += chunk.len();
        }
        let _ = tls3.flush().await;

        // Confirm via a read, not just eventual write failure: OS socket
        // buffers can absorb a fair amount even after the peer stops
        // reading, so a write succeeding doesn't by itself mean the node
        // is still accepting the data into its own memory.
        let mut probe = [0u8; 16];
        let read_result = tokio::time::timeout(Duration::from_secs(5), tls3.read(&mut probe)).await;
        let connection_was_closed =
            write_failed || matches!(read_result, Ok(Ok(0))) || matches!(read_result, Ok(Err(_)));
        report.record(
            "F3: an oversized unterminated line from a validly-pinned peer gets the connection closed, not buffered without bound (A13)",
            connection_was_closed,
            if connection_was_closed {
                format!("node closed the connection after {sent} bytes sent without a '\\n' terminator, as expected")
            } else {
                format!(
                    "node did NOT close the connection after {sent} bytes without a terminator \
                     (timed out waiting for it to) -- the line-length bound looks absent or too loose"
                )
            },
        );

        // And the node must still be alive and serving other connections
        // after rejecting the oversized one -- a length cap that closes
        // the bad connection by crashing the whole process would be
        // worse than the original unbounded-memory finding.
        let stream4 = TcpStream::connect(&addr).await.unwrap();
        let mut tls4 = build_legit_connector()
            .connect(ServerName::try_from("quorum-node").unwrap(), stream4)
            .await
            .expect(
                "the node should still accept new connections after rejecting the oversized one",
            );
        let node_still_serving = probe_survives(&mut tls4).await;
        report.record(
            "F3b: the node stays alive and keeps serving other connections after rejecting the oversized line",
            node_still_serving,
            if node_still_serving {
                "a fresh, well-behaved connection made after the attack got a real response".to_string()
            } else {
                "the node did not respond to a subsequent well-behaved connection -- the oversized-line \
                 attack may have wedged or crashed it, which would be worse than the original finding"
                    .to_string()
            },
        );
    }

    kill_all(&mut q.children);
}

/// After a TLS handshake that MIGHT have been optimistically accepted by
/// the client side even though the server intends to reject it (a real
/// TLS 1.3 subtlety: the server's fatal alert in response to an
/// unacceptable client certificate can arrive after the handshake
/// completes from the client's point of view), sends one well-formed
/// request and checks whether a real response comes back. Returns `true`
/// only if the connection is genuinely usable end to end.
async fn probe_survives<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    tls: &mut S,
) -> bool {
    let msg = Message::GetAuditLog { invoice_id: None };
    let mut line = serde_json::to_vec(&msg).unwrap();
    line.push(b'\n');
    if tls.write_all(&line).await.is_err() {
        return false;
    }
    if tls.flush().await.is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            // Got bytes back -- confirm they're actually a valid response,
            // not e.g. a TLS alert misread as plaintext.
            serde_json::from_slice::<Message>(&buf[..n]).is_ok()
        }
        _ => false,
    }
}

// =========================================================================
// TEST G: HTTP penetration test against quorum_service.
// =========================================================================
async fn test_g_http_pentest(report: &mut Report) {
    // Reuses a fresh quorum, but only needs it up long enough to give
    // quorum_service a valid group public key file and live nodes to
    // (potentially) call -- most of this test never reaches derive at all.
    let mut q = spin_up_quorum("adversarial_test_g", 9560).await;

    let db_check = tokio_postgres::connect(
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        tokio_postgres::NoTls,
    )
    .await;
    if db_check.is_err() {
        report.record("G: HTTP pen-test suite", false, "SKIPPED -- could not connect to Postgres (ciphersettle_adversarial); run setup from PHASE3_README.md first");
        kill_all(&mut q.children);
        return;
    }

    let service_binary = locate_sibling_binary("quorum_service");
    // Deliberately NOT in the 9560-9564 range spin_up_quorum just used for
    // its 5 nodes -- a port collision here would make quorum_service fail
    // to bind (or worse, silently talk to the wrong process), which is
    // exactly the kind of test-harness bug that produces misleading
    // "FAIL" results that aren't about the system under test at all.
    let service_addr = "127.0.0.1:9569".to_string();
    let issuer_key = "pentest-issuer-key";
    let config = serde_json::json!({
        "listen_addr": service_addr,
        "db_url": "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        "admin_caller_id": "pentest-admin",
        "api_keys": [{"key": issuer_key, "caller_id": "pentest-issuer"}, {"key": "pentest-admin-key", "caller_id": "pentest-admin"}],
        "client_cert_der_b64": b64(&q.client_identity.cert_der),
        "client_key_der_b64": b64(&q.client_identity.key_der),
        "service_auth_key_b64": b64(&q.service_auth_key),
        "quorum_nodes": ([0usize, 1, 2]).iter().map(|&i| serde_json::json!({
            "id": i, "addr": q.addrs[i], "cert_der_b64": b64(&q.node_identities[i].cert_der),
        })).collect::<Vec<_>>(),
        "notary_addr": null,
        "notary_cert_der_b64": null,
        "group_pubkey_file": q.pubkey_files[0].to_string_lossy(),
        "quorum_threshold": T,
        "max_ciphertext_bytes": 1024,
        "ciphertext_retention_ms": 999_999_999u64,
        "derive_rate_limit_max_calls": 2,
        "derive_rate_limit_window_ms": 60_000u64,
        "acknowledge_pre_cutover_data": true, // scratch test DB: accumulates rows across runs, no marker
    });
    let config_path = q.work_dir.join("service.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut service_child = Command::new(&service_binary)
        .arg(&config_path)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&service_addr).await.is_ok() {
            break;
        }
        if Instant::now() > deadline {
            report.record(
                "G: HTTP pen-test suite",
                false,
                "quorum_service never started listening",
            );
            let _ = service_child.kill();
            let _ = service_child.wait();
            kill_all(&mut q.children);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // G1: no Authorization header at all.
    let (status, _) = http_json(&service_addr, "POST", "/invoices", None, Some(r#"{"invoice_id":"x","nullifier_hash":"y","ciphertext_b64":"eg==","commitment_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#)).await;
    report.record(
        "G1: request with no Authorization header",
        status == 401,
        format!("got HTTP {status} (expected 401)"),
    );

    // G2: malformed / unknown bearer token.
    let (status, _) = http_json(&service_addr, "POST", "/invoices", Some("totally-made-up-key"), Some(r#"{"invoice_id":"x","nullifier_hash":"y","ciphertext_b64":"eg==","commitment_b64":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#)).await;
    report.record(
        "G2: request with an unknown API key",
        status == 401,
        format!("got HTTP {status} (expected 401)"),
    );

    // G3: SQL-injection-shaped invoice_id in a path parameter. Postgres
    // queries throughout use parameterized $1/$2 placeholders (never
    // string concatenation), so this should be handled as inert data --
    // confirm the request just 404s (no such invoice) rather than
    // producing a SQL error or, worse, succeeding destructively.
    let injection = "x'; DROP TABLE invoices; --";
    let encoded = injection
        .replace(' ', "%20")
        .replace('\'', "%27")
        .replace(';', "%3B");
    let (status, body) = http_json(
        &service_addr,
        "POST",
        &format!("/invoices/{encoded}/settle"),
        Some(issuer_key),
        None,
    )
    .await;
    report.record(
        "G3: SQL-injection-shaped path parameter is treated as inert data",
        status == 404,
        format!("got HTTP {status} (expected 404 -- not found, not a SQL error): {body}"),
    );
    // Confirm the table really does still exist and is queryable.
    let (client, connection) = tokio_postgres::connect(
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(connection);
    let table_survives = client
        .query_one("SELECT COUNT(*) FROM invoices", &[])
        .await
        .is_ok();
    report.record(
        "G3b: invoices table still exists after the injection attempt",
        table_survives,
        "confirmed table intact",
    );

    // G4: oversized ciphertext payload (service configured with a 1024-byte max above).
    let oversized = "A".repeat(4000);
    let oversized_b64 = b64(oversized.as_bytes());
    let (status, body) = http_json(
        &service_addr,
        "POST",
        "/invoices",
        Some(issuer_key),
        Some(&serde_json::json!({"invoice_id": "oversize-test", "nullifier_hash": "null-oversize", "ciphertext_b64": oversized_b64, "commitment_b64": sample_commitment_b64("oversize-test")}).to_string()),
    )
    .await;
    report.record(
        "G4: oversized ciphertext payload is rejected",
        status == 400,
        format!("got HTTP {status} (expected 400): {body}"),
    );

    // G5: rate limit on derive-key (configured max 2 calls / window above).
    // First register + grant self-access so derive would otherwise be
    // authorized -- we want to hit the RATE limit specifically, not an
    // access-control 403.
    let inv_id = "rate-limit-test-invoice";
    let (status, _) = http_json(
        &service_addr,
        "POST",
        "/invoices",
        Some(issuer_key),
        Some(&serde_json::json!({"invoice_id": inv_id, "nullifier_hash": "null-rate", "ciphertext_b64": b64(b"x"), "commitment_b64": sample_commitment_b64(inv_id)}).to_string()),
    )
    .await;
    let mut last_status = status;
    let rate_limit_transport_pk_b64 = b64(&quorum_vetseal::TransportSecretKey::random(
        &mut rand::thread_rng(),
    )
    .public_key()
    .to_bytes());
    for _ in 0..3 {
        let (s, _) = http_json(
            &service_addr,
            "POST",
            &format!("/invoices/{inv_id}/derive-key"),
            Some(issuer_key),
            Some(
                &serde_json::json!({"transport_public_key_b64": rate_limit_transport_pk_b64})
                    .to_string(),
            ),
        )
        .await;
        last_status = s;
    }
    report.record(
        "G5: derive-key rate limit is enforced after repeated calls",
        last_status == 409,
        format!("after registering + 3 rapid derive-key calls (limit 2/window), last call returned HTTP {last_status} (expected 409)"),
    );

    let _ = service_child.kill();
    let _ = service_child.wait();
    kill_all(&mut q.children);
}

// =========================================================================
// TEST M: the sealed-share NIZK gate (CRYPTO-004).
// =========================================================================
//
// Node 0 is replaced by the strong adversary from `spawn_garbage_adversary`:
// it invents its own scalar and sends a share plus a fully VALID proof for
// that scalar -- a sound proof of the wrong statement, i.e. "this ciphertext
// encrypts a share of SOME key", not of node 0's DKG share. The gate must
// reject it by checking against the group's public key share for node 0.
//
// M1 runs with the gate on. M2 is the discriminating control: the identical
// adversary with the gate off gets into the combine and the result fails
// verification -- so M1 passing is due to the gate and not to luck.
async fn test_m_share_proof_gate(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_m", 9630).await;
    let identity = "inv-adversarial-m";
    q.children[0].kill().unwrap();
    q.children[0].wait().ok();
    spawn_garbage_adversary(&q, 0, q.addrs[0].clone()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let addrs = node_addr_list(&q, &[0, 1, 2, 3, 4]);
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let transport_pk = transport_sk.public_key();

    let gated = quorum_client::collect_sealed_derived_key(
        &q.connector,
        &addrs,
        identity,
        T,
        &q.service_auth_key,
        &transport_pk,
        &q.group_pks,
        quorum_client::ProofPolicy::Require,
        &[],
    )
    .await;
    let (m1_ok, m1_note) = match &gated {
        Ok(c) => {
            let excluded = !c.used_node_ids.contains(&0);
            let opens = quorum_client::open_sealed_derived_key(
                &c.sealed,
                &transport_sk,
                &q.group_pks,
                identity,
            )
            .is_ok();
            (
                excluded && opens,
                format!(
                    "used nodes {:?}; adversary excluded={excluded}; result verifies={opens}",
                    c.used_node_ids
                ),
            )
        }
        Err(e) => (false, format!("collect failed: {e:?}")),
    };
    report.record(
        "M1: NIZK gate excludes a valid-proof-for-the-wrong-key adversary BEFORE the combine, on the first round",
        m1_ok,
        m1_note,
    );

    let ungated = quorum_client::collect_sealed_derived_key(
        &q.connector,
        &addrs,
        identity,
        T,
        &q.service_auth_key,
        &transport_pk,
        &q.group_pks,
        quorum_client::ProofPolicy::Skip,
        &[],
    )
    .await;
    let (m2_ok, m2_note) = match &ungated {
        Ok(c) => {
            let admitted = c.used_node_ids.contains(&0);
            let bad = quorum_client::open_sealed_derived_key(
                &c.sealed,
                &transport_sk,
                &q.group_pks,
                identity,
            )
            .is_err();
            (
                admitted && bad,
                format!(
                    "used nodes {:?}; adversary admitted={admitted}; result rejected={bad}",
                    c.used_node_ids
                ),
            )
        }
        Err(e) => (false, format!("collect failed: {e:?}")),
    };
    report.record(
        "M2: control -- with the gate OFF the same adversary poisons round 1 (proves M1 is due to the gate)",
        m2_ok,
        m2_note,
    );

    kill_all(&mut q.children);
}

async fn http_json(
    addr: &str,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let connect = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => return (0, format!("connect failed: {e}")),
    };
    let mut stream = connect;
    let body_bytes = body.unwrap_or("");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(key) = api_key {
        req.push_str(&format!("Authorization: Bearer {key}\r\n"));
    }
    if !body_bytes.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    req.push_str("\r\n");
    req.push_str(body_bytes);
    if let Err(e) = stream.write_all(req.as_bytes()).await {
        return (0, format!("write failed: {e}"));
    }
    let mut resp = Vec::new();
    if let Err(e) = stream.read_to_end(&mut resp).await {
        return (0, format!("read failed: {e}"));
    }
    let resp_str = String::from_utf8_lossy(&resp).to_string();
    let status_line = resp_str.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp_str.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

// =========================================================================
// TEST J: audit finding A12 -- the multi-round sealed-share retry
// protocol, exercised end-to-end against a live quorum_service process
// and a genuinely bad node (not just unit-testing the selection logic in
// isolation).
// =========================================================================
async fn test_j_sealed_share_retry_protocol(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_j", 9580).await;

    let db_check = tokio_postgres::connect(
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        tokio_postgres::NoTls,
    )
    .await;
    if db_check.is_err() {
        report.record("J: sealed-share retry protocol (A12)", false, "SKIPPED -- could not connect to Postgres (ciphersettle_adversarial); run setup from PHASE3_README.md first");
        kill_all(&mut q.children);
        return;
    }

    // Replace node 0 with the same garbage adversary Test A uses: a
    // real mTLS handshake (so it's indistinguishable from a live node to
    // anything that only checks the pinned certificate), but every
    // DeriveRequest gets a syntactically-valid, sealed, but WRONG
    // signature share back. Node 0 is picked deliberately: node_addrs is
    // built in ID order, so an unmodified (pre-A12) implementation would
    // put node 0 in the very first subset it ever tries.
    q.children[0].kill().unwrap();
    q.children[0].wait().ok();
    let adversary_addr = q.addrs[0].clone();
    spawn_garbage_adversary(&q, 0, adversary_addr).await;
    tokio::time::sleep(Duration::from_millis(200)).await; // let it bind

    let service_binary = locate_sibling_binary("quorum_service");
    let service_addr = "127.0.0.1:9589".to_string(); // outside spin_up_quorum's 9580-9584 range
    let issuer_key = "j-issuer-key";
    let config = serde_json::json!({
        "listen_addr": service_addr,
        "db_url": "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        "admin_caller_id": "j-admin",
        "api_keys": [{"key": issuer_key, "caller_id": "j-issuer"}],
        "client_cert_der_b64": b64(&q.client_identity.cert_der),
        "client_key_der_b64": b64(&q.client_identity.key_der),
        "service_auth_key_b64": b64(&q.service_auth_key),
        // All 5 nodes, in ID order -- this is what makes node 0 (the
        // adversary) land in the very first subset any pre-A12
        // implementation would try, and what gives collect_sealed_derived_key
        // 5 nodes' worth of combinations (C(5,3) = 10) to search through
        // once it needs to retry.
        "quorum_nodes": (0..N).map(|i| serde_json::json!({
            "id": i, "addr": q.addrs[i], "cert_der_b64": b64(&q.node_identities[i].cert_der),
        })).collect::<Vec<_>>(),
        "notary_addr": null,
        "notary_cert_der_b64": null,
        "group_pubkey_file": q.pubkey_files[1].to_string_lossy(), // node 0's own file is fine too, but 1 is unambiguously honest
        "quorum_threshold": T,
        "max_ciphertext_bytes": 1024,
        "ciphertext_retention_ms": 999_999_999u64,
        "derive_rate_limit_max_calls": 10,
        "derive_rate_limit_window_ms": 60_000u64,
        "acknowledge_pre_cutover_data": true, // scratch test DB: accumulates rows across runs, no marker
        // The NIZK gate (Test M) now excludes this adversary before the
        // combine, which would make the A12 retry path unreachable. Turn the
        // gate off HERE ONLY so this test keeps exercising the defense-in-depth
        // retry protocol it was written for.
        "insecure_skip_share_proofs": true,
    });
    let config_path = q.work_dir.join("service.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut service_child = Command::new(&service_binary)
        .arg(&config_path)
        .env(
            "CIPHERSETTLE_ALLOW_INSECURE_TEST_FLAGS",
            "i-understand-this-disables-security-checks",
        )
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&service_addr).await.is_ok() {
            break;
        }
        if Instant::now() > deadline {
            report.record(
                "J: sealed-share retry protocol (A12)",
                false,
                "quorum_service never started listening",
            );
            let _ = service_child.kill();
            let _ = service_child.wait();
            kill_all(&mut q.children);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let invoice_id = format!(
        "j-retry-invoice-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let (status, body) = http_json(
        &service_addr,
        "POST",
        "/invoices",
        Some(issuer_key),
        Some(&serde_json::json!({"invoice_id": invoice_id, "nullifier_hash": format!("j-null-{invoice_id}"), "ciphertext_b64": b64(b"x"), "commitment_b64": sample_commitment_b64(&invoice_id)}).to_string()),
    )
    .await;
    if status != 200 && status != 201 {
        report.record(
            "J: sealed-share retry protocol (A12)",
            false,
            format!("setup failed: creating the invoice returned HTTP {status}: {body}"),
        );
        let _ = service_child.kill();
        let _ = service_child.wait();
        kill_all(&mut q.children);
        return;
    }

    // The true caller's transport keypair -- this is the ONLY place in
    // this test that ever holds the secret half, exactly like the real
    // architecture requires (quorum_service must never see it).
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let transport_pk_b64 = b64(&transport_sk.public_key().to_bytes());

    // --- Round 1: first attempt, no history yet. Node 0 (the adversary)
    // should land in this subset given the ID-ordered node list above.
    let (status1, body1) = http_json(
        &service_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(issuer_key),
        Some(&serde_json::json!({"transport_public_key_b64": transport_pk_b64, "tried_subsets": Vec::<Vec<usize>>::new()}).to_string()),
    )
    .await;
    if status1 != 200 {
        report.record(
            "J: sealed-share retry protocol (A12)",
            false,
            format!("round 1 derive-key call itself failed: HTTP {status1}: {body1}"),
        );
        let _ = service_child.kill();
        let _ = service_child.wait();
        kill_all(&mut q.children);
        return;
    }
    let resp1: serde_json::Value = serde_json::from_str(&body1).unwrap();
    let used1: Vec<usize> = serde_json::from_value(resp1["used_node_ids"].clone()).unwrap();
    let round1_includes_adversary = used1.contains(&0);
    report.record(
        "J1: the adversary lands in round 1's subset (sanity check that this test actually tests something)",
        round1_includes_adversary,
        format!("round 1 used nodes {used1:?}"),
    );
    if !round1_includes_adversary {
        // Not necessarily a bug -- node ordering/timing could vary -- but
        // this specific test's premise didn't hold, so its later
        // assertions wouldn't mean what they claim to. Report honestly
        // and stop rather than pass for the wrong reason.
        report.record(
            "J: sealed-share retry protocol (A12)",
            false,
            "test premise didn't hold (see J1); rerun",
        );
        let _ = service_child.kill();
        let _ = service_child.wait();
        kill_all(&mut q.children);
        return;
    }

    let sealed1 = quorum_vetseal::SealedDerivedKey::from_bytes(&b64_decode_fixed::<
        { quorum_vetseal::SEALED_COMPRESSED_SIZE },
    >(
        resp1["sealed_derived_key_b64"].as_str().unwrap(),
    ))
    .unwrap();
    let round1_result =
        quorum_client::open_sealed_derived_key(&sealed1, &transport_sk, &q.group_pks, &invoice_id);
    report.record(
        "J2: round 1's sealed result correctly fails client-side verification (the adversary's garbage share poisoned it)",
        round1_result.is_err(),
        match &round1_result {
            Err(e) => format!("correctly rejected: {e}"),
            Ok(_) => "INCORRECTLY verified despite including the adversary's garbage share".to_string(),
        },
    );

    // --- Retry until recovery or exhaustion. NOT guaranteed to succeed
    // on the very next attempt: with a 3-of-5 quorum, a single bad node
    // still appears in 6 of the 10 possible 3-node subsets (more than
    // the 4 that exclude it -- see `collect_sealed_derived_key`'s doc
    // comment for the exact math and why an earlier version of this
    // test wrongly assumed recovery-in-one-retry). What IS guaranteed:
    // recovery within a bounded number of rounds (at most
    // `C(5,3) - 1 = 9` failed retries before the one remaining subset
    // must be clean), and a different subset each round (confirmed for
    // the first retry specifically below).
    let mut tried_subsets = vec![used1.clone()];
    let mut previous_used = used1.clone();
    let mut recovered = false;
    let mut rounds_after_first = 0u32;
    let max_rounds = 10; // C(5,3); a correct implementation can never need more
    while rounds_after_first < max_rounds {
        rounds_after_first += 1;
        let (status_n, body_n) = http_json(
            &service_addr,
            "POST",
            &format!("/invoices/{invoice_id}/derive-key"),
            Some(issuer_key),
            Some(&serde_json::json!({"transport_public_key_b64": transport_pk_b64, "tried_subsets": tried_subsets.clone()}).to_string()),
        )
        .await;
        if status_n == 409 {
            break; // genuinely exhausted -- shouldn't happen before recovery given only 1 bad node
        }
        if status_n != 200 {
            report.record(
                "J: sealed-share retry protocol (A12)",
                false,
                format!(
                    "retry round {rounds_after_first} got unexpected HTTP {status_n}: {body_n}"
                ),
            );
            let _ = service_child.kill();
            let _ = service_child.wait();
            kill_all(&mut q.children);
            return;
        }
        let resp_n: serde_json::Value = serde_json::from_str(&body_n).unwrap();
        let used_n: Vec<usize> = serde_json::from_value(resp_n["used_node_ids"].clone()).unwrap();

        if rounds_after_first == 1 {
            let mut a = previous_used.clone();
            a.sort_unstable();
            let mut b = used_n.clone();
            b.sort_unstable();
            report.record(
                "J3: the first retry selects a DIFFERENT node subset than round 1, not the same one again",
                a != b,
                format!("round 1 used {previous_used:?}, first retry used {used_n:?}"),
            );
        }
        previous_used = used_n.clone();

        let sealed_n = quorum_vetseal::SealedDerivedKey::from_bytes(&b64_decode_fixed::<
            { quorum_vetseal::SEALED_COMPRESSED_SIZE },
        >(
            resp_n["sealed_derived_key_b64"].as_str().unwrap(),
        ))
        .unwrap();
        let result_n = quorum_client::open_sealed_derived_key(
            &sealed_n,
            &transport_sk,
            &q.group_pks,
            &invoice_id,
        );
        if let Ok(sig) = &result_n {
            if quorum_core::verify_combined(&q.group_pks, &invoice_id, sig) {
                recovered = true;
                break;
            }
        }
        tried_subsets.push(used_n);
    }
    report.record(
        "J4: retrying automatically recovers within the guaranteed bound (at most 9 failed retries for this quorum shape), without any human manually intervening beyond following the documented protocol",
        recovered,
        if recovered {
            format!("recovered after {rounds_after_first} retry round(s) following the initial failure")
        } else {
            format!("did NOT recover within {max_rounds} retries -- with only 1 known-bad node this should be impossible; investigate")
        },
    );

    // --- Exhaustion: report every possible 3-of-5 subset as already
    // tried. No untried combination remains, so this must be a clear
    // terminal failure (409), not a 500 or -- worse -- a fabricated
    // success.
    let all_subsets: Vec<Vec<usize>> = (0..N)
        .flat_map(|a| (a + 1..N).flat_map(move |b| (b + 1..N).map(move |c| vec![a, b, c])))
        .collect();
    let (status3, body3) = http_json(
        &service_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(issuer_key),
        Some(&serde_json::json!({"transport_public_key_b64": transport_pk_b64, "tried_subsets": all_subsets}).to_string()),
    )
    .await;
    report.record(
        "J5: once every subset has been reported as tried, the service returns a clear terminal failure (409), not a fabricated success",
        status3 == 409,
        format!("got HTTP {status3} (expected 409): {body3}"),
    );

    let _ = service_child.kill();
    let _ = service_child.wait();
    kill_all(&mut q.children);
}

/// `resp["field"].as_str()` is base64; this decodes it into a
/// fixed-size array of exactly `LEN` bytes, panicking (test-only helper,
/// not production code) if the response was shaped unexpectedly.
fn b64_decode_fixed<const LEN: usize>(s: &str) -> [u8; LEN] {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap()
        .try_into()
        .unwrap()
}

/// A `rustls::client::ServerCertVerifier` that accepts any certificate.
/// Test-only, and deliberately so -- this proves the port under test
/// speaks real TLS at all (audit finding A5), which is orthogonal to
/// certificate trust policy (in a real deployment that's the browser's
/// or OS's job, not this project's). Equivalent to `curl -k`.
struct AcceptAnyServerCert;
impl rustls::client::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

// =========================================================================
// TEST N: cutover guard -- the service must refuse to serve a database
// written under a different cryptographic scheme (the blstrs cutover was
// not backward compatible: old derived keys do not open old ciphertexts).
// Real quorum_service process, real Postgres, a throwaway database.
// N3 is the control: the same pre-cutover state, differing ONLY in the
// operator's explicit acknowledgement, starts -- so N1's refusal is
// attributable to the guard rather than to some unrelated startup failure.
// =========================================================================
async fn test_n_cutover_guard(report: &mut Report) {
    const ADMIN_DSN: &str =
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=postgres";
    const N_DSN: &str =
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_cutover_n";
    const EPOCH: &str = "blstrs-rfc9380-v1";

    let mut q = spin_up_quorum("adversarial_test_n", 9640).await;
    let Ok((admin, admin_conn)) = tokio_postgres::connect(ADMIN_DSN, tokio_postgres::NoTls).await
    else {
        report.record(
            "N: cutover guard",
            false,
            "SKIPPED -- could not connect to Postgres admin database",
        );
        kill_all(&mut q.children);
        return;
    };
    tokio::spawn(admin_conn);
    let _ = admin
        .batch_execute("DROP DATABASE IF EXISTS ciphersettle_cutover_n")
        .await;
    if let Err(e) = admin
        .batch_execute("CREATE DATABASE ciphersettle_cutover_n")
        .await
    {
        report.record(
            "N: cutover guard",
            false,
            format!("could not create scratch database: {e}"),
        );
        kill_all(&mut q.children);
        return;
    }

    let service_binary = locate_sibling_binary("quorum_service");
    let write_config = |name: &str, addr: &str, ack: bool| -> PathBuf {
        let cfg = serde_json::json!({
            "listen_addr": addr,
            "db_url": N_DSN,
            "admin_caller_id": "n-admin",
            "api_keys": [{"key": "n-issuer-key", "caller_id": "n-issuer"}],
            "client_cert_der_b64": b64(&q.client_identity.cert_der),
            "client_key_der_b64": b64(&q.client_identity.key_der),
            "service_auth_key_b64": b64(&q.service_auth_key),
            "quorum_nodes": (0..N).map(|i| serde_json::json!({
                "id": i, "addr": q.addrs[i], "cert_der_b64": b64(&q.node_identities[i].cert_der),
            })).collect::<Vec<_>>(),
            "notary_addr": null,
            "notary_cert_der_b64": null,
            "group_pubkey_file": q.pubkey_files[0].to_string_lossy(),
            "quorum_threshold": T,
            "max_ciphertext_bytes": 1024,
            "ciphertext_retention_ms": 999_999_999u64,
            "derive_rate_limit_max_calls": 10,
            "derive_rate_limit_window_ms": 60_000u64,
            "acknowledge_pre_cutover_data": ack,
        });
        let path = q.work_dir.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        path
    };
    // Starts the service; returns Some(child) if it began listening within
    // the deadline, None if it exited (or never bound) instead.
    let try_start = |config: PathBuf, addr: &'static str| {
        let bin = service_binary.clone();
        async move {
            let mut child = Command::new(&bin).arg(&config).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(8);
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    return None;
                }
                if TcpStream::connect(addr).await.is_ok() {
                    return Some(child);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    };
    async fn marker(c: &tokio_postgres::Client) -> Option<String> {
        c.query_opt(
            "SELECT value FROM crypto_meta WHERE key = 'crypto_epoch'",
            &[],
        )
        .await
        .ok()
        .flatten()
        .map(|r| r.get::<_, String>(0))
    }

    // N0: an empty database is stamped automatically and the service starts.
    let n0_child = try_start(
        write_config("n0.json", "127.0.0.1:19610", false),
        "127.0.0.1:19610",
    )
    .await;
    let Ok((db, db_conn)) = tokio_postgres::connect(N_DSN, tokio_postgres::NoTls).await else {
        report.record(
            "N: cutover guard",
            false,
            "could not connect to scratch database",
        );
        kill_all(&mut q.children);
        return;
    };
    tokio::spawn(db_conn);
    let stamped = marker(&db).await;
    let n0_ok = n0_child.is_some() && stamped.as_deref() == Some(EPOCH);
    report.record(
        "N0: an empty database is stamped with the current crypto epoch and the service starts",
        n0_ok,
        format!(
            "started: {}, marker after start: {stamped:?}",
            n0_child.is_some()
        ),
    );
    if let Some(mut c) = n0_child {
        let _ = c.kill();
        let _ = c.wait();
    }

    // Simulate a pre-cutover database: rows exist, no marker.
    let _ = db.batch_execute("DELETE FROM crypto_meta").await;
    let seeded = db
        .execute(
            "INSERT INTO invoices (invoice_id, issuer, status, created_at_ms) VALUES ('legacy-inv-1', 'legacy-issuer', 'active', 1)",
            &[],
        )
        .await;

    // N1: rows but no marker, no acknowledgement -> refuse to start.
    let n1_child = try_start(
        write_config("n1.json", "127.0.0.1:19611", false),
        "127.0.0.1:19611",
    )
    .await;
    let n1_marker = marker(&db).await;
    report.record(
        "N1: a database with invoices but no crypto-epoch marker is refused (pre-cutover data)",
        seeded.is_ok() && n1_child.is_none() && n1_marker.is_none(),
        format!(
            "seed ok: {}, service started: {}, marker written: {n1_marker:?}",
            seeded.is_ok(),
            n1_child.is_some()
        ),
    );
    if let Some(mut c) = n1_child {
        let _ = c.kill();
        let _ = c.wait();
    }

    // N2: a marker from a different epoch is refused even when acknowledged.
    let _ = db
        .execute("INSERT INTO crypto_meta (key, value) VALUES ('crypto_epoch', 'threshold_crypto-legacy')", &[])
        .await;
    let n2_child = try_start(
        write_config("n2.json", "127.0.0.1:19612", true),
        "127.0.0.1:19612",
    )
    .await;
    let n2_marker = marker(&db).await;
    report.record(
        "N2: a mismatched epoch marker is refused even with the acknowledgement set",
        n2_child.is_none() && n2_marker.as_deref() == Some("threshold_crypto-legacy"),
        format!(
            "service started: {}, marker left as: {n2_marker:?}",
            n2_child.is_some()
        ),
    );
    if let Some(mut c) = n2_child {
        let _ = c.kill();
        let _ = c.wait();
    }

    // N3 (control): same pre-cutover state as N1, ONLY the acknowledgement differs.
    let _ = db.batch_execute("DELETE FROM crypto_meta").await;
    let n3_child = try_start(
        write_config("n3.json", "127.0.0.1:19613", true),
        "127.0.0.1:19613",
    )
    .await;
    let n3_marker = marker(&db).await;
    report.record(
        "N3: control -- identical pre-cutover state starts and is stamped once explicitly acknowledged",
        n3_child.is_some() && n3_marker.as_deref() == Some(EPOCH),
        format!("service started: {}, marker after start: {n3_marker:?}", n3_child.is_some()),
    );
    if let Some(mut c) = n3_child {
        let _ = c.kill();
        let _ = c.wait();
    }

    drop(db);
    let _ = admin
        .batch_execute("DROP DATABASE IF EXISTS ciphersettle_cutover_n")
        .await;
    kill_all(&mut q.children);
}

// =========================================================================
// TEST K: audit finding A5 -- TLS termination on quorum_service's HTTP
// API, exercised against the live binary: refuses to start off-loopback
// without TLS, and actually terminates real TLS when configured to.
// =========================================================================
async fn test_k_tls_termination(report: &mut Report) {
    let mut q = spin_up_quorum("adversarial_test_k", 9590).await;

    let db_check = tokio_postgres::connect(
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
        tokio_postgres::NoTls,
    )
    .await;
    if db_check.is_err() {
        report.record("K: TLS termination (A5)", false, "SKIPPED -- could not connect to Postgres (ciphersettle_adversarial); run setup from PHASE3_README.md first");
        kill_all(&mut q.children);
        return;
    }

    let service_binary = locate_sibling_binary("quorum_service");
    let base_config = |listen_addr: &str, tls: Option<(Vec<u8>, Vec<u8>)>| {
        let mut cfg = serde_json::json!({
            "listen_addr": listen_addr,
            "db_url": "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_adversarial",
            "admin_caller_id": "k-admin",
            "api_keys": [{"key": "k-issuer-key", "caller_id": "k-issuer"}],
            "client_cert_der_b64": b64(&q.client_identity.cert_der),
            "client_key_der_b64": b64(&q.client_identity.key_der),
            "service_auth_key_b64": b64(&q.service_auth_key),
            "quorum_nodes": (0..N).map(|i| serde_json::json!({
                "id": i, "addr": q.addrs[i], "cert_der_b64": b64(&q.node_identities[i].cert_der),
            })).collect::<Vec<_>>(),
            "notary_addr": null,
            "notary_cert_der_b64": null,
            "group_pubkey_file": q.pubkey_files[0].to_string_lossy(),
            "quorum_threshold": T,
            "max_ciphertext_bytes": 1024,
            "ciphertext_retention_ms": 999_999_999u64,
            "derive_rate_limit_max_calls": 10,
            "derive_rate_limit_window_ms": 60_000u64,
            "acknowledge_pre_cutover_data": true, // scratch test DB: accumulates rows across runs, no marker
        });
        if let Some((cert, key)) = tls {
            cfg["tls_cert_der_b64"] = serde_json::json!(b64(&cert));
            cfg["tls_key_der_b64"] = serde_json::json!(b64(&key));
        }
        cfg
    };
    let write_config = |name: &str, cfg: &serde_json::Value| -> PathBuf {
        let path = q.work_dir.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(cfg).unwrap()).unwrap();
        path
    };

    // --- K1: off-loopback, no TLS configured -- must refuse to start,
    // fast, and specifically BEFORE binding anything (checked via: the
    // port never becomes connectable).
    {
        let config_path = write_config("k1_config.json", &base_config("0.0.0.0:19599", None));
        let mut child = Command::new(&service_binary)
            .arg(&config_path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let exited = child.try_wait().ok().flatten();
        let never_bound = TcpStream::connect("127.0.0.1:19599").await.is_err();
        report.record(
            "K1: quorum_service refuses to start when configured off-loopback without TLS",
            exited.is_some() && never_bound,
            format!(
                "process exited: {}, port never became connectable: {never_bound}",
                exited.is_some()
            ),
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    // --- K2: loopback, no TLS -- the one plaintext configuration that
    // remains allowed (backward compatible with every other test in this
    // suite, which all use exactly this shape).
    {
        let config_path = write_config("k2_config.json", &base_config("127.0.0.1:19598", None));
        let mut child = Command::new(&service_binary)
            .arg(&config_path)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut connected = false;
        while Instant::now() < deadline {
            if TcpStream::connect("127.0.0.1:19598").await.is_ok() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        report.record(
            "K2: plaintext loopback still works (backward compatible)",
            connected,
            format!("connected: {connected}"),
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    // --- K3: loopback WITH TLS configured -- must actually terminate
    // real TLS: handshake succeeds, and a plain (non-TLS) request against
    // the same port fails rather than being served in the clear.
    {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.serialize_private_key_der();
        let config_path = write_config(
            "k3_config.json",
            &base_config("127.0.0.1:19597", Some((cert_der, key_der))),
        );
        let mut child = Command::new(&service_binary)
            .arg(&config_path)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect("127.0.0.1:19597").await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tcp = TcpStream::connect("127.0.0.1:19597").await.unwrap();
        let tls_result = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await;
        let handshake_ok = matches!(tls_result, Ok(Ok(_)));
        report.record(
            "K3a: quorum_service with TLS configured completes a real TLS handshake",
            handshake_ok,
            format!(
                "handshake result: {}",
                if handshake_ok { "OK" } else { "FAILED" }
            ),
        );

        if let Ok(Ok(mut tls_stream)) = tls_result {
            let req = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let _ = tls_stream.write_all(req.as_bytes()).await;
            let mut resp = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), tls_stream.read_to_end(&mut resp))
                .await;
            let got_http_response = String::from_utf8_lossy(&resp).starts_with("HTTP/1.1");
            report.record(
                "K3b: the TLS-wrapped connection actually carries a real HTTP response",
                got_http_response,
                format!(
                    "first bytes: {:?}",
                    String::from_utf8_lossy(&resp).lines().next()
                ),
            );
        }

        // A plain (non-TLS) client speaking directly must NOT get a
        // plaintext HTTP response -- the TLS handshake bytes should look
        // like garbage to an HTTP parser, not a valid response.
        let mut plain = TcpStream::connect("127.0.0.1:19597").await.unwrap();
        let _ = plain
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await;
        let mut plain_resp = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), plain.read_to_end(&mut plain_resp)).await;
        let looks_like_plaintext_http =
            String::from_utf8_lossy(&plain_resp).starts_with("HTTP/1.1");
        report.record(
            "K3c: a plaintext (non-TLS) request against the TLS port does NOT get a plaintext HTTP response",
            !looks_like_plaintext_http,
            format!("got {} bytes back, looked like plaintext HTTP: {looks_like_plaintext_http}", plain_resp.len()),
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    kill_all(&mut q.children);
}

// kill), using iptables to drop traffic to two nodes' ports for a while
// during DKG, then restoring it.
//
// Caveat, discovered by this test's first run: blocking `--dport <port>`
// for nodes 3/4's listening ports only stops OTHERS from connecting IN to
// 3/4 -- it does NOT stop 3/4 from connecting OUT to 0/1/2 (an outbound
// connection's destination is 0/1/2's ports, which aren't blocked; its
// source port is an OS-assigned ephemeral port, not 3/4's listening
// port). Since quorum_node's DKG is a PUSH protocol (every node dials out
// to deliver its own contribution), this produces an ASYMMETRIC
// partition: 3 and 4 can still successfully deliver their shares to
// 0/1/2, so 0/1/2 legitimately receive everything and finish DKG, while
// 3/4 never receive 0/1/2's shares and stay stuck. A true bidirectional
// split-brain on loopback would need network namespaces (separate netns
// per simulated node, cut with a veth/bridge rule) -- meaningfully more
// infrastructure than this sandboxed harness sets up elsewhere. This test
// now asserts what the ACHIEVABLE partition shape should actually
// produce, and says so, rather than asserting a bidirectional-partition
// outcome this setup can't create.
// =========================================================================
async fn test_h_network_partition(report: &mut Report) {
    let base_port: u16 = 9570;
    let blocked_ports = [base_port + 3, base_port + 4]; // nodes 3 and 4

    clear_iptables_block(&blocked_ports);
    println!("[H] blocking INBOUND traffic to nodes 3 and 4's ports BEFORE starting any node (see this test's doc comment for why this is a one-way, not bidirectional, partition)...");
    apply_iptables_block(&blocked_ports);

    let work_dir = PathBuf::from("/tmp/adversarial_test_h");
    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir).unwrap();
    let node_identities: Vec<GeneratedIdentity> = (0..N).map(|_| generate_identity()).collect();
    let node_audit_keys: Vec<SigningKey> = (0..N).map(|_| generate_audit_keypair()).collect();
    let client_identity = generate_identity();
    let addrs: Vec<String> = (0..N)
        .map(|i| format!("127.0.0.1:{}", base_port + i as u16))
        .collect();
    let service_auth_key = generate_service_auth_key();
    let node_binary = locate_sibling_binary("quorum_node");
    let mut children = Vec::with_capacity(N);
    let mut ready_files = Vec::with_capacity(N);
    for id in 0..N {
        let peers: Vec<PeerConfig> = (0..N)
            .filter(|&j| j != id)
            .map(|j| PeerConfig {
                id: j,
                addr: addrs[j].clone(),
                cert_der_b64: b64(&node_identities[j].cert_der),
                audit_pubkey_b64: b64(&node_audit_keys[j].verifying_key().to_bytes()),
            })
            .collect();
        let ready_file = work_dir.join(format!("node{id}.ready"));
        let config = NodeConfig {
            node_id: id,
            listen_addr: addrs[id].clone(),
            n: N,
            t: T,
            cert_der_b64: b64(&node_identities[id].cert_der),
            key_der_b64: b64(&node_identities[id].key_der),
            audit_keypair_b64: b64(&node_audit_keys[id].to_bytes()),
            peers,
            client_cert_der_b64: b64(&client_identity.cert_der),
            ready_file: ready_file.to_string_lossy().to_string(),
            pubkey_file: work_dir
                .join(format!("node{id}.pubkey.json"))
                .to_string_lossy()
                .to_string(),
            audit_log_file: work_dir
                .join(format!("node{id}.audit_log.json"))
                .to_string_lossy()
                .to_string(),
            service_auth_key_b64: b64(&quorum_core::derive_node_auth_key(&service_auth_key, id)),
            persistence: None,
            allow_ephemeral_share: true, // throwaway test quorum
        };
        let config_path = work_dir.join(format!("node{id}.json"));
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        children.push(
            Command::new(&node_binary)
                .arg(&config_path)
                .spawn()
                .unwrap(),
        );
        ready_files.push(ready_file);
    }

    // While partitioned: nodes 3 and 4 specifically must NOT become ready
    // (they can never receive 0/1/2's contributions). We do NOT assert
    // anything about 0/1/2 here -- per this partition's actual shape,
    // them finishing is the correct, expected outcome, not a bug.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let node3_or_4_ready = ready_files[3].exists() || ready_files[4].exists();
    report.record(
        "H1: the genuinely cut-off nodes (3, 4) do not finalize while partitioned",
        !node3_or_4_ready,
        if node3_or_4_ready {
            "unexpected: node 3 or 4 reported ready despite being unable to receive 0/1/2's contributions -- investigate".to_string()
        } else {
            format!(
                "confirmed: nodes 3/4 have not finalized (as expected). Nodes 0/1/2 ready = {:?} -- them being ready is the CORRECT outcome for this one-way partition shape (see this test's doc comment), not evidence the partition failed to apply",
                [0, 1, 2].iter().map(|&i| ready_files[i].exists()).collect::<Vec<_>>()
            )
        },
    );

    println!("[H] healing the partition...");
    clear_iptables_block(&blocked_ports);

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut all_ready = true;
    for f in &ready_files {
        while !f.exists() {
            if Instant::now() > deadline {
                all_ready = false;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    report.record(
        "H2: DKG completes for ALL nodes once the partition heals (retry logic works)",
        all_ready,
        if all_ready {
            "all 5 nodes finalized DKG once connectivity was restored -- push_dkg_to_peer's unbounded 200ms retry loop successfully rode out a real network partition (not just a process restart), including the previously cut-off nodes 3/4 catching up"
                .to_string()
        } else {
            "one or more nodes never finalized even after the partition healed and a 20s grace period -- investigate".to_string()
        },
    );

    kill_all(&mut children);
    clear_iptables_block(&blocked_ports);
}

fn apply_iptables_block(ports: &[u16]) {
    for &port in ports {
        let _ = Command::new("iptables")
            .args([
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .status();
        let _ = Command::new("iptables")
            .args([
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "DROP",
            ])
            .status();
    }
}

fn clear_iptables_block(ports: &[u16]) {
    for &port in ports {
        // Repeat the delete a few times in case a rule was added more than once.
        for _ in 0..3 {
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "DROP",
                ])
                .status();
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "DROP",
                ])
                .status();
        }
    }
}

// =========================================================================
// TEST P (Gap 1): key shares survive a restart; bad/missing share => refuse.
// =========================================================================
struct PNodes {
    work: PathBuf,
    ids: Vec<GeneratedIdentity>,
    audit: Vec<SigningKey>,
    client: GeneratedIdentity,
    addrs: Vec<String>,
    auth_key: [u8; 32],
}

impl PNodes {
    fn path(&self, kind: &str, id: usize) -> PathBuf {
        self.work.join(format!("node{id}.{kind}"))
    }
    fn share_file(&self, id: usize) -> PathBuf {
        self.work.join(format!("share{id}")).join("share.v1.json")
    }
    fn kek_file(&self, id: usize) -> PathBuf {
        self.work.join("keks").join(format!("node{id}.kek"))
    }
    fn write_kek(&self, id: usize) {
        use rand::RngCore;
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(self.work.join("keks")).unwrap();
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        let p = self.kek_file(id);
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, k).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn config(
        &self,
        id: usize,
        persistence: Option<quorum_core::config::SharePersistenceConfig>,
    ) -> NodeConfig {
        let peers: Vec<PeerConfig> = (0..N)
            .filter(|&j| j != id)
            .map(|j| PeerConfig {
                id: j,
                addr: self.addrs[j].clone(),
                cert_der_b64: b64(&self.ids[j].cert_der),
                audit_pubkey_b64: b64(&self.audit[j].verifying_key().to_bytes()),
            })
            .collect();
        NodeConfig {
            node_id: id,
            listen_addr: self.addrs[id].clone(),
            n: N,
            t: T,
            cert_der_b64: b64(&self.ids[id].cert_der),
            key_der_b64: b64(&self.ids[id].key_der),
            audit_keypair_b64: b64(&self.audit[id].to_bytes()),
            peers,
            client_cert_der_b64: b64(&self.client.cert_der),
            ready_file: self.path("ready", id).to_string_lossy().to_string(),
            pubkey_file: self.path("pubkey.json", id).to_string_lossy().to_string(),
            audit_log_file: self
                .path("audit_log.json", id)
                .to_string_lossy()
                .to_string(),
            service_auth_key_b64: b64(&quorum_core::derive_node_auth_key(&self.auth_key, id)),
            persistence,
            allow_ephemeral_share: false,
        }
    }
    fn launch(&self, id: usize, cfg: &NodeConfig, tag: &str) -> Child {
        let cfg_path = self.path(&format!("{tag}.json"), id);
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(cfg).unwrap()).unwrap();
        let log = std::fs::File::create(self.path("log", id)).unwrap();
        Command::new(locate_sibling_binary("quorum_node"))
            .arg(&cfg_path)
            .stderr(log)
            .spawn()
            .unwrap()
    }
    /// `ceremony` = the explicit one-time init switch.
    fn spawn(&self, id: usize, ceremony: bool) -> Child {
        let cfg = self.config(
            id,
            Some(quorum_core::config::SharePersistenceConfig {
                dir: self
                    .work
                    .join(format!("share{id}"))
                    .to_string_lossy()
                    .to_string(),
                kek_file: self.kek_file(id).to_string_lossy().to_string(),
                expected_group_pubkey_sha256_hex: None,
                init_ceremony: ceremony,
            }),
        );
        self.launch(id, &cfg, "cfg")
    }
    /// NEITHER `persistence` NOR `allow_ephemeral_share`.
    fn spawn_unconfigured(&self, id: usize) -> Child {
        let cfg = self.config(id, None);
        self.launch(id, &cfg, "unconfigured")
    }
    fn clear_outputs(&self, id: usize) {
        let _ = std::fs::remove_file(self.path("ready", id));
        let _ = std::fs::remove_file(self.path("pubkey.json", id));
    }
}

/// True iff the child exits with a non-zero status within `within`.
async fn p_exits_nonzero(child: &mut Child, within: Duration) -> (bool, String) {
    let deadline = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (!status.success(), format!("{status}")),
            Ok(None) => {}
            Err(e) => return (false, format!("try_wait error {e}")),
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return (
                false,
                format!("still running after {within:?} (did not refuse)"),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn test_p_share_persistence(report: &mut Report) {
    let work = PathBuf::from("/tmp/adversarial_test_p");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let base_port = 9900u16;
    let nodes = PNodes {
        work: work.clone(),
        ids: (0..N).map(|_| generate_identity()).collect(),
        audit: (0..N).map(|_| generate_audit_keypair()).collect(),
        client: generate_identity(),
        addrs: (0..N)
            .map(|i| format!("127.0.0.1:{}", base_port + i as u16))
            .collect(),
        auth_key: generate_service_auth_key(),
    };
    for id in 0..N {
        nodes.write_kek(id);
    }
    let ready: Vec<PathBuf> = (0..N).map(|i| nodes.path("ready", i)).collect();
    let guard = Duration::from_millis(
        quorum_core::MAX_DERIVE_AUTH_WINDOW_MS - quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS + 500,
    );
    let connector = quorum_client::build_connector(
        nodes.client.cert_der.clone(),
        nodes.client.key_der.clone(),
        nodes.ids.iter().map(|n| n.cert_der.clone()).collect(),
    )
    .expect("test TLS identity");
    let addrs: Vec<(usize, String)> = nodes.addrs.iter().cloned().enumerate().collect();
    let identity = "p-invoice-1";
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let transport_pk = transport_sk.public_key();

    // ---- Phase 1: one-time ceremony ----
    let mut children: Vec<Child> = (0..N).map(|i| nodes.spawn(i, true)).collect();
    wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;
    tokio::time::sleep(guard).await;
    let pk_before: Vec<Vec<u8>> = (0..N)
        .map(|i| std::fs::read(nodes.path("pubkey.json", i)).unwrap_or_default())
        .collect();
    let group_before: PublicKeySet = serde_json::from_slice(&pk_before[0]).unwrap();
    let derive = |gp: PublicKeySet| {
        let connector = connector.clone();
        let addrs = addrs.clone();
        let key = nodes.auth_key;
        let tpk = transport_pk;
        async move {
            quorum_client::collect_sealed_derived_key(
                &connector,
                &addrs,
                identity,
                T,
                &key,
                &tpk,
                &gp,
                quorum_client::ProofPolicy::Require,
                &[],
            )
            .await
        }
    };
    let before = derive(group_before.clone()).await;
    let key_before = before.as_ref().ok().and_then(|c| {
        quorum_client::open_sealed_derived_key(&c.sealed, &transport_sk, &group_before, identity)
            .ok()
    });
    let files_ok = (0..N).all(|i| nodes.share_file(i).exists());
    report.record(
        "P1: after the ceremony every node has persisted an encrypted share file and a derive works",
        files_ok && key_before.is_some(),
        format!("share files present={files_ok} derive_ok={}", key_before.is_some()),
    );

    // Leak check material: raw shares are not extractable from outside, so the
    // check below scans for the KEK bytes (hex and base64) in every node log
    // and in the share files.
    let mut kek_needles: Vec<String> = Vec::new();
    for i in 0..N {
        use base64::Engine;
        let k = std::fs::read(nodes.kek_file(i)).unwrap();
        kek_needles.push(k.iter().map(|b| format!("{b:02x}")).collect());
        kek_needles.push(base64::engine::general_purpose::STANDARD.encode(&k));
    }

    // ---- Phase 2: stop ALL nodes, restart ALL without the ceremony switch ----
    kill_all(&mut children);
    for i in 0..N {
        nodes.clear_outputs(i);
    }
    let mut children: Vec<Child> = (0..N).map(|i| nodes.spawn(i, false)).collect();
    wait_for_ready(&ready, &mut children, Duration::from_secs(30)).await;
    tokio::time::sleep(guard).await;
    let pk_after: Vec<Vec<u8>> = (0..N)
        .map(|i| std::fs::read(nodes.path("pubkey.json", i)).unwrap_or_default())
        .collect();
    report.record(
        "P2: group public key is UNCHANGED after stopping and restarting every node",
        pk_before == pk_after && !pk_after[0].is_empty(),
        format!("identical on all {N} nodes = {}", pk_before == pk_after),
    );
    let group_after: PublicKeySet =
        serde_json::from_slice(&pk_after[0]).unwrap_or_else(|_| group_before.clone());
    let after = derive(group_after.clone()).await;
    let key_after = after.as_ref().ok().and_then(|c| {
        quorum_client::open_sealed_derived_key(&c.sealed, &transport_sk, &group_before, identity)
            .ok()
    });
    report.record(
        "P3: a pre-restart invoice key is still derivable and is byte-identical (verifies against the ORIGINAL group key)",
        matches!((&key_before, &key_after), (Some(a), Some(b)) if a.to_bytes() == b.to_bytes()),
        format!("before_some={} after_some={}", key_before.is_some(), key_after.is_some()),
    );
    // P8 (leak check) runs while the healthy logs exist.
    let mut leaked = Vec::new();
    for i in 0..N {
        let log = std::fs::read_to_string(nodes.path("log", i)).unwrap_or_default();
        let shr = std::fs::read_to_string(nodes.share_file(i)).unwrap_or_default();
        for n in &kek_needles {
            if log.contains(n.as_str()) || shr.contains(n.as_str()) {
                leaked.push(i);
            }
        }
    }
    report.record(
        "P8: no node log or share file contains any node's KEK (hex or base64)",
        leaked.is_empty() && !kek_needles.is_empty(),
        format!("nodes with a hit: {leaked:?}"),
    );
    kill_all(&mut children);

    // ---- Phase 3: bad share material => refuse, never silently run DKG ----
    // P4: corrupted share file (one flipped byte in the middle).
    {
        let f = nodes.share_file(2);
        let mut raw = std::fs::read(&f).unwrap_or_default();
        let had_file = !raw.is_empty();
        if raw.is_empty() {
            raw = b"x".to_vec();
        }
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, raw).unwrap();
        nodes.clear_outputs(2);
        let mut c = nodes.spawn(2, false);
        let (refused, note) = p_exits_nonzero(&mut c, Duration::from_secs(6)).await;
        let no_outputs = !nodes.path("ready", 2).exists() && !nodes.path("pubkey.json", 2).exists();
        report.record(
            "P4: a node with a CORRUPTED share file refuses to start (non-zero exit, no ready/pubkey output, no DKG)",
            had_file && refused && no_outputs,
            format!("{note}; no outputs written={no_outputs}"),
        );
    }
    // P5: missing share file, no ceremony switch.
    {
        let _ = std::fs::remove_file(nodes.share_file(3));
        nodes.clear_outputs(3);
        let mut c = nodes.spawn(3, false);
        let (refused, note) = p_exits_nonzero(&mut c, Duration::from_secs(6)).await;
        let no_outputs = !nodes.path("ready", 3).exists();
        report.record(
            "P5: a node with a MISSING share file (and no ceremony switch) refuses to start instead of re-running DKG",
            refused && no_outputs,
            format!("{note}; no ready file={no_outputs}"),
        );
    }
    // P6: right file, wrong KEK.
    {
        nodes.write_kek(4);
        nodes.clear_outputs(4);
        let mut c = nodes.spawn(4, false);
        let (refused, note) = p_exits_nonzero(&mut c, Duration::from_secs(6)).await;
        report.record(
            "P6: a node whose KEK cannot decrypt its share file refuses to start",
            refused && !nodes.path("ready", 4).exists(),
            note,
        );
    }
    // P7: ceremony switch while a share exists must never overwrite it.
    {
        let before = std::fs::read(nodes.share_file(1)).unwrap_or_default();
        nodes.clear_outputs(1);
        let mut c = nodes.spawn(1, true);
        let (refused, note) = p_exits_nonzero(&mut c, Duration::from_secs(6)).await;
        let unchanged = !before.is_empty()
            && std::fs::read(nodes.share_file(1))
                .map(|a| a == before)
                .unwrap_or(false);
        report.record(
            "P7: init_ceremony=true with an existing share file is refused and the share file is left untouched",
            refused && unchanged,
            format!("{note}; share file unchanged={unchanged}"),
        );
    }
    // P9: forgetting the persistence section must NOT silently mean "ephemeral".
    {
        nodes.clear_outputs(0);
        let mut c = nodes.spawn_unconfigured(0);
        let (refused, note) = p_exits_nonzero(&mut c, Duration::from_secs(6)).await;
        report.record(
            "P9: a config with no `persistence` and no explicit allow_ephemeral_share refuses to start (fail closed)",
            refused && !nodes.path("ready", 0).exists(),
            note,
        );
    }
}

#[tokio::main]
async fn main() {
    // Harness change (roadmap T1-1 / T1-5): `--only A,E` runs a subset of
    // groups so a flaky group can be looped; the process now exits non-zero
    // if any check failed so CI can gate on it. No assertion was altered.
    let only: Option<Vec<char>> = {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .position(|a| a == "--only")
            .and_then(|i| args.get(i + 1))
            .map(|v| {
                v.split(',')
                    .filter_map(|t| t.trim().chars().next())
                    .map(|c| c.to_ascii_uppercase())
                    .collect()
            })
    };
    let want = |c: char| only.as_ref().is_none_or(|o| o.contains(&c));
    // Group X is a probe, not part of the default run: it runs only when named.
    let want_x = only.as_ref().is_some_and(|o| o.contains(&'X'));
    let proposers: usize = {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .position(|a| a == "--proposers")
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(3)
    };

    println!("=== Phase 4: Adversarial Testing (run against the real system) ===\n");
    let mut report = Report::new();

    if want('A') {
        println!("--- Test A: malicious minority node ---");
        test_a_malicious_minority(&mut report).await;
    }
    if want('B') {
        println!("\n--- Test B: below-threshold collusion ---");
        test_b_below_threshold_combine(&mut report).await;
    }
    if want('C') {
        println!("\n--- Test C: node-level access-control bypass (CRITICAL) ---");
        test_c_node_level_bypass(&mut report).await;
    }
    if want('D') {
        println!("\n--- Test D: replay attack ---");
        test_d_replay(&mut report).await;
    }
    if want('M') {
        println!("\n--- Test M: sealed-share NIZK gate ---");
        test_m_share_proof_gate(&mut report).await;
    }
    if want('L') {
        println!("\n--- Test L: replay across a node restart (T1-2) ---");
        test_l_restart_replay(&mut report).await;
    }
    if want('E') {
        println!("\n--- Test E: concurrent audit-proposer race ---");
        test_e_concurrent_audit_race(&mut report).await;
    }
    if want('I') {
        println!("\n--- Test I: majority tip read ---");
        test_i_majority_tip_read(&mut report).await;
    }
    if want('F') {
        println!("\n--- Test F: mTLS penetration test ---");
        test_f_mtls_pentest(&mut report).await;
    }
    if want('G') {
        println!("\n--- Test G: HTTP penetration test ---");
        test_g_http_pentest(&mut report).await;
    }
    if want('J') {
        println!("\n--- Test J: sealed-share retry protocol (A12) ---");
        test_j_sealed_share_retry_protocol(&mut report).await;
    }
    if want('K') {
        println!("\n--- Test K: TLS termination (A5) ---");
        test_k_tls_termination(&mut report).await;
    }
    if want('N') {
        println!("\n--- Test N: crypto cutover guard ---");
        test_n_cutover_guard(&mut report).await;
    }
    if want_x {
        println!("\n--- Test X: {proposers} concurrent audit proposers (opt-in probe) ---");
        test_x_n_concurrent_proposers(&mut report, proposers).await;
    }
    if only.as_ref().is_some_and(|o| o.contains(&'Y')) {
        println!("\n--- Test Y: forced vote split (opt-in, F-13) ---");
        test_y_forced_vote_split(&mut report).await;
    }
    if want('Z') {
        println!("\n--- Test Z: service audit semantics (F-13/F-14) ---");
        test_z_service_audit_semantics(&mut report).await;
    }
    if want('P') {
        println!("\n--- Test P: key-share persistence across restart (Gap 1) ---");
        test_p_share_persistence(&mut report).await;
    }
    if want('Q') {
        println!("\n--- Test Q: audit-log durability (Gap 13) ---");
        test_q_audit_log_durability(&mut report).await;
    }
    if want('R') {
        println!("\n--- Test R: acknowledged => durable (F-19) ---");
        test_r_ack_implies_durable(&mut report).await;
    }
    if want('S') {
        println!("\n--- Test S: leaked single-node auth key (Gap 3 step 1) ---");
        test_s_leaked_node_key_is_contained(&mut report).await;
    }
    if want('T') {
        println!("\n--- Test T: secrets from files (Gap 9) ---");
        test_t_secret_files(&mut report).await;
    }
    if want('W') {
        println!("\n--- Test W: parser fuzz smoke (Gap 8 / T-9) ---");
        let iters: Option<usize> = {
            let args: Vec<String> = std::env::args().collect();
            args.iter()
                .position(|a| a == "--fuzz-iters")
                .and_then(|i| args.get(i + 1))
                .and_then(|v| v.parse().ok())
        };
        for o in fuzz_smoke::run(iters) {
            report.record(&o.name, o.passed, o.notes);
        }
    }
    if want('H') {
        println!("\n--- Test H: real network partition ---");
        test_h_network_partition(&mut report).await;
    }

    report.print_summary();
    if report.results.iter().any(|(_, passed, _)| !*passed) {
        std::process::exit(1);
    }
}
