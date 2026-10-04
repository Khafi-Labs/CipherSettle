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
            service_auth_key_b64: b64(&service_auth_key),
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
    );

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
            quorum_client::build_server_config(cert_der, key_der, vec![client_cert]);
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
    let req = quorum_core::build_derive_request(
        &q.service_auth_key,
        identity,
        quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
        transport_pk,
    );
    for (id, addr) in addrs.iter().take(T) {
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
        &q.service_auth_key,
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
        &q.service_auth_key,
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
        &q.service_auth_key,
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
    );
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
            service_auth_key_b64: b64(&service_auth_key),
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
    let want = |c: char| only.as_ref().map_or(true, |o| o.contains(&c));

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
    if want('H') {
        println!("\n--- Test H: real network partition ---");
        test_h_network_partition(&mut report).await;
    }

    report.print_summary();
    if report.results.iter().any(|(_, passed, _)| !*passed) {
        std::process::exit(1);
    }
}
