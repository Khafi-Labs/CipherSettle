//! Test harness driving the roadmap's Phase 1 AND Phase 2 exit criteria
//! end to end, against real separate OS processes over real mTLS.
//!
//! Phase 1 (see PHASE1_README.md for detail): spawn 5 `quorum_node`
//! processes, wait for DKG, kill 2 to simulate an outage, derive from the
//! 3 survivors, round-trip decrypt.
//!
//! Phase 2 (this addition):
//!  6. Build an audit event for the derive that just happened, reusing
//!     `ciphersettle_core::audit_action_for` UNCHANGED, per the roadmap's
//!     explicit instruction.
//!  7. Propose it to the 3 surviving nodes, collect their individual
//!     co-signatures, and replicate the fully co-signed entry back to them.
//!  8. Spawn a separate `quorum_notary` process (a genuinely different
//!     identity/process playing "somewhere outside every quorum member's
//!     control") and notarize the log's root hash on a short repeating
//!     schedule -- a compressed stand-in for "hourly or daily."
//!  9. **Tamper with a node's on-disk audit log after taking it offline**:
//!     fully recompute its hash chain so the tampered copy is internally
//!     self-consistent (the hard case, not just corrupted JSON).
//! 10. Run reconciliation across all 5 nodes' logs (the still-live nodes
//!     over mTLS, the offline ones read directly from their last-persisted
//!     disk state) and confirm it flags exactly the tampered node with a
//!     hash mismatch -- while correctly NOT flagging the two nodes that
//!     were offline before the entry even existed (they're just behind,
//!     which reconciliation reports as a length mismatch, not tampering).
//!
//! Phase 3 (this addition): spins up `quorum_service` against the still-live
//! 3 nodes + notary, pointed at a real Postgres database, and drives the
//! full product lifecycle over plain HTTP: register -> grant -> derive (via
//! the quorum) -> settle -> (reject an early prune) -> prune -> read the
//! audit trail back -- plus a regulator-access check and an
//! access-denied check, exercising `resolve_access`'s full decision space,
//! not just the happy path.

use ciphersettle_core::{audit_action_for, AccessRole};
use ed25519_dalek::SigningKey;
use quorum_audit::wire::NotaryMessage;
use quorum_audit::{AuditEvent, AuditLog};
use quorum_core::config::{NodeConfig, PeerConfig};
use quorum_core::Message;
use rand::rngs::OsRng;
// Audit finding A4: rand 0.8's OsRng, aliased distinctly from the rand
// 0.7 `OsRng` above -- see Cargo.toml's comment on the `rand08`
// dependency for why this crate needs both. Used only for
// `SigningKey::generate`.
use quorum_core::PublicKeySet;
use rand::rngs::OsRng as OsRng08;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const N: usize = 5;
const T: usize = 2; // 3-of-5

struct GeneratedIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_identity() -> GeneratedIdentity {
    let cert = rcgen::generate_simple_self_signed(vec!["quorum-node".to_string()])
        .expect("self-signed cert generation should not fail");
    GeneratedIdentity {
        cert_der: cert
            .serialize_der()
            .expect("DER serialization should not fail"),
        key_der: cert.serialize_private_key_der(),
    }
}

// Audit finding A4: SigningKey::to_bytes() is 32 bytes (the seed
// only), unlike 1.x's Keypair::to_bytes() (64 bytes, secret||public
// concatenated) -- every writer AND reader of audit_keypair_b64 in
// this workspace was updated together in this migration, and since
// this project always generates fresh keys per run rather than
// reading externally-provisioned ones, there's no real old-format
// data to stay compatible with.
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
/// request (Phase 6a wiring), so every test harness call needs one.
fn sample_commitment_b64(invoice_reference: &str) -> String {
    use ciphersettle_core::InvoiceFields;
    let fields = InvoiceFields {
        invoice_reference: invoice_reference.to_string(),
        issuer: "Orchestrator Test Issuer".to_string(),
        debtor: "Orchestrator Test Debtor".to_string(),
        amount_minor_units: 1_234_500,
        currency: "EGP".to_string(),
        issue_date: "2026-09-01".to_string(),
        due_date: "2026-12-01".to_string(),
    };
    let commitment = ciphersettle_core::InvoiceCommitment::compute(&fields, &mut OsRng08);
    b64(&commitment.to_bytes())
}

#[tokio::main]
async fn main() {
    let work_dir = PathBuf::from("/tmp/ciphersettle_quorum_demo");
    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir).expect("failed to create work dir");

    println!("=== Phase 1 + Phase 2 exit-criteria demo ===\n");

    // ---------------------------------------------------------------
    // Step 1: generate identities. Two DISTINCT keypairs per node -- a TLS
    // cert (network auth) and an ed25519 audit-signing key (co-signature
    // auth) -- plus one client identity and one notary identity.
    // ---------------------------------------------------------------
    let node_identities: Vec<GeneratedIdentity> = (0..N).map(|_| generate_identity()).collect();
    let node_audit_keys: Vec<SigningKey> = (0..N).map(|_| generate_audit_keypair()).collect();
    let client_identity = generate_identity();
    let notary_identity = generate_identity();
    let notary_audit_key = generate_audit_keypair();
    let service_auth_key = generate_service_auth_key();
    println!("[setup] generated {N} node TLS identities + {N} node audit-signing keys + client + notary identities + the service_auth_key.");

    let ports: Vec<u16> = (0..N).map(|i| 9100 + i as u16).collect();
    let addrs: Vec<String> = ports.iter().map(|p| format!("127.0.0.1:{p}")).collect();
    let notary_addr = "127.0.0.1:9200".to_string();

    // ---------------------------------------------------------------
    // Step 2: write each node's config and spawn it as its own process.
    // ---------------------------------------------------------------
    let node_binary = locate_sibling_binary("quorum_node");
    let notary_binary = locate_sibling_binary("quorum_notary");
    println!("[setup] node binary: {}", node_binary.display());
    println!("[setup] notary binary: {}\n", notary_binary.display());

    let mut children: Vec<Child> = Vec::with_capacity(N);
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
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap())
            .expect("failed to write node config");

        let child = Command::new(&node_binary)
            .arg(&config_path)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn node {id}: {e}"));
        println!(
            "[setup] spawned node {id} (pid {}) listening on {}",
            child.id(),
            addrs[id]
        );
        children.push(child);
        ready_files.push(ready_file);
        pubkey_files.push(pubkey_file);
        audit_log_files.push(audit_log_file);
    }

    // Spawn the notary as its own separate process/identity too.
    let notary_receipts_file = work_dir.join("notary_receipts.jsonl");
    #[derive(serde::Serialize)]
    struct NotaryConfigOut {
        listen_addr: String,
        cert_der_b64: String,
        key_der_b64: String,
        audit_keypair_b64: String,
        allowed_client_certs_b64: Vec<String>,
        receipts_file: String,
    }
    let notary_config = NotaryConfigOut {
        listen_addr: notary_addr.clone(),
        cert_der_b64: b64(&notary_identity.cert_der),
        key_der_b64: b64(&notary_identity.key_der),
        audit_keypair_b64: b64(&notary_audit_key.to_bytes()),
        allowed_client_certs_b64: vec![b64(&client_identity.cert_der)],
        receipts_file: notary_receipts_file.to_string_lossy().to_string(),
    };
    let notary_config_path = work_dir.join("notary.json");
    std::fs::write(
        &notary_config_path,
        serde_json::to_vec_pretty(&notary_config).unwrap(),
    )
    .unwrap();
    let mut notary_child = Command::new(&notary_binary)
        .arg(&notary_config_path)
        .spawn()
        .expect("failed to spawn notary");
    println!(
        "[setup] spawned notary (pid {}) listening on {notary_addr}\n",
        notary_child.id()
    );
    tokio::time::sleep(Duration::from_millis(300)).await; // let it bind before we connect

    // ---------------------------------------------------------------
    // Step 3: wait for all 5 nodes to finish DKG.
    // ---------------------------------------------------------------
    println!("[dkg] waiting for all {N} nodes to finalize DKG over mTLS...");
    let deadline = Instant::now() + Duration::from_secs(30);
    for (id, ready_file) in ready_files.iter().enumerate() {
        while !ready_file.exists() {
            if Instant::now() > deadline {
                kill_all(&mut children);
                let _ = notary_child.kill();
                panic!("timed out waiting for node {id} to finish DKG -- check its stderr above");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    println!("[dkg] all {N} nodes report DKG finalized.\n");

    // T1-2: each node refuses new derive requests for
    // `MAX_DERIVE_AUTH_WINDOW_MS - DEFAULT_DERIVE_AUTH_VALIDITY_MS` after its
    // process start (restart-replay guard). DKG can complete faster than
    // that, so wait it out before the first derive; timing only.
    tokio::time::sleep(Duration::from_millis(
        quorum_core::MAX_DERIVE_AUTH_WINDOW_MS - quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS + 500,
    ))
    .await;

    let group_pks: PublicKeySet = {
        let raw =
            std::fs::read(&pubkey_files[0]).expect("failed to read published group public key");
        serde_json::from_slice(&raw).expect("published public key file is corrupt")
    };
    for (id, f) in pubkey_files.iter().enumerate() {
        let raw = std::fs::read(f).unwrap();
        let pks: PublicKeySet = serde_json::from_slice(&raw).unwrap();
        assert!(
            pks.public_key() == group_pks.public_key(),
            "node {id} published a different group public key"
        );
    }
    println!(
        "[dkg] confirmed all {N} nodes independently derived the identical group public key.\n"
    );

    // ---------------------------------------------------------------
    // Step 4: kill 2 of 5 node processes to simulate an outage.
    // ---------------------------------------------------------------
    let killed_ids = [3usize, 4usize];
    println!(
        "[outage] killing nodes {killed_ids:?} (SIGKILL), leaving {}-of-{} alive...",
        N - killed_ids.len(),
        N
    );
    for &id in &killed_ids {
        children[id].kill().expect("failed to kill node process");
        children[id].wait().ok();
    }
    let surviving_ids: Vec<usize> = (0..N).filter(|id| !killed_ids.contains(id)).collect();
    println!("[outage] surviving nodes: {surviving_ids:?}\n");

    // ---------------------------------------------------------------
    // Step 5: derive over mTLS from the 3 survivors (Phase 1).
    // ---------------------------------------------------------------
    let client_verifier_certs: Vec<Vec<u8>> = node_identities
        .iter()
        .map(|n| n.cert_der.clone())
        .chain(std::iter::once(notary_identity.cert_der.clone()))
        .collect();
    let connector = quorum_client::build_connector(
        client_identity.cert_der.clone(),
        client_identity.key_der.clone(),
        client_verifier_certs,
    )
    .expect("test TLS identity");

    let identity = "inv-2026-000042";
    println!("[derive] requesting a derive for identity {identity:?} from nodes {surviving_ids:?} over mTLS...");

    // Finding 2.3 fix: this harness now plays the role of the true end
    // caller -- it generates its own transport secret key locally, sends
    // only the public half out with the request, and is the only party
    // that ever opens the sealed result. `quorum_client::send_request`
    // below is standing in for what would otherwise be
    // `quorum_service`'s `collect_sealed_derived_key` call; the point of
    // this test is that even fully inlined like this, nothing between
    // "node signs" and "this harness decrypts" is ever a usable
    // plaintext share.
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut OsRng);
    let transport_pk = transport_sk.public_key();

    let mut sealed_shares: Vec<(usize, quorum_vetseal::SealedShare)> = Vec::new();
    for &id in &surviving_ids {
        let req = quorum_core::build_derive_request(
            &quorum_core::derive_node_auth_key(&service_auth_key, id),
            identity,
            quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS,
            transport_pk,
        );
        match quorum_client::send_request(&connector, &addrs[id], &req).await {
            Some(Message::DerivePartial {
                sealed_share,
                proof,
                ..
            }) => {
                assert!(
                    quorum_core::verify_sealed_partial(
                        &group_pks,
                        id,
                        identity,
                        &transport_pk,
                        &sealed_share,
                        &proof
                    ),
                    "node {id}'s sealed partial failed NIZK verification"
                );
                println!("[derive] node {id} returned a sealed partial (NIZK verified).");
                sealed_shares.push((id, sealed_share));
            }
            other => panic!("unexpected response from node {id}: {other:?}"),
        }
    }
    let sealed_combined = quorum_vetseal::combine_sealed_shares(&sealed_shares)
        .expect("combine of sealed shares failed");
    let combined =
        quorum_core::Signature::from_bytes(&transport_sk.decrypt_combined(&sealed_combined))
            .expect("decrypting the combined sealed result failed");
    assert!(
        quorum_core::verify_combined(&group_pks, identity, &combined),
        "combined key failed verification"
    );
    println!(
        "\n[derive] combined {}-of-{} sealed partials; decrypted locally and verified against the group public key.",
        sealed_shares.len(),
        N
    );

    let plaintext = b"invoice amount: 48,500.00; counterparty: Example Bank N.A.";
    let key = symmetric_key_from_derived(&combined);
    let ciphertext = xor(&key, plaintext);
    let recovered = xor(&key, &ciphertext);
    assert_eq!(recovered, plaintext);
    println!(
        "[round trip] decrypted locally: {:?}\n",
        String::from_utf8_lossy(&recovered)
    );

    // ---------------------------------------------------------------
    // Step 6 (Phase 2): build the audit event, reusing
    // ciphersettle_core::audit_action_for UNCHANGED per the roadmap.
    // Real role resolution is Phase 3's job; this demo hardcodes the
    // "Bank" role to match the round-trip plaintext's counterparty.
    // ---------------------------------------------------------------
    let action = audit_action_for(&AccessRole::Bank);
    let event = AuditEvent {
        invoice_id: identity.to_string(),
        actor: "demo-bank-principal".to_string(),
        action: action.to_string(),
        timestamp_unix_ms: now_unix_ms(),
    };
    println!("[audit] built event: invoice_id={:?} action={:?} (via ciphersettle_core::audit_action_for)", event.invoice_id, event.action);

    // Genesis: this is the first audit entry in this whole demo.
    let local_log = AuditLog::default();
    let mut entry = local_log.propose_next(event);

    println!(
        "[audit] proposing entry seq {} to nodes {surviving_ids:?} for co-signature...",
        entry.seq
    );
    for &id in &surviving_ids {
        let req = Message::AppendAuditEntry {
            entry: entry.clone(),
        };
        match quorum_client::send_request(&connector, &addrs[id], &req).await {
            Some(Message::AuditEntrySigned { node_id, signature }) => {
                entry.signatures.insert(node_id, signature);
                println!("[audit] node {node_id} co-signed.");
            }
            Some(Message::AuditAppendRejected { node_id, reason }) => {
                panic!("node {node_id} rejected the audit append: {reason}");
            }
            other => panic!("unexpected response from node {id}: {other:?}"),
        }
    }
    println!(
        "[audit] entry now has {} co-signatures.\n",
        entry.signatures.len()
    );

    println!("[audit] replicating the fully co-signed entry back to nodes {surviving_ids:?} (and best-effort to the 2 offline nodes)...");
    for &id in &surviving_ids {
        let req = Message::ReplicateAuditEntry {
            entry: entry.clone(),
        };
        let _ = quorum_client::send_fire_and_forget(&connector, &addrs[id], &req).await;
    }
    for &id in &killed_ids {
        // Best-effort: these nodes are down, so this will simply fail to
        // connect. A real deployment retries this once the node returns --
        // exactly the "replicate across all quorum nodes... once
        // reachable" gap this demo does not implement.
        let req = Message::ReplicateAuditEntry {
            entry: entry.clone(),
        };
        let delivered = quorum_client::send_fire_and_forget(&connector, &addrs[id], &req).await;
        if !delivered {
            println!("[audit] node {id} is offline; will replicate once it returns (not implemented in this demo).");
        }
    }
    println!();

    // ---------------------------------------------------------------
    // Step 7 (Phase 2): external notarization, on a short repeating
    // schedule (compressed stand-in for "hourly or daily").
    // ---------------------------------------------------------------
    println!("[notarize] running the notarization job on a (compressed, demo-speed) schedule...");
    let mut last_receipt = None;
    for round in 0..3 {
        let root_hash = entry.entry_hash; // in a longer-lived log this would be log.tip_hash()
        let req = NotaryMessage::NotarizeRequest { root_hash };
        let response = quorum_client::send_notary_request(&connector, &notary_addr, &req).await;
        match response {
            Some(NotaryMessage::NotarizeResponse { receipt }) => {
                assert!(
                    receipt.verify(&notary_audit_key.verifying_key()),
                    "notary receipt failed signature verification"
                );
                println!(
                    "[notarize] round {round}: sequence {} notarized at t={}ms, receipt verified against the notary's own public key.",
                    receipt.sequence, receipt.notarized_at_unix_ms
                );
                last_receipt = Some(receipt);
            }
            other => panic!("unexpected notary response: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    println!(
        "[notarize] {} total notarization(s) now exist, each independently verifiable and outside any quorum node's control.\n",
        last_receipt.as_ref().map(|r| r.sequence + 1).unwrap_or(0)
    );

    // ---------------------------------------------------------------
    // Step 8 (Phase 2): tamper with a node's on-disk copy AFTER it has
    // genuinely persisted the entry. Nodes 3/4 never received it at all
    // (they were already offline during the append/replicate step above)
    // -- tampering with an empty file wouldn't test anything. Rather than
    // also taking node 2 offline (which would leave only 2-of-5 alive --
    // not enough for Phase 3's derive calls below), we tamper with node
    // 2's PERSISTED file while its process keeps running. This is
    // actually a more realistic threat model, not a lesser one: an
    // operator with filesystem/backup access can rewrite a node's
    // on-disk state without ever touching the live process, and the
    // live process's own in-memory copy (which is all its own
    // `GetAuditLog` responses ever reflect -- it never reloads from
    // disk) would look completely untampered the whole time. Catching
    // this requires reconciliation to specifically audit PERSISTED
    // state, not just trust a node's live self-report -- exactly what
    // you'd want after restoring from a backup or during a forensic
    // review, and a strictly harder case than an offline node.
    // ---------------------------------------------------------------
    let tampered_node = 2usize;
    println!("[tamper] rewriting node {tampered_node}'s ON-DISK audit log while its process keeps running (fully re-chained, so it looks internally valid; its live in-memory copy is untouched and still correct)...");
    tamper_audit_log_on_disk(&audit_log_files[tampered_node]);
    println!("[tamper] done.\n");

    // All 3 original survivors are still genuinely alive -- node 2's
    // *process* was never touched, only its on-disk file. That matters
    // for Phase 3 below, which needs a real 3-of-5 quorum to derive from.
    let live_ids = surviving_ids.clone();
    let offline_honest_ids: Vec<usize> = killed_ids.to_vec(); // 3, 4 -- never got the entry at all; that's a real gap, not tampering

    // ---------------------------------------------------------------
    // Step 9 (Phase 2): reconciliation. For nodes 0/1, ask the live
    // process (mTLS `GetAuditLog`) -- this is the normal path. For node 2,
    // deliberately read its file from disk instead of asking it live,
    // since asking it live would only return its correct, UNTAMPERED
    // in-memory copy and prove nothing; the whole point here is auditing
    // what's actually persisted. For 3/4, read from disk because they're
    // genuinely offline and there's no live process to ask.
    // ---------------------------------------------------------------
    println!("[reconcile] fetching each node's audit log (live over mTLS for 0/1; from disk for node {tampered_node} -- to audit its PERSISTED state rather than trust its live self-report -- and for the genuinely offline nodes {offline_honest_ids:?})...");
    let mut logs: BTreeMap<usize, AuditLog> = BTreeMap::new();
    let live_query_ids: Vec<usize> = live_ids
        .iter()
        .copied()
        .filter(|&id| id != tampered_node)
        .collect();
    for &id in &live_query_ids {
        let req = Message::GetAuditLog { invoice_id: None };
        match quorum_client::send_request(&connector, &addrs[id], &req).await {
            Some(Message::AuditLogEntries { entries }) => {
                logs.insert(id, AuditLog { entries });
            }
            other => panic!("unexpected response from node {id}: {other:?}"),
        }
    }
    let disk_read_ids: Vec<usize> = offline_honest_ids
        .iter()
        .copied()
        .chain(std::iter::once(tampered_node))
        .collect();
    for &id in &disk_read_ids {
        // Missing snapshot and journal = the node never received anything.
        let log: AuditLog = quorum_audit::journal::load_log(&audit_log_files[id])
            .expect("persisted audit log is corrupt");
        logs.insert(id, log);
    }

    // Each node's own copy should still be internally self-consistent --
    // including the tampered one, which is exactly why this check ALONE
    // is not enough (see quorum_audit's module doc comment).
    for (id, log) in &logs {
        let chain_ok = log.verify_chain().is_ok();
        println!(
            "[reconcile] node {id}: {} entries, internally self-consistent = {chain_ok}",
            log.entries.len()
        );
    }

    // Reconcile every node's copy against a MAJORITY-AGREED reference,
    // not one hardcoded node (Stage F fix for Finding 2.2). Previously
    // this compared everyone against node 0's copy specifically, which
    // meant "no single node can rewrite history" secretly depended on
    // node 0 not being the compromised one. `AuditLog::majority_reference`
    // instead takes a per-sequence hash vote across every reporting
    // node's copy, so the tampered node here (node 2) is outvoted by the
    // other 3 honest respondents rather than being trusted as ground truth
    // just because of its position in a config file.
    println!(
        "\n[reconcile] building a majority-agreed reference from all {} reporting nodes' copies...",
        logs.len()
    );
    let reference = AuditLog::majority_reference(&logs);
    println!(
        "[reconcile] majority reference has {} entries (out of a max reported length of {}).",
        reference.entries.len(),
        logs.values().map(|l| l.entries.len()).max().unwrap_or(0)
    );
    let mut hash_mismatch_found_at = None;
    for (&id, log) in &logs {
        match reference.diverges_from(log) {
            None => println!("[reconcile] node {id}: matches the majority reference. \u{2713}"),
            Some(quorum_audit::Divergence::LengthMismatch { ours, theirs }) => {
                println!(
                    "[reconcile] node {id}: behind the majority reference ({theirs} vs {ours} entries) -- consistent with it having been offline before this entry was ever proposed to it, NOT evidence of tampering."
                );
            }
            Some(d @ quorum_audit::Divergence::HashMismatch { .. }) => {
                println!("[reconcile] node {id}: DIVERGES from the majority reference -- {d:?}  \u{26a0}\u{fe0f}  TAMPER DETECTED");
                hash_mismatch_found_at = Some(id);
            }
        }
    }
    let flagged_node = hash_mismatch_found_at
        .expect("reconciliation should have caught the tampered node via a hash mismatch");
    assert_eq!(
        flagged_node, tampered_node,
        "reconciliation flagged the wrong node"
    );
    println!("\n=== Phase 1 + Phase 2 exit-criteria demo complete: mTLS DKG -> outage -> derive -> round trip -> co-signed audit append -> scheduled notarization -> tamper node {tampered_node} -> reconciliation correctly flags node {tampered_node} (and separately, honestly reports nodes {offline_honest_ids:?} as merely behind). ===\n");

    // =================================================================
    // PHASE 3: spin up quorum_service against the still-live 3-node
    // quorum + notary, backed by a real Postgres database, and drive the
    // full product lifecycle over plain HTTP.
    // =================================================================
    run_phase3_demo(
        &node_identities,
        &live_ids,
        &addrs,
        &notary_addr,
        &notary_identity,
        &client_identity,
        &pubkey_files[live_ids[0]],
        T,
        &service_auth_key,
    )
    .await;

    kill_all(&mut children);
    let _ = notary_child.kill();
    let _ = notary_child.wait();
}

/// Phase 3: spins up `quorum_service` pointed at the given (still-live)
/// quorum nodes + notary + a real Postgres database, then drives
/// register -> grant -> derive (via the quorum) -> settle -> prune over
/// plain HTTP, plus a regulator-access check and an access-denied check.
// 9 arguments is a demo-orchestrator smell, not a correctness or security
// issue; grouping them into a config struct is reasonable future cleanup
// but out of scope for the audit remediation roadmap this pass is working
// through. Tracked as known style debt.
#[allow(clippy::too_many_arguments)]
async fn run_phase3_demo(
    node_identities: &[GeneratedIdentity],
    live_ids: &[usize],
    addrs: &[String],
    notary_addr: &str,
    notary_identity: &GeneratedIdentity,
    client_identity: &GeneratedIdentity,
    group_pubkey_file: &std::path::Path,
    threshold: usize,
    service_auth_key: &[u8],
) {
    println!("=== Phase 3: product API (quorum_service) over Postgres + the live quorum ===\n");

    let group_pks: PublicKeySet = {
        let raw =
            std::fs::read(group_pubkey_file).expect("failed to read published group public key");
        serde_json::from_slice(&raw).expect("published public key file is corrupt")
    };

    let service_binary = locate_sibling_binary("quorum_service");
    let work_dir = PathBuf::from("/tmp/ciphersettle_quorum_demo");
    let service_listen_addr = "127.0.0.1:9300".to_string();
    let db_url =
        "host=127.0.0.1 user=postgres password=ciphersettle_dev dbname=ciphersettle_phase3"
            .to_string();

    let issuer_key = "issuer-key-demo";
    let bank_key = "bank-key-demo";
    let regulator_key = "regulator-key-demo";
    let stranger_key = "stranger-key-demo";
    let admin_key = "admin-key-demo";
    let admin_caller_id = "demo-admin";

    let config = json!({
        "listen_addr": service_listen_addr,
        "db_url": db_url,
        "admin_caller_id": admin_caller_id,
        "api_keys": [
            {"key": issuer_key, "caller_id": "demo-issuer"},
            {"key": bank_key, "caller_id": "demo-bank"},
            {"key": regulator_key, "caller_id": "demo-regulator"},
            {"key": stranger_key, "caller_id": "demo-stranger"},
            {"key": admin_key, "caller_id": admin_caller_id},
        ],
        "client_cert_der_b64": b64(&client_identity.cert_der),
        "client_key_der_b64": b64(&client_identity.key_der),
        "service_auth_key_b64": b64(service_auth_key),
        "quorum_nodes": live_ids.iter().map(|&id| json!({
            "id": id,
            "addr": addrs[id],
            "cert_der_b64": b64(&node_identities[id].cert_der),
        })).collect::<Vec<_>>(),
        "notary_addr": notary_addr,
        "notary_cert_der_b64": b64(&notary_identity.cert_der),
        "group_pubkey_file": group_pubkey_file.to_string_lossy(),
        "quorum_threshold": threshold,
        "max_ciphertext_bytes": 65536,
        "ciphertext_retention_ms": 1500u64, // compressed for demo purposes; a real deployment uses days, not milliseconds
        "derive_rate_limit_max_calls": 5,
        "derive_rate_limit_window_ms": 10_000u64,
        "acknowledge_pre_cutover_data": true, // scratch demo DB reused across runs; no marker on first run
    });
    let config_path = work_dir.join("service.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

    let mut service_child = Command::new(&service_binary)
        .arg(&config_path)
        .spawn()
        .expect("failed to spawn quorum_service");
    println!(
        "[phase3] spawned quorum_service (pid {}) listening on {service_listen_addr}",
        service_child.id()
    );

    // Wait for it to actually bind before hammering it with requests.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&service_listen_addr).await.is_ok() {
            break;
        }
        if Instant::now() > deadline {
            let _ = service_child.kill();
            panic!("quorum_service never started listening on {service_listen_addr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("[phase3] service is up.\n");

    let invoice_id = format!("inv-phase3-{}", now_unix_ms());

    // 1. register_invoice (as issuer)
    let ciphertext_b64 =
        b64(b"this is the confidential invoice payload, opaque to every quorum node");
    let (status, body) = http_json(
        &service_listen_addr,
        "POST",
        "/invoices",
        Some(issuer_key),
        Some(&json!({"invoice_id": invoice_id, "nullifier_hash": format!("null-{invoice_id}"), "ciphertext_b64": ciphertext_b64, "commitment_b64": sample_commitment_b64(&invoice_id)}).to_string()),
    )
    .await;
    assert_eq!(status, 201, "register_invoice failed: {body}");
    println!("[phase3] register_invoice -> 201 Created");

    // Re-registering the same invoice_id must fail (uniqueness).
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        "/invoices",
        Some(issuer_key),
        Some(&json!({"invoice_id": invoice_id, "nullifier_hash": format!("null2-{invoice_id}"), "ciphertext_b64": ciphertext_b64, "commitment_b64": sample_commitment_b64(&invoice_id)}).to_string()),
    )
    .await;
    assert_eq!(status, 409, "duplicate invoice_id should be rejected");
    println!("[phase3] duplicate register_invoice correctly rejected -> 409 Conflict");

    // A stranger cannot derive yet (no access granted). Include a
    // well-formed (if unused) transport_public_key_b64 so the request
    // body itself is valid and the test genuinely exercises the 403
    // access-control path, not a 4xx from a malformed body.
    let stranger_transport_pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        quorum_vetseal::TransportSecretKey::random(&mut OsRng)
            .public_key()
            .to_bytes(),
    );
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(stranger_key),
        Some(&json!({"transport_public_key_b64": stranger_transport_pk_b64}).to_string()),
    )
    .await;
    assert_eq!(
        status, 403,
        "a stranger with no relationship to the invoice must be denied"
    );
    println!("[phase3] unauthorized derive-key correctly rejected -> 403 Forbidden");

    // 2. grant_settlement_access (as issuer, to bank)
    let (status, body) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/grant"),
        Some(issuer_key),
        Some(&json!({"bank": "demo-bank"}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "grant_settlement_access failed: {body}");
    println!("[phase3] grant_settlement_access -> 200 OK");

    // 3. derive_invoice_key (as issuer) -- brokered against the live quorum.
    // Finding 2.3 fix: this harness generates its own transport key
    // locally (standing in for a browser/CLI caller), sends only the
    // public half to quorum_service, and is the only party that ever
    // opens the sealed response -- quorum_service itself never holds a
    // plaintext key.
    let issuer_transport_sk = quorum_vetseal::TransportSecretKey::random(&mut OsRng);
    let issuer_transport_pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        issuer_transport_sk.public_key().to_bytes(),
    );
    let (status, body) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(issuer_key),
        Some(&json!({"transport_public_key_b64": issuer_transport_pk_b64}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "derive_invoice_key (issuer) failed: {body}");
    let derived: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sealed_b64 = derived["sealed_derived_key_b64"]
        .as_str()
        .filter(|s| !s.is_empty())
        .expect("derive_invoice_key must return a non-empty sealed_derived_key_b64");
    // Confirm the sealed response actually opens, client-side, to a key
    // that verifies against the group public key -- the end-to-end proof
    // that quorum_service brokered a real derive without ever seeing the
    // plaintext result itself.
    let sealed_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sealed_b64)
            .expect("sealed_derived_key_b64 must be valid base64");
    let sealed_arr: [u8; quorum_vetseal::SEALED_COMPRESSED_SIZE] = sealed_bytes
        .try_into()
        .expect("unexpected sealed derived key length");
    let sealed = quorum_vetseal::SealedDerivedKey::from_bytes(&sealed_arr)
        .expect("malformed sealed derived key");
    let opened = quorum_core::Signature::from_bytes(&issuer_transport_sk.decrypt_combined(&sealed))
        .expect("failed to open sealed derived key");
    assert!(
        quorum_core::verify_combined(&group_pks, &invoice_id, &opened),
        "opened derived key failed verification against the group public key"
    );
    println!(
        "[phase3] derive_invoice_key (issuer) -> 200 OK, sealed key opened and verified client-side via the live 3-of-5 quorum"
    );

    // Same, as the bank -- also authorized, should log under a different action.
    let bank_transport_pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        quorum_vetseal::TransportSecretKey::random(&mut OsRng)
            .public_key()
            .to_bytes(),
    );
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(bank_key),
        Some(&json!({"transport_public_key_b64": bank_transport_pk_b64}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "derive_invoice_key (bank) failed");
    println!("[phase3] derive_invoice_key (bank) -> 200 OK");

    // Register a regulator (admin-only) and confirm regulator access works
    // regardless of issuer/bank relationship.
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        "/regulators",
        Some(admin_key),
        Some(&json!({"principal": "demo-regulator"}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "register_regulator failed");
    let regulator_transport_pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        quorum_vetseal::TransportSecretKey::random(&mut OsRng)
            .public_key()
            .to_bytes(),
    );
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/derive-key"),
        Some(regulator_key),
        Some(&json!({"transport_public_key_b64": regulator_transport_pk_b64}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "derive_invoice_key (regulator) failed");
    println!("[phase3] register_regulator (admin) + derive_invoice_key (regulator) -> both 200 OK");

    // A non-admin cannot register regulators.
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        "/regulators",
        Some(issuer_key),
        Some(&json!({"principal": "demo-stranger"}).to_string()),
    )
    .await;
    assert_eq!(
        status, 403,
        "a non-admin must not be able to register regulators"
    );
    println!("[phase3] non-admin register_regulator correctly rejected -> 403 Forbidden");

    // 4. mark_settled (as bank)
    let (status, body) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/settle"),
        Some(bank_key),
        None,
    )
    .await;
    assert_eq!(status, 200, "mark_settled failed: {body}");
    println!("[phase3] mark_settled (bank) -> 200 OK");

    // 5. prune_ciphertext too early must fail (retention window not elapsed)
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/prune"),
        Some(stranger_key),
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "pruning before the retention window elapses must be rejected"
    );
    println!("[phase3] early prune_ciphertext correctly rejected -> 409 Conflict (retention window not yet elapsed)");

    println!("[phase3] waiting out the (demo-compressed) retention window...");
    tokio::time::sleep(Duration::from_millis(1700)).await;

    // prune_ciphertext is callable by anyone once eligible, matching the
    // original canister's documented design (storage hygiene, not access
    // control).
    let (status, body) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/prune"),
        Some(stranger_key),
        None,
    )
    .await;
    assert_eq!(status, 200, "prune_ciphertext failed: {body}");
    println!("[phase3] prune_ciphertext (by a stranger, once eligible) -> 200 OK");

    // Pruning again must fail (already pruned).
    let (status, _) = http_json(
        &service_listen_addr,
        "POST",
        &format!("/invoices/{invoice_id}/prune"),
        Some(stranger_key),
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "re-pruning an already-pruned invoice must be rejected"
    );
    println!("[phase3] re-pruning correctly rejected -> 409 Conflict");

    // 6. get_audit_log -- public, should show the full lifecycle in order.
    let (status, body) = http_json(
        &service_listen_addr,
        "GET",
        &format!("/audit-log?invoice_id={invoice_id}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200, "get_audit_log failed: {body}");
    let entries: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    let actions: Vec<&str> = entries
        .iter()
        .map(|e| e["event"]["action"].as_str().unwrap_or("?"))
        .collect();
    println!(
        "[phase3] get_audit_log -> {} entries for {invoice_id}: {actions:?}",
        entries.len()
    );
    assert!(actions.contains(&"invoice_registered"));
    assert!(actions.contains(&"settlement_access_granted"));
    assert!(actions.contains(&"key_derived_issuer"));
    assert!(actions.contains(&"key_derived_bank"));
    assert!(actions.contains(&"disclosure_request")); // the regulator's derive call
    assert!(actions.contains(&"invoice_settled"));
    assert!(actions.contains(&"ciphertext_pruned"));

    println!("\n=== Phase 3 exit-criteria demo complete: register -> grant -> derive (via the live quorum) -> settle -> prune, end to end over HTTP against a real Postgres-backed service, API surface matching the original .did method set. ===");

    let _ = service_child.kill();
    let _ = service_child.wait();
}

/// Minimal hand-rolled HTTP/1.1 client (deliberately no `reqwest` dependency
/// -- this is a controlled localhost demo, not a general-purpose client).
/// Sends `Connection: close` so the server closes after responding, which
/// makes a plain `read_to_end` a correct way to capture the whole response.
async fn http_json(
    addr: &str,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to connect to {addr}: {e}"));
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

    stream
        .write_all(req.as_bytes())
        .await
        .expect("write failed");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.expect("read failed");
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

/// Loads an on-disk `AuditLog`, mutates the first entry's action, and then
/// fully recomputes every downstream `entry_hash`/`prev_hash` (leaving the
/// now-stale signatures in place, since a real attacker who can edit the
/// file but not forge signatures would face exactly this problem) so the
/// resulting file is internally self-consistent under `verify_chain()`.
fn tamper_audit_log_on_disk(path: &std::path::Path) {
    // F-20: nodes persist a snapshot plus an append-only journal; read both.
    let mut log: AuditLog =
        quorum_audit::journal::load_log(path).expect("failed to read audit log to tamper with");
    if log.entries.is_empty() {
        panic!("nothing to tamper with -- log is empty");
    }
    log.entries[0].event.action = "TAMPERED_key_derived_issuer".to_string();

    // Recompute the whole chain from scratch using the mutated content.
    let mut rebuilt = AuditLog::default();
    for entry in log.entries {
        let mut fresh = rebuilt.propose_next(entry.event);
        fresh.signatures = entry.signatures; // now-stale, but we keep them: a signature check is a SEPARATE detection path from hash-chain reconciliation
        rebuilt
            .try_append(fresh)
            .expect("rebuilding the tampered chain should always succeed locally");
    }
    assert!(
        rebuilt.verify_chain().is_ok(),
        "tampered chain must be internally self-consistent for this to be the hard test case"
    );
    std::fs::write(path, serde_json::to_vec_pretty(&rebuilt).unwrap())
        .expect("failed to write tampered log back to disk");
    // The tampered state is a plain snapshot; the journal would only re-apply the
    // original entries over it.
    let _ = std::fs::remove_file(quorum_audit::journal::journal_path(path));
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

fn symmetric_key_from_derived(sig: &quorum_core::Signature) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sig.to_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn xor(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

fn locate_sibling_binary(name: &str) -> PathBuf {
    let mut exe = std::env::current_exe().expect("failed to locate current executable");
    exe.pop();
    let candidate = exe.join(name);
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "could not find sibling binary `{name}` next to {}; build it first with `cargo build -p {name}`",
        exe.display()
    );
}

fn kill_all(children: &mut [Child]) {
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
}
