//! Standalone quorum node service: runs the DKG and serves derive requests
//! over real mutual TLS between separate OS processes, per Phase 1 of the
//! threshold-quorum roadmap ("a standalone, independently-testable
//! 'quorum node' binary that does DKG and threshold derivation, with zero
//! product logic in it yet").
//!
//! All the actual crypto lives in `quorum_core`; this binary is the
//! network/transport wiring around it: TLS setup, connection handling,
//! and translating `quorum_core::Message`s to and from the wire.
//!
//! Usage: `quorum_node <path-to-config.json>`
//! (see `config.rs` for the config shape; `quorum_orchestrator` generates
//! it for you rather than expecting it to be hand-written.)
//!
//! ## What's still open after this binary (see also quorum_core's docs)
//! - No dispute-resolution round when a `Complaint` fires -- a node that
//!   receives a bad share simply never reaches `is_ready()`, rather than
//!   the quorum collectively excluding the cheating dealer and continuing
//!   without it.
//! - No resharing/rotation: a node's identity cert and DKG share are both
//!   fixed for the process's whole lifetime.
//! - Invoice-level access control (is THIS caller allowed THIS invoice)
//!   is still `quorum_service`'s job (`ciphersettle_core::resolve_access`)
//!   -- this binary has no concept of invoices, issuers, or banks. What
//!   this binary DOES now check, after Phase 4 Stage A (fixing Findings
//!   1.1/2.1): that a `DeriveRequest` actually carries a valid,
//!   unexpired, not-previously-used authorization signed with the shared
//!   `service_auth_key`.
//! - ~~No bound on node-to-node wire message length...~~ Fixed (audit
//!   finding A13): `handle_inbound` now reads through
//!   `bounded_line_reader::BoundedLineReader` instead of
//!   `BufReader::lines()`; see that module's doc for the cap and why it
//!   was set where it was.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]
mod audit_store;
mod bounded_line_reader;
mod powerloss;
mod share_store;
mod tls;

use bounded_line_reader::BoundedLineReader;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quorum_audit::AuditLog;
use quorum_core::config::{b64_decode, or_fatal, NodeConfig};
use quorum_core::{
    derive_request_predates_restart, now_unix_ms, verify_derive_auth, DkgSession, Message,
    MAX_DERIVE_AUTH_WINDOW_MS,
};
use quorum_core::{PublicKeySet, SecretKeyShare};
use rand::thread_rng;
use rustls::{Certificate, PrivateKey, ServerName};
use share_store::{FileKek, ShareStore};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

enum NodeState {
    Dkg(DkgSession),
    Ready {
        secret_share: SecretKeyShare,
        group_pks: PublicKeySet,
    },
}

struct Shared {
    node_id: usize,
    t: usize,
    state: Mutex<NodeState>,
    ready_file: String,
    pubkey_file: String,
    audit_log: Mutex<AuditLog>,
    audit_log_file: String,
    audit_keypair: SigningKey,
    /// Every quorum member's audit-signing public key (including this
    /// node's own), used to verify co-signatures on a replicated entry
    /// before accepting it -- a node doesn't just trust "seq/hash line up"
    /// for entries it didn't personally co-sign, it also checks that
    /// enough of the claimed signers actually signed.
    audit_pubkeys: BTreeMap<usize, VerifyingKey>,
    /// Shared secret proving a `DeriveRequest` actually came from
    /// `quorum_service`, not merely from anyone holding a pinned mTLS
    /// cert (Phase 4 Finding 1.1). See `quorum_core::verify_derive_auth`.
    service_auth_key: Vec<u8>,
    /// Nonces already spent by a served `DeriveRequest`, mapped to the
    /// unix-ms time after which they can be forgotten (their request's own
    /// expiry) -- closes the replay gap Phase 4 Test D found (Finding
    /// 2.1).
    used_derive_nonces: Mutex<HashMap<[u8; 16], u64>>,
    /// Wall-clock time this process started (T1-2 / T-3). The spent-nonce
    /// set above is memory-only, so after a restart the node refuses any
    /// request a previous process could have accepted -- see
    /// `quorum_core::derive_request_predates_restart`.
    process_start_unix_ms: u64,
    /// T1-1: the single entry this node has co-signed (voted for) at the
    /// log's next seq but not yet seen committed. See AppendAuditEntry.
    pending_audit: Mutex<quorum_audit::VoteSlot>,
    /// Gap 1: set ONLY during the one-time ceremony; the finalized share is
    /// persisted through it BEFORE this node reports ready.
    ceremony_store: Option<ShareStore>,
    node_n: usize,
}

/// Gap 1: how this process obtains its share.
enum Boot {
    /// Legacy ephemeral share (explicit opt-in only; throwaway quorums).
    Ephemeral,
    /// One-time ceremony: no share file exists and `init_ceremony` is set.
    Ceremony(ShareStore),
    /// Normal start: share file decrypted and verified against the group key.
    Resume {
        secret_share: SecretKeyShare,
        group_pks: PublicKeySet,
    },
}

fn fatal(msg: &str) -> ! {
    eprintln!("[node] FATAL: {msg}");
    std::process::exit(2)
}

/// Startup-only base64 decode of a config value: exits cleanly on bad input.
fn cfg_b64(field: &str, s: &str) -> Vec<u8> {
    match b64_decode(s) {
        Ok(v) => v,
        Err(e) => fatal(&format!("config field {field}: {e}")),
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return Err("expected 64 hex characters".to_string());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = s
            .get(2 * i..2 * i + 2)
            .ok_or_else(|| "invalid hex".to_string())?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| "invalid hex".to_string())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every error here is FATAL: a node whose persistence config cannot produce
/// its share must never fall back to a fresh DKG (it would orphan every key).
fn decide_boot(config: &NodeConfig) -> Result<Boot, String> {
    let Some(p) = &config.persistence else {
        if !config.allow_ephemeral_share {
            return Err("share persistence is not configured (no `persistence` section) and \
                 allow_ephemeral_share is not set. Refusing to start: an ephemeral share is destroyed on \
                 restart, which orphans every derived key. Configure `persistence`, or (throwaway test \
                 quorums only) set allow_ephemeral_share=true."
                .to_string());
        }
        eprintln!(
            "[node {}] WARNING: share persistence is NOT configured; restarting this node re-runs DKG \
             and produces a NEW group key. Never use this mode with real data.",
            config.node_id
        );
        return Ok(Boot::Ephemeral);
    };
    let kek = FileKek::load(Path::new(&p.kek_file)).map_err(|e| e.to_string())?;
    let store = ShareStore::new(std::path::PathBuf::from(&p.dir), Box::new(kek));
    let pin = match &p.expected_group_pubkey_sha256_hex {
        Some(h) => {
            Some(parse_hex32(h).map_err(|e| format!("expected_group_pubkey_sha256_hex: {e}"))?)
        }
        None => None,
    };
    let exists = store.exists().map_err(|e| e.to_string())?;
    match (exists, p.init_ceremony) {
        (true, true) => Err(
            "init_ceremony=true but a share file already exists; refusing to \
             overwrite or re-run DKG. Set init_ceremony=false to resume."
                .to_string(),
        ),
        (false, false) => Err(
            "no share file found and init_ceremony=false; refusing to run DKG on a \
             normal start. Restore the share file from backup, or run the one-time ceremony \
             (init_ceremony=true)."
                .to_string(),
        ),
        (false, true) => {
            eprintln!(
                "[node {}] one-time ceremony: no share exists; running DKG and persisting the result",
                config.node_id
            );
            Ok(Boot::Ceremony(store))
        }
        (true, false) => {
            let (secret_share, group_pks) = store
                .load(config.node_id, config.n, config.t, pin.as_ref())
                .map_err(|e| e.to_string())?;
            eprintln!(
                "[node {}] share loaded from disk; group public key fingerprint sha256={}",
                config.node_id,
                hex(&group_pks.fingerprint_sha256())
            );
            Ok(Boot::Resume {
                secret_share,
                group_pks,
            })
        }
    }
}

/// Publishes the group public key, then the ready marker, atomically. A
/// failure to publish is fatal: readiness must never be reported without the
/// files that other components read.
/// Signs a partial for `identity` and returns it only if it verifies against
/// the group public key set under this node's id.
fn checked_partial(
    secret_share: &SecretKeyShare,
    group_pks: &PublicKeySet,
    node_id: usize,
    identity: &str,
) -> Option<quorum_core::SignatureShare> {
    let partial = quorum_core::sign_partial(secret_share, identity);
    quorum_core::verify_partial(group_pks, node_id, identity, &partial).then_some(partial)
}

fn write_pubkey_and_ready(pubkey_file: &str, ready_file: &str, group_pks: &PublicKeySet) {
    let pubkey_json = match serde_json::to_vec(group_pks) {
        Ok(j) => j,
        Err(e) => fatal(&format!("could not serialize the group public key: {e}")),
    };
    if let Err(e) = audit_store::write_atomic(Path::new(pubkey_file), &pubkey_json) {
        fatal(&format!("could not write {pubkey_file}: {e}"));
    }
    if let Err(e) = audit_store::write_atomic(Path::new(ready_file), b"ready\n") {
        fatal(&format!("could not write {ready_file}: {e}"));
    }
}

/// How long a vote blocks a *different* entry at the same seq. Trade-off
/// (NEEDS_HUMAN_CRYPTO_REVIEW): long enough for a proposer to gather
/// signatures and replicate; short enough that a proposer that crashed
/// mid-round cannot wedge the log. After expiry a node may vote for a
/// different entry at that seq, which weakens (but does not remove) the
/// one-vote-per-seq guarantee. The pending vote is memory-only and is lost
/// on restart.
const PENDING_AUDIT_VOTE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Monotonic milliseconds since first call; feeds `quorum_audit::VoteSlot`
/// (which takes an injected clock so its race semantics are unit-testable).
fn mono_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

#[tokio::main]
async fn main() {
    // Provisioning helper (Gap 3 step 1): prints the base64 derive-auth key for
    // node <id> from the service's master secret. The output is a SECRET; put
    // it only in that node's config (`service_auth_key_b64`).
    //   quorum_node derive-auth-key <master_b64> <node_id>
    if std::env::args().nth(1).as_deref() == Some("derive-auth-key") {
        let (Some(master_b64), Some(id)) = (
            std::env::args().nth(2),
            std::env::args()
                .nth(3)
                .and_then(|v| v.parse::<usize>().ok()),
        ) else {
            fatal("usage: quorum_node derive-auth-key <master_b64> <node_id>");
        };
        let master = cfg_b64("master_b64", &master_b64);
        if master.len() < quorum_core::MIN_AUTH_MASTER_BYTES {
            fatal("master secret must decode to at least 32 bytes");
        }
        use base64::Engine;
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD
                .encode(quorum_core::derive_node_auth_key(&master, id))
        );
        return;
    }
    // Gap 13 power-loss rehearsal tools (see powerloss.rs and VERIFICATION_RUNBOOK.md).
    match std::env::args().nth(1).as_deref() {
        Some("audit-powerloss-workload") => {
            let (Some(log), Some(ack)) = (std::env::args().nth(2), std::env::args().nth(3)) else {
                fatal("usage: quorum_node audit-powerloss-workload <log_file> <ack_file> [max_entries]");
            };
            let max = std::env::args().nth(4).and_then(|v| v.parse::<u64>().ok());
            match powerloss::workload(Path::new(&log), Path::new(&ack), max) {
                Ok(()) => return,
                Err(e) => fatal(&e),
            }
        }
        Some("audit-powerloss-verify") => {
            let Some(log) = std::env::args().nth(2) else {
                fatal("usage: quorum_node audit-powerloss-verify <log_file> [ack_file]");
            };
            let ack = std::env::args().nth(3);
            match powerloss::verify(Path::new(&log), ack.as_deref().map(Path::new)) {
                Ok(msg) => {
                    println!("{msg}");
                    return;
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {}
    }
    let Some(config_path) = std::env::args().nth(1) else {
        fatal("usage: quorum_node <config.json>");
    };
    let config: NodeConfig = {
        let raw = or_fatal(
            "node",
            &format!("failed to read config {config_path}"),
            std::fs::read_to_string(&config_path),
        );
        or_fatal(
            "node",
            "invalid config",
            quorum_core::secret_files::load_config::<NodeConfig>(&raw),
        )
    };

    eprintln!(
        "[node {}] starting: n={} t={} listen={}",
        config.node_id, config.n, config.t, config.listen_addr
    );

    // Gap 1: decide the boot mode FIRST, so a refusal happens before any port
    // is bound or any DKG message is sent.
    let boot = match decide_boot(&config) {
        Ok(b) => b,
        Err(e) => fatal(&e),
    };

    let own_cert = Certificate(cfg_b64("cert_der_b64", &config.cert_der_b64));
    let own_key = PrivateKey(cfg_b64("key_der_b64", &config.key_der_b64));
    let client_cert_der = cfg_b64("client_cert_der_b64", &config.client_cert_der_b64);

    // Pinned allow-list: every other quorum member's cert, plus the
    // designated derive-client's cert. This node's own cert is not in the
    // list -- it never connects to itself over the network.
    let mut allowed: Vec<Vec<u8>> = config
        .peers
        .iter()
        .map(|p| cfg_b64("peers[].cert_der_b64", &p.cert_der_b64))
        .collect();
    allowed.push(client_cert_der);
    let verifier = tls::PinnedCertVerifier::new(allowed);

    let server_config = or_fatal(
        "node",
        "bad own cert/key for server config",
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(vec![own_cert.clone()], own_key.clone()),
    );
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let client_config = or_fatal(
        "node",
        "bad own cert/key for client config",
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![own_cert], own_key),
    );
    let connector = TlsConnector::from(Arc::new(client_config));

    // --- DKG setup: become our own dealer, and immediately self-loop our
    // own commitment and share so this node's session ends up needing
    // exactly the same n commitments/n shares as every other node's,
    // rather than a special-cased n-1. ---
    let mut rng = thread_rng();
    let (mut session, my_commitment) =
        DkgSession::new(config.node_id, config.n, config.t, &mut rng);
    or_fatal(
        "node",
        "own DKG commitment rejected (must have exactly t+1 coefficients)",
        session
            .receive_commitment(config.node_id, my_commitment.clone())
            .map_err(|c| format!("{c:?}")),
    );
    let my_self_share = session.share_for(config.node_id);
    or_fatal(
        "node",
        "own DKG share failed to verify",
        session
            .receive_share(config.node_id, my_self_share)
            .map_err(|c| format!("{c:?}")),
    );

    // Pre-compute every peer's share now, before the session moves behind
    // a shared lock -- outbound push tasks don't need session access at
    // all, only these two already-computed values.
    let outbound_shares: Vec<([u8; 32], usize, String)> = if matches!(boot, Boot::Resume { .. }) {
        Vec::new() // resuming: this node takes no part in any DKG
    } else {
        config
            .peers
            .iter()
            .map(|p| (session.share_for(p.id), p.id, p.addr.clone()))
            .collect()
    };

    let is_ready_already = session.is_ready(); // only true if n == 1, i.e. never in practice

    let audit_keypair_bytes = cfg_b64("audit_keypair_b64", &config.audit_keypair_b64);
    let audit_keypair_seed: [u8; 32] = audit_keypair_bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| fatal(&format!(
            "invalid audit_keypair_b64: expected 32 bytes (ed25519-dalek 2.x SigningKey seed), got {}. \
             If this config predates audit finding A4's migration, it was generated against \
             ed25519-dalek 1.x's 64-byte Keypair::to_bytes() format and needs regenerating.",
            audit_keypair_bytes.len()
        )));
    // Audit finding A4: SigningKey::from_bytes takes exactly a 32-byte
    // seed (2.x), not the 64-byte secret||public blob 1.x's
    // Keypair::from_bytes expected -- audit_keypair_seed is already
    // 32 bytes post-migration (see the writer in quorum_orchestrator).
    let audit_keypair = SigningKey::from_bytes(&audit_keypair_seed);
    let mut audit_pubkeys: BTreeMap<usize, VerifyingKey> = config
        .peers
        .iter()
        .map(|p| {
            let bytes = cfg_b64("peers[].audit_pubkey_b64", &p.audit_pubkey_b64);
            let array: [u8; 32] = bytes.as_slice().try_into().unwrap_or_else(|_| {
                fatal(&format!(
                    "invalid peer audit pubkey for node {}: expected 32 bytes, got {}",
                    p.id,
                    bytes.len()
                ))
            });
            (
                p.id,
                or_fatal(
                    "node",
                    &format!("invalid peer audit pubkey for node {} in config", p.id),
                    VerifyingKey::from_bytes(&array),
                ),
            )
        })
        .collect();
    audit_pubkeys.insert(config.node_id, audit_keypair.verifying_key());

    // Gap 13: a missing file is a first start; a file that exists but is
    // corrupt / truncated / has a broken hash chain is FATAL (never silently
    // replaced by an empty log, which would erase audit evidence).
    let audit_log = match audit_store::load_audit_log(Path::new(&config.audit_log_file)) {
        Ok(l) => l,
        Err(e) => fatal(&format!(
            "audit log file {} cannot be used: {e}. Refusing to start; restore it from backup or investigate.",
            config.audit_log_file
        )),
    };
    let service_auth_key = cfg_b64("service_auth_key_b64", &config.service_auth_key_b64);

    let (initial_state, ceremony_store, resumed_pks) = match boot {
        Boot::Resume {
            secret_share,
            group_pks,
        } => {
            let pks = group_pks.clone();
            (
                NodeState::Ready {
                    secret_share,
                    group_pks,
                },
                None,
                Some(pks),
            )
        }
        Boot::Ceremony(store) => (NodeState::Dkg(session), Some(store), None),
        Boot::Ephemeral => (NodeState::Dkg(session), None, None),
    };
    let shared = Arc::new(Shared {
        node_id: config.node_id,
        t: config.t,
        state: Mutex::new(initial_state),
        ready_file: config.ready_file.clone(),
        pubkey_file: config.pubkey_file.clone(),
        audit_log: Mutex::new(audit_log),
        audit_log_file: config.audit_log_file.clone(),
        audit_keypair,
        audit_pubkeys,
        service_auth_key,
        used_derive_nonces: Mutex::new(HashMap::new()),
        process_start_unix_ms: now_unix_ms(),
        pending_audit: Mutex::new(quorum_audit::VoteSlot::new()),
        ceremony_store,
        node_n: config.n,
    });
    if is_ready_already && resumed_pks.is_none() {
        finalize_if_ready(&shared).await;
    }

    // --- Inbound: accept peer/client connections and serve them. ---
    let listener = or_fatal(
        "node",
        &format!("failed to bind {}", config.listen_addr),
        TcpListener::bind(&config.listen_addr).await,
    );
    {
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[node {}] accept error: {e}", shared.node_id);
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_inbound(acceptor, stream, shared.clone()).await {
                        eprintln!(
                            "[node {} <- {peer_addr}] connection error: {e}",
                            shared.node_id
                        );
                    }
                });
            }
        });
    }

    // Resume mode: ready as soon as listening (after the bind above).
    if let Some(pks) = &resumed_pks {
        write_pubkey_and_ready(&config.pubkey_file, &config.ready_file, pks);
        eprintln!(
            "[node {}] resumed from persisted share; DKG skipped.",
            config.node_id
        );
    }

    // --- Outbound: push our commitment + this peer's private share to
    // every other node. Retries briefly since peers may not have bound
    // their listener yet (process startup order isn't synchronized). ---
    for (share, peer_id, addr) in outbound_shares {
        let connector = connector.clone();
        let my_id = config.node_id;
        let commitment = my_commitment.clone();
        tokio::spawn(async move {
            push_dkg_to_peer(connector, &addr, my_id, peer_id, commitment, share).await;
        });
    }

    // Keep the process alive serving derive requests indefinitely.
    // quorum_orchestrator kills the process directly (SIGKILL) to
    // simulate a node outage; there's no graceful-shutdown RPC.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

async fn push_dkg_to_peer(
    connector: TlsConnector,
    addr: &str,
    my_id: usize,
    peer_id: usize,
    commitment: quorum_core::Commitment,
    share: [u8; 32],
) {
    let Ok(server_name) = ServerName::try_from("quorum-node") else {
        eprintln!("[node {my_id} -> {peer_id}] internal: invalid static server name");
        return;
    };
    // Peers may start in any order; retry the connection briefly.
    let stream = loop {
        match TcpStream::connect(addr).await {
            Ok(s) => break s,
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        }
    };
    let mut tls = match connector.connect(server_name, stream).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[node {my_id} -> {peer_id}] TLS connect failed: {e}");
            return;
        }
    };
    let commitment_msg = Message::DkgCommitment {
        from: my_id,
        commitment,
    };
    let share_msg = Message::DkgShare {
        from: my_id,
        to: peer_id,
        share,
    };
    for msg in [commitment_msg, share_msg] {
        let Ok(mut line) = serde_json::to_vec(&msg) else {
            eprintln!("[node {my_id} -> {peer_id}] could not serialize message; aborting push");
            return;
        };
        line.push(b'\n');
        if let Err(e) = tls.write_all(&line).await {
            eprintln!("[node {my_id} -> {peer_id}] write failed: {e}");
            return;
        }
    }
    let _ = tls.shutdown().await;
    eprintln!("[node {my_id} -> {peer_id}] sent commitment + share");
}

async fn handle_inbound(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let tls = acceptor.accept(stream).await?;
    let (read_half, mut write_half) = tokio::io::split(tls);
    // Audit finding A13: was `BufReader::new(read_half).lines()`, which
    // has no maximum line length. See `bounded_line_reader`'s module doc.
    let mut lines = BoundedLineReader::new(read_half);
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Message = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[node {}] bad message, ignoring: {e}", shared.node_id);
                continue;
            }
        };
        if let Some(response) = handle_message(&shared, msg).await {
            let Ok(mut out) = serde_json::to_vec(&response) else {
                eprintln!(
                    "[node {}] could not serialize response; dropping it",
                    shared.node_id
                );
                continue;
            };
            out.push(b'\n');
            write_half.write_all(&out).await?;
        }
    }
    Ok(())
}

/// Applies one inbound message to node state, returning a response message
/// to write back on the same connection, if any (only derive requests get
/// a response; DKG pushes are one-way).
async fn handle_message(shared: &Arc<Shared>, msg: Message) -> Option<Message> {
    match msg {
        Message::DkgCommitment { from, commitment } => {
            let mut state = shared.state.lock().await;
            if let NodeState::Dkg(session) = &mut *state {
                // C-1: a dealer whose commitment has the wrong degree (or an
                // out-of-range id) is recorded as a complaint; this node then
                // never reaches is_ready(), same as for a bad share.
                if let Err(c) = session.receive_commitment(from, commitment) {
                    eprintln!(
                        "[node {}] rejected commitment from dealer {}: {}",
                        shared.node_id, c.accused_dealer, c.reason
                    );
                }
            }
            drop(state);
            finalize_if_ready(shared).await;
            None
        }
        Message::DkgShare { from, to, share } => {
            if to != shared.node_id {
                eprintln!(
                    "[node {}] received a share addressed to node {to}, ignoring (routing bug or malicious relay)",
                    shared.node_id
                );
                return None;
            }
            let mut state = shared.state.lock().await;
            if let NodeState::Dkg(session) = &mut *state {
                if let Err(complaint) = session.receive_share(from, share) {
                    eprintln!(
                        "[node {}] COMPLAINT against dealer {}: {}",
                        shared.node_id, complaint.accused_dealer, complaint.reason
                    );
                }
            }
            drop(state);
            finalize_if_ready(shared).await;
            None
        }
        Message::DkgComplaint {
            from,
            against,
            reason,
        } => {
            eprintln!(
                "[node {}] peer {from} reports a complaint against dealer {against}: {reason}",
                shared.node_id
            );
            None
        }
        Message::DkgReady { from } => {
            eprintln!("[node {}] peer {from} reports DKG ready", shared.node_id);
            None
        }
        Message::DeriveRequest {
            identity,
            expires_at_unix_ms,
            nonce,
            mac,
            transport_public_key,
        } => {
            let now = now_unix_ms();
            if expires_at_unix_ms > now.saturating_add(MAX_DERIVE_AUTH_WINDOW_MS) {
                return Some(Message::DeriveReject {
                    from: shared.node_id,
                    reason: format!(
                        "requested authorization window exceeds the {MAX_DERIVE_AUTH_WINDOW_MS}ms maximum this node will accept"
                    ),
                });
            }
            if now > expires_at_unix_ms {
                return Some(Message::DeriveReject {
                    from: shared.node_id,
                    reason: "derive authorization has expired".to_string(),
                });
            }
            if !verify_derive_auth(
                &shared.service_auth_key,
                &identity,
                expires_at_unix_ms,
                &nonce,
                &transport_public_key,
                &mac,
            ) {
                eprintln!(
                    "[node {}] REJECTED derive request for {identity:?}: invalid authorization MAC \
                     (not from quorum_service, or the request was tampered with)",
                    shared.node_id
                );
                return Some(Message::DeriveReject {
                    from: shared.node_id,
                    reason: "invalid derive authorization".to_string(),
                });
            }
            // T1-2 / T-3: the nonce set below is memory-only. Refuse anything
            // a previous incarnation of this process could have accepted, so
            // a request captured before a restart cannot be replayed after it.
            if derive_request_predates_restart(shared.process_start_unix_ms, expires_at_unix_ms) {
                eprintln!(
                    "[node {}] REJECTED derive request for {identity:?}: predates this process's start guard \
                     (restart-replay protection)",
                    shared.node_id
                );
                return Some(Message::DeriveReject {
                    from: shared.node_id,
                    reason: "RESTART_GUARD: request could have been accepted by a previous process; retry with a fresh request".to_string(),
                });
            }
            {
                let mut used = shared.used_derive_nonces.lock().await;
                used.retain(|_, &mut exp| exp > now);
                if used.contains_key(&nonce) {
                    eprintln!(
                        "[node {}] REJECTED derive request for {identity:?}: nonce already used (replay)",
                        shared.node_id
                    );
                    return Some(Message::DeriveReject {
                        from: shared.node_id,
                        reason: "this derive request has already been served (replay detected)"
                            .to_string(),
                    });
                }
                used.insert(nonce, expires_at_unix_ms);
            }

            let state = shared.state.lock().await;
            match &*state {
                NodeState::Ready {
                    secret_share,
                    group_pks,
                } => {
                    // Self-check at RUNTIME (F-22): a node never seals and ships a
                    // partial it would not itself trust. Was a debug_assert!.
                    if checked_partial(secret_share, group_pks, shared.node_id, &identity).is_none()
                    {
                        eprintln!(
                            "[node {}] own partial failed self-verification; refusing to derive",
                            shared.node_id
                        );
                        return Some(Message::DeriveReject {
                            from: shared.node_id,
                            reason: "internal error: partial failed self-verification".to_string(),
                        });
                    }
                    // Finding 2.3 fix: seal the partial under the
                    // caller-supplied transport public key rather than
                    // returning it in the clear. Only the true end
                    // caller, holding the matching TransportSecretKey,
                    // can ever recover a usable share from this --
                    // quorum_service, or anyone else relaying this
                    // response, sees only ciphertext. Sealing our own
                    // genuine, already-verified share cannot fail (the
                    // only failure mode in quorum_vetseal::encrypt_share
                    // is a malformed point, and `partial` was just
                    // produced by our own BLS signing code).
                    //
                    // Now also attaches a NIZK that the ciphertext encrypts
                    // THIS node's genuine partial (CRYPTO-004), so the
                    // verifier can reject a bad share
                    // before combining. An encoding failure is rejected
                    // rather than panicking the node.
                    match quorum_core::seal_partial_with_proof(
                        secret_share,
                        &identity,
                        &transport_public_key,
                        &mut thread_rng(),
                    ) {
                        Ok((sealed_share, proof)) => Some(Message::DerivePartial {
                            from: shared.node_id,
                            sealed_share,
                            proof,
                        }),
                        Err(e) => {
                            eprintln!(
                                "[node {}] failed to seal partial with proof: {e}",
                                shared.node_id
                            );
                            Some(Message::DeriveReject {
                                from: shared.node_id,
                                reason: "internal error sealing partial".to_string(),
                            })
                        }
                    }
                }
                NodeState::Dkg(_) => Some(Message::DeriveReject {
                    from: shared.node_id,
                    reason: "DKG has not finalized on this node yet".to_string(),
                }),
            }
        }
        Message::DerivePartial { .. } | Message::DeriveReject { .. } => {
            // Only a client should ever receive these; a node receiving one
            // means it was addressed as if it were a client. Ignore.
            None
        }

        // ---- Phase 2: audit log ----
        Message::AppendAuditEntry { entry } => {
            if !entry.verify_hash() {
                return Some(Message::AuditAppendRejected {
                    node_id: shared.node_id,
                    reason: "proposed entry's hash does not match its own content".to_string(),
                });
            }
            let seq = entry.seq;
            // Two-phase (T1-1 / TASK-011): casting a vote does NOT append. The
            // entry enters the log only via ReplicateAuditEntry with > t valid
            // co-signatures, so a proposer that fails to reach quorum can
            // never leave an uncommitted fork in any node's log.
            let log = shared.audit_log.lock().await;
            if let Err(reason) = log.check_extends(&entry) {
                eprintln!(
                    "[node {}] refused audit append at seq {seq}: {reason}",
                    shared.node_id
                );
                return Some(Message::AuditAppendRejected {
                    node_id: shared.node_id,
                    reason,
                });
            }
            let mut pending = shared.pending_audit.lock().await;
            if let Err(reason) = pending.try_vote(
                seq,
                entry.entry_hash,
                mono_ms(),
                PENDING_AUDIT_VOTE_TTL.as_millis() as u64,
            ) {
                eprintln!(
                    "[node {}] refused audit append at seq {seq}: {reason}",
                    shared.node_id
                );
                return Some(Message::AuditAppendRejected {
                    node_id: shared.node_id,
                    reason,
                });
            }
            let sig = quorum_audit::sign_entry_hash(&shared.audit_keypair, &entry.entry_hash);
            eprintln!(
                "[node {}] co-signed (pending) audit entry seq {seq}.",
                shared.node_id
            );
            Some(Message::AuditEntrySigned {
                node_id: shared.node_id,
                signature: sig,
            })
        }
        Message::AuditEntrySigned { .. }
        | Message::AuditAppendRejected { .. }
        | Message::AuditEntryCommitted { .. } => {
            // Only the proposer (client/coordinator) should receive these.
            None
        }
        Message::ReplicateAuditEntry { entry } => {
            let mut entry = entry;
            // Which attached signatures actually verify over THIS entry's hash.
            // Only these may ever be stored (review finding R-1: previously every
            // attached signature was merged/persisted once the count gate passed,
            // so a peer could overwrite a stored valid co-signature with garbage).
            let valid_ids: Vec<usize> = entry
                .signatures
                .keys()
                .copied()
                .filter(|id| {
                    shared
                        .audit_pubkeys
                        .get(id)
                        .map(|pk| entry.verify_signature(*id, pk))
                        .unwrap_or(false)
                })
                .collect();
            let valid_sigs = valid_ids.len();
            if valid_sigs <= shared.t {
                eprintln!(
                    "[node {}] refusing replicated entry seq {}: only {valid_sigs} valid co-signature(s), need > {}",
                    shared.node_id, entry.seq, shared.t
                );
                return None;
            }
            let seq = entry.seq;
            let mut log = shared.audit_log.lock().await;
            if seq < log.next_seq() {
                // We already have this entry (e.g. we're one of the
                // original co-signers) -- just merge in any signatures we
                // didn't have yet, rather than treating this as an error.
                // R-1: the replicated entry must be the SAME entry we hold at this
                // seq, and only verified signatures may be merged.
                if log.entries[seq as usize].entry_hash != entry.entry_hash {
                    eprintln!(
                        "[node {}] refusing replicated entry seq {seq}: hash differs from the entry already committed here",
                        shared.node_id
                    );
                    return None;
                }
                // Persist-then-swap: the in-memory log only changes after the
                // new state is durable, so memory never runs ahead of disk.
                let mut updated = (*log).clone();
                let mut sig_records = Vec::new();
                for (id, sig) in entry.signatures {
                    if valid_ids.contains(&id)
                        && updated.merge_signature(seq, id, sig.clone()).is_ok()
                    {
                        sig_records.push(quorum_audit::journal::Record::Sig {
                            seq,
                            node_id: id,
                            sig,
                        });
                    }
                }
                // Whether or not merging the extra signatures could be persisted,
                // the entry itself is already durable here (the in-memory log
                // only ever holds durable state), so this node can acknowledge.
                match audit_store::commit(
                    Path::new(&shared.audit_log_file),
                    &sig_records,
                    &updated,
                ) {
                    Ok(()) => *log = updated,
                    Err(e) => eprintln!(
                        "[node {}] could not persist merged signatures for seq {seq}: {e}; keeping the previous (durable) state",
                        shared.node_id
                    ),
                }
                return Some(Message::AuditEntryCommitted {
                    node_id: shared.node_id,
                    seq,
                    entry_hash: log.entries[seq as usize].entry_hash,
                });
            }
            // R-1: strip unverified signatures before the entry becomes part of the log.
            entry.signatures.retain(|id, _| valid_ids.contains(id));
            // Persist-then-swap (Gap 13): the entry becomes part of the node's
            // log only once the new log is durable on disk. If persisting
            // fails the node does NOT claim the entry (it keeps its last
            // durable state and its pending vote) and says so loudly.
            let mut updated = (*log).clone();
            let journal_entry = entry.clone();
            match updated.try_append(entry) {
                Ok(()) => {
                    if let Err(e) = audit_store::commit(
                        Path::new(&shared.audit_log_file),
                        &[quorum_audit::journal::Record::Append {
                            entry: journal_entry,
                        }],
                        &updated,
                    ) {
                        eprintln!(
                            "[node {}] PERSIST FAILED for audit entry seq {seq}: {e}; entry NOT committed on this node",
                            shared.node_id
                        );
                        return None;
                    }
                    *log = updated;
                    {
                        shared.pending_audit.lock().await.on_commit(seq);
                    }
                    eprintln!(
                        "[node {}] replicated audit entry seq {seq} ({valid_sigs} valid co-signatures).",
                        shared.node_id
                    );
                    return Some(Message::AuditEntryCommitted {
                        node_id: shared.node_id,
                        seq,
                        entry_hash: log.entries[seq as usize].entry_hash,
                    });
                }
                Err(reason) => {
                    eprintln!(
                        "[node {}] could not replicate audit entry seq {seq}: {reason}",
                        shared.node_id
                    );
                }
            }
            None
        }
        Message::GetAuditLog { invoice_id } => {
            let log = shared.audit_log.lock().await;
            let entries = log
                .filter_by_invoice(invoice_id.as_deref())
                .into_iter()
                .cloned()
                .collect();
            Some(Message::AuditLogEntries { entries })
        }
        Message::AuditLogEntries { .. } => None, // only a reader should receive this
    }
}

async fn finalize_if_ready(shared: &Arc<Shared>) {
    let mut state = shared.state.lock().await;
    let ready = matches!(&*state, NodeState::Dkg(s) if s.is_ready());
    if !ready {
        return;
    }
    let placeholder = DkgSession::new(shared.node_id, 1, 0, &mut thread_rng()).0;
    let old = std::mem::replace(&mut *state, NodeState::Dkg(placeholder));
    let session = match old {
        NodeState::Dkg(s) => s,
        ready @ NodeState::Ready { .. } => {
            // Cannot happen (checked under the same lock above); restore and
            // return rather than panic a running node.
            *state = ready;
            return;
        }
    };
    match session.finalize() {
        Ok((secret_share, group_pks)) => {
            eprintln!("[node {}] DKG finalized.", shared.node_id);
            // Gap 1: in the one-time ceremony the share is made durable BEFORE
            // this node reports ready. If it cannot be persisted, exit.
            if let Some(store) = &shared.ceremony_store {
                match store.create_new(
                    shared.node_id,
                    shared.node_n,
                    shared.t,
                    &secret_share,
                    &group_pks,
                ) {
                    Ok(()) => eprintln!(
                        "[node {}] share persisted (encrypted). Pin this group public key fingerprint in config: sha256={}",
                        shared.node_id,
                        hex(&group_pks.fingerprint_sha256())
                    ),
                    Err(e) => fatal(&format!("could not persist the DKG share: {e}")),
                }
            }
            write_pubkey_and_ready(&shared.pubkey_file, &shared.ready_file, &group_pks);
            *state = NodeState::Ready {
                secret_share,
                group_pks,
            };
            drop(state);
        }
        Err(e) => {
            eprintln!(
                "[node {}] finalize() reported not ready: {e}",
                shared.node_id
            );
        }
    }
}

#[cfg(test)]
mod self_check_tests {
    use super::*;
    use quorum_core::DkgSession;

    fn run_dkg(n: usize, t: usize) -> Vec<(SecretKeyShare, PublicKeySet)> {
        let mut rng = thread_rng();
        let mut sessions = Vec::new();
        let mut commitments = Vec::new();
        for id in 0..n {
            let (s, c) = DkgSession::new(id, n, t, &mut rng);
            sessions.push(s);
            commitments.push(c);
        }
        for s in sessions.iter_mut() {
            for (d, c) in commitments.iter().enumerate() {
                s.receive_commitment(d, c.clone()).unwrap();
            }
        }
        let shares: Vec<Vec<[u8; 32]>> = (0..n)
            .map(|d| (0..n).map(|p| sessions[d].share_for(p)).collect())
            .collect();
        for (p, s) in sessions.iter_mut().enumerate() {
            for (d, ds) in shares.iter().enumerate() {
                s.receive_share(d, ds[p]).unwrap();
            }
        }
        sessions
            .into_iter()
            .map(|s| s.finalize().unwrap())
            .collect()
    }

    #[test]
    fn self_check_accepts_a_genuine_partial() {
        let nodes = run_dkg(3, 1);
        let (share, pks) = &nodes[0];
        assert!(checked_partial(share, pks, 0, "inv-1").is_some());
    }

    #[test]
    fn self_check_rejects_a_partial_that_does_not_match_the_group_key() {
        // Share from one DKG, group key from another: the partial cannot verify,
        // and this must be refused at RUNTIME (F-22: it used to be debug-only).
        let a = run_dkg(3, 1);
        let b = run_dkg(3, 1);
        assert!(checked_partial(&a[0].0, &b[0].1, 0, "inv-1").is_none());
    }
}
