//! External notarization service: an identity and process genuinely
//! outside the quorum's own control, per Phase 2 of the threshold-quorum
//! roadmap:
//!
//! > "External notarization: periodically ... publish the current log
//! > root hash somewhere outside every quorum member's control -- an RFC
//! > 3161 timestamp authority, a public git commit, or a third-party
//! > transparency-log service. This is what stops even a colluding
//! > *majority* of the quorum from rewriting history undetected after the
//! > fact."
//!
//! This binary plays the role of "a third-party transparency-log
//! service" -- the roadmap's third named option. It is a genuinely
//! separate process, with its own identity keypair, run by nobody who
//! also runs a quorum node, whose only job is: accept a root hash, stamp
//! it with a sequence number and wall-clock time, sign the tuple, persist
//! it to an append-only file, and hand back a receipt that anyone can
//! verify independently (they don't have to trust this service's own
//! word for what it published -- `NotarizationReceipt::verify` checks
//! the signature against this service's known public key).
//!
//! Usage: `quorum_notary <path-to-config.json>`
//!
//! ## Why this alone isn't "real" external notarization yet
//! Swapping in an actual RFC 3161 timestamp authority, a public git
//! commit, or a real third-party transparency log (Certificate
//! Transparency-style) is a drop-in replacement for this process from the
//! quorum's point of view -- the wire contract (`NotarizeRequest` in,
//! `NotarizationReceipt` out) doesn't need to change. What would need to
//! change: this demo's receipts file lives on the same sandbox host as
//! everything else, which is NOT "outside every quorum member's control"
//! in any real deployment -- it's outside this repo's *quorum node*
//! processes, but not outside whoever operates this sandbox. Treat this
//! as a protocol-correct stand-in, not a production notary.

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
mod tls;

use ed25519_dalek::{Signer, SigningKey};
use quorum_audit::wire::NotaryMessage;
use quorum_audit::NotarizationReceipt;
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotaryConfig {
    listen_addr: String,
    cert_der_b64: String,
    key_der_b64: String,
    /// This service's own ed25519 signing keypair (base64 of, post
    /// audit finding A4, `SigningKey::to_bytes()`: the 32-byte seed),
    /// distinct from every quorum node's audit
    /// keypair -- a receipt signed by THIS key is what makes it
    /// independently verifiable as coming from outside the quorum.
    audit_keypair_b64: String,
    /// Base64 DER of every TLS client certificate allowed to submit or
    /// list notarizations (typically: the quorum orchestrator/coordinator
    /// process, playing the role of "whoever runs the scheduled
    /// notarization job").
    allowed_client_certs_b64: Vec<String>,
    /// Append-only JSON-lines file: one `NotarizationReceipt` per line,
    /// in the order they were issued. Never rewritten, only appended to.
    receipts_file: String,
}

struct Shared {
    keypair: SigningKey,
    receipts: Mutex<Vec<NotarizationReceipt>>,
    receipts_file: String,
}

/// Startup-only: print and exit 1 (Gap 8: no panic on unusable configuration).
fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("[notary] refusing to start: {msg}");
    std::process::exit(1)
}

fn or_fatal<T, E: std::fmt::Display>(what: &str, r: Result<T, E>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => fatal(format!("{what}: {e}")),
    }
}

fn b64_decode(field: &str, s: &str) -> Vec<u8> {
    use base64::Engine;
    or_fatal(
        &format!("config field {field}"),
        base64::engine::general_purpose::STANDARD.decode(s),
    )
}

#[tokio::main]
async fn main() {
    let Some(config_path) = std::env::args().nth(1) else {
        fatal("usage: quorum_notary <config.json>");
    };
    let config: NotaryConfig = {
        let raw = or_fatal(
            &format!("failed to read config {config_path}"),
            std::fs::read_to_string(&config_path),
        );
        or_fatal(
            "invalid config",
            quorum_core::secret_files::load_config::<NotaryConfig>(&raw),
        )
    };

    eprintln!("[notary] starting on {}", config.listen_addr);

    let own_cert = Certificate(b64_decode("cert_der_b64", &config.cert_der_b64));
    let own_key = PrivateKey(b64_decode("key_der_b64", &config.key_der_b64));
    let allowed: Vec<Vec<u8>> = config
        .allowed_client_certs_b64
        .iter()
        .map(|s| b64_decode("allowed_client_certs_b64[]", s))
        .collect();
    let verifier = tls::PinnedCertVerifier::new(allowed);

    let server_config = or_fatal(
        "bad notary cert/key",
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![own_cert], own_key),
    );
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let keypair_bytes = b64_decode("audit_keypair_b64", &config.audit_keypair_b64);
    let keypair_seed: [u8; 32] = keypair_bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| {
            fatal(format!(
                "invalid audit_keypair_b64: expected 32 bytes (ed25519-dalek 2.x SigningKey seed), got {}",
                keypair_bytes.len()
            ))
        });
    // Audit finding A4: SigningKey::from_bytes is infallible (any 32
    // bytes is a valid seed) -- the old .expect() here was catching
    // the wrong-length case, now handled explicitly above.
    let keypair = SigningKey::from_bytes(&keypair_seed);

    let existing = load_receipts(&config.receipts_file);
    eprintln!(
        "[notary] loaded {} existing receipt(s) from {}",
        existing.len(),
        config.receipts_file
    );

    let shared = Arc::new(Shared {
        keypair,
        receipts: Mutex::new(existing),
        receipts_file: config.receipts_file.clone(),
    });

    let listener = or_fatal(
        &format!("failed to bind {}", config.listen_addr),
        TcpListener::bind(&config.listen_addr).await,
    );
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[notary] accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(acceptor, stream, shared).await {
                eprintln!("[notary <- {peer_addr}] connection error: {e}");
            }
        });
    }
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    stream: TcpStream,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let tls = acceptor.accept(stream).await?;
    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: NotaryMessage = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[notary] bad message, ignoring: {e}");
                continue;
            }
        };
        let response = match msg {
            NotaryMessage::NotarizeRequest { root_hash } => {
                let mut receipts = shared.receipts.lock().await;
                let sequence = receipts.len() as u64;
                // Never sign a receipt with a bogus time: if the clock is before
                // the epoch, refuse (the client sees no receipt) instead of panicking.
                let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                    eprintln!("[notary] system clock is before the epoch; refusing to notarize");
                    continue;
                };
                let notarized_at_unix_ms = since_epoch.as_millis() as u64;
                let bytes =
                    NotarizationReceipt::signable_bytes(sequence, &root_hash, notarized_at_unix_ms);
                let notary_signature = shared.keypair.sign(&bytes).to_bytes().to_vec();
                let receipt = NotarizationReceipt {
                    sequence,
                    root_hash,
                    notarized_at_unix_ms,
                    notary_signature,
                };
                // Persist FIRST: a receipt that is not on disk is never recorded
                // or returned (the client sees no receipt, like a clock refusal).
                if let Err(e) = append_receipt(&shared.receipts_file, &receipt) {
                    eprintln!(
                        "[notary] could not persist receipt {sequence}: {e}; refusing to notarize"
                    );
                    continue;
                }
                receipts.push(receipt.clone());
                eprintln!(
                    "[notary] notarized root hash at sequence {sequence} (t={notarized_at_unix_ms}ms)"
                );
                NotaryMessage::NotarizeResponse { receipt }
            }
            NotaryMessage::ListRequest => {
                let receipts = shared.receipts.lock().await;
                NotaryMessage::ListResponse {
                    receipts: receipts.clone(),
                }
            }
            NotaryMessage::NotarizeResponse { .. } | NotaryMessage::ListResponse { .. } => {
                continue; // only a client should ever send these
            }
        };
        let Ok(mut out) = serde_json::to_vec(&response) else {
            eprintln!("[notary] could not serialize response; dropping it");
            continue;
        };
        out.push(b'\n');
        write_half.write_all(&out).await?;
    }
    Ok(())
}

fn load_receipts(path: &str) -> Vec<NotarizationReceipt> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Durably append one receipt line: single write, fsync the file, fsync the
/// directory. Any failure is returned so the caller never hands out a receipt
/// that would be lost on restart (F-23).
fn append_receipt(path: &str, receipt: &NotarizationReceipt) -> std::io::Result<()> {
    let p = std::path::Path::new(path);
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(receipt)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    file.write_all(line.as_bytes())?;
    file.sync_all()?;
    if let Some(parent) = parent {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod receipt_persistence_tests {
    use super::*;

    fn receipt(seq: u64) -> NotarizationReceipt {
        NotarizationReceipt {
            sequence: seq,
            root_hash: [7u8; 32],
            notarized_at_unix_ms: 1,
            notary_signature: vec![1, 2, 3],
        }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("notary_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn append_reports_failure_when_path_is_unwritable() {
        // Parent "directory" is a regular file: the append cannot succeed and the
        // caller MUST be told (F-23: this used to be swallowed).
        let d = tmpdir("unwritable");
        let blocker = d.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let path = blocker.join("receipts.jsonl");
        assert!(append_receipt(path.to_str().unwrap(), &receipt(0)).is_err());
    }

    #[test]
    fn append_persists_whole_lines_that_reload() {
        let d = tmpdir("ok");
        let path = d.join("sub").join("receipts.jsonl");
        let p = path.to_str().unwrap();
        append_receipt(p, &receipt(0)).unwrap();
        append_receipt(p, &receipt(1)).unwrap();
        let loaded = load_receipts(p);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].sequence, 1);
    }

    #[test]
    fn unpersisted_receipt_is_not_handed_out() {
        // The handler must persist BEFORE it records/returns a receipt.
        let src = include_str!("main.rs");
        let h = src
            .find("NotaryMessage::NotarizeRequest { root_hash } =>")
            .unwrap();
        let body = &src[h..];
        let a = body.find("append_receipt(").unwrap();
        let p = body.find("receipts.push(").unwrap();
        assert!(
            a < p,
            "receipt must be persisted before it is pushed/returned"
        );
    }
}
