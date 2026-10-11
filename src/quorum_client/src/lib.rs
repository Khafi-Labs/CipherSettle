//! Shared mTLS client logic for talking to a `quorum_node` cluster and a
//! `quorum_notary`. Factored out of `quorum_orchestrator` (which used to
//! duplicate all of this inline) so that `quorum_service` -- the Phase 3
//! product API, which needs to broker real derive calls and audit
//! appends against the same quorum -- doesn't have to reimplement it a
//! third time. Same zero-duplication principle the rest of this codebase
//! already follows for `ciphersettle_core` and `quorum_core`.
//!
//! This crate owns exactly three things: building a pinned-certificate
//! `TlsConnector`, sending one request and reading one response over it,
//! and the composite operations every caller needs --
//! [`collect_sealed_derived_key`] / [`open_sealed_derived_key`] (split per
//! Finding 2.3's fix: collecting is safe anywhere, opening must run only
//! where the transport secret key lives) and
//! [`propose_and_cosign_and_replicate`].

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
use quorum_audit::wire::NotaryMessage;
use quorum_audit::{AuditEntry, AuditEvent, AuditLog};
use quorum_core::Message;
use quorum_core::{PublicKeySet, Signature};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const DERIVE_AUTH_VALIDITY_MS: u64 = quorum_core::DEFAULT_DERIVE_AUTH_VALIDITY_MS; // T1-2: was 15_000; the restart guard refuses shorter windows for 30s after node start

/// Pins the server certificate by exact byte match -- no CA, same model as
/// every other mTLS verifier in this codebase (see `quorum_node::tls`'s
/// doc comment for the reasoning).
#[derive(Debug)]
struct PinnedServerVerifier {
    allowed_der: Vec<Vec<u8>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if self
            .allowed_der
            .iter()
            .any(|c| c.as_slice() == end_entity.as_ref())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate is not in the client's pinned allow-list".into(),
            ))
        }
    }

    // rustls 0.23 leaves the handshake-signature check to the verifier. It is what proves
    // the peer HOLDS the pinned certificate's private key, so it must never be stubbed.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_provider::default_provider())
}

fn parse_key(key_der: Vec<u8>) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::try_from(key_der).map_err(|e| format!("unrecognised private key format: {e}"))
}

/// Builds a `TlsConnector` that presents `(client_cert_der, client_key_der)`
/// as its own identity and accepts only servers whose certificate exactly
/// matches one of `allowed_server_certs_der`.
pub fn build_connector(
    client_cert_der: Vec<u8>,
    client_key_der: Vec<u8>,
    allowed_server_certs_der: Vec<Vec<u8>>,
) -> Result<TlsConnector, String> {
    let provider = provider();
    let verifier = Arc::new(PinnedServerVerifier {
        allowed_der: allowed_server_certs_der,
        algs: provider.signature_verification_algorithms,
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("protocol versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(client_cert_der)],
            parse_key(client_key_der)?,
        )
        .map_err(|e| format!("bad client cert/key: {e}"))?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Server-side pinned-certificate verifier: same exact-byte-match model,
/// used when something in this codebase needs to accept mTLS connections
/// (a real `quorum_node`, or -- as in `quorum_adversarial` -- something
/// deliberately impersonating one to test how the rest of the system
/// reacts).
#[derive(Debug)]
struct PinnedClientVerifier {
    allowed_der: Vec<Vec<u8>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if self
            .allowed_der
            .iter()
            .any(|c| c.as_slice() == end_entity.as_ref())
        {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "client certificate is not in the pinned allow-list".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Builds a `rustls::ServerConfig` presenting `(cert_der, key_der)` as its
/// own identity and requiring every connecting client to present a
/// certificate exactly matching one of `allowed_client_certs_der`.
pub fn build_server_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    allowed_client_certs_der: Vec<Vec<u8>>,
) -> Result<rustls::ServerConfig, String> {
    let provider = provider();
    let verifier = Arc::new(PinnedClientVerifier {
        allowed_der: allowed_client_certs_der,
        algs: provider.signature_verification_algorithms,
    });
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("protocol versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(cert_der)], parse_key(key_der)?)
        .map_err(|e| format!("bad server cert/key: {e}"))
}

/// Same as [`send_request`] but for messages that never get a response
/// (currently: `ReplicateAuditEntry`). Writes the message and returns as
/// soon as the write completes -- it does NOT wait to read a line back,
/// so callers don't pay a full timeout per node for a response that was
/// never coming. Returns `true` if the write succeeded (the node may
/// still reject/ignore the message; this only confirms delivery attempt).
pub async fn send_fire_and_forget(connector: &TlsConnector, addr: &str, msg: &Message) -> bool {
    send_fire_and_forget_with_timeout(connector, addr, msg, DEFAULT_TIMEOUT).await
}

pub async fn send_fire_and_forget_with_timeout(
    connector: &TlsConnector,
    addr: &str,
    msg: &Message,
    timeout: Duration,
) -> bool {
    let Ok(server_name) = ServerName::try_from("quorum-node") else {
        return false;
    };
    let Ok(Ok(stream)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await else {
        return false;
    };
    let Ok(mut tls) = connector.connect(server_name, stream).await else {
        return false;
    };

    let Ok(mut line) = serde_json::to_vec(msg) else {
        return false;
    };
    line.push(b'\n');
    if tls.write_all(&line).await.is_err() {
        return false;
    }
    let _ = tls.flush().await;
    let _ = tls.shutdown().await; // clean TLS close_notify rather than an abrupt drop
    true
}

/// Sends one `quorum_core::Message` to `addr` and returns the single-line
/// JSON response, or `None` on any failure (unreachable, TLS error,
/// timeout, bad response) -- callers that need to tolerate an offline
/// node treat `None` as "this node didn't answer," not a hard error.
pub async fn send_request(connector: &TlsConnector, addr: &str, msg: &Message) -> Option<Message> {
    send_request_with_timeout(connector, addr, msg, DEFAULT_TIMEOUT).await
}

pub async fn send_request_with_timeout(
    connector: &TlsConnector,
    addr: &str,
    msg: &Message,
    timeout: Duration,
) -> Option<Message> {
    let server_name = ServerName::try_from("quorum-node").ok()?;
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let mut tls = connector.connect(server_name, stream).await.ok()?;

    let mut line = serde_json::to_vec(msg).ok()?;
    line.push(b'\n');
    tls.write_all(&line).await.ok()?;
    tls.flush().await.ok();

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();
    let response_line = tokio::time::timeout(timeout, lines.next_line())
        .await
        .ok()?
        .ok()??;
    let _ = write_half.shutdown().await;
    serde_json::from_str(&response_line).ok()
}

/// Same as [`send_request`] but for the notary's separate wire protocol.
pub async fn send_notary_request(
    connector: &TlsConnector,
    addr: &str,
    msg: &NotaryMessage,
) -> Option<NotaryMessage> {
    let server_name = ServerName::try_from("quorum-node").ok()?;
    let stream = tokio::time::timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let mut tls = connector.connect(server_name, stream).await.ok()?;

    let mut line = serde_json::to_vec(msg).ok()?;
    line.push(b'\n');
    tls.write_all(&line).await.ok()?;
    tls.flush().await.ok();

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();
    let response_line = tokio::time::timeout(DEFAULT_TIMEOUT, lines.next_line())
        .await
        .ok()?
        .ok()??;
    let _ = write_half.shutdown().await;
    serde_json::from_str(&response_line).ok()
}

/// Requests a NotarizeRequest and returns the receipt, or an error string.
pub async fn notarize(
    connector: &TlsConnector,
    notary_addr: &str,
    root_hash: [u8; 32],
) -> Result<quorum_audit::NotarizationReceipt, String> {
    let req = NotaryMessage::NotarizeRequest { root_hash };
    match send_notary_request(connector, notary_addr, &req).await {
        Some(NotaryMessage::NotarizeResponse { receipt }) => Ok(receipt),
        Some(other) => Err(format!("unexpected notary response: {other:?}")),
        None => Err(format!("notary at {notary_addr} did not respond")),
    }
}

/// Convenience wrapper for callers that are both the broker AND the true
/// end caller in the same process -- test harnesses (`quorum_orchestrator`,
/// `quorum_adversarial`) mostly. Generates an ephemeral transport keypair
/// and speaks the exact same sealed wire protocol
/// `collect_sealed_derived_key`/`quorum_node` do; the only difference is
/// that here the same process also holds `transport_secret_key`, which is
/// fine when that process genuinely is the trusted recipient (a test
/// harness standing in for "the end caller"). **Never use this inside
/// `quorum_service`** -- see
/// [`collect_sealed_derived_key`]/[`open_sealed_derived_key`] for the
/// split that keeps a backend broker from ever seeing a plaintext key,
/// which is the whole point of Finding 2.3's fix.
///
/// Because a bad node's sealed ciphertext can't be caught until *after*
/// combine+decrypt (see `quorum_vetseal`'s module docs), this gathers
/// every sealed share it can get rather than stopping at the first
/// `threshold + 1`, then tries successive `T+1`-sized subsets -- the same
/// "drop to an alternate subset and retry" recovery this workspace's
/// k-of-n liveness already relies on, just now also covering "one
/// responding node's ciphertext was bad" rather than only "one node
/// didn't respond." This in-process version predates, and is now mirrored
/// by, the real network protocol: `collect_sealed_derived_key`'s
/// `tried_subsets` parameter and `quorum_service`'s `/derive-key`
/// endpoint implement the same combination search as an actual
/// multi-round collect/attempt-open/retry conversation between the
/// service and the true caller (audit finding A12). See that function's
/// doc comment for the protocol and the fault-tolerance math this
/// project's actual 3-of-5 deployment shape implies.
pub async fn derive_from_quorum(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
    group_pks: &PublicKeySet,
    identity: &str,
    threshold: usize,
    service_auth_key: &[u8],
) -> Result<Signature, String> {
    let transport_sk = quorum_vetseal::TransportSecretKey::random(&mut rand::thread_rng());
    let transport_pk = transport_sk.public_key();
    let mut sealed_shares: Vec<(usize, quorum_vetseal::SealedShare)> = Vec::new();
    for (id, addr) in node_addrs {
        // Gap 3 step 1: each node verifies a MAC under ITS OWN derived key.
        let req = quorum_core::build_derive_request(
            &quorum_core::derive_node_auth_key(service_auth_key, *id),
            identity,
            DERIVE_AUTH_VALIDITY_MS,
            transport_pk,
        );
        match send_request(connector, addr, &req).await {
            Some(Message::DerivePartial {
                sealed_share,
                proof,
                ..
            }) => {
                // NIZK gate: a share that does not provably encrypt THIS
                // node's genuine partial never enters the combine, and the
                // lying node is identified right here.
                if quorum_core::verify_sealed_partial(
                    group_pks,
                    *id,
                    identity,
                    &transport_pk,
                    &sealed_share,
                    &proof,
                ) {
                    sealed_shares.push((*id, sealed_share));
                } else {
                    eprintln!("[quorum_client] node {id} sent a sealed share whose proof FAILED verification; excluded");
                }
            }
            Some(Message::DeriveReject { reason, .. }) => {
                eprintln!("[quorum_client] node {id} rejected derive: {reason}");
            }
            _ => {} // unreachable/offline node
        }
    }

    let want = threshold + 1;
    if sealed_shares.len() < want {
        return Err(format!(
            "only collected {} sealed share(s), need at least {want}",
            sealed_shares.len()
        ));
    }

    for subset in combinations(&sealed_shares, want) {
        let Ok(combined) = quorum_vetseal::combine_sealed_shares(&subset) else {
            continue;
        };
        let Ok(sig) = Signature::from_bytes(&transport_sk.decrypt_combined(&combined)) else {
            continue;
        };
        if quorum_core::verify_combined(group_pks, identity, &sig) {
            return Ok(sig);
        }
    }
    Err(format!(
        "collected {} sealed share(s) but no {want}-subset decrypted to a key that verifies against \
         the group public key -- likely more than {} bad node(s) among those that responded",
        sealed_shares.len(),
        sealed_shares.len().saturating_sub(want)
    ))
}

/// Every size-`k` combination of `items`, in the order combinations of
/// small collections are naturally enumerated -- fine for this
/// workspace's single-digit thresholds; not intended for large `n`.
fn combinations<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
    if k == 0 {
        return vec![Vec::new()];
    }
    if items.len() < k {
        return Vec::new();
    }
    let mut result = Vec::new();
    for i in 0..=(items.len() - k) {
        for mut rest in combinations(&items[i + 1..], k - 1) {
            let mut combo = vec![items[i].clone()];
            combo.append(&mut rest);
            result.push(combo);
        }
    }
    result
}

/// Brokers a k-of-n derive and returns the result **sealed** under
/// `transport_public_key` -- this function never touches a plaintext
/// derived key or a plaintext partial, which is exactly what makes it
/// safe to run inside `quorum_service` (a backend broker, not the true
/// end caller) per Finding 2.3's fix.
///
/// `tried_subsets` (audit finding A12): every node-ID combination a
/// previous round already returned and that the caller found, after
/// decrypting client-side, did NOT verify. Pass an empty slice on a
/// first attempt. This function contacts every node in `node_addrs`
/// (not just the first `threshold + 1` reachable ones -- see below for
/// why), then picks the first `threshold + 1`-sized combination of
/// currently-reachable node IDs that isn't already in `tried_subsets`.
///
/// This mirrors [`derive_from_quorum`]'s exhaustive `combinations()`
/// search rather than simply excluding every node that was ever in a
/// failed subset. That distinction matters and was wrong in an earlier
/// version of this function: this project's actual deployment shape is
/// a 3-of-5 quorum (`threshold + 1 == 3`, `n == 5`). Excluding an entire
/// failed 3-node subset leaves only 2 nodes -- never enough to try
/// again, ever, regardless of which node was actually bad. Retrying by
/// combination instead is at least *guaranteed to terminate correctly*:
/// with one bad node among five, `C(4,3) = 4` of the `C(5,3) = 10` total
/// subsets exclude it and will succeed, so recovery always happens
/// within a bounded number of rounds rather than immediately exhausting
/// fault tolerance.
///
/// That bound is real but not tight: `C(4,2) = 6` of the 10 subsets
/// *contain* the bad node (more than the 4 that don't, since with only 5
/// nodes and a 3-node subset, any single node appears in most
/// combinations) and a naive lexicographic search can hit several of
/// those 6 before reaching a clean one -- confirmed empirically by this
/// crate's own `quorum_adversarial` Test J, which took two rounds in one
/// run to recover, not one. Worst case is `C(n, want) - 1` failed
/// rounds before the last remaining subset must be the good one. A
/// smarter selection (e.g. deprioritizing nodes that appeared in more
/// failed subsets, once more than one failure has been observed) could
/// tighten this; not implemented here since the current version is
/// still correct and terminating, just not latency-optimal, and
/// improving it further is a genuine design choice rather than a
/// mechanical fix. The cost of contacting every node every round
/// (instead of stopping early at `threshold + 1`) is acceptable
/// regardless, since this path only runs on a *retry*, i.e. already the
/// unhappy, non-hot path, and `n` in this project's deployments is
/// small.
///
/// Returns an error if no reachable, untried subset exists -- see
/// [`CollectSealedError`] for the two distinct ways that happens and why
/// a retry loop needs to tell them apart.
// Nine parameters after the NIZK gate added `group_pks` and `proof_policy`.
// A params struct is the right follow-up refactor; not done here to keep the
// security change reviewable on its own.
#[allow(clippy::too_many_arguments)]
pub async fn collect_sealed_derived_key(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
    identity: &str,
    threshold: usize,
    service_auth_key: &[u8],
    transport_public_key: &quorum_vetseal::TransportPublicKey,
    group_pks: &PublicKeySet,
    proof_policy: ProofPolicy,
    tried_subsets: &[Vec<usize>],
) -> Result<CollectedSealedShares, CollectSealedError> {
    let want = threshold + 1;

    // Contact every configured node (not stopping at the first `want`
    // reachable ones) so there's real choice among combinations -- see
    // the doc comment above.
    let mut sealed_shares: std::collections::BTreeMap<usize, quorum_vetseal::SealedShare> =
        std::collections::BTreeMap::new();
    for (id, addr) in node_addrs {
        let req = quorum_core::build_derive_request(
            &quorum_core::derive_node_auth_key(service_auth_key, *id),
            identity,
            DERIVE_AUTH_VALIDITY_MS,
            *transport_public_key,
        );
        match send_request(connector, addr, &req).await {
            Some(Message::DerivePartial {
                sealed_share,
                proof,
                ..
            }) => {
                let ok = match proof_policy {
                    ProofPolicy::Skip => true,
                    ProofPolicy::Require => quorum_core::verify_sealed_partial(
                        group_pks,
                        *id,
                        identity,
                        transport_public_key,
                        &sealed_share,
                        &proof,
                    ),
                };
                if ok {
                    sealed_shares.insert(*id, sealed_share);
                } else {
                    eprintln!("[quorum_client] node {id} sent a sealed share whose proof FAILED verification; excluded");
                }
            }
            Some(Message::DeriveReject { reason, .. }) => {
                eprintln!("[quorum_client] node {id} rejected derive: {reason}");
            }
            _ => {} // unreachable/offline node
        }
    }

    if sealed_shares.len() < want {
        return Err(CollectSealedError::InsufficientNodes {
            available: sealed_shares.len(),
            needed: want,
        });
    }

    let reachable_ids: Vec<usize> = sealed_shares.keys().copied().collect();
    let already_tried: Vec<std::collections::BTreeSet<usize>> = tried_subsets
        .iter()
        .map(|s| s.iter().copied().collect())
        .collect();

    let chosen: Option<Vec<usize>> = combinations(&reachable_ids, want)
        .into_iter()
        .find(|combo| !already_tried.contains(&combo.iter().copied().collect()));

    let Some(used_node_ids) = chosen else {
        return Err(CollectSealedError::SubsetsExhausted {
            tried: tried_subsets.to_vec(),
            needed: want,
        });
    };

    let subset: Vec<(usize, quorum_vetseal::SealedShare)> = used_node_ids
        .iter()
        .map(|id| (*id, sealed_shares[id]))
        .collect();
    let sealed = quorum_vetseal::combine_sealed_shares(&subset).map_err(|e| {
        CollectSealedError::Combine(format!("failed to combine sealed shares: {e}"))
    })?;
    Ok(CollectedSealedShares {
        sealed,
        used_node_ids,
    })
}

/// Whether [`collect_sealed_derived_key`] checks each node's NIZK before
/// combining. Production callers MUST use `Require`. `Skip` exists only so
/// the adversarial suite can still exercise the post-combine retry
/// protocol (audit finding A12), which a sound proof otherwise makes
/// unreachable; it is never a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPolicy {
    Require,
    Skip,
}

/// The result of one round of [`collect_sealed_derived_key`]: the sealed
/// key itself, plus exactly which node IDs' shares went into it. A
/// caller (or `quorum_service`, forwarding this to the true caller) that
/// later finds this sealed result doesn't verify should add
/// `used_node_ids` to the accumulated `tried_subsets` list and try
/// again -- see [`collect_sealed_derived_key`]'s doc comment for why
/// this is a combination search, not simple node exclusion.
#[derive(Debug, Clone)]
pub struct CollectedSealedShares {
    pub sealed: quorum_vetseal::SealedDerivedKey,
    pub used_node_ids: Vec<usize>,
}

/// Distinguishes the two ways [`collect_sealed_derived_key`] can fail to
/// produce a result, because a retry loop needs to react to them
/// differently (audit finding A12's "cap retries with a clear terminal
/// failure mode").
#[derive(Debug, Clone)]
pub enum CollectSealedError {
    /// Fewer than `needed` nodes responded with a usable share at all --
    /// could be transient (nodes temporarily unreachable) and might
    /// succeed if retried later with the same `tried_subsets`.
    InsufficientNodes { available: usize, needed: usize },
    /// Enough nodes are reachable, but every `needed`-sized combination
    /// of them is already in `tried`. This is terminal for the current
    /// identity/request: it means every subset has already been shown
    /// (by a previous round's failed client-side verification) to
    /// contain at least one bad node, which is past this quorum's
    /// fault-tolerance budget and needs operator attention, not another
    /// automatic retry.
    SubsetsExhausted {
        tried: Vec<Vec<usize>>,
        needed: usize,
    },
    /// Enough shares were collected but combining them failed outright
    /// (malformed share, not just "verifies wrong after decrypt" --
    /// this function still can't decrypt to check that part, per
    /// Finding 2.3).
    Combine(String),
}

impl std::fmt::Display for CollectSealedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectSealedError::InsufficientNodes { available, needed } => {
                write!(f, "only collected {available} sealed share(s), need at least {needed}")
            }
            CollectSealedError::SubsetsExhausted { tried, needed } => write!(
                f,
                "every reachable {needed}-node combination has already been tried and failed ({} tried) \
                 -- likely more than this quorum's fault-tolerance budget of bad nodes for this request",
                tried.len()
            ),
            CollectSealedError::Combine(msg) => write!(f, "{msg}"),
        }
    }
}
impl std::error::Error for CollectSealedError {}

/// Opens a [`SealedDerivedKey`](quorum_vetseal::SealedDerivedKey) produced
/// by [`collect_sealed_derived_key`]. MUST run wherever
/// `transport_secret_key` lives -- i.e. **never** inside `quorum_service`
/// or any other broker/backend process. This is the function a
/// browser/CLI calls locally, using a transport secret key it generated
/// itself and never sent anywhere.
///
/// This is also where a bad node's contribution is finally caught (see
/// [`collect_sealed_derived_key`]'s docs on why the check moved here): a
/// verification failure means retry `collect_sealed_derived_key` with a
/// different `T+1` subset, the same k-of-n liveness recovery this
/// workspace already relies on elsewhere.
pub fn open_sealed_derived_key(
    sealed: &quorum_vetseal::SealedDerivedKey,
    transport_secret_key: &quorum_vetseal::TransportSecretKey,
    group_pks: &PublicKeySet,
    identity: &str,
) -> Result<Signature, String> {
    let sig = Signature::from_bytes(&transport_secret_key.decrypt_combined(sealed))
        .map_err(|e| format!("failed to decrypt sealed derived key: {e}"))?;
    if !quorum_core::verify_combined(group_pks, identity, &sig) {
        return Err(
            "decrypted derived key failed verification against the group public key -- \
             a node in this subset likely sealed a bad ciphertext; retry with a different \
             T+1 subset"
                .to_string(),
        );
    }
    Ok(sig)
}

/// Fetches a node's complete local audit log replica. Used both for
/// reconciliation (compare several nodes' copies) and, via
/// [`fetch_majority_tip`], as one input to the "what's the current tip"
/// step before proposing the next entry.
pub async fn fetch_full_log(connector: &TlsConnector, addr: &str) -> Result<AuditLog, String> {
    let req = Message::GetAuditLog { invoice_id: None };
    match send_request(connector, addr, &req).await {
        Some(Message::AuditLogEntries { entries }) => Ok(AuditLog { entries }),
        Some(other) => Err(format!(
            "unexpected response fetching log from {addr}: {other:?}"
        )),
        None => Err(format!("node at {addr} did not respond")),
    }
}

/// Establishes the log's current tip by reading from every node and
/// requiring majority agreement, rather than trusting one hardcoded node.
///
/// ## Phase 4 Stage F: closing Finding 2.2
/// The previous version of [`try_propose_once`] read the tip from
/// `node_addrs[0]` specifically. That node is not distinguished in any
/// way -- it's just the first entry in a config-file list -- so trusting
/// it alone had two real failure modes: (a) if it happened to be behind
/// (e.g. it lost a previous propose race and hadn't caught up via
/// replication yet), every subsequent propose would build against a
/// stale tip and get rejected, wasting round trips that Stage B's retry
/// loop absorbed but didn't eliminate; and (b) if it was simply offline,
/// the entire propose operation failed outright after `MAX_PROPOSE_ATTEMPTS`,
/// even though the other four nodes -- an easy majority -- were healthy
/// and reachable the whole time.
///
/// The fix: query every node in `node_addrs` for its full log, discard
/// any response that doesn't arrive or whose hash chain fails
/// [`AuditLog::verify_chain`] (a malformed or dishonest node can't poison
/// the tip read), require that at least a majority of `node_addrs`
/// produced a valid response, and return the most caught-up
/// (highest [`AuditLog::next_seq`]) log among them. This is safe against
/// picking a lone unconfirmed outlier: every entry that ever gets
/// appended anywhere first collected `threshold + 1` real co-signatures
/// from separate nodes, so the most-advanced valid log in a majority
/// sample is never a single node's unconfirmed fabrication -- at least
/// one *other* honest node had to have signed off on it too.
///
/// This does not require every node to be reachable, only a majority --
/// consistent with the rest of this protocol's threshold assumptions,
/// and strictly better than the single-node dependency it replaces.
pub async fn fetch_majority_tip(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
) -> Result<AuditLog, String> {
    if node_addrs.is_empty() {
        return Err("no quorum nodes configured".to_string());
    }

    let mut valid_logs: Vec<AuditLog> = Vec::new();
    let mut responded = 0usize;
    for (_, addr) in node_addrs {
        match fetch_full_log(connector, addr).await {
            Ok(log) => {
                responded += 1;
                if log.verify_chain().is_ok() {
                    valid_logs.push(log);
                }
                // A response that fails verify_chain() is silently
                // dropped from the candidate pool rather than treated as
                // an error: a single malformed/dishonest replica
                // shouldn't be able to abort a tip read that a majority
                // of *other* nodes could otherwise satisfy.
            }
            Err(_) => {
                // Offline or unreachable node; not counted toward
                // `responded` or the majority requirement below.
            }
        }
    }

    let majority_needed = node_addrs.len() / 2 + 1;
    if valid_logs.len() < majority_needed {
        return Err(format!(
            "only {} of {} nodes returned a valid, chain-verified log ({} responded at all) -- need at \
             least {majority_needed} (a majority) to establish a trustworthy tip",
            valid_logs.len(),
            node_addrs.len(),
            responded,
        ));
    }

    valid_logs
        .into_iter()
        .max_by_key(|log| log.next_seq())
        .ok_or_else(|| "no valid audit log available to establish a tip".to_string())
}

/// The composite operation a product-layer caller actually wants:
/// "record this event in the tamper-evident log," reliably, even if
/// another caller is proposing an entry for the same log at the same
/// moment. This is a thin retry wrapper around [`try_propose_once`] --
/// see that function for the actual propose/collect/replicate mechanics.
///
/// ## Phase 4 Stage B: closing Finding 1.2
/// The single-shot version of this function had no recovery from a losing
/// race: a
/// proposer whose `AppendAuditEntry` requests arrived at a node after a
/// competing proposer had already claimed that `seq` simply got
/// `AuditAppendRejected` from that node and, if it couldn't scrape together
/// `threshold + 1` signatures elsewhere, returned a bare `Err` -- the
/// event was never persisted anywhere and the caller had no built-in way
/// to recover short of re-implementing this exact retry logic itself.
/// (Concretely: with `n` nodes and needing `threshold + 1` signatures,
/// two proposers can only *both* reach quorum for the *same* `seq` if
/// `2 * (threshold + 1) <= n`; this deployment's `n=5, threshold=2` avoids
/// that specific split, but offered no relief from the ordinary "I lost
/// the race and my event just vanished" case, which happens under any
/// concurrency at all.)
///
/// The fix: on failure, re-fetch the log's current tip (which by now
/// reflects whatever the winning proposer just committed), rebuild a
/// fresh entry against that new tip, and try again, with a small
/// randomized backoff so that two proposers retrying at the same moment
/// don't just collide again in lockstep. This is the
/// "conflict-detection-and-retry loop" option this function's own
/// original doc comment named as one valid fix (the other two -- a single
/// designated writer, or a real distributed lock -- would also work, but
/// this one requires no new coordination infrastructure and degrades
/// gracefully: every proposer either lands at a distinct `seq` or
/// eventually gives up loudly after `MAX_PROPOSE_ATTEMPTS`, never silently.
pub async fn propose_and_cosign_and_replicate(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
    threshold: usize,
    event: AuditEvent,
) -> Result<AuditEntry, String> {
    propose_audit_entry(connector, node_addrs, threshold, event)
        .await
        .map_err(|e| e.to_string())
}

/// Why an audit proposal ended without a committed entry (F-13). A proposal
/// NEVER ends silently: it either returns the committed entry or one of these,
/// each carrying enough detail to be recorded and acted on by the caller.
/// Retry budget and vote TTL are deliberately NOT widened to avoid this
/// (widening the TTL window worsens SECURITY_REVIEW R-2); the caller owns
/// durable retry (see the service's audit outbox).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeError {
    /// Nodes were reachable and answered but refused our entry (a competing
    /// proposal holds their vote slot) so no entry reached quorum.
    Contention {
        attempts: usize,
        signed: usize,
        needed: usize,
        rejections: usize,
    },
    /// Too few nodes answered at all (outage / partition / no tip majority).
    QuorumUnavailable { attempts: usize, detail: String },
    /// The entry reached signing quorum but fewer than t+1 nodes confirmed it
    /// durable. It may exist on some nodes; do NOT assume it was not recorded.
    NotDurable {
        seq: u64,
        acks: usize,
        needed: usize,
    },
    /// No nodes configured.
    NotConfigured,
}

impl std::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposeError::Contention {
                attempts,
                signed,
                needed,
                rejections,
            } => write!(
                f,
                "audit contention: gave up after {attempts} attempts; best attempt collected {signed} \
                 co-signature(s), need {needed}; {rejections} node refusal(s) in the last attempt \
                 (a competing proposal holds the vote slots; they free on commit or after the vote TTL)"
            ),
            ProposeError::QuorumUnavailable { attempts, detail } => write!(
                f,
                "audit quorum unavailable: gave up after {attempts} attempts; last error: {detail}"
            ),
            ProposeError::NotDurable { seq, acks, needed } => write!(
                f,
                "audit entry seq {seq} was co-signed but only {acks} node(s) confirmed it durable, need {needed}; it may exist on some nodes"
            ),
            ProposeError::NotConfigured => write!(f, "no quorum nodes configured"),
        }
    }
}

impl std::error::Error for ProposeError {}

/// Typed form of [`propose_and_cosign_and_replicate`]; same protocol and the
/// same retry budget (not widened), but the failure is classified.
pub async fn propose_audit_entry(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
    threshold: usize,
    event: AuditEvent,
) -> Result<AuditEntry, ProposeError> {
    const MAX_PROPOSE_ATTEMPTS: usize = 8;
    let mut last = AttemptError::NoAttempts;
    for attempt in 0..MAX_PROPOSE_ATTEMPTS {
        match try_propose_once(connector, node_addrs, threshold, event.clone()).await {
            Ok(entry) => return Ok(entry),
            Err(AttemptError::NotConfigured) => return Err(ProposeError::NotConfigured),
            // Never re-propose after a durability failure: some nodes may already
            // hold the entry and a retry could duplicate it.
            Err(AttemptError::NotDurable { seq, acks, needed }) => {
                return Err(ProposeError::NotDurable { seq, acks, needed })
            }
            Err(e) => {
                last = e;
                // Jittered backoff derived from the clock rather than a new
                // `rand` dependency in this crate -- good enough to
                // de-synchronize two colliding retriers (not a security use).
                let jitter_ms = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
                    % 40) as u64;
                let backoff_ms = 10 + (attempt as u64 * 15) + jitter_ms;
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
    Err(match last {
        AttemptError::QuorumNotReached {
            signed,
            needed,
            rejections,
        } if rejections > 0 => ProposeError::Contention {
            attempts: MAX_PROPOSE_ATTEMPTS,
            signed,
            needed,
            rejections,
        },
        AttemptError::QuorumNotReached { signed, needed, .. } => ProposeError::QuorumUnavailable {
            attempts: MAX_PROPOSE_ATTEMPTS,
            detail: format!("only {signed} co-signature(s), need {needed}, and no node refused (nodes unreachable)"),
        },
        AttemptError::TipUnavailable(detail) => ProposeError::QuorumUnavailable {
            attempts: MAX_PROPOSE_ATTEMPTS,
            detail,
        },
        AttemptError::NotDurable { seq, acks, needed } => ProposeError::NotDurable { seq, acks, needed },
        AttemptError::NotConfigured | AttemptError::NoAttempts => ProposeError::NotConfigured,
    })
}

/// Outcome of a single propose attempt (internal; classified by
/// [`propose_audit_entry`]).
enum AttemptError {
    NoAttempts,
    NotConfigured,
    TipUnavailable(String),
    QuorumNotReached {
        signed: usize,
        needed: usize,
        rejections: usize,
    },
    NotDurable {
        seq: u64,
        acks: usize,
        needed: usize,
    },
}

/// One single-shot attempt at "propose, collect co-signatures, replicate."
/// Fetches the current tip fresh on every call (including retries), so
/// each attempt proposes against whatever the log's tip actually is *now*
/// -- not a stale view from a previous failed attempt.
///
/// The tip is read via [`fetch_majority_tip`] -- a majority of
/// `node_addrs`, not one hardcoded node (Stage F fix for Finding 2.2; see
/// that function's doc comment for the reasoning).
async fn try_propose_once(
    connector: &TlsConnector,
    node_addrs: &[(usize, String)],
    threshold: usize,
    event: AuditEvent,
) -> Result<AuditEntry, AttemptError> {
    if node_addrs.is_empty() {
        return Err(AttemptError::NotConfigured);
    }
    let current_log = fetch_majority_tip(connector, node_addrs)
        .await
        .map_err(AttemptError::TipUnavailable)?;
    let mut entry = current_log.propose_next(event);

    let mut signed_count = 0usize;
    let mut rejections = 0usize;
    for (id, addr) in node_addrs {
        if signed_count > threshold {
            break;
        }
        let req = Message::AppendAuditEntry {
            entry: entry.clone(),
        };
        match send_request(connector, addr, &req).await {
            Some(Message::AuditEntrySigned { node_id, signature }) => {
                entry.signatures.insert(node_id, signature);
                signed_count += 1;
            }
            Some(Message::AuditAppendRejected { node_id, reason }) => {
                rejections += 1;
                eprintln!("[quorum_client] node {node_id} rejected audit append: {reason}");
            }
            _ => {
                let _ = id; // offline node; replication below will catch it up later (not implemented)
            }
        }
    }
    if signed_count <= threshold {
        return Err(AttemptError::QuorumNotReached {
            signed: signed_count,
            needed: threshold + 1,
            rejections,
        });
    }

    // F-19: replicate and WAIT for durable acknowledgements. The entry is only
    // reported as committed once at least `threshold + 1` nodes confirm it is
    // on their disk. Replication is idempotent, so non-acknowledging nodes get
    // a few more rounds before we give up. No re-proposal on failure (that
    // could duplicate an entry some nodes already hold).
    let needed = threshold + 1;
    let mut acked: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for _round in 0..3 {
        for (id, addr) in node_addrs {
            if acked.contains(id) {
                continue;
            }
            let req = Message::ReplicateAuditEntry {
                entry: entry.clone(),
            };
            if let Some(Message::AuditEntryCommitted {
                node_id,
                seq,
                entry_hash,
            }) = send_request(connector, addr, &req).await
            {
                if node_id == *id && seq == entry.seq && entry_hash == entry.entry_hash {
                    acked.insert(node_id);
                }
            }
        }
        if acked.len() >= node_addrs.len() {
            break;
        }
        if acked.len() >= needed {
            // Quorum-durable; stragglers are caught up by later reads/replication.
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if acked.len() < needed {
        return Err(AttemptError::NotDurable {
            seq: entry.seq,
            acks: acked.len(),
            needed,
        });
    }

    Ok(entry)
}

/// Test support: the server name every pinned connection uses.
#[doc(hidden)]
pub fn server_name_for_tests() -> Option<ServerName<'static>> {
    ServerName::try_from("quorum-node").ok()
}
