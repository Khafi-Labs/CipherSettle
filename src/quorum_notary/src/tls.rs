//! Certificate-pinned mutual TLS for a small, known, permissioned set of
//! peers -- exactly the roadmap's Phase 1 wording: "Not internet-open --
//! this is a small, known, permissioned set of peers."
//!
//! There is deliberately no certificate authority here. Each node's
//! identity is its own self-signed certificate, generated once and then
//! distributed out-of-band to every other quorum member before the DKG
//! runs (in this codebase, `quorum_orchestrator` plays the role of that
//! out-of-band distribution step). Trust is "is this the exact certificate
//! I was told to expect for this peer," not "does this chain to a root
//! I trust" -- which is the right model for a fixed, small membership set
//! and the wrong model for anything open-enrollment.
//!
//! Real rotation (a member's cert changing) is Phase 1's other named
//! open item (proactive secret resharing) and is not handled here: this
//! verifier's pinned set is fixed for the lifetime of one node process.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use std::sync::Arc;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_provider::default_provider())
}

/// Parses a PKCS#8 / PKCS#1 / SEC1 private key from DER bytes.
pub fn parse_key(key_der: Vec<u8>) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::try_from(key_der).map_err(|e| format!("unrecognised private key format: {e}"))
}

/// Verifies a peer's certificate by exact byte match against a fixed
/// allow-list, in both TLS client and server roles. One instance is
/// shared (via `Arc`) between this process's outbound `ClientConfig` and
/// inbound `ServerConfig`.
///
/// rustls 0.23 leaves the handshake-signature check to the verifier. That
/// check is what proves the peer HOLDS the pinned certificate's private key
/// (the certificate itself is public), so it delegates to the crypto
/// provider and must never be stubbed. `quorum_client/tests/pinning.rs`
/// holds the mutation-checked tests for this.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    allowed_der: Vec<Vec<u8>>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    pub fn new(allowed_der: Vec<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            allowed_der,
            algs: provider().signature_verification_algorithms,
        })
    }

    fn is_allowed(&self, cert: &CertificateDer<'_>) -> bool {
        self.allowed_der
            .iter()
            .any(|c| c.as_slice() == cert.as_ref())
    }

    /// Server config presenting `(cert, key)` and requiring a pinned client certificate.
    pub fn server_config(
        self: &Arc<Self>,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<rustls::ServerConfig, String> {
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("protocol versions: {e}"))?
            .with_client_cert_verifier(self.clone())
            .with_single_cert(vec![CertificateDer::from(cert_der)], parse_key(key_der)?)
            .map_err(|e| format!("bad cert/key: {e}"))
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.is_allowed(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "peer certificate is not in this node's pinned allow-list".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for PinnedCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Intentionally empty: we pin by exact certificate identity, not by CA subject hints.
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
    ) -> Result<ClientCertVerified, Error> {
        if self.is_allowed(end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General(
                "peer certificate is not in this node's pinned allow-list".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
