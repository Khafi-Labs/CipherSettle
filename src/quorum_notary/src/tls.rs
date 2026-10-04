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

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, DistinguishedName, Error, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

/// Verifies a peer's certificate by exact byte match against a fixed
/// allow-list, in both TLS client and server roles. One instance is
/// shared (via `Arc`) between this node's outbound `ClientConfig` and
/// inbound `ServerConfig`.
pub struct PinnedCertVerifier {
    allowed_der: Vec<Vec<u8>>,
}

impl PinnedCertVerifier {
    pub fn new(allowed_der: Vec<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self { allowed_der })
    }

    fn is_allowed(&self, cert: &Certificate) -> bool {
        self.allowed_der
            .iter()
            .any(|c| c.as_slice() == cert.0.as_slice())
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.is_allowed(end_entity) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(
                "peer certificate is not in this node's pinned allow-list".into(),
            ))
        }
    }
}

impl ClientCertVerifier for PinnedCertVerifier {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        // Intentionally empty: we pin by exact certificate identity, not by
        // CA subject hints. `offer_client_auth`/`client_auth_mandatory`
        // below are what actually make client-cert presentation mandatory.
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
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        if self.is_allowed(end_entity) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General(
                "peer certificate is not in this node's pinned allow-list".into(),
            ))
        }
    }
}
