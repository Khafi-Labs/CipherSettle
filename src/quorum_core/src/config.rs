use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub id: usize,
    pub addr: String,
    /// Base64 of the peer's self-signed certificate, DER-encoded. This is
    /// the "provisioned out-of-band before DKG" identity binding the
    /// roadmap calls for -- `quorum_orchestrator` plays the role of that
    /// out-of-band provisioning step in this codebase.
    pub cert_der_b64: String,
    /// Base64 of the peer's ed25519 audit-signing public key (32 bytes).
    /// Deliberately a SEPARATE keypair from the TLS identity above: the
    /// TLS cert authenticates network connections, this key authenticates
    /// individual audit-log co-signatures -- two different security
    /// properties (see `quorum_audit`'s module doc comment), kept
    /// cryptographically distinct rather than reusing one key for both.
    pub audit_pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: usize,
    pub listen_addr: String,
    /// Total quorum size.
    pub n: usize,
    /// Threshold: t+1 shares needed to derive.
    pub t: usize,
    pub cert_der_b64: String,
    pub key_der_b64: String,
    /// This node's ed25519 audit-signing keypair, base64 of
    /// `Keypair::to_bytes()` (64 bytes: 32-byte secret + 32-byte public).
    pub audit_keypair_b64: String,
    /// Base64 of the shared HMAC key known only to `quorum_service` and
    /// every quorum node -- deliberately NOT the mTLS client cert, which
    /// Phase 4 Test C proved is not a sufficient authorization boundary
    /// (it's shared with, and effectively as powerful as, every other
    /// direct caller of the raw node protocol). Every `DeriveRequest` must
    /// carry a MAC computed with this key or the node refuses it. See
    /// `quorum_core::sign_derive_auth` / `verify_derive_auth`.
    pub service_auth_key_b64: String,
    /// Every OTHER node in the quorum (not including self).
    pub peers: Vec<PeerConfig>,
    /// The designated derive-requesting client's certificate, also pinned
    /// as an allowed connector to this node's TLS listener.
    pub client_cert_der_b64: String,
    /// This node writes an empty file at this path the moment its DKG
    /// share finalizes, so an external orchestrator/test harness can poll
    /// for readiness without parsing this node's stdout.
    pub ready_file: String,
    /// This node writes the JSON-serialized group `PublicKeySet` here on
    /// finalize -- this is the "published, used for IBE encryption by
    /// clients" master public key the roadmap's Phase 1 calls for. Safe to
    /// be genuinely public: it contains no secret material.
    pub pubkey_file: String,
    /// Where this node persists its local `quorum_audit::AuditLog` replica
    /// (JSON). "Replicate the log across all quorum nodes, not just the
    /// operator's" means every node gets one of these, not just node 0.
    pub audit_log_file: String,
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("config contains invalid base64 -- corrupt or hand-edited config file")
}
