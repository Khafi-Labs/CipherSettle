use serde::{Deserialize, Serialize};

fn default_db_pool_max_size() -> usize {
    16
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub key: String,
    pub caller_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumNodeRef {
    pub id: usize,
    pub addr: String,
    pub cert_der_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub listen_addr: String,
    pub db_url: String,
    /// Maximum number of pooled Postgres connections (audit finding A10).
    /// Defaults to 16 if the config file predates this field, so existing
    /// deployment configs don't need to be touched to keep working.
    #[serde(default = "default_db_pool_max_size")]
    pub db_pool_max_size: usize,
    /// The one caller_id treated as admin (register/revoke regulators).
    /// Whichever pre-provisioned API key maps to this caller_id is the
    /// admin key -- there is no separate "is_admin" flag on a key itself.
    pub admin_caller_id: String,
    /// Pre-provisioned API keys. This IS the "real API-key/subscription
    /// layer" the roadmap says to budget for sooner rather than later --
    /// deliberately not self-service signup: an admin has to add an entry
    /// here (or, in a real deployment, a row in a keys table) before a
    /// caller can make any authenticated call at all. Closes the
    /// many-cheap-principals Sybil gap the original README flagged,
    /// since creating a new "principal" now costs whatever it costs to
    /// get a key issued, not zero.
    pub api_keys: Vec<ApiKeyConfig>,

    /// This service's own mTLS client identity for talking to the quorum.
    pub client_cert_der_b64: String,
    pub client_key_der_b64: String,
    /// The shared secret proving to every quorum node that a derive
    /// request genuinely came from this service (Phase 4 Stage A fix for
    /// Finding 1.1) -- NOT the same thing as the mTLS client identity
    /// above. Must match the `service_auth_key_b64` configured into every
    /// node in `quorum_nodes`.
    pub service_auth_key_b64: String,
    pub quorum_nodes: Vec<QuorumNodeRef>,
    pub notary_addr: Option<String>,
    pub notary_cert_der_b64: Option<String>,
    /// Path to a node's published group `PublicKeySet` JSON (see
    /// `quorum_node`'s `pubkey_file`).
    pub group_pubkey_file: String,
    /// t: need t+1 partials/co-signatures.
    pub quorum_threshold: usize,

    pub max_ciphertext_bytes: usize,
    pub ciphertext_retention_ms: u64,
    pub derive_rate_limit_max_calls: usize,
    pub derive_rate_limit_window_ms: u64,

    /// Audit finding A5. Both present together, or both absent -- a
    /// server certificate is meaningless without its matching key, and
    /// vice versa. Absent is only accepted when `listen_addr` resolves
    /// to a loopback interface (127.0.0.1, ::1, or "localhost"); see
    /// `main`'s startup check. This is DER bytes, base64-encoded, the
    /// same encoding this config already uses for the mTLS node
    /// identity above -- until A2's KMS/Vault-backed provisioning
    /// layer exists, a config file is where every secret in this demo
    /// lives, TLS material included.
    #[serde(default)]
    pub tls_cert_der_b64: Option<String>,
    #[serde(default)]
    pub tls_key_der_b64: Option<String>,

    /// TEST-ONLY escape hatch. When false (the default, and the only value
    /// a deployment should ever use) every node's sealed share must carry
    /// a NIZK that verifies against the group's public key share for that
    /// node before it is combined. Setting this to true disables that
    /// check so the adversarial suite can exercise the post-combine retry
    /// protocol (A12). The service logs a loud warning at startup if set.
    #[serde(default)]
    pub insecure_skip_share_proofs: bool,

    /// Cutover guard (`db::enforce_crypto_epoch`). A database that already
    /// contains invoices but carries no crypto-epoch marker pre-dates the
    /// blstrs cutover; the service refuses to start on it. Set this to
    /// true ONCE, after purging or re-encrypting that data, to stamp the
    /// database with the current epoch. Has no effect on a database whose
    /// marker already matches, and never overrides a mismatched marker.
    #[serde(default)]
    pub acknowledge_pre_cutover_data: bool,
}
