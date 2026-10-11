//! F-27: TLS for the Postgres connection.
//!
//! Policy (mirrors the listener guard of audit finding A5): a database on a non-loopback TCP
//! host must be reached with `sslmode=require`, and `require` is only accepted together with
//! at least one trust anchor (`db_tls_ca_der_b64`), because the connector verifies the server
//! certificate chain and name against those roots. Loopback hosts and unix sockets may stay
//! plaintext (local development, tests).
use rustls::pki_types::CertificateDer;
use std::net::IpAddr;
use std::sync::Arc;
use tokio_postgres::config::{Host, SslMode};

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

pub fn check_db_tls_policy(cfg: &tokio_postgres::Config) -> Result<(), String> {
    let remote = cfg.get_hosts().iter().find_map(|h| match h {
        Host::Tcp(name) if !is_loopback(name) => Some(name.clone()),
        _ => None,
    });
    match remote {
        Some(host) if cfg.get_ssl_mode() != SslMode::Require => Err(format!(
            "refusing to connect to Postgres host {host}: it is not loopback and the db_url does \
             not say sslmode=require (finding F-27). Add `?sslmode=require` and set \
             db_tls_ca_der_b64 to the CA that signed the database certificate."
        )),
        _ => Ok(()),
    }
}

/// Without a configured CA there is nothing to verify a server certificate against, so a
/// non-`require` connection (loopback only, by `check_db_tls_policy`) stays plaintext.
pub fn apply_tls_defaults(cfg: &mut tokio_postgres::Config, ca_ders: &[Vec<u8>]) {
    if cfg.get_ssl_mode() != SslMode::Require && ca_ders.is_empty() {
        cfg.ssl_mode(SslMode::Disable);
    }
}

/// Builds the connector. The root store holds exactly the configured CAs (no bundled web roots).
pub fn build_connector(
    cfg: &tokio_postgres::Config,
    ca_ders: &[Vec<u8>],
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, String> {
    if cfg.get_ssl_mode() == SslMode::Require && ca_ders.is_empty() {
        return Err(
            "sslmode=require needs at least one CA in db_tls_ca_der_b64 to verify the database \
             certificate; refusing to start"
                .into(),
        );
    }
    let mut roots = rustls::RootCertStore::empty();
    for ca in ca_ders {
        roots
            .add(CertificateDer::from(ca.clone()))
            .map_err(|e| format!("bad db_tls_ca_der_b64 entry: {e}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> tokio_postgres::Config {
        url.parse().unwrap()
    }

    #[test]
    fn loopback_plaintext_is_allowed() {
        assert!(check_db_tls_policy(&cfg("postgres://u@127.0.0.1/db")).is_ok());
        assert!(check_db_tls_policy(&cfg("postgres://u@localhost/db")).is_ok());
        assert!(check_db_tls_policy(&cfg("postgres://u@[::1]/db")).is_ok());
    }

    #[test]
    fn remote_host_without_require_is_refused() {
        for url in [
            "postgres://u@db.internal/db",
            "postgres://u@10.0.0.5/db?sslmode=prefer",
            "postgres://u@10.0.0.5/db?sslmode=disable",
        ] {
            let e = check_db_tls_policy(&cfg(url)).unwrap_err();
            assert!(e.contains("sslmode=require"), "{url}: {e}");
        }
    }

    #[test]
    fn remote_host_with_require_is_allowed() {
        assert!(check_db_tls_policy(&cfg("postgres://u@db.internal/db?sslmode=require")).is_ok());
    }

    #[test]
    fn any_remote_host_among_several_triggers_the_refusal() {
        assert!(check_db_tls_policy(&cfg("postgres://u@127.0.0.1,db.internal/db")).is_err());
    }

    #[test]
    fn local_default_without_a_ca_is_plain_not_a_failing_handshake() {
        // `prefer` against a local server that offers TLS must not attempt a handshake it can
        // only fail (empty trust store); it stays plaintext, as it did before F-27.
        let mut c = cfg("postgres://u@127.0.0.1/db");
        apply_tls_defaults(&mut c, &[]);
        assert_eq!(c.get_ssl_mode(), SslMode::Disable);
        // With a CA configured, verified TLS is kept.
        let mut c = cfg("postgres://u@127.0.0.1/db");
        apply_tls_defaults(&mut c, &[vec![1]]);
        assert_eq!(c.get_ssl_mode(), SslMode::Prefer);
        // `require` is never downgraded.
        let mut c = cfg("postgres://u@db/db?sslmode=require");
        apply_tls_defaults(&mut c, &[]);
        assert_eq!(c.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn unix_socket_is_local() {
        assert!(check_db_tls_policy(&cfg("postgres://u@%2Fvar%2Frun%2Fpostgresql/db")).is_ok());
    }

    #[test]
    fn require_without_any_trust_anchor_is_refused() {
        let c = cfg("postgres://u@db.internal/db?sslmode=require");
        assert!(build_connector(&c, &[]).is_err());
    }

    // ---- live tests against the TLS-enabled cluster from ci/setup_ssl_test_db.sh ----

    fn ssl_dir() -> Option<std::path::PathBuf> {
        match std::env::var("CIPHERSETTLE_SSL_DB_DIR") {
            Ok(d) if !d.is_empty() => Some(d.into()),
            _ => {
                let required = matches!(std::env::var("CIPHERSETTLE_TEST_DB_REQUIRED"),
                    Ok(v) if !v.is_empty() && v != "0");
                assert!(
                    !required,
                    "DB_REQUIRED_BUT_UNREACHABLE: live DB TLS test needs CIPHERSETTLE_SSL_DB_DIR \
                     (run ci/setup_ssl_test_db.sh)"
                );
                eprintln!("SKIPPED live DB TLS test: CIPHERSETTLE_SSL_DB_DIR not set");
                None
            }
        }
    }

    fn port() -> String {
        std::env::var("CIPHERSETTLE_SSL_DB_PORT").unwrap_or_else(|_| "5433".into())
    }

    /// Connects and returns whether the session is really encrypted, or an error string.
    async fn connect(host: &str, ca: &[u8]) -> Result<bool, String> {
        // `hostaddr` fixes the socket address, so `host` is only the name the certificate is
        // verified against (no DNS involved).
        let dsn = format!(
            "host={host} hostaddr=127.0.0.1 port={} user=postgres password=ciphersettle_dev \
             dbname=postgres sslmode=require",
            port()
        );
        let c: tokio_postgres::Config = dsn.parse().map_err(|e| format!("{e}"))?;
        check_db_tls_policy(&c)?;
        let tls = build_connector(&c, &[ca.to_vec()])?;
        let (client, conn) = c.connect(tls).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let row = client
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.get::<_, bool>(0))
    }

    #[tokio::test]
    async fn live_verified_tls_connection_is_encrypted() {
        let Some(d) = ssl_dir() else { return };
        let ca = std::fs::read(d.join("ca.der")).unwrap();
        assert_eq!(connect("localhost", &ca).await, Ok(true));
    }

    #[tokio::test]
    async fn live_wrong_ca_is_refused() {
        let Some(d) = ssl_dir() else { return };
        let other = std::fs::read(d.join("other_ca.der")).unwrap();
        assert!(connect("localhost", &other).await.is_err());
    }

    #[tokio::test]
    async fn live_certificate_name_mismatch_is_refused() {
        let Some(d) = ssl_dir() else { return };
        let ca = std::fs::read(d.join("ca.der")).unwrap();
        // Positive control: same socket, correct name.
        assert_eq!(connect("localhost", &ca).await, Ok(true));
        // Same socket and CA, but a name that is not in the certificate's SAN list.
        let r = connect("wrong.example", &ca).await;
        assert!(r.is_err(), "unexpected success: {r:?}");
    }
}
