//! F-30 migration guard: the pinned-certificate mTLS must (a) accept the exact pinned
//! certificates, (b) refuse an unpinned certificate, and (c) refuse a peer that presents
//! a pinned certificate WITHOUT holding its private key. (c) is the one a hand-written
//! verifier can silently lose when the TLS library changes: rustls 0.23 requires custom
//! verifiers to check the handshake signature themselves.
use quorum_client::{build_connector, build_server_config};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Id {
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn id(name: &str) -> Id {
    let c = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    Id {
        cert: c.serialize_der().unwrap(),
        key: c.serialize_private_key_der(),
    }
}

/// Starts a one-shot TLS server; returns its address and a handle yielding whether it
/// completed a handshake AND read the client's byte.
async fn serve(cfg: rustls_cfg::Cfg) -> (std::net::SocketAddr, tokio::task::JoinHandle<bool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let h = tokio::spawn(async move {
        let Ok((s, _)) = l.accept().await else {
            return false;
        };
        let Ok(mut t) = acc.accept(s).await else {
            return false;
        };
        let mut b = [0u8; 1];
        let ok = t.read_exact(&mut b).await.is_ok();
        let _ = t.write_all(b"k").await;
        let _ = t.shutdown().await;
        ok
    });
    (addr, h)
}

mod rustls_cfg {
    pub type Cfg = rustls::ServerConfig;
}

/// Returns true iff the client got a full round trip.
async fn client_round_trip(addr: std::net::SocketAddr, own: &Id, pinned_server: &Id) -> bool {
    let conn = build_connector(
        own.cert.clone(),
        own.key.clone(),
        vec![pinned_server.cert.clone()],
    )
    .unwrap();
    let Ok(tcp) = TcpStream::connect(addr).await else {
        return false;
    };
    let name = quorum_client::server_name_for_tests().unwrap();
    let Ok(mut t) = conn.connect(name, tcp).await else {
        return false;
    };
    if t.write_all(b"x").await.is_err() {
        return false;
    }
    let mut b = [0u8; 1];
    t.read_exact(&mut b).await.is_ok()
}

#[tokio::test]
async fn pinned_peers_complete_a_round_trip() {
    let (server, client) = (id("quorum-node"), id("quorum-node"));
    let cfg = build_server_config(
        server.cert.clone(),
        server.key.clone(),
        vec![client.cert.clone()],
    )
    .unwrap();
    let (addr, h) = serve(cfg).await;
    assert!(client_round_trip(addr, &client, &server).await);
    assert!(h.await.unwrap());
}

#[tokio::test]
async fn unpinned_server_certificate_is_refused() {
    let (server, other, client) = (id("quorum-node"), id("quorum-node"), id("quorum-node"));
    let cfg = build_server_config(
        server.cert.clone(),
        server.key.clone(),
        vec![client.cert.clone()],
    )
    .unwrap();
    let (addr, _h) = serve(cfg).await;
    // The client pins `other`, not the certificate the server presents.
    assert!(!client_round_trip(addr, &client, &other).await);
}

#[tokio::test]
async fn unpinned_client_certificate_is_refused() {
    let (server, client, stranger) = (id("quorum-node"), id("quorum-node"), id("quorum-node"));
    let cfg = build_server_config(
        server.cert.clone(),
        server.key.clone(),
        vec![client.cert.clone()],
    )
    .unwrap();
    let (addr, h) = serve(cfg).await;
    assert!(!client_round_trip(addr, &stranger, &server).await);
    assert!(!h.await.unwrap());
}

/// A `CertifiedKey` that pairs `cert` with a DIFFERENT private key. rustls 0.23's
/// `with_single_cert` refuses such a pair at configuration time, so build it through the
/// resolver path, which is how a malicious peer would actually present it.
fn mismatched(cert: &Id, key: &Id) -> Arc<rustls::sign::CertifiedKey> {
    let signer = rustls::crypto::ring::sign::any_supported_type(
        &rustls::pki_types::PrivateKeyDer::try_from(key.key.clone()).unwrap(),
    )
    .unwrap();
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(cert.cert.clone())],
        signer,
    ))
}

#[derive(Debug)]
struct Resolver(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for Resolver {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}
impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[tokio::test]
async fn pinned_certificate_without_its_private_key_is_refused() {
    let (real, impostor_key, client) = (id("quorum-node"), id("quorum-node"), id("quorum-node"));
    // The impostor knows the pinned certificate (it is public) but signs with another key.
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(mismatched(&real, &impostor_key))));
    let (addr, _h) = serve(cfg).await;
    assert!(!client_round_trip(addr, &client, &real).await);
}

/// Accepts any server certificate but still checks handshake signatures, so the only
/// thing under test is the SERVER's verification of the client's proof of key possession.
#[derive(Debug)]
struct AcceptServer(rustls::crypto::WebPkiSupportedAlgorithms);
impl rustls::client::danger::ServerCertVerifier for AcceptServer {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[tokio::test]
async fn client_presenting_a_pinned_certificate_without_its_key_is_refused() {
    let (server, real_client, impostor) = (id("quorum-node"), id("quorum-node"), id("quorum-node"));
    let cfg = build_server_config(
        server.cert.clone(),
        server.key.clone(),
        vec![real_client.cert.clone()],
    )
    .unwrap();
    let (addr, h) = serve(cfg).await;
    let ccfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptServer(
            provider().signature_verification_algorithms,
        )))
        .with_client_cert_resolver(Arc::new(Resolver(mismatched(&real_client, &impostor))));
    let conn = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = quorum_client::server_name_for_tests().unwrap();
    let got = match conn.connect(name, tcp).await {
        Ok(mut t) => {
            let _ = t.write_all(b"x").await;
            let mut b = [0u8; 1];
            t.read_exact(&mut b).await.is_ok()
        }
        Err(_) => false,
    };
    assert!(!got, "client round trip must fail");
    assert!(
        !h.await.unwrap(),
        "server must not accept the forged client"
    );
}
