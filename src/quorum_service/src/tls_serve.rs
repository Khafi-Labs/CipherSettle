//! Audit finding A5: TLS termination for `quorum_service`'s HTTP API.
//! Previously this service only ever bound plaintext HTTP, safe only
//! because every deployment so far has talked to it exclusively over
//! `127.0.0.1`. This module makes that safety property explicit and
//! enforced rather than incidental: [`refuse_plaintext_off_loopback`]
//! is a hard startup-time gate, and [`serve`] does the actual TLS
//! termination when certificate material is configured.
//!
//! Deliberately hand-rolled against `hyper`/`hyper-util` directly
//! (axum's own documented "low-level rustls" pattern) rather than via
//! the `axum-server` crate -- see `Cargo.toml`'s comment on the `hyper`/
//! `hyper-util` dependencies for why: `axum-server`'s latest release is
//! API-incompatible with the `hyper-util` version this workspace's axum
//! already resolves to. This is materially the same amount of code
//! `axum-server` would have been anyway.

use axum::Router;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::Service;

/// Returns `Ok(())` if `listen_addr` is safe to bind without TLS
/// (resolves to a loopback interface), or an error describing why not.
/// Called before binding anything, so a misconfigured non-loopback
/// plaintext deployment fails fast and loudly at startup rather than
/// quietly serving plaintext HTTP to the world.
///
/// This checks `listen_addr`'s *host*, not whether TLS config happens to
/// be present -- the two are independent knobs: TLS config presence
/// decides which code path `main` takes (`serve` vs plain
/// `axum::serve`), this function decides whether taking the plaintext
/// path is *allowed* at all for the requested address.
pub fn refuse_plaintext_off_loopback(listen_addr: &str) -> Result<(), String> {
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("invalid listen_addr {listen_addr:?}: {e}"))?;
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing to bind {listen_addr} without TLS configured: {listen_addr} is not a loopback \
             address. Audit finding A5: this service must not serve plaintext HTTP off loopback. Either \
             bind to 127.0.0.1/::1, or set tls_cert_der_b64 and tls_key_der_b64 in the config."
        ))
    }
}

/// Accepts TLS connections on `listener` and serves `app` over each one,
/// HTTP/1.1 only (see `Cargo.toml`'s comment on why HTTP/2 support is
/// deliberately not enabled here). One task per connection, matching
/// `quorum_node`'s existing `handle_inbound` connection-handling shape
/// elsewhere in this workspace.
pub async fn serve(
    app: Router,
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[service] TCP accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let tower_service = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[service] TLS handshake failed from {remote_addr}: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    // axum::Router implements tower::Service<Request<axum::body::Body>>,
                    // not Request<Incoming> directly -- axum::body::Body::new
                    // accepts anything implementing http_body::Body, which
                    // hyper::body::Incoming does.
                    tower_service
                        .clone()
                        .call(request.map(axum::body::Body::new))
                },
            );
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_service)
                .with_upgrades()
                .await
            {
                // Ordinary on a normal client disconnect; not worth
                // treating as a hard error for the whole listener loop.
                eprintln!("[service] connection error from {remote_addr}: {err}");
            }
        });
    }
}

/// Builds a `TlsAcceptor` from DER-encoded certificate and key bytes.
/// Single-certificate chain (no intermediate bundling) -- sufficient for
/// this project's demo deployments and the adversarial test suite; a
/// real production deployment terminating TLS for external clients
/// would want a full chain, which this can be extended to accept
/// (`Vec<Certificate>`) without changing the shape of anything else
/// here.
pub fn build_acceptor(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<tokio_rustls::TlsAcceptor, String> {
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| format!("unrecognised TLS private key format: {e}"))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS protocol versions: {e}"))?
    .with_no_client_auth()
    .with_single_cert(vec![rustls::pki_types::CertificateDer::from(cert_der)], key)
    .map_err(|e| format!("bad TLS server cert/key: {e}"))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
