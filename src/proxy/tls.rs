//! TLS support for the centralized enforcement gateway (FR-5 §5.5.6)
//!
//! ## What this does
//!
//! Provides optional TLS termination on the gateway's listener socket.
//! When `--tls-cert` and `--tls-key` are passed to `agentwall start`,
//! the gateway listens on HTTPS instead of plain HTTP.
//!
//! ## Why rustls (not native-tls / OpenSSL)?
//!
//! 1. Already in the dependency tree — reqwest and tokio-tungstenite both
//!    pull rustls transitively, so this adds zero new C dependencies.
//! 2. No OpenSSL CVE surface — rustls is pure Rust with a much smaller
//!    attack surface, which matters for a security gateway.
//! 3. The PRD config block (§5.5.6) specifies PEM cert/key paths, which
//!    rustls-pemfile handles natively.
//!
//! ## MaybeTlsStream
//!
//! The `MaybeTlsStream` enum wraps either a plain `TcpStream` or a
//! `TlsStream<TcpStream>`, implementing `AsyncRead + AsyncWrite` so that
//! `run_server` can use a single `service_fn` definition regardless of
//! whether TLS is active. Without this, we'd need to duplicate the entire
//! service closure for each branch (hyper's `serve_connection` is generic
//! over the IO type and consumes the service by value).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
pub use tokio_rustls::TlsAcceptor;

// ─── MaybeTlsStream ─────────────────────────────────────────────────────────

/// A TCP stream that may or may not be TLS-wrapped.
///
/// Both variants are `Unpin` (TcpStream and TlsStream<TcpStream> are both
/// Unpin), so `Pin::new(s)` in the trait impls is safe without pin_project.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ─── TLS Acceptor Builder ────────────────────────────────────────────────────

/// Build a `TlsAcceptor` from PEM certificate chain and private key files.
///
/// ## Certificate chain
/// The cert file should contain the leaf certificate first, followed by any
/// intermediate certificates. The root CA certificate is optional (clients
/// typically have it in their trust store).
///
/// ## Private key
/// Accepts PKCS#8 (`BEGIN PRIVATE KEY`), RSA (`BEGIN RSA PRIVATE KEY`),
/// or EC (`BEGIN EC PRIVATE KEY`) PEM formats.
///
/// ## Client authentication
/// This builds with `with_no_client_auth()` — no client certificate required.
/// mTLS (mutual TLS for gateway↔dashboard) is a separate item (FR-23) and
/// will be added by extending this function with an optional `client_ca_path`.
///
/// ## Error cases
/// - File not found → "Cannot open TLS cert/key '<path>': No such file"
/// - Empty/invalid PEM → "No valid certificates/key found in '<path>'"
/// - Cert/key mismatch → "TLS config error (cert/key mismatch?): ..."
pub fn build_tls_acceptor(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::BufReader;

    // ── Load certificate chain ───────────────────────────────────────────
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| format!("Cannot open TLS cert '{}': {}", cert_path.display(), e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Invalid PEM in cert file '{}': {}", cert_path.display(), e))?;

    if certs.is_empty() {
        return Err(
            format!("No valid certificates found in '{}'", cert_path.display()).into(),
        );
    }

    // ── Load private key (PKCS#8 / RSA / EC) ─────────────────────────────
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("Cannot open TLS key '{}': {}", key_path.display(), e))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("Invalid PEM in key file '{}': {}", key_path.display(), e))?
        .ok_or_else(|| format!("No private key found in '{}'", key_path.display()))?;

    // ── Build ServerConfig ───────────────────────────────────────────────
    // with_no_client_auth() — no mTLS yet (FR-23 scope).
    // with_single_cert() — validates that the key matches the leaf cert.
    //
    // Why builder_with_provider() instead of builder()?
    // Both `ring` and `aws-lc-rs` are in the dependency tree (reqwest
    // pulls ring, tokio-tungstenite pulls aws-lc-rs). rustls 0.23 panics
    // at runtime if it can't auto-detect a single provider. Explicitly
    // selecting ring avoids the ambiguity without touching other deps.
    let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
        Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS protocol version error: {}", e))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| format!("TLS config error (cert/key mismatch?): {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn missing_cert_file_returns_error() {
        let result = build_tls_acceptor(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        let err = result.err().expect("expected an error").to_string();
        assert!(
            err.contains("Cannot open TLS cert"),
            "Expected 'Cannot open TLS cert', got: {}",
            err
        );
    }

    #[test]
    fn empty_cert_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, "").unwrap();
        std::fs::write(&key, "").unwrap();

        let result = build_tls_acceptor(&cert, &key);
        let err = result.err().expect("expected an error").to_string();
        assert!(
            err.contains("No valid certificates"),
            "Expected 'No valid certificates', got: {}",
            err
        );
    }
}