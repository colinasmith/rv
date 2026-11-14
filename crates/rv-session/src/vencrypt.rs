//! RFB security negotiation: the version exchange, VeNCrypt (security type
//! 19) with TLS, and a stream wrapper that replays a synthetic RFB 3.8
//! greeting so `vnc-rs` can finish authentication on whatever transport we
//! ended up with.
//!
//! Two TLS stacks are involved on purpose. The `X509*` subtypes carry a
//! certificate and go through rustls with the WebPKI roots. The plain `TLS*`
//! subtypes (TigerVNC's default `TLSVnc`) mean *anonymous* Diffie-Hellman —
//! no certificate at all — which rustls refuses to implement, so those use
//! OpenSSL with anonymous cipher suites.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::SessionError;

pub const SEC_NONE: u8 = 1;
pub const SEC_VNC_AUTH: u8 = 2;
pub const VENCRYPT_SECURITY_TYPE: u8 = 19;

const TLS_NONE: u32 = 257;
const TLS_VNC: u32 = 258;
const X509_NONE: u32 = 260;
const X509_VNC: u32 = 261;
const X509_PLAIN: u32 = 262;
const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_FAILURE_BYTES: u32 = 4096;

const RFB_VERSION: &[u8; 12] = b"RFB 003.008\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VencryptAuth {
    None,
    Vnc,
    Plain,
}

impl VencryptAuth {
    fn security_type(self) -> u8 {
        match self {
            Self::None => SEC_NONE,
            Self::Vnc => SEC_VNC_AUTH,
            Self::Plain => SEC_NONE,
        }
    }
}

/// Human-readable name of an RFB security type, for error messages.
pub fn security_type_name(t: u8) -> String {
    match t {
        SEC_NONE => "None".into(),
        SEC_VNC_AUTH => "VncAuth".into(),
        5 => "RA2".into(),
        6 => "RA2ne".into(),
        16 => "Tight".into(),
        18 => "TLS".into(),
        VENCRYPT_SECURITY_TYPE => "VeNCrypt".into(),
        30 => "ARD".into(),
        other => format!("type {other}"),
    }
}

/// Do the RFB version exchange and return the server's security type list.
pub async fn read_security_types(stream: &mut TcpStream) -> Result<Vec<u8>, SessionError> {
    let mut version = [0u8; 12];
    stream.read_exact(&mut version).await?;
    if !version.starts_with(b"RFB ") {
        return Err(SessionError::msg("not an RFB server"));
    }
    stream.write_all(RFB_VERSION).await?;

    let count = stream.read_u8().await?;
    if count == 0 {
        let reason_len = stream.read_u32().await.unwrap_or(0);
        let mut reason = vec![0u8; reason_len.min(4096) as usize];
        let _ = stream.read_exact(&mut reason).await;
        return Err(SessionError::msg(
            String::from_utf8_lossy(&reason).into_owned(),
        ));
    }
    let mut types = vec![0u8; count as usize];
    stream.read_exact(&mut types).await?;
    Ok(types)
}

enum Transport {
    Plain(TcpStream),
    Verified(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Anonymous(Box<tokio_openssl::SslStream<TcpStream>>),
    UnverifiedCert(Box<tokio_openssl::SslStream<TcpStream>>),
}

/// Stream handed to `vnc-rs`.
///
/// The connector insists on running the version exchange and reading the
/// security list itself, but by the time we know which transport to use we
/// have already done that on the raw socket. So this replays a greeting
/// matching the real negotiation and swallows the client's version reply
/// (plus its type choice when VeNCrypt or ARD already consumed that step).
pub struct RfbStream {
    inner: Transport,
    prefix: Vec<u8>,
    prefix_off: usize,
    swallow_write: usize,
    /// A write left bytes in the TLS BIO that still owe a flush to the socket.
    flush_pending: bool,
}

impl RfbStream {
    /// No encryption: replay the server's real list; the client's choice
    /// byte is forwarded to the server, which is still waiting for it.
    pub fn plain(stream: TcpStream, types: &[u8]) -> Self {
        Self {
            inner: Transport::Plain(stream),
            prefix: greeting(types),
            prefix_off: 0,
            swallow_write: RFB_VERSION.len(),
            flush_pending: false,
        }
    }

    /// ARD has already checked the real SecurityResult. Replay success only
    /// after that check: vnc-rs does not validate the result for None auth.
    pub(crate) fn authenticated(stream: TcpStream) -> Self {
        Self::authenticated_transport(Transport::Plain(stream))
    }

    fn authenticated_transport(inner: Transport) -> Self {
        let mut result = Self::negotiated(inner, VencryptAuth::None);
        result.prefix.extend_from_slice(&0u32.to_be_bytes());
        result
    }

    fn negotiated(inner: Transport, auth: VencryptAuth) -> Self {
        Self {
            inner,
            prefix: greeting(&[auth.security_type()]),
            prefix_off: 0,
            // Version reply + the type choice: the server already knows.
            swallow_write: RFB_VERSION.len() + 1,
            flush_pending: false,
        }
    }

    fn poll_inner_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Transport::Plain(s) => Pin::new(s).poll_flush(cx),
            Transport::Verified(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Transport::Anonymous(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Transport::UnverifiedCert(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
}

fn greeting(types: &[u8]) -> Vec<u8> {
    let mut g = RFB_VERSION.to_vec();
    g.push(types.len() as u8);
    g.extend_from_slice(types);
    g
}

impl AsyncRead for RfbStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_off < self.prefix.len() {
            let rest = &self.prefix[self.prefix_off..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.prefix_off += n;
            return Poll::Ready(Ok(()));
        }
        // Drain any write left unflushed. vnc-rs polls for frames every tick,
        // so this guarantees a queued input record reaches the socket even
        // though vnc-rs itself never flushes.
        if self.flush_pending && self.poll_inner_flush(cx).is_ready() {
            self.flush_pending = false;
        }
        match &mut self.inner {
            Transport::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Transport::Verified(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Transport::Anonymous(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Transport::UnverifiedCert(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RfbStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.swallow_write > 0 {
            let n = buf.len().min(self.swallow_write);
            self.swallow_write -= n;
            return Poll::Ready(Ok(n));
        }
        let n = match &mut self.inner {
            Transport::Plain(s) => std::task::ready!(Pin::new(s).poll_write(cx, buf)),
            Transport::Verified(s) => std::task::ready!(Pin::new(s.as_mut()).poll_write(cx, buf)),
            Transport::Anonymous(s) => std::task::ready!(Pin::new(s.as_mut()).poll_write(cx, buf)),
            Transport::UnverifiedCert(s) => {
                std::task::ready!(Pin::new(s.as_mut()).poll_write(cx, buf))
            }
        }?;
        // Push the bytes to the socket now. vnc-rs writes control messages
        // (key, pointer) without ever flushing, and a TLS stream buffers them
        // in its BIO otherwise — so the remote never sees the input. If the
        // flush cannot finish yet, the next poll_read completes it.
        self.flush_pending = self.poll_inner_flush(cx).is_pending();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Transport::Plain(s) => Pin::new(s).poll_flush(cx),
            Transport::Verified(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Transport::Anonymous(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Transport::UnverifiedCert(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Transport::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Transport::Verified(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Transport::Anonymous(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Transport::UnverifiedCert(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// vnc-rs requires `Sync` on the stream type although it never shares it
// across threads: the stream is moved into one task and driven from there.
// Every transport is `Send`; the wrapper's replay state is plain data.
unsafe impl Sync for RfbStream {}

/// Run the VeNCrypt sub-handshake on a socket whose security list offered
/// type 19, then bring up TLS. Returns a stream ready for `vnc-rs` to
/// perform None / VncAuth on, or after completing Plain authentication.
pub async fn handshake(
    mut stream: TcpStream,
    host: &str,
    username: Option<&str>,
    password: Option<&str>,
    unverified: bool,
) -> Result<RfbStream, SessionError> {
    stream.write_u8(VENCRYPT_SECURITY_TYPE).await?;

    let major = stream.read_u8().await?;
    let minor = stream.read_u8().await?;
    if major != 0 || minor < 2 {
        return Err(SessionError::msg(format!(
            "unsupported VeNCrypt version {major}.{minor}"
        )));
    }
    stream.write_all(&[0, 2]).await?;

    let version_ok = stream.read_u8().await?;
    if version_ok != 0 {
        return Err(SessionError::msg("server rejected VeNCrypt 0.2"));
    }

    let n = stream.read_u8().await?;
    if n == 0 {
        return Err(SessionError::msg("server offered no VeNCrypt subtypes"));
    }
    let mut subtypes = Vec::with_capacity(n as usize);
    for _ in 0..n {
        subtypes.push(stream.read_u32().await?);
    }

    let (chosen, auth, x509) = if unverified {
        validate_plain_credentials(username, password)?;
        if !subtypes.contains(&X509_PLAIN) {
            return Err(SessionError::msg("server does not offer X509Plain"));
        }
        (X509_PLAIN, VencryptAuth::Plain, true)
    } else {
        pick_subtype(&subtypes, username.is_some_and(|s| !s.is_empty())).ok_or_else(|| {
            if subtypes.contains(&X509_PLAIN) {
                SessionError::msg("X509Plain requires a username and password")
            } else {
                SessionError::msg(format!(
                    "no supported VeNCrypt subtype in {subtypes:?} (supported: X509Plain / TLSVnc / TLSNone / X509Vnc / X509None)"
                ))
            }
        })?
    };

    if auth == VencryptAuth::Plain {
        validate_plain_credentials(username, password)?;
    }

    stream.write_u32(chosen).await?;
    let accept = stream.read_u8().await?;
    if accept != 1 {
        return Err(SessionError::msg(
            "server rejected the chosen VeNCrypt subtype",
        ));
    }

    let mut transport = if x509 && !unverified {
        Transport::Verified(Box::new(verified_tls(stream, host).await?))
    } else if x509 {
        Transport::UnverifiedCert(Box::new(unverified_cert_tls(stream, host).await?))
    } else {
        Transport::Anonymous(Box::new(anonymous_tls(stream).await?))
    };
    if auth == VencryptAuth::Plain {
        plain_auth(&mut transport, username.unwrap(), password.unwrap()).await?;
        Ok(RfbStream::authenticated_transport(transport))
    } else {
        Ok(RfbStream::negotiated(transport, auth))
    }
}

/// With a username, prefer Plain. Otherwise keep VncAuth over None. Within
/// each authentication method, prefer an X509 subtype.
fn pick_subtype(available: &[u32], has_username: bool) -> Option<(u32, VencryptAuth, bool)> {
    if has_username && available.contains(&X509_PLAIN) {
        return Some((X509_PLAIN, VencryptAuth::Plain, true));
    }
    const PREF: [(u32, VencryptAuth, bool); 4] = [
        (X509_VNC, VencryptAuth::Vnc, true),
        (TLS_VNC, VencryptAuth::Vnc, false),
        (X509_NONE, VencryptAuth::None, true),
        (TLS_NONE, VencryptAuth::None, false),
    ];
    for (id, auth, x509) in PREF {
        if available.contains(&id) {
            return Some((id, auth, x509));
        }
    }
    None
}

fn validate_plain_credentials(
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), SessionError> {
    let (Some(username), Some(password)) = (username, password) else {
        return Err(SessionError::msg(
            "VeNCrypt Plain requires a username and password",
        ));
    };
    if username.is_empty() {
        return Err(SessionError::msg("VeNCrypt Plain requires a username"));
    }
    if password.is_empty() {
        return Err(SessionError::msg("VeNCrypt Plain requires a password"));
    }
    for (label, value) in [("username", username), ("password", password)] {
        if value.len() > MAX_CREDENTIAL_BYTES || value.contains('\0') {
            return Err(SessionError::msg(format!(
                "VeNCrypt Plain {label} must be at most {MAX_CREDENTIAL_BYTES} UTF-8 bytes and contain no NUL"
            )));
        }
        u32::try_from(value.len())
            .map_err(|_| SessionError::msg("VeNCrypt Plain credential is too long"))?;
    }
    Ok(())
}

async fn plain_auth(
    transport: &mut Transport,
    username: &str,
    password: &str,
) -> Result<(), SessionError> {
    match transport {
        Transport::Plain(s) => plain_auth_stream(s, username, password).await,
        Transport::Verified(s) => plain_auth_stream(s.as_mut(), username, password).await,
        Transport::Anonymous(s) => plain_auth_stream(s.as_mut(), username, password).await,
        Transport::UnverifiedCert(s) => plain_auth_stream(s.as_mut(), username, password).await,
    }
}

async fn plain_auth_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), SessionError> {
    stream.write_u32(username.len() as u32).await?;
    stream.write_u32(password.len() as u32).await?;
    stream.write_all(username.as_bytes()).await?;
    stream.write_all(password.as_bytes()).await?;
    stream.flush().await?;
    let result = stream.read_u32().await?;
    if result == 0 {
        return Ok(());
    }
    // RFB failures use status 1 followed by a length. x11vnc's Plain
    // failure instead sends the string length directly.
    let length = if result == 1 {
        stream.read_u32().await?
    } else {
        result
    };
    if length > MAX_FAILURE_BYTES {
        return Err(SessionError::msg("VeNCrypt Plain login was rejected"));
    }
    let mut reason = vec![0; length as usize];
    stream.read_exact(&mut reason).await?;
    Err(SessionError::msg(format!(
        "VeNCrypt Plain login was rejected: {}",
        String::from_utf8_lossy(&reason)
    )))
}

/// `X509*`: rustls, server certificate checked against the WebPKI roots.
async fn verified_tls(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SessionError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("vnc.local").expect("static name"));
    TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(|e| SessionError::Tls(e.to_string()))
}

/// `X509*` with explicit unverified TLS: encrypt without checking the server
/// certificate. This has the same server identity guarantee as anonymous TLS.
async fn unverified_cert_tls(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_openssl::SslStream<TcpStream>, SessionError> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_verify(SslVerifyMode::NONE);
    let mut ssl = Ssl::new(&builder.build())?;
    if host.parse::<std::net::IpAddr>().is_err() {
        ssl.set_hostname(host)?;
    }
    let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
    Pin::new(&mut tls)
        .connect()
        .await
        .map_err(|e| SessionError::Tls(format!("unverified TLS handshake failed: {e}")))?;
    Ok(tls)
}

/// `TLS*`: anonymous Diffie-Hellman through OpenSSL.
///
/// There is no certificate to verify, so this is encryption without
/// authentication — the same guarantee every other VNC viewer gives for
/// these subtypes. Anonymous suites only exist up to TLS 1.2 and OpenSSL
/// hides them above security level 0.
async fn anonymous_tls(
    stream: TcpStream,
) -> Result<tokio_openssl::SslStream<TcpStream>, SessionError> {
    let mut builder = SslContext::builder(SslMethod::tls_client())?;
    builder.set_security_level(0);
    builder.set_cipher_list("aNULL:!eNULL")?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_verify(SslVerifyMode::NONE);
    let ssl = Ssl::new(&builder.build())?;
    let mut tls = tokio_openssl::SslStream::new(ssl, stream)?;
    Pin::new(&mut tls)
        .connect()
        .await
        .map_err(|e| SessionError::Tls(format!("anonymous TLS handshake failed: {e}")))?;
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_x509_over_anonymous_tls() {
        let (id, auth, x509) = pick_subtype(&[TLS_VNC, X509_VNC], false).unwrap();
        assert_eq!((id, auth, x509), (X509_VNC, VencryptAuth::Vnc, true));
        let (id, auth, x509) = pick_subtype(&[TLS_NONE, TLS_VNC], false).unwrap();
        assert_eq!((id, auth, x509), (TLS_VNC, VencryptAuth::Vnc, false));
        assert!(pick_subtype(&[999], false).is_none());
        assert_eq!(
            pick_subtype(&[X509_PLAIN], true),
            Some((X509_PLAIN, VencryptAuth::Plain, true))
        );
        assert_eq!(pick_subtype(&[X509_PLAIN], false), None);
        assert_eq!(
            pick_subtype(&[TLS_NONE, X509_VNC], false),
            Some((X509_VNC, VencryptAuth::Vnc, true))
        );
    }

    #[tokio::test]
    async fn plain_auth_frames_credentials_and_checks_success() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            assert_eq!(server.read_u32().await.unwrap(), 5);
            assert_eq!(server.read_u32().await.unwrap(), 6);
            let mut bytes = [0u8; 11];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"alicesecret");
            server.write_u32(0).await.unwrap();
        });
        plain_auth_stream(&mut client, "alice", "secret")
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn plain_auth_rejects_standard_and_x11vnc_failures() {
        for x11vnc in [false, true] {
            let (mut client, mut server) = tokio::io::duplex(128);
            let peer = tokio::spawn(async move {
                let len = server.read_u32().await.unwrap() + server.read_u32().await.unwrap();
                let mut credentials = vec![0; len as usize];
                server.read_exact(&mut credentials).await.unwrap();
                if !x11vnc {
                    server.write_u32(1).await.unwrap();
                }
                server.write_u32(13).await.unwrap();
                server.write_all(b"unixpw failed").await.unwrap();
            });
            let error = plain_auth_stream(&mut client, "alice", "bad")
                .await
                .unwrap_err();
            assert!(error.to_string().contains("unixpw failed"));
            peer.await.unwrap();
        }
    }

    #[test]
    fn plain_credentials_are_bounded() {
        assert!(validate_plain_credentials(None, Some("secret")).is_err());
        assert!(validate_plain_credentials(Some("alice"), None).is_err());
        assert!(validate_plain_credentials(Some("alice"), Some("")).is_err());
        assert!(validate_plain_credentials(Some("alice\0bob"), Some("secret")).is_err());
        assert!(validate_plain_credentials(Some("alice"), Some(&"a".repeat(4097))).is_err());
    }

    #[test]
    fn greeting_replays_rfb_38_security_list() {
        assert_eq!(greeting(&[2]), b"RFB 003.008\n\x01\x02".to_vec());
        assert_eq!(
            greeting(&[1, 2, 19]),
            b"RFB 003.008\n\x03\x01\x02\x13".to_vec()
        );
    }

    #[test]
    fn anonymous_context_builds() {
        // The cipher string and protocol cap must be accepted by the linked
        // OpenSSL, or every TLSVnc connection would fail at runtime.
        let mut b = SslContext::builder(SslMethod::tls_client()).unwrap();
        b.set_security_level(0);
        b.set_cipher_list("aNULL:!eNULL").unwrap();
        b.set_max_proto_version(Some(SslVersion::TLS1_2)).unwrap();
        let ctx = b.build();
        assert!(Ssl::new(&ctx).is_ok());
    }
}
