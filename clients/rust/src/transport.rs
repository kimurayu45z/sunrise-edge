//! A small, deterministic transport trait plus this crate's two production
//! implementations: a strict, synchronous, loopback-only plaintext HTTP/1.1
//! transport, and a strict, synchronous TLS HTTP/1.1 transport for a remote
//! target. Both share one private bounded-stream abstraction, so the exact
//! same request/response framing, byte bounds, and deadline handling apply
//! to plaintext and TLS traffic alike.

use core::fmt;
use std::error::Error;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// HTTP method used by one bounded request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`, used by every bounded query route.
    Get,
    /// `POST`, used by the event-submission route.
    Post,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One bounded outbound HTTP request.
#[derive(Clone, Debug)]
pub struct WireRequest {
    /// HTTP method.
    pub method: Method,
    /// Exact request path, including any query-selector segment.
    pub path: String,
    /// `Content-Type` header value, sent only when present.
    pub content_type: Option<&'static str>,
    /// Request body. Empty for every `GET` call this client makes.
    pub body: Vec<u8>,
    /// Optional caller deadline for the complete exchange. Both transports
    /// combine it with their own configured total bound and use whichever
    /// expires first.
    pub deadline: Option<Instant>,
}

/// One bounded HTTP response.
#[derive(Clone, Debug)]
pub struct WireResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type` header value, if the response declared exactly one.
    pub content_type: Option<String>,
    /// Exact response body, bounded to the transport's configured maximum.
    pub body: Vec<u8>,
}

/// A deterministic transport for one bounded request/response exchange.
///
/// Implementations must not retry, cache, follow redirects, or perform any
/// work after returning. When [`WireRequest::deadline`] is present, an
/// implementation must stop the complete exchange by that monotonic deadline.
/// [`LoopbackHttpTransport`] and [`RemoteTlsHttpTransport`] are the only
/// production implementations this crate ships; tests supply a fake
/// implementing this same trait.
pub trait Transport {
    /// Sends one request and returns its complete, bounded response.
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError>;
}

/// Errors from either bounded HTTP/1.1 transport this crate ships.
#[derive(Debug)]
pub enum TransportError {
    /// The configured target address was not a loopback address.
    NonLoopbackAddress(SocketAddr),
    /// A configured timeout was zero.
    ZeroTimeout,
    /// The configured DNS server name for SNI/hostname validation was empty,
    /// not a syntactically valid DNS name, or an IP-address literal; this
    /// transport never falls back to using the target IP address as the
    /// hostname.
    InvalidServerName,
    /// The configured CA trust-anchor DER was empty.
    EmptyCaCertificate,
    /// The configured CA trust-anchor DER exceeded the configured maximum.
    CaCertificateTooLarge {
        /// Configured maximum trust-anchor DER length, in bytes.
        maximum: usize,
    },
    /// The configured CA trust-anchor DER was not a valid X.509 certificate
    /// usable as a trust anchor.
    InvalidCaCertificate(rustls::Error),
    /// Constructing the TLS client session failed.
    TlsSessionSetup(rustls::Error),
    /// The TLS protocol layer rejected a handshake or application-data
    /// record.
    TlsProtocol(rustls::Error),
    /// The connection closed before the TLS handshake completed.
    TlsHandshakeClosed,
    /// The request target was not one absolute, visible-ASCII path and could
    /// therefore alter the HTTP request framing.
    InvalidRequestPath,
    /// The request content type contained bytes unsafe for one HTTP header
    /// value.
    InvalidRequestContentType,
    /// The configured per-stage timeouts could not form one total request
    /// budget on the monotonic clock.
    RequestDeadlineOverflow,
    /// The complete request exceeded its transport or caller deadline.
    RequestDeadlineExceeded,
    /// Opening the bounded `TcpStream` failed.
    Connect(std::io::Error),
    /// Configuring a socket timeout failed.
    SetTimeout(std::io::Error),
    /// Writing the request failed.
    Write(std::io::Error),
    /// Reading the response failed.
    Read(std::io::Error),
    /// The response headers exceeded the configured bound before a
    /// terminating blank line was observed.
    ResponseHeaderTooLarge {
        /// Configured maximum header byte length.
        maximum: usize,
    },
    /// The connection closed before the response headers were complete.
    TruncatedResponseHeaders,
    /// The response headers were not valid UTF-8.
    MalformedHeaders,
    /// The status line was not `"<version> <code> <reason>"`.
    MalformedStatusLine,
    /// The status line declared an HTTP version other than `HTTP/1.1`.
    UnsupportedHttpVersion,
    /// The status line's status code was not a valid integer.
    InvalidStatusCode,
    /// A header line was not `"Name: value"`.
    MalformedHeaderLine,
    /// The response had no `Content-Length` header.
    MissingContentLength,
    /// The response had more than one `Content-Length` header.
    DuplicateContentLength,
    /// The response's `Content-Length` value was not a valid integer.
    InvalidContentLength,
    /// The response declared `Transfer-Encoding`, which this transport
    /// never accepts.
    TransferEncodingUnsupported,
    /// The response had more than one `Content-Type` header.
    DuplicateContentType,
    /// The declared `Content-Length` exceeded the configured maximum body
    /// bound.
    ResponseBodyTooLarge {
        /// Declared body length in bytes.
        declared: usize,
        /// Configured maximum body length in bytes.
        maximum: usize,
    },
    /// The connection closed before the declared body was fully received.
    TruncatedResponseBody {
        /// Declared body length in bytes.
        expected: usize,
        /// Body bytes actually received before the connection closed.
        received: usize,
    },
    /// The server sent bytes beyond its own declared `Content-Length`.
    TrailingResponseBytes,
    /// The server did not close the `Connection: close` response after the
    /// exact declared body within the configured read timeout.
    ResponseDidNotClose,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackAddress(addr) => {
                write!(f, "transport target {addr} is not a loopback address")
            }
            Self::ZeroTimeout => f.write_str("configured timeout must not be zero"),
            Self::InvalidServerName => {
                f.write_str("configured DNS server name is not a valid, non-IP DNS name")
            }
            Self::EmptyCaCertificate => f.write_str("configured CA trust-anchor DER was empty"),
            Self::CaCertificateTooLarge { maximum } => {
                write!(f, "configured CA trust-anchor DER exceeded {maximum} bytes")
            }
            Self::InvalidCaCertificate(error) => {
                write!(f, "configured CA trust-anchor DER was invalid: {error}")
            }
            Self::TlsSessionSetup(error) => write!(f, "failed to start TLS session: {error}"),
            Self::TlsProtocol(error) => write!(f, "TLS protocol error: {error}"),
            Self::TlsHandshakeClosed => {
                f.write_str("connection closed before the TLS handshake completed")
            }
            Self::InvalidRequestPath => f.write_str("request path is not safe visible ASCII"),
            Self::InvalidRequestContentType => {
                f.write_str("request content type is not a safe HTTP header value")
            }
            Self::RequestDeadlineOverflow => {
                f.write_str("configured request timeouts overflow the monotonic clock")
            }
            Self::RequestDeadlineExceeded => f.write_str("request deadline exceeded"),
            Self::Connect(error) => write!(f, "failed to connect: {error}"),
            Self::SetTimeout(error) => write!(f, "failed to configure socket timeout: {error}"),
            Self::Write(error) => write!(f, "failed to write request: {error}"),
            Self::Read(error) => write!(f, "failed to read response: {error}"),
            Self::ResponseHeaderTooLarge { maximum } => {
                write!(f, "response headers exceeded {maximum} bytes")
            }
            Self::TruncatedResponseHeaders => {
                f.write_str("connection closed before response headers were complete")
            }
            Self::MalformedHeaders => f.write_str("response headers were not valid UTF-8"),
            Self::MalformedStatusLine => f.write_str("malformed HTTP status line"),
            Self::UnsupportedHttpVersion => {
                f.write_str("response declared an HTTP version other than HTTP/1.1")
            }
            Self::InvalidStatusCode => f.write_str("response status code was not a valid integer"),
            Self::MalformedHeaderLine => f.write_str("malformed response header line"),
            Self::MissingContentLength => f.write_str("response had no Content-Length header"),
            Self::DuplicateContentLength => {
                f.write_str("response had more than one Content-Length header")
            }
            Self::InvalidContentLength => {
                f.write_str("response Content-Length was not a valid integer")
            }
            Self::TransferEncodingUnsupported => {
                f.write_str("response declared Transfer-Encoding, which is unsupported")
            }
            Self::DuplicateContentType => {
                f.write_str("response had more than one Content-Type header")
            }
            Self::ResponseBodyTooLarge { declared, maximum } => write!(
                f,
                "response declared a {declared}-byte body, maximum is {maximum}"
            ),
            Self::TruncatedResponseBody { expected, received } => write!(
                f,
                "connection closed after {received} of {expected} declared body bytes"
            ),
            Self::TrailingResponseBytes => {
                f.write_str("response carried bytes beyond its declared Content-Length")
            }
            Self::ResponseDidNotClose => {
                f.write_str("Connection: close response did not close within the read timeout")
            }
        }
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect(error)
            | Self::SetTimeout(error)
            | Self::Write(error)
            | Self::Read(error) => Some(error),
            Self::InvalidCaCertificate(error)
            | Self::TlsSessionSetup(error)
            | Self::TlsProtocol(error) => Some(error),
            _ => None,
        }
    }
}

/// A private bounded, deadline-checked byte stream: one blocking read and
/// one blocking write primitive, each re-armed with the remaining slice of
/// an overall monotonic deadline before every underlying I/O call. Both
/// [`LoopbackHttpTransport`] and [`RemoteTlsHttpTransport`] drive the exact
/// same HTTP/1.1 request/response framing (see [`write_all_until`],
/// [`flush_until`], and [`read_response`]) over whichever implementation
/// they hold, so plaintext and TLS traffic are parsed identically.
trait BoundedTransportIo {
    fn write_once(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<usize, TransportError>;

    fn flush_io(
        &mut self,
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<(), TransportError>;

    fn read_once(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<usize, TransportError>;
}

impl BoundedTransportIo for TcpStream {
    fn write_once(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<usize, TransportError> {
        self.set_write_timeout(Some(remaining_timeout(deadline, write_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        Write::write(self, buffer).map_err(|error| {
            if is_timeout(&error) && Instant::now() >= deadline {
                TransportError::RequestDeadlineExceeded
            } else {
                TransportError::Write(error)
            }
        })
    }

    fn flush_io(
        &mut self,
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        self.set_write_timeout(Some(remaining_timeout(deadline, write_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        Write::flush(self).map_err(|error| {
            if is_timeout(&error) && Instant::now() >= deadline {
                TransportError::RequestDeadlineExceeded
            } else {
                TransportError::Write(error)
            }
        })
    }

    fn read_once(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<usize, TransportError> {
        self.set_read_timeout(Some(remaining_timeout(deadline, read_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        Read::read(self, buffer).map_err(|error| {
            if is_timeout(&error) && Instant::now() >= deadline {
                TransportError::RequestDeadlineExceeded
            } else {
                TransportError::Read(error)
            }
        })
    }
}

/// Strict, synchronous, loopback-only plaintext HTTP/1.1 transport.
///
/// Opens exactly one bounded [`TcpStream`] per request, sends
/// `Connection: close`, and enforces connect/read/write timeouts plus
/// header/body byte bounds. It requires an exact `Content-Length` on the
/// response and rejects `Transfer-Encoding`, a missing/duplicate/invalid
/// `Content-Length`, a truncated or trailing body, and any non-loopback
/// target. It performs no TLS handshake, never follows a redirect, never
/// uses a proxy, never reuses a connection across requests, and does no
/// work after returning: there is no background thread, retry, or async
/// runtime anywhere in this type. These are deliberate limits, not gaps —
/// remote transport is [`RemoteTlsHttpTransport`] (see `ARCHITECTURE.md`
/// §44 / DR-0083, DR-0085).
///
/// The hard complete-request budget is
/// `connect_timeout + write_timeout + read_timeout`. A
/// [`WireRequest::deadline`] may tighten that budget but never extend it;
/// expiry at any connect/write/read/close stage returns
/// [`TransportError::RequestDeadlineExceeded`].
#[derive(Clone, Debug)]
pub struct LoopbackHttpTransport {
    addr: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_response_header_bytes: usize,
    max_response_body_bytes: usize,
}

impl LoopbackHttpTransport {
    /// Creates a bounded transport targeting `addr`.
    ///
    /// Rejects a non-loopback address or a zero timeout before opening any
    /// connection. The three timeouts also form a hard total budget by checked
    /// addition; an optional per-request deadline can only shorten that total.
    pub fn new(
        addr: SocketAddr,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        max_response_header_bytes: NonZeroUsize,
        max_response_body_bytes: NonZeroUsize,
    ) -> Result<Self, TransportError> {
        if !addr.ip().is_loopback() {
            return Err(TransportError::NonLoopbackAddress(addr));
        }
        if connect_timeout.is_zero() || read_timeout.is_zero() || write_timeout.is_zero() {
            return Err(TransportError::ZeroTimeout);
        }
        Ok(Self {
            addr,
            connect_timeout,
            read_timeout,
            write_timeout,
            max_response_header_bytes: max_response_header_bytes.get(),
            max_response_body_bytes: max_response_body_bytes.get(),
        })
    }

    /// Returns the configured loopback target address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Transport for LoopbackHttpTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        validate_request(request)?;
        let transport_budget = self
            .connect_timeout
            .checked_add(self.write_timeout)
            .and_then(|value| value.checked_add(self.read_timeout))
            .ok_or(TransportError::RequestDeadlineOverflow)?;
        let deadline = combined_deadline(request.deadline, transport_budget)?;
        let connect_timeout = remaining_timeout(deadline, self.connect_timeout)?;
        let mut stream =
            TcpStream::connect_timeout(&self.addr, connect_timeout).map_err(|error| {
                if is_timeout(&error) && Instant::now() >= deadline {
                    TransportError::RequestDeadlineExceeded
                } else {
                    TransportError::Connect(error)
                }
            })?;

        let host = self.addr.to_string();
        send_request(
            &mut stream,
            request,
            &host,
            deadline,
            self.write_timeout,
            self.read_timeout,
            self.max_response_header_bytes,
            self.max_response_body_bytes,
        )
    }
}

/// Maximum accepted CA trust-anchor DER length, in bytes. Ordinary X.509
/// certificates, including RSA-4096 ones, are well under this bound; it
/// exists only to keep the constructor's DER parse bounded before any
/// network I/O.
///
/// This is `pub` so callers that read a CA certificate from a file (such as
/// `apps/cli`) can cap the read at the exact same bound this constructor
/// enforces, instead of maintaining a second, possibly-drifting constant.
pub const MAX_CA_CERTIFICATE_DER_BYTES: usize = 16 * 1024;

/// Strict, synchronous TLS HTTP/1.1 transport for one remote target.
///
/// Opens exactly one bounded [`TcpStream`] per request, drives a TLS 1.2/1.3
/// handshake against one explicitly configured CA trust anchor and one
/// explicitly configured DNS server name (used for both SNI and hostname
/// validation), sends `Connection: close`, and parses the response with the
/// identical strict framing [`LoopbackHttpTransport`] uses. It never
/// resolves DNS itself (the caller supplies an already-resolved
/// [`SocketAddr`]), never falls back to validating the connection's IP
/// address as a hostname, never trusts system root certificates or an
/// insecure/no-op verifier, and never follows a redirect, retries, uses a
/// proxy, reuses a connection across requests, or does any work after
/// returning: there is no background thread or async runtime anywhere in
/// this type (see `ARCHITECTURE.md` §44 / DR-0083, DR-0085).
///
/// The hard complete-request budget is
/// `connect_timeout + handshake_read_timeout + handshake_write_timeout +
/// write_timeout + read_timeout`. A [`WireRequest::deadline`] may tighten
/// that budget but never extend it; expiry at any stage returns
/// [`TransportError::RequestDeadlineExceeded`]. The handshake itself is
/// driven by individually deadline-checked `read_tls`/`write_tls`/
/// `process_new_packets` steps, never by `rustls`'s unbounded
/// `complete_io`.
#[derive(Clone)]
pub struct RemoteTlsHttpTransport {
    addr: SocketAddr,
    server_name: ServerName<'static>,
    /// The validated DNS name plus the configured port, `"<dns-name>:<port>"`.
    /// This is the exact `Host` header value this transport sends; it is
    /// computed once, from the same validated DNS name `server_name` holds,
    /// so `send` never needs to re-derive or assume a particular
    /// [`ServerName`] variant.
    authority: String,
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    handshake_read_timeout: Duration,
    handshake_write_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_response_header_bytes: usize,
    max_response_body_bytes: usize,
}

impl fmt::Debug for RemoteTlsHttpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTlsHttpTransport")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("authority", &self.authority)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_read_timeout", &self.handshake_read_timeout)
            .field("handshake_write_timeout", &self.handshake_write_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("max_response_header_bytes", &self.max_response_header_bytes)
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish_non_exhaustive()
    }
}

impl RemoteTlsHttpTransport {
    /// Creates a bounded TLS transport targeting `addr`.
    ///
    /// `dns_name` is validated as a syntactically valid, non-empty DNS name
    /// — never an IP-address literal — and is used for both the TLS SNI
    /// extension and post-handshake hostname validation; this transport
    /// performs no DNS resolution of its own. `ca_der` must be exactly one
    /// non-empty, DER-encoded X.509 certificate no larger than
    /// [`MAX_CA_CERTIFICATE_DER_BYTES`] and is the transport's sole trust
    /// anchor: no system root store is ever consulted. Every timeout must be
    /// nonzero. All of this is validated before any connection is opened.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: SocketAddr,
        dns_name: &str,
        ca_der: &[u8],
        connect_timeout: Duration,
        handshake_read_timeout: Duration,
        handshake_write_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
        max_response_header_bytes: NonZeroUsize,
        max_response_body_bytes: NonZeroUsize,
    ) -> Result<Self, TransportError> {
        if connect_timeout.is_zero()
            || handshake_read_timeout.is_zero()
            || handshake_write_timeout.is_zero()
            || read_timeout.is_zero()
            || write_timeout.is_zero()
        {
            return Err(TransportError::ZeroTimeout);
        }
        if ca_der.is_empty() {
            return Err(TransportError::EmptyCaCertificate);
        }
        if ca_der.len() > MAX_CA_CERTIFICATE_DER_BYTES {
            return Err(TransportError::CaCertificateTooLarge {
                maximum: MAX_CA_CERTIFICATE_DER_BYTES,
            });
        }
        let server_name = ServerName::try_from(dns_name.to_string())
            .map_err(|_| TransportError::InvalidServerName)?;
        if !matches!(server_name, ServerName::DnsName(_)) {
            return Err(TransportError::InvalidServerName);
        }
        // The HTTP authority is built from the same validated `dns_name` the
        // TLS layer uses for SNI/hostname verification, plus the configured
        // port — always included, even for port 443 — never from `addr`'s
        // (possibly non-hostname) IP.
        let authority = format!("{dns_name}:{}", addr.port());

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .map_err(TransportError::InvalidCaCertificate)?;
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            addr,
            server_name,
            authority,
            tls_config: Arc::new(tls_config),
            connect_timeout,
            handshake_read_timeout,
            handshake_write_timeout,
            read_timeout,
            write_timeout,
            max_response_header_bytes: max_response_header_bytes.get(),
            max_response_body_bytes: max_response_body_bytes.get(),
        })
    }

    /// Returns the configured target address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Transport for RemoteTlsHttpTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        validate_request(request)?;
        let transport_budget = self
            .connect_timeout
            .checked_add(self.handshake_read_timeout)
            .and_then(|value| value.checked_add(self.handshake_write_timeout))
            .and_then(|value| value.checked_add(self.write_timeout))
            .and_then(|value| value.checked_add(self.read_timeout))
            .ok_or(TransportError::RequestDeadlineOverflow)?;
        let deadline = combined_deadline(request.deadline, transport_budget)?;

        let connect_timeout = remaining_timeout(deadline, self.connect_timeout)?;
        let tcp = TcpStream::connect_timeout(&self.addr, connect_timeout).map_err(|error| {
            if is_timeout(&error) && Instant::now() >= deadline {
                TransportError::RequestDeadlineExceeded
            } else {
                TransportError::Connect(error)
            }
        })?;

        let conn = ClientConnection::new(Arc::clone(&self.tls_config), self.server_name.clone())
            .map_err(TransportError::TlsSessionSetup)?;
        let mut stream = TlsBoundedStream { conn, sock: tcp };
        stream.handshake(
            deadline,
            self.handshake_read_timeout,
            self.handshake_write_timeout,
        )?;

        send_request(
            &mut stream,
            request,
            &self.authority,
            deadline,
            self.write_timeout,
            self.read_timeout,
            self.max_response_header_bytes,
            self.max_response_body_bytes,
        )
    }
}

/// A TCP socket paired with its `rustls` client session, implementing
/// [`BoundedTransportIo`] by manually pumping `read_tls`/`write_tls`/
/// `process_new_packets` under the caller's deadline for every operation,
/// both during and after the handshake.
struct TlsBoundedStream {
    conn: ClientConnection,
    sock: TcpStream,
}

impl TlsBoundedStream {
    /// Drives the TLS handshake to completion using individually
    /// deadline-checked `read_tls`/`write_tls`/`process_new_packets` steps.
    /// Never calls `rustls`'s unbounded `complete_io`.
    fn handshake(
        &mut self,
        deadline: Instant,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        while self.conn.is_handshaking() {
            if self.conn.wants_write() {
                self.pump_write_once(deadline, write_timeout)?;
                continue;
            }
            if self.conn.wants_read() {
                self.pump_handshake_read_once(deadline, read_timeout)?;
                continue;
            }
            return Err(TransportError::TlsHandshakeClosed);
        }
        Ok(())
    }

    fn pump_write_once(
        &mut self,
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        self.sock
            .set_write_timeout(Some(remaining_timeout(deadline, write_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        match self.conn.write_tls(&mut self.sock) {
            Ok(0) => Err(TransportError::Write(io::Error::new(
                ErrorKind::WriteZero,
                "TLS write_tls returned zero bytes",
            ))),
            Ok(_) => Ok(()),
            Err(error) if is_timeout(&error) && Instant::now() >= deadline => {
                Err(TransportError::RequestDeadlineExceeded)
            }
            Err(error) => Err(TransportError::Write(error)),
        }
    }

    /// Performs one deadline-checked `read_tls` call and returns the number
    /// of raw bytes read (`0` means the peer closed the raw TCP connection).
    fn raw_read_tls(
        &mut self,
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<usize, TransportError> {
        self.sock
            .set_read_timeout(Some(remaining_timeout(deadline, read_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        match self.conn.read_tls(&mut self.sock) {
            Ok(read) => Ok(read),
            Err(error) if is_timeout(&error) && Instant::now() >= deadline => {
                Err(TransportError::RequestDeadlineExceeded)
            }
            Err(error) => Err(TransportError::Read(error)),
        }
    }

    /// One deadline-checked handshake read step. Unlike
    /// [`Self::pump_read_once`], a raw TCP EOF here (the peer closed the
    /// connection before the handshake finished) fails immediately with
    /// [`TransportError::TlsHandshakeClosed`] rather than calling
    /// `process_new_packets` and looping: once the socket has reached EOF,
    /// every further `read_tls` call also returns `Ok(0)` without blocking,
    /// so — because a handshake never has already-authenticated plaintext
    /// to drain — retrying would busy-spin until the deadline instead of
    /// failing promptly.
    fn pump_handshake_read_once(
        &mut self,
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<(), TransportError> {
        if self.raw_read_tls(deadline, read_timeout)? == 0 {
            return Err(TransportError::TlsHandshakeClosed);
        }
        self.conn
            .process_new_packets()
            .map(|_| ())
            .map_err(TransportError::TlsProtocol)
    }

    /// One deadline-checked application-data read step, used only after the
    /// handshake has completed. A raw TCP EOF here still reaches
    /// `process_new_packets` (recording it), so [`BoundedTransportIo::read_once`]
    /// can first drain any already-authenticated plaintext and only then
    /// treat the closed connection like a TCP EOF — never busy-spinning,
    /// since the very next `reader().read()` call deterministically returns
    /// either that buffered plaintext or a terminal `UnexpectedEof`.
    fn pump_read_once(
        &mut self,
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<(), TransportError> {
        self.raw_read_tls(deadline, read_timeout)?;
        self.conn
            .process_new_packets()
            .map(|_| ())
            .map_err(TransportError::TlsProtocol)
    }
}

impl BoundedTransportIo for TlsBoundedStream {
    fn write_once(
        &mut self,
        buffer: &[u8],
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<usize, TransportError> {
        let written = self
            .conn
            .writer()
            .write(buffer)
            .map_err(TransportError::Write)?;
        while self.conn.wants_write() {
            self.pump_write_once(deadline, write_timeout)?;
        }
        Ok(written)
    }

    fn flush_io(
        &mut self,
        deadline: Instant,
        write_timeout: Duration,
    ) -> Result<(), TransportError> {
        while self.conn.wants_write() {
            self.pump_write_once(deadline, write_timeout)?;
        }
        Ok(())
    }

    fn read_once(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        read_timeout: Duration,
    ) -> Result<usize, TransportError> {
        loop {
            match self.conn.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.pump_read_once(deadline, read_timeout)?;
                }
                // A peer that closes the raw TCP connection without sending a
                // TLS `close_notify` surfaces here as `UnexpectedEof`. This
                // transport treats it exactly like a plain TCP EOF (`Ok(0)`):
                // the strict `Content-Length` framing shared with
                // `LoopbackHttpTransport` already detects any truncation this
                // would otherwise catch, so both transports must react to a
                // closed connection identically.
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(0),
                Err(error) => return Err(TransportError::Read(error)),
            }
        }
    }
}

fn validate_request(request: &WireRequest) -> Result<(), TransportError> {
    if !is_safe_request_path(&request.path) {
        return Err(TransportError::InvalidRequestPath);
    }
    if request
        .content_type
        .is_some_and(|value| !is_safe_header_value(value))
    {
        return Err(TransportError::InvalidRequestContentType);
    }
    Ok(())
}

fn combined_deadline(
    caller_deadline: Option<Instant>,
    transport_budget: Duration,
) -> Result<Instant, TransportError> {
    let transport_deadline = Instant::now()
        .checked_add(transport_budget)
        .ok_or(TransportError::RequestDeadlineOverflow)?;
    Ok(caller_deadline.map_or(transport_deadline, |value| value.min(transport_deadline)))
}

#[allow(clippy::too_many_arguments)]
fn send_request<S: BoundedTransportIo>(
    stream: &mut S,
    request: &WireRequest,
    host: &str,
    deadline: Instant,
    write_timeout: Duration,
    read_timeout: Duration,
    max_response_header_bytes: usize,
    max_response_body_bytes: usize,
) -> Result<WireResponse, TransportError> {
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        request.method.as_str(),
        request.path,
        host,
    );
    if let Some(content_type) = request.content_type {
        head.push_str("Content-Type: ");
        head.push_str(content_type);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", request.body.len()));

    write_all_until(stream, head.as_bytes(), deadline, write_timeout)?;
    if !request.body.is_empty() {
        write_all_until(stream, &request.body, deadline, write_timeout)?;
    }
    flush_until(stream, deadline, write_timeout)?;

    read_response(
        stream,
        max_response_header_bytes,
        max_response_body_bytes,
        deadline,
        read_timeout,
    )
}

fn read_response<S: BoundedTransportIo>(
    stream: &mut S,
    max_header_bytes: usize,
    max_body_bytes: usize,
    deadline: Instant,
    read_timeout: Duration,
) -> Result<WireResponse, TransportError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(position) = find_header_terminator(&buffer) {
            if position + 4 > max_header_bytes {
                return Err(TransportError::ResponseHeaderTooLarge {
                    maximum: max_header_bytes,
                });
            }
            break position;
        }
        if buffer.len() >= max_header_bytes {
            return Err(TransportError::ResponseHeaderTooLarge {
                maximum: max_header_bytes,
            });
        }
        let read = read_until(stream, &mut chunk, deadline, read_timeout)?;
        if read == 0 {
            return Err(TransportError::TruncatedResponseHeaders);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let header_text =
        std::str::from_utf8(&buffer[..header_end]).map_err(|_| TransportError::MalformedHeaders)?;
    let mut already_read_body = buffer[header_end + 4..].to_vec();

    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(TransportError::MalformedStatusLine)?;
    let status = parse_status_line(status_line)?;

    let mut content_length: Option<usize> = None;
    let mut content_type: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::MalformedHeaderLine)?;
        if !is_http_token(name) {
            return Err(TransportError::MalformedHeaderLine);
        }
        let value = value.trim_matches([' ', '\t']);
        if !is_safe_header_value(value) {
            return Err(TransportError::MalformedHeaderLine);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(TransportError::DuplicateContentLength);
            }
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TransportError::InvalidContentLength);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| TransportError::InvalidContentLength)?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(TransportError::TransferEncodingUnsupported);
        } else if name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(TransportError::DuplicateContentType);
            }
            content_type = Some(value.to_string());
        }
    }

    let content_length = content_length.ok_or(TransportError::MissingContentLength)?;
    if content_length > max_body_bytes {
        return Err(TransportError::ResponseBodyTooLarge {
            declared: content_length,
            maximum: max_body_bytes,
        });
    }

    if already_read_body.len() > content_length {
        return Err(TransportError::TrailingResponseBytes);
    }
    while already_read_body.len() < content_length {
        let read = read_until(stream, &mut chunk, deadline, read_timeout)?;
        if read == 0 {
            return Err(TransportError::TruncatedResponseBody {
                expected: content_length,
                received: already_read_body.len(),
            });
        }
        let remaining = content_length - already_read_body.len();
        let take = read.min(remaining);
        already_read_body.extend_from_slice(&chunk[..take]);
        if take < read {
            return Err(TransportError::TrailingResponseBytes);
        }
    }

    // Bounded trailing-byte probe: `Content-Length` declared the exact body
    // size, so any further byte before the peer closes is a protocol
    // violation. A timeout here (the peer simply has not closed yet) is not
    // itself evidence of trailing bytes.
    match stream.read_once(&mut chunk, deadline, read_timeout) {
        Ok(0) => {}
        Ok(_) => return Err(TransportError::TrailingResponseBytes),
        Err(TransportError::RequestDeadlineExceeded) => {
            return Err(TransportError::RequestDeadlineExceeded);
        }
        Err(TransportError::Read(error)) if is_timeout(&error) => {
            return Err(TransportError::ResponseDidNotClose);
        }
        Err(error) => return Err(error),
    }

    Ok(WireResponse {
        status,
        content_type,
        body: already_read_body,
    })
}

fn remaining_timeout(
    deadline: Instant,
    per_operation: Duration,
) -> Result<Duration, TransportError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(TransportError::RequestDeadlineExceeded)?;
    if remaining.is_zero() {
        return Err(TransportError::RequestDeadlineExceeded);
    }
    Ok(remaining.min(per_operation))
}

fn write_all_until<S: BoundedTransportIo>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
    write_timeout: Duration,
) -> Result<(), TransportError> {
    while !bytes.is_empty() {
        let written = stream.write_once(bytes, deadline, write_timeout)?;
        if written == 0 {
            return Err(TransportError::Write(std::io::Error::new(
                ErrorKind::WriteZero,
                "failed to write the complete request",
            )));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

fn flush_until<S: BoundedTransportIo>(
    stream: &mut S,
    deadline: Instant,
    write_timeout: Duration,
) -> Result<(), TransportError> {
    stream.flush_io(deadline, write_timeout)
}

fn read_until<S: BoundedTransportIo>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
    read_timeout: Duration,
) -> Result<usize, TransportError> {
    stream.read_once(buffer, deadline, read_timeout)
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_status_line(line: &str) -> Result<u16, TransportError> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(TransportError::MalformedStatusLine)?;
    if version != "HTTP/1.1" {
        return Err(TransportError::UnsupportedHttpVersion);
    }
    let code = parts.next().ok_or(TransportError::MalformedStatusLine)?;
    let reason = parts.next().ok_or(TransportError::MalformedStatusLine)?;
    if !is_safe_header_value(reason)
        || code.len() != 3
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TransportError::InvalidStatusCode);
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| TransportError::InvalidStatusCode)?;
    if !(100..=599).contains(&status) {
        return Err(TransportError::InvalidStatusCode);
    }
    Ok(status)
}

fn is_safe_request_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('#')
        && path.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

fn is_safe_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || matches!(byte, 0x20..=0x7e))
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn rejects_a_non_loopback_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80);
        let result = LoopbackHttpTransport::new(
            addr,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        );
        assert!(matches!(
            result,
            Err(TransportError::NonLoopbackAddress(a)) if a == addr
        ));
    }

    #[test]
    fn rejects_a_zero_timeout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let result = LoopbackHttpTransport::new(
            addr,
            Duration::ZERO,
            Duration::from_millis(100),
            Duration::from_millis(100),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        );
        assert!(matches!(result, Err(TransportError::ZeroTimeout)));
    }

    #[test]
    fn accepts_ipv6_loopback() {
        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 12345);
        let result = LoopbackHttpTransport::new(
            addr,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_request_framing_injection_before_connecting() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let transport = LoopbackHttpTransport::new(
            addr,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        )
        .unwrap();
        let invalid_path = WireRequest {
            method: Method::Get,
            path: "/v1/context\r\nX-Injected: yes".to_string(),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        };
        assert!(matches!(
            transport.send(&invalid_path),
            Err(TransportError::InvalidRequestPath)
        ));

        let invalid_content_type = WireRequest {
            method: Method::Post,
            path: "/v1/events".to_string(),
            content_type: Some("application/test\r\nX-Injected: yes"),
            body: Vec::new(),
            deadline: None,
        };
        assert!(matches!(
            transport.send(&invalid_content_type),
            Err(TransportError::InvalidRequestContentType)
        ));
    }

    fn remote_tls_transport_args(
        addr: SocketAddr,
    ) -> (
        SocketAddr,
        &'static str,
        Vec<u8>,
        Duration,
        Duration,
        Duration,
        Duration,
        Duration,
        NonZeroUsize,
        NonZeroUsize,
    ) {
        (
            addr,
            "example.invalid",
            vec![0_u8; 4],
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_millis(100),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        )
    }

    #[test]
    fn remote_tls_rejects_a_zero_timeout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            dns_name,
            ca_der,
            _connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let result = RemoteTlsHttpTransport::new(
            addr,
            dns_name,
            &ca_der,
            Duration::ZERO,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(result, Err(TransportError::ZeroTimeout)));
    }

    #[test]
    fn remote_tls_rejects_an_empty_ca_certificate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            dns_name,
            _ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let result = RemoteTlsHttpTransport::new(
            addr,
            dns_name,
            &[],
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(result, Err(TransportError::EmptyCaCertificate)));
    }

    #[test]
    fn remote_tls_rejects_an_oversized_ca_certificate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            dns_name,
            _ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let oversized = vec![0_u8; MAX_CA_CERTIFICATE_DER_BYTES + 1];
        let result = RemoteTlsHttpTransport::new(
            addr,
            dns_name,
            &oversized,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(
            result,
            Err(TransportError::CaCertificateTooLarge { maximum }) if maximum == MAX_CA_CERTIFICATE_DER_BYTES
        ));
    }

    #[test]
    fn remote_tls_rejects_invalid_ca_der() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            dns_name,
            ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let result = RemoteTlsHttpTransport::new(
            addr,
            dns_name,
            &ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(
            result,
            Err(TransportError::InvalidCaCertificate(_))
        ));
    }

    #[test]
    fn remote_tls_rejects_an_ip_address_server_name() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            _dns_name,
            ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let result = RemoteTlsHttpTransport::new(
            addr,
            "127.0.0.1",
            &ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(result, Err(TransportError::InvalidServerName)));
    }

    #[test]
    fn remote_tls_rejects_an_empty_server_name() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let (
            addr,
            _dns_name,
            ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        ) = remote_tls_transport_args(addr);
        let result = RemoteTlsHttpTransport::new(
            addr,
            "",
            &ca_der,
            connect,
            handshake_read,
            handshake_write,
            read,
            write,
            max_header,
            max_body,
        );
        assert!(matches!(result, Err(TransportError::InvalidServerName)));
    }
}
