//! A small, deterministic transport trait plus the one production
//! implementation: a strict, synchronous, loopback-only HTTP/1.1 transport.

use core::fmt;
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

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
    /// Optional caller deadline for the complete exchange. The loopback
    /// transport combines it with its own configured total bound and uses
    /// whichever expires first.
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
/// [`LoopbackHttpTransport`] is the only production implementation this crate
/// ships; tests supply a fake implementing this same trait.
pub trait Transport {
    /// Sends one request and returns its complete, bounded response.
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError>;
}

/// Errors from the bounded HTTP/1.1 transport.
#[derive(Debug)]
pub enum TransportError {
    /// The configured target address was not a loopback address.
    NonLoopbackAddress(SocketAddr),
    /// A configured timeout was zero.
    ZeroTimeout,
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
            _ => None,
        }
    }
}

/// Strict, synchronous, loopback-only HTTP/1.1 transport.
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
/// production remote transport is explicitly deferred (see
/// `ARCHITECTURE.md` §44 / DR-0083).
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
    /// connection.
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
        if !is_safe_request_path(&request.path) {
            return Err(TransportError::InvalidRequestPath);
        }
        if request
            .content_type
            .is_some_and(|value| !is_safe_header_value(value))
        {
            return Err(TransportError::InvalidRequestContentType);
        }
        let transport_budget = self
            .connect_timeout
            .checked_add(self.write_timeout)
            .and_then(|value| value.checked_add(self.read_timeout))
            .ok_or(TransportError::RequestDeadlineOverflow)?;
        let transport_deadline = Instant::now()
            .checked_add(transport_budget)
            .ok_or(TransportError::RequestDeadlineOverflow)?;
        let deadline = request
            .deadline
            .map_or(transport_deadline, |value| value.min(transport_deadline));
        let connect_timeout = remaining_timeout(deadline, self.connect_timeout)?;
        let mut stream =
            TcpStream::connect_timeout(&self.addr, connect_timeout).map_err(|error| {
                if is_timeout(&error) && Instant::now() >= deadline {
                    TransportError::RequestDeadlineExceeded
                } else {
                    TransportError::Connect(error)
                }
            })?;

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            request.method.as_str(),
            request.path,
            self.addr,
        );
        if let Some(content_type) = request.content_type {
            head.push_str("Content-Type: ");
            head.push_str(content_type);
            head.push_str("\r\n");
        }
        head.push_str(&format!("Content-Length: {}\r\n\r\n", request.body.len()));

        write_all_until(&mut stream, head.as_bytes(), deadline, self.write_timeout)?;
        if !request.body.is_empty() {
            write_all_until(&mut stream, &request.body, deadline, self.write_timeout)?;
        }
        flush_until(&mut stream, deadline, self.write_timeout)?;

        read_response(
            &mut stream,
            self.max_response_header_bytes,
            self.max_response_body_bytes,
            deadline,
            self.read_timeout,
        )
    }
}

fn read_response(
    stream: &mut TcpStream,
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
    stream
        .set_read_timeout(Some(remaining_timeout(deadline, read_timeout)?))
        .map_err(TransportError::SetTimeout)?;
    match stream.read(&mut chunk) {
        Ok(0) => {}
        Ok(_) => return Err(TransportError::TrailingResponseBytes),
        Err(error) if is_timeout(&error) && Instant::now() >= deadline => {
            return Err(TransportError::RequestDeadlineExceeded);
        }
        Err(error) if is_timeout(&error) => return Err(TransportError::ResponseDidNotClose),
        Err(error) => return Err(TransportError::Read(error)),
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

fn write_all_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
    write_timeout: Duration,
) -> Result<(), TransportError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining_timeout(deadline, write_timeout)?))
            .map_err(TransportError::SetTimeout)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(TransportError::Write(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write the complete request",
                )));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if is_timeout(&error) && Instant::now() >= deadline => {
                return Err(TransportError::RequestDeadlineExceeded);
            }
            Err(error) => return Err(TransportError::Write(error)),
        }
    }
    Ok(())
}

fn flush_until(
    stream: &mut TcpStream,
    deadline: Instant,
    write_timeout: Duration,
) -> Result<(), TransportError> {
    stream
        .set_write_timeout(Some(remaining_timeout(deadline, write_timeout)?))
        .map_err(TransportError::SetTimeout)?;
    stream.flush().map_err(|error| {
        if is_timeout(&error) && Instant::now() >= deadline {
            TransportError::RequestDeadlineExceeded
        } else {
            TransportError::Write(error)
        }
    })
}

fn read_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    read_timeout: Duration,
) -> Result<usize, TransportError> {
    stream
        .set_read_timeout(Some(remaining_timeout(deadline, read_timeout)?))
        .map_err(TransportError::SetTimeout)?;
    stream.read(buffer).map_err(|error| {
        if is_timeout(&error) && Instant::now() >= deadline {
            TransportError::RequestDeadlineExceeded
        } else {
            TransportError::Read(error)
        }
    })
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
}
