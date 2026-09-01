//! Real loopback-TCP TLS tests for [`RemoteTlsHttpTransport`], plus one
//! plaintext regression check that the shared bounded-stream refactor left
//! [`LoopbackHttpTransport`]'s behavior unchanged.
//!
//! Each TLS test spins up an ephemeral `rcgen`-issued CA/leaf pair, serves
//! exactly one real `rustls` `ServerConnection` over one accepted loopback
//! connection, and drives the actual `RemoteTlsHttpTransport` client code
//! against it — never a fake `Transport`. This exercises real certificate
//! verification, real hostname validation, and a real handshake, all
//! confined to `127.0.0.1`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sunrise_edge_client::{
    LoopbackHttpTransport, Method, RemoteTlsHttpTransport, Transport, TransportError, WireRequest,
};

/// One ephemeral CA plus one leaf certificate issued for `leaf_dns_name` and
/// signed by that CA, ready for a test-only `rustls` server.
struct TestCertificate {
    ca_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
}

fn issue_certificate(leaf_dns_name: &str) -> TestCertificate {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sunrise-edge remote-tls test CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params = CertificateParams::new(vec![leaf_dns_name.to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, leaf_dns_name);
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let private_key: PrivateKeyDer<'static> =
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_cert.der().clone()], private_key)
        .unwrap();

    TestCertificate {
        ca_der: ca_cert.der().to_vec(),
        server_config: Arc::new(server_config),
    }
}

/// Maximum bytes [`read_request_bounded`] will ever accumulate before giving
/// up: comfortably larger than any request this test suite sends, but still
/// a fixed ceiling rather than an unbounded read loop.
const MAX_TEST_REQUEST_BYTES: usize = 4096;

/// Finite read timeout set on every accepted test-server socket, so a
/// handshake or request read that never completes (for example because a
/// client aborted the connection after failing certificate verification)
/// bounds this thread's blocking `read` calls instead of hanging forever.
const TEST_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Reads from `stream` in small chunks until either the HTTP header
/// terminator `\r\n\r\n` has been observed or [`MAX_TEST_REQUEST_BYTES`] have
/// been read, whichever comes first. A single `Read::read` call on a TLS
/// stream may return far fewer bytes than one complete HTTP request (a TLS
/// record boundary does not need to align with the application-level framing
/// at all), so this test helper — unlike a single one-shot `read` — never
/// assumes the entire request headers arrive in one call. Combined with the
/// finite [`TEST_SOCKET_READ_TIMEOUT`] set on the underlying socket, this is
/// still bounded: a peer that never sends a terminator, or never sends
/// anything at all, causes each `read` to time out rather than block
/// indefinitely.
fn read_request_bounded<S: Read>(stream: &mut S) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() >= MAX_TEST_REQUEST_BYTES {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    buffer
}

/// Accepts exactly one loopback connection, completes a real TLS handshake
/// as the server, reads the request headers (bounded by
/// [`read_request_bounded`]) — sent back whole over `request_sender` for the
/// caller to inspect — and writes `response_bytes` back.
fn serve_tls_once(
    server_config: Arc<ServerConfig>,
    response_bytes: Vec<u8>,
    request_sender: mpsc::Sender<Vec<u8>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((sock, _)) = listener.accept() else {
            return;
        };
        sock.set_read_timeout(Some(TEST_SOCKET_READ_TIMEOUT))
            .unwrap();
        let Ok(conn) = ServerConnection::new(server_config) else {
            return;
        };
        let mut tls = StreamOwned::new(conn, sock);
        let raw_request = read_request_bounded(&mut tls);
        let _ = request_sender.send(raw_request);
        let _ = tls.write_all(&response_bytes);
        let _ = tls.flush();
    });
    addr
}

/// Accepts exactly one loopback connection and then holds it open without
/// ever writing a byte, so a client's TLS handshake read stalls until its
/// own deadline expires.
fn serve_and_stall() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // Hold the accepted socket open (and thus the client's read
            // stalled) for well beyond any deadline this test configures,
            // then let it drop and close.
            thread::sleep(Duration::from_secs(5));
            drop(stream);
        }
    });
    addr
}

/// Accepts exactly one loopback connection and immediately closes it without
/// sending a single byte, so the client's very first handshake read
/// observes a raw TCP EOF before any TLS record has arrived.
fn serve_and_close_immediately() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });
    addr
}

fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.sunrise-edge.query-result\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn get_request() -> WireRequest {
    WireRequest {
        method: Method::Get,
        path: "/v1/context".to_string(),
        content_type: None,
        body: Vec::new(),
        deadline: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn remote_transport(
    addr: SocketAddr,
    dns_name: &str,
    ca_der: &[u8],
) -> Result<RemoteTlsHttpTransport, TransportError> {
    RemoteTlsHttpTransport::new(
        addr,
        dns_name,
        ca_der,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
}

#[test]
fn succeeds_with_the_correct_hostname_and_ca() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let body = b"hello over tls";
    let (request_sender, request_receiver) = mpsc::channel();
    let addr = serve_tls_once(cert.server_config, ok_response(body), request_sender);

    let transport = remote_transport(addr, "sunrise-edge-test.invalid", &cert.ca_der).unwrap();
    let response = transport.send(&get_request()).unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(
        response.content_type.as_deref(),
        Some("application/vnd.sunrise-edge.query-result")
    );
    assert_eq!(response.body, body);

    // The `Host` header must be the validated DNS name plus the configured
    // port (never the connected `SocketAddr`'s IP, and never omitting the
    // port just because it happens to be a non-443 ephemeral port).
    let raw_request = request_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let raw_request = String::from_utf8(raw_request).unwrap();
    let expected_host_line = format!("Host: sunrise-edge-test.invalid:{}\r\n", addr.port());
    assert!(
        raw_request.contains(&expected_host_line),
        "expected exact Host header {expected_host_line:?} in request:\n{raw_request}"
    );
}

#[test]
fn rejects_a_wrong_hostname() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    // The server never gets far enough to read a request or reply, since the
    // client must fail certificate verification during the handshake.
    let (request_sender, _request_receiver) = mpsc::channel();
    let addr = serve_tls_once(
        cert.server_config,
        ok_response(b"unreachable"),
        request_sender,
    );

    let transport = remote_transport(addr, "wrong-hostname.invalid", &cert.ca_der).unwrap();
    let error = transport.send(&get_request()).unwrap_err();

    assert!(
        matches!(error, TransportError::TlsProtocol(_)),
        "expected a TLS protocol error from the failed hostname check, got {error:?}"
    );
}

#[test]
fn rejects_a_wrong_ca() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let wrong_ca = issue_certificate("sunrise-edge-test.invalid");
    let (request_sender, _request_receiver) = mpsc::channel();
    let addr = serve_tls_once(
        cert.server_config,
        ok_response(b"unreachable"),
        request_sender,
    );

    let transport = remote_transport(addr, "sunrise-edge-test.invalid", &wrong_ca.ca_der).unwrap();
    let error = transport.send(&get_request()).unwrap_err();

    assert!(
        matches!(error, TransportError::TlsProtocol(_)),
        "expected a TLS protocol error from the failed trust-anchor check, got {error:?}"
    );
}

#[test]
fn stalled_handshake_hits_the_configured_deadline() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let addr = serve_and_stall();

    // Every stage shares the same short bound, so whichever stage the
    // stalled handshake read blocks in is deadline-checked the same way:
    // the transport must fail well before the server's multi-second stall
    // ends, either because that single deadline-checked read itself timed
    // out, or because the shared total budget was exhausted first.
    let transport = RemoteTlsHttpTransport::new(
        addr,
        "sunrise-edge-test.invalid",
        &cert.ca_der,
        Duration::from_millis(300),
        Duration::from_millis(300),
        Duration::from_millis(300),
        Duration::from_millis(300),
        Duration::from_millis(300),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
    .unwrap();

    let started = Instant::now();
    let error = transport.send(&get_request()).unwrap_err();
    let elapsed = started.elapsed();

    match &error {
        TransportError::RequestDeadlineExceeded => {}
        TransportError::Read(io_error) => assert!(
            matches!(
                io_error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "expected a read-timeout flavored I/O error, got {io_error:?}"
        ),
        other => panic!("expected a bounded deadline/read-timeout error, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "handshake deadline was not enforced promptly: {elapsed:?}"
    );
}

#[test]
fn peer_closing_before_the_handshake_completes_fails_promptly() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let addr = serve_and_close_immediately();

    // Every stage is given a generous multi-second budget. If a raw TCP EOF
    // during the handshake were mishandled as "keep waiting for more
    // packets" instead of failing immediately, the client would busy-spin
    // `read_tls` (which returns `Ok(0)` instantly once the socket has hit
    // EOF, never blocking again) until this entire budget elapsed — a slow,
    // CPU-spinning multi-second failure instead of a prompt one. This test's
    // tight elapsed-time bound only passes if the fix short-circuits on the
    // first observed EOF.
    let transport = RemoteTlsHttpTransport::new(
        addr,
        "sunrise-edge-test.invalid",
        &cert.ca_der,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
    .unwrap();

    let started = Instant::now();
    let error = transport.send(&get_request()).unwrap_err();
    let elapsed = started.elapsed();

    assert!(
        matches!(error, TransportError::TlsHandshakeClosed),
        "expected TlsHandshakeClosed for a peer that closed before the handshake finished, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "peer closing before the handshake finished was not detected promptly: {elapsed:?}"
    );
}

#[test]
fn a_caller_deadline_tightens_the_configured_transport_budget() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let addr = serve_and_stall();

    // Every transport-configured timeout is generously large; only a short
    // `WireRequest::deadline` should make this request fail quickly.
    let transport = RemoteTlsHttpTransport::new(
        addr,
        "sunrise-edge-test.invalid",
        &cert.ca_der,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
    .unwrap();
    let mut request = get_request();
    request.deadline = Some(Instant::now() + Duration::from_millis(100));

    let started = Instant::now();
    let error = transport.send(&request).unwrap_err();
    let elapsed = started.elapsed();

    assert!(
        matches!(error, TransportError::RequestDeadlineExceeded),
        "expected the short caller deadline to be enforced, got {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "the caller deadline did not tighten the much larger configured transport budget: {elapsed:?}"
    );
}

#[test]
fn constructor_rejects_malformed_inputs_before_any_network_io() {
    let cert = issue_certificate("sunrise-edge-test.invalid");
    let unused_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    assert!(matches!(
        remote_transport(unused_addr, "not a dns name!", &cert.ca_der),
        Err(TransportError::InvalidServerName)
    ));
    assert!(matches!(
        remote_transport(unused_addr, "127.0.0.1", &cert.ca_der),
        Err(TransportError::InvalidServerName)
    ));
    assert!(matches!(
        remote_transport(unused_addr, "sunrise-edge-test.invalid", &[]),
        Err(TransportError::EmptyCaCertificate)
    ));
    assert!(matches!(
        remote_transport(
            unused_addr,
            "sunrise-edge-test.invalid",
            b"not a certificate"
        ),
        Err(TransportError::InvalidCaCertificate(_))
    ));
    assert!(matches!(
        RemoteTlsHttpTransport::new(
            unused_addr,
            "sunrise-edge-test.invalid",
            &cert.ca_der,
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            NonZeroUsize::new(1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        ),
        Err(TransportError::ZeroTimeout)
    ));
}

/// Regression check: the shared bounded-stream refactor that introduced
/// [`RemoteTlsHttpTransport`] must not have changed
/// [`LoopbackHttpTransport`]'s plaintext behavior at all.
#[test]
fn loopback_transport_still_round_trips_plaintext() {
    let body = b"unchanged plaintext framing";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0_u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(&ok_response(body));
            let _ = stream.flush();
        }
    });

    let transport = LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(8 * 1024).unwrap(),
    )
    .unwrap();
    let response = transport.send(&get_request()).unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, body);
}
