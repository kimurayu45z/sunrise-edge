//! Deterministic local TLS integration tests for the `sunrise-edge-cli`
//! binary's `--tls-server-name`/`--tls-ca-cert-der-file` flags.
//!
//! Each test spins up an ephemeral `rcgen`-issued CA/leaf pair and serves a
//! real `rustls` `ServerConnection` over a real loopback TCP connection,
//! then drives the actual `sunrise_edge_cli::run` entry point against it —
//! never a fake transport — exactly as a user invoking the binary would.
//! Everything here is confined to `127.0.0.1` with fixed, bounded fixtures:
//! no external network, no unbounded waits.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sunrise_edge_client::{
    AtomicityDomainId, ChainId, ClientError, Epoch, HashSuiteId, HttpContextQueryResult,
    ProtocolContextMismatch, ProtocolVersion, QUERY_RESULT_MEDIA_TYPE,
};

static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(1);

struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str, contents: &[u8]) -> Self {
        let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sunrise-edge-cli-tls-e2e-{label}-{}-{sequence}",
            std::process::id()
        ));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self(path)
    }

    fn path_str(&self) -> String {
        self.0.to_str().unwrap().to_string()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.0);
    }
}

struct TestCertificate {
    ca_der: Vec<u8>,
    server_config: Arc<ServerConfig>,
}

fn issue_certificate(leaf_dns_name: &str) -> TestCertificate {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sunrise-edge cli TLS test CA");
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

fn ok_context_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {QUERY_RESULT_MEDIA_TYPE}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Maximum bytes [`read_request_bounded`] will ever accumulate before giving
/// up: comfortably larger than any request this test suite sends, but still
/// a fixed ceiling rather than an unbounded read loop.
const MAX_TEST_REQUEST_BYTES: usize = 4096;

/// Finite read timeout set on every accepted test-server socket, so a
/// request read that never completes bounds this thread's blocking `read`
/// calls instead of hanging forever.
const TEST_SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// How long [`serve_context_once`] polls for a second connection attempt,
/// nonblocking, after serving the first — long enough that a synchronous
/// second dispatch from the very same test (which would already be
/// connecting, not scheduled for later) is reliably observed, but still a
/// fixed ceiling rather than an indefinite blocking `accept`.
const SECOND_CONNECTION_POLL_WINDOW: Duration = Duration::from_millis(200);

/// Reads from `stream` in small chunks until either the HTTP header
/// terminator `\r\n\r\n` has been observed or [`MAX_TEST_REQUEST_BYTES`] have
/// been read, whichever comes first. A single `Read::read` call on a TLS
/// stream may return far fewer bytes than one complete HTTP request, so this
/// test helper — unlike a single one-shot `read` — never assumes the entire
/// request headers arrive in one call. Combined with the finite
/// [`TEST_SOCKET_READ_TIMEOUT`] set on the underlying socket, this stays
/// bounded even against a peer that never sends a terminator.
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

/// Accepts loopback TLS connections and serves `response_bytes` for exactly
/// the first one — sending its raw request bytes (read via
/// [`read_request_bounded`], under a finite socket read timeout) over
/// `request_sender` for the caller to inspect. After that first connection is
/// fully handled and dropped, this polls a nonblocking `accept` for a fixed
/// [`SECOND_CONNECTION_POLL_WINDOW`] so a synchronous second dispatch attempt
/// is still counted (proving a test that expects exactly one dispatch would
/// notice a bug), without ever blocking this thread indefinitely waiting for
/// a connection that may never arrive. The returned [`JoinHandle`] lets a
/// caller wait for this bounded observation window to finish before
/// asserting on `connection_count`.
fn serve_context_once(
    server_config: Arc<ServerConfig>,
    response_bytes: Vec<u8>,
    request_sender: mpsc::Sender<Vec<u8>>,
) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connection_count);
    let handle = thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            counted.fetch_add(1, Ordering::SeqCst);
            sock.set_read_timeout(Some(TEST_SOCKET_READ_TIMEOUT))
                .unwrap();
            if let Ok(conn) = ServerConnection::new(Arc::clone(&server_config)) {
                let mut tls = StreamOwned::new(conn, sock);
                let raw_request = read_request_bounded(&mut tls);
                let _ = request_sender.send(raw_request);
                let _ = tls.write_all(&response_bytes);
                let _ = tls.flush();
                drop(tls);
            }
        }

        // Bounded second-connection observation window: a real second
        // dispatch attempt from this same process would already be
        // connecting by now, so a short nonblocking poll after the first
        // connection is fully served is enough to catch it, while a
        // listener that never sees a second connection lets this thread
        // return promptly instead of blocking on `accept` forever.
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + SECOND_CONNECTION_POLL_WINDOW;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((sock, _)) => {
                    counted.fetch_add(1, Ordering::SeqCst);
                    drop(sock);
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (addr, connection_count, handle)
}

fn context_result(chain_id: &str) -> HttpContextQueryResult {
    HttpContextQueryResult::new(
        ChainId::new(chain_id).unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(5),
        HashSuiteId::new(1),
        1,
        sunrise_edge_client::SignatureSchemeId::Ed25519.as_u16(),
        sunrise_edge_client::ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        AtomicityDomainId::new([0x44; 32]).unwrap(),
        vec![0xAA],
    )
    .unwrap()
}

#[test]
fn cli_context_command_succeeds_over_tls_with_exact_host_authority() {
    let dns_name = "cli-tls-e2e-context.invalid";
    let cert = issue_certificate(dns_name);
    let ca_file = TempFile::new("ca", &cert.ca_der);
    let body = context_result("cli-tls-e2e-chain").encode().unwrap();
    let (request_sender, request_receiver) = mpsc::channel();
    let (addr, _connection_count, server_handle) = serve_context_once(
        cert.server_config,
        ok_context_response(&body),
        request_sender,
    );

    let result = sunrise_edge_cli::run(vec![
        OsString::from("context"),
        OsString::from("--endpoint"),
        OsString::from(addr.to_string()),
        OsString::from("--tls-server-name"),
        OsString::from(dns_name),
        OsString::from("--tls-ca-cert-der-file"),
        OsString::from(ca_file.path_str()),
    ]);

    result.expect("context command should succeed over a correctly authenticated TLS connection");

    let raw_request = request_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("server should have received exactly one request");
    let raw_request = String::from_utf8(raw_request).unwrap();
    let expected_host_line = format!("Host: {dns_name}:{}\r\n", addr.port());
    assert!(
        raw_request.contains(&expected_host_line),
        "expected exact Host header {expected_host_line:?} in request:\n{raw_request}"
    );

    server_handle
        .join()
        .expect("test server thread should not panic");
}

#[test]
fn cli_transfer_command_over_tls_stops_after_one_mismatched_context_request() {
    let dns_name = "cli-tls-e2e-transfer.invalid";
    let cert = issue_certificate(dns_name);
    let ca_file = TempFile::new("ca", &cert.ca_der);
    // The server's chain id deliberately disagrees with `--expected-chain-id`
    // below; the TLS handshake itself succeeds (proving the transport
    // endpoint was correctly authenticated), so only the separate, mandatory
    // `/v1/context` expected-context check can be what fails this transfer.
    let body = context_result("server-actual-chain").encode().unwrap();
    let (request_sender, _request_receiver) = mpsc::channel();
    let (addr, connection_count, server_handle) = serve_context_once(
        cert.server_config,
        ok_context_response(&body),
        request_sender,
    );

    let seed_file = TempFile::new("seed", "5a".repeat(32).as_bytes());

    let result = sunrise_edge_cli::run(vec![
        OsString::from("transfer"),
        OsString::from("--endpoint"),
        OsString::from(addr.to_string()),
        OsString::from("--tls-server-name"),
        OsString::from(dns_name),
        OsString::from("--tls-ca-cert-der-file"),
        OsString::from(ca_file.path_str()),
        OsString::from("--seed-file"),
        OsString::from(seed_file.path_str()),
        OsString::from("--module-id"),
        OsString::from("01".repeat(32)),
        OsString::from("--module-version"),
        OsString::from("1"),
        OsString::from("--module-digest-algorithm"),
        OsString::from("1"),
        OsString::from("--module-digest"),
        OsString::from("02".repeat(32)),
        OsString::from("--source-object"),
        OsString::from("10".repeat(32)),
        OsString::from("--destination-object"),
        OsString::from("20".repeat(32)),
        OsString::from("--destination-owner"),
        OsString::from("88".repeat(32)),
        OsString::from("--amount"),
        OsString::from("250"),
        OsString::from("--gas-limit"),
        OsString::from("1000"),
        OsString::from("--request-id"),
        OsString::from("30".repeat(32)),
        OsString::from("--expected-chain-id"),
        OsString::from("locally-expected-chain"),
        OsString::from("--expected-protocol-version"),
        OsString::from("3"),
        OsString::from("--expected-epoch"),
        OsString::from("5"),
        OsString::from("--expected-hash-suite-id"),
        OsString::from("1"),
        OsString::from("--expected-domain"),
        OsString::from("44".repeat(32)),
    ]);

    let error = result.expect_err(
        "transfer should fail on the mismatched expected-context check, never reaching nonce/object/sign/submit",
    );
    match error {
        sunrise_edge_cli::CliError::Client(boxed) => match *boxed {
            ClientError::ProtocolContextMismatch(ProtocolContextMismatch::ChainId { .. }) => {}
            other => panic!("expected a ChainId ProtocolContextMismatch, got {other:?}"),
        },
        other => panic!("expected CliError::Client(ProtocolContextMismatch), got {other:?}"),
    }

    server_handle
        .join()
        .expect("test server thread should not panic");

    // Exactly one connection (and therefore exactly one `/v1/context`
    // request) was made: a second dispatch attempt would have connected to
    // this same listener during the bounded observation window above and
    // been visible here.
    assert_eq!(
        connection_count.load(Ordering::SeqCst),
        1,
        "transfer must stop after exactly one context request on a mismatch"
    );
}
