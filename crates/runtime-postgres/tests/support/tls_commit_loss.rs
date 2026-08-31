//! Bounded PostgreSQL commit-loss proxy with a TLS-protected client leg.
//!
//! The proxy implements PostgreSQL's ordinary `SSLRequest` negotiation,
//! authenticates an ephemeral `localhost` certificate through a private test
//! CA, terminates TLS, and relays plaintext PostgreSQL frames to the dedicated
//! live-test database. This isolates the driver's TLS connection-loss path
//! while leaving the existing plaintext proxy as independent evidence. It is
//! deliberately not an end-to-end PostgreSQL-server TLS or production PKI
//! fixture.

use postgres::{
    Config,
    config::{SslMode, SslNegotiation},
};
use postgres_rustls::{MakeTlsConnector, tokio, tokio_rustls};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use runtime::conformance::CommitFaultPoint;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    io,
    net::{SocketAddr, TcpStream as StdTcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Builder,
    sync::watch,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const MAX_INSPECTED_MESSAGE_BYTES: u32 = 64 * 1024;
const COPY_CHUNK_BYTES: usize = 8 * 1024;
const MAX_ACCEPTED_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

#[derive(Default)]
struct ProxyState {
    armed: Mutex<Option<CommitFaultPoint>>,
    fault_fired: AtomicBool,
    backend_commit_accepted: AtomicBool,
    tls_handshakes: AtomicUsize,
}

/// Test-only TLS terminator and PostgreSQL frame-aware commit-loss proxy.
pub(crate) struct TlsCommitLossProxy {
    local_addr: SocketAddr,
    state: Arc<ProxyState>,
    shutdown: watch::Sender<bool>,
    accept_handle: Option<thread::JoinHandle<()>>,
}

impl TlsCommitLossProxy {
    /// Starts the bounded proxy and returns the strictly verifying client
    /// connector that trusts only this proxy's ephemeral CA.
    pub(crate) fn spawn(backend_addr: SocketAddr) -> (Self, MakeTlsConnector) {
        let (server_config, client_connector) = tls_configs();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let local_addr = listener.local_addr().unwrap();
        let state = Arc::new(ProxyState::default());
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let accept_state = Arc::clone(&state);
        let accept_handle = thread::spawn(move || {
            let runtime = Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(run_accept_loop(
                listener,
                backend_addr,
                server_config,
                accept_state,
                shutdown_receiver,
            ));
        });
        (
            Self {
                local_addr,
                state,
                shutdown,
                accept_handle: Some(accept_handle),
            },
            client_connector,
        )
    }

    pub(crate) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn arm(&self, fault_point: CommitFaultPoint) {
        self.state.fault_fired.store(false, Ordering::SeqCst);
        self.state
            .backend_commit_accepted
            .store(false, Ordering::SeqCst);
        *self.state.armed.lock().unwrap() = Some(fault_point);
    }

    pub(crate) fn fault_fired(&self) -> bool {
        self.state.fault_fired.load(Ordering::SeqCst)
    }

    pub(crate) fn backend_commit_accepted(&self) -> bool {
        self.state.backend_commit_accepted.load(Ordering::SeqCst)
    }

    pub(crate) fn tls_handshakes(&self) -> usize {
        self.state.tls_handshakes.load(Ordering::SeqCst)
    }
}

impl Drop for TlsCommitLossProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        let _ = StdTcpStream::connect(self.local_addr);
        if let Some(handle) = self.accept_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Builds a config that requires ordinary PostgreSQL TLS negotiation and uses
/// `localhost` so rustls must validate the leaf SAN rather than an IP literal.
pub(crate) fn proxied_config(database_url: &str, proxy_addr: SocketAddr) -> Config {
    proxied_config_for_host(database_url, proxy_addr, "localhost")
}

/// Builds the otherwise identical required-TLS config with an IP hostname
/// that the proxy's `localhost`-only certificate must reject. This is a live
/// negative check that the client connector has not disabled name validation.
pub(crate) fn wrong_hostname_config(database_url: &str, proxy_addr: SocketAddr) -> Config {
    proxied_config_for_host(database_url, proxy_addr, "127.0.0.1")
}

fn proxied_config_for_host(database_url: &str, proxy_addr: SocketAddr, host: &str) -> Config {
    let original: Config = database_url.parse().unwrap();
    let mut proxied = Config::new();
    if let Some(user) = original.get_user() {
        proxied.user(user);
    }
    if let Some(password) = original.get_password() {
        proxied.password(password);
    }
    if let Some(dbname) = original.get_dbname() {
        proxied.dbname(dbname);
    }
    proxied
        .host(host)
        .port(proxy_addr.port())
        .ssl_mode(SslMode::Require)
        .ssl_negotiation(SslNegotiation::Postgres)
        .application_name("sunrise-edge-pr90-tls-commit-loss");
    proxied
}

fn tls_configs() -> (Arc<ServerConfig>, MakeTlsConnector) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Sunrise Edge ephemeral test CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
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

    let mut roots = RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    (Arc::new(server_config), MakeTlsConnector::new(connector))
}

async fn run_accept_loop(
    listener: std::net::TcpListener,
    backend_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = TcpListener::from_std(listener).unwrap();
    for _ in 0..MAX_ACCEPTED_CONNECTIONS {
        let accepted = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let _ = changed;
                return;
            }
            accepted = listener.accept() => accepted,
        };
        let Ok((client, _)) = accepted else {
            return;
        };
        if *shutdown.borrow() {
            return;
        }
        handle_connection(
            client,
            backend_addr,
            Arc::clone(&server_config),
            Arc::clone(&state),
            shutdown.clone(),
        )
        .await;
    }
}

async fn handle_connection(
    mut client: TcpStream,
    backend_addr: SocketAddr,
    server_config: Arc<ServerConfig>,
    state: Arc<ProxyState>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Disable Nagle's algorithm on the client leg, matching the plain proxy:
    // every relayed message is a small write, and leaving Nagle enabled
    // serializes each one behind the peer's delayed-ACK timer.
    let _ = client.set_nodelay(true);
    let mut ssl_request = [0_u8; POSTGRES_SSL_REQUEST.len()];
    if bounded_read_exact(&mut client, &mut ssl_request)
        .await
        .is_err()
        || ssl_request != POSTGRES_SSL_REQUEST
        || bounded_write_all(&mut client, b"S").await.is_err()
    {
        return;
    }
    let acceptor = TlsAcceptor::from(server_config);
    let Ok(Ok(tls_client)) = timeout(IO_TIMEOUT, acceptor.accept(client)).await else {
        return;
    };
    state.tls_handshakes.fetch_add(1, Ordering::SeqCst);
    let Ok(Ok(mut backend)) = timeout(IO_TIMEOUT, TcpStream::connect(backend_addr)).await else {
        return;
    };
    // Same rationale as the client leg: disable Nagle's algorithm so the
    // relayed messages are not delayed behind the backend's delayed-ACK timer.
    let _ = backend.set_nodelay(true);
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_client);
    if relay_startup_message(&mut client_reader, &mut backend)
        .await
        .is_err()
    {
        return;
    }
    let (mut backend_reader, mut backend_writer) = backend.into_split();
    let awaiting_ack = Arc::new(AtomicBool::new(false));
    let client_state = Arc::clone(&state);
    let client_awaiting_ack = Arc::clone(&awaiting_ack);
    let backend_state = Arc::clone(&state);
    let backend_awaiting_ack = Arc::clone(&awaiting_ack);
    let client_to_backend = relay_client_to_backend(
        &mut client_reader,
        &mut backend_writer,
        &client_state,
        &client_awaiting_ack,
    );
    let backend_to_client = relay_backend_to_client(
        &mut backend_reader,
        &mut client_writer,
        &backend_state,
        &backend_awaiting_ack,
    );
    tokio::pin!(client_to_backend);
    tokio::pin!(backend_to_client);
    tokio::select! {
        biased;
        changed = shutdown.changed() => { let _ = changed; }
        _ = &mut client_to_backend => {}
        _ = &mut backend_to_client => {}
    }
}

async fn relay_startup_message<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    bounded_read_exact(reader, &mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes);
    let payload_len = length.checked_sub(4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "startup length below minimum")
    })?;
    if payload_len > MAX_INSPECTED_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup message exceeds bounded size",
        ));
    }
    let mut payload = vec![0_u8; payload_len as usize];
    bounded_read_exact(reader, &mut payload).await?;
    let mut message = Vec::with_capacity(length_bytes.len() + payload.len());
    message.extend_from_slice(&length_bytes);
    message.extend_from_slice(&payload);
    bounded_write_all(writer, &message).await
}

async fn read_header<R>(reader: &mut R) -> io::Result<Option<(u8, u32)>>
where
    R: AsyncRead + Unpin,
{
    let mut type_byte = [0_u8; 1];
    match bounded_read_exact(reader, &mut type_byte).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut length_bytes = [0_u8; 4];
    bounded_read_exact(reader, &mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes);
    let payload_len = length.checked_sub(4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "message length below minimum")
    })?;
    Ok(Some((type_byte[0], payload_len)))
}

async fn relay_client_to_backend<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &Arc<ProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let (message_type, payload_len) = match read_header(reader).await {
            Ok(Some(header)) => header,
            Ok(None) | Err(_) => return,
        };
        if message_type == b'Q' && payload_len <= MAX_INSPECTED_MESSAGE_BYTES {
            let mut payload = vec![0_u8; payload_len as usize];
            if bounded_read_exact(reader, &mut payload).await.is_err() {
                return;
            }
            if payload == b"COMMIT\0" {
                let armed = state.armed.lock().unwrap().take();
                match armed {
                    Some(CommitFaultPoint::BeforeCommitDispatch) => {
                        state.fault_fired.store(true, Ordering::SeqCst);
                        return;
                    }
                    Some(CommitFaultPoint::AfterBackendCommitAccepted) => {
                        awaiting_ack.store(true, Ordering::SeqCst);
                    }
                    None => {}
                }
            }
            if forward_message(writer, message_type, &payload)
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        if forward_header(writer, message_type, payload_len)
            .await
            .is_err()
            || stream_copy(reader, writer, u64::from(payload_len))
                .await
                .is_err()
        {
            return;
        }
    }
}

async fn relay_backend_to_client<R, W>(
    reader: &mut R,
    writer: &mut W,
    state: &Arc<ProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut commit_complete_seen = false;
    loop {
        let (message_type, payload_len) = match read_header(reader).await {
            Ok(Some(header)) => header,
            Ok(None) | Err(_) => return,
        };
        if awaiting_ack.load(Ordering::SeqCst) {
            if payload_len > MAX_INSPECTED_MESSAGE_BYTES {
                if drain(reader, u64::from(payload_len)).await.is_err() {
                    return;
                }
                continue;
            }
            let mut payload = vec![0_u8; payload_len as usize];
            if bounded_read_exact(reader, &mut payload).await.is_err() {
                return;
            }
            if message_type == b'C' && payload.starts_with(b"COMMIT") {
                commit_complete_seen = true;
                continue;
            }
            if message_type == b'Z' {
                if commit_complete_seen {
                    state.backend_commit_accepted.store(true, Ordering::SeqCst);
                }
                state.fault_fired.store(true, Ordering::SeqCst);
                return;
            }
            continue;
        }
        if forward_header(writer, message_type, payload_len)
            .await
            .is_err()
            || stream_copy(reader, writer, u64::from(payload_len))
                .await
                .is_err()
        {
            return;
        }
    }
}

async fn forward_message<W>(writer: &mut W, message_type: u8, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len() + 4)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    let mut message = Vec::with_capacity(5 + payload.len());
    message.push(message_type);
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    bounded_write_all(writer, &message).await
}

async fn forward_header<W>(writer: &mut W, message_type: u8, payload_len: u32) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = payload_len
        .checked_add(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message length overflow"))?;
    let mut header = [0_u8; 5];
    header[0] = message_type;
    header[1..].copy_from_slice(&length.to_be_bytes());
    bounded_write_all(writer, &header).await
}

async fn stream_copy<R, W>(reader: &mut R, writer: &mut W, mut remaining: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; COPY_CHUNK_BYTES];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        bounded_read_exact(reader, &mut buffer[..chunk]).await?;
        bounded_write_all(writer, &buffer[..chunk]).await?;
        remaining -= chunk as u64;
    }
    Ok(())
}

async fn drain<R>(reader: &mut R, mut remaining: u64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0_u8; COPY_CHUNK_BYTES];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        bounded_read_exact(reader, &mut buffer[..chunk]).await?;
        remaining -= chunk as u64;
    }
    Ok(())
}

async fn bounded_read_exact<R>(reader: &mut R, buffer: &mut [u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    timeout(IO_TIMEOUT, reader.read_exact(buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bounded read timed out"))??;
    Ok(())
}

async fn bounded_write_all<W>(writer: &mut W, buffer: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, writer.write_all(buffer))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bounded write timed out"))??;
    timeout(IO_TIMEOUT, writer.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bounded flush timed out"))??;
    Ok(())
}
