use objects::{Address, Object, Owner, encode_object, encode_owner};
use postgres::{
    Client, Config, NoTls,
    config::{Host, SslMode},
    error::SqlState,
};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DueOutboxClaimRequest,
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectPayload, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableOutboxAcknowledgement,
    DurableOutboxAcknowledgementOutcome, DurableOutboxAcknowledgementRejection, DurableOutboxBatch,
    DurableOutboxClaimOutcome, DurableOutboxClaimRejection, DurableOutboxLeaseId,
    DurableOutboxMessage, DurableReadError, DurableRequestId, DurableRequestReceipt,
    DurableStateTransaction, IndexedOutboxRepository, ObjectId, RequestOutboxClaimRequest,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, WriterFenceGeneration,
    conformance::{
        CommitFaultPoint, CommitLossFixture, ConformanceFailure, ConformanceResult,
        DurableStoreFixture, SchemaSkewFixture, run_commit_loss_conformance,
        run_durable_object_conformance, run_durable_store_conformance, run_schema_skew_conformance,
    },
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresSchemaError, PostgresTransactionPolicy,
    advance_writer_fence as advance_postgres_writer_fence, apply_initial_schema,
    bootstrap_namespace, build_postgres_pool, inspect_namespace, verify_initial_schema,
};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TEST_DATABASE: &str = "sunrise_edge_test";

type TestPostgresManager = PostgresConnectionManager<NoTls>;

// --- Bounded, test-only commit-boundary connection-loss proxy -------------
//
// This proxy never negotiates TLS; every proxied client must use `NoTls` and
// `SslMode::Disable`. It relays the untyped frontend `StartupMessage`
// verbatim, then inspects every later `1-byte-type + 4-byte-length` frame to
// find the exact simple-query `COMMIT` round trip a durable commit dispatches
// last. See https://www.postgresql.org/docs/current/protocol-message-formats.html
// for the frame layout this parser relies on.

/// Hard bound on a single wire message the proxy buffers in memory before
/// deciding whether to forward, drop, or intercept it. Larger messages are
/// streamed through in fixed-size chunks instead, so proxy memory never
/// grows with message size.
const COMMIT_LOSS_MAX_INSPECTED_MESSAGE_BYTES: u32 = 64 * 1024;
/// Fixed chunk size used to stream oversized or uninspected payload bytes.
const COMMIT_LOSS_COPY_CHUNK_BYTES: usize = 8 * 1024;
/// Bounded number of physical connections the proxy accepts before its
/// accept loop exits. Comfortably covers every fault case plus ordinary pool
/// churn in the shared commit-loss conformance suite.
const COMMIT_LOSS_MAX_ACCEPTED_CONNECTIONS: usize = 32;
/// Bounded per-socket read/write timeout so a stalled peer cannot block a
/// proxy thread indefinitely.
const COMMIT_LOSS_IO_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct CommitLossProxyState {
    armed: Mutex<Option<CommitFaultPoint>>,
    fault_fired: AtomicBool,
    backend_commit_accepted: AtomicBool,
}

/// Cloned handles to the one physical connection the accept loop is
/// currently servicing, kept so [`CommitLossProxy::drop`] can sever it
/// directly instead of waiting for the pool's own client to close it.
struct CommitLossActiveConnection {
    client: TcpStream,
    backend: TcpStream,
}

/// Locks `active_connection`, recovering the guard even if a prior panic
/// poisoned the lock. This is test-only teardown bookkeeping, not protocol
/// state, so a poisoned lock must not stop the proxy from shutting sockets
/// down cleanly.
fn commit_loss_lock_active_connection(
    active_connection: &Mutex<Option<CommitLossActiveConnection>>,
) -> std::sync::MutexGuard<'_, Option<CommitLossActiveConnection>> {
    active_connection
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Registers clones of the given sockets as the one active connection before
/// the accept loop enters its (possibly long-lived) serial handler. Returns
/// `Err` if cloning fails; the caller must not proceed with an unregistered
/// connection, since `Drop` could then no longer sever it deterministically.
fn commit_loss_register_active_connection(
    active_connection: &Mutex<Option<CommitLossActiveConnection>>,
    client: &TcpStream,
    backend: &TcpStream,
) -> io::Result<()> {
    let client = client.try_clone()?;
    let backend = backend.try_clone()?;
    *commit_loss_lock_active_connection(active_connection) =
        Some(CommitLossActiveConnection { client, backend });
    Ok(())
}

/// Clears the active-connection registry once the serial handler for that
/// connection has returned on its own.
fn commit_loss_clear_active_connection(
    active_connection: &Mutex<Option<CommitLossActiveConnection>>,
) {
    *commit_loss_lock_active_connection(active_connection) = None;
}

/// Bounded, test-only PostgreSQL wire-protocol proxy that deterministically
/// severs a client connection at a chosen point relative to one dispatched
/// `COMMIT`.
struct CommitLossProxy {
    local_addr: SocketAddr,
    state: Arc<CommitLossProxyState>,
    shutdown: Arc<AtomicBool>,
    active_connection: Arc<Mutex<Option<CommitLossActiveConnection>>>,
    accept_handle: Option<thread::JoinHandle<()>>,
}

impl CommitLossProxy {
    fn spawn(backend_addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local_addr = listener.local_addr().unwrap();
        let state = Arc::new(CommitLossProxyState::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_connection: Arc<Mutex<Option<CommitLossActiveConnection>>> =
            Arc::new(Mutex::new(None));
        let accept_state = Arc::clone(&state);
        let accept_shutdown = Arc::clone(&shutdown);
        let accept_active_connection = Arc::clone(&active_connection);
        let accept_handle = thread::spawn(move || {
            for _ in 0..COMMIT_LOSS_MAX_ACCEPTED_CONNECTIONS {
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(_) => break,
                };
                if accept_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(backend) = TcpStream::connect(backend_addr) else {
                    continue;
                };
                // Install the active-connection registry before entering the
                // handler, which can block for the life of this physical
                // connection: `Drop` must always be able to find and sever
                // whichever sockets the accept thread is currently serving.
                if commit_loss_register_active_connection(
                    &accept_active_connection,
                    &client,
                    &backend,
                )
                .is_err()
                {
                    continue;
                }
                // `Drop` may have set the shutdown flag and already tried to
                // sever the active connection between the check above and
                // this registration, finding nothing registered yet. Re-check
                // now that registration is visible: if shutdown is set, sever
                // and clear this exact connection ourselves and stop before
                // entering a handler that would otherwise have no way to be
                // told to return, rather than block for
                // `COMMIT_LOSS_IO_TIMEOUT`.
                if accept_shutdown.load(Ordering::SeqCst) {
                    if let Some(active) =
                        commit_loss_lock_active_connection(&accept_active_connection).take()
                    {
                        commit_loss_shutdown_both(&active.client, &active.backend);
                    }
                    break;
                }
                commit_loss_handle_connection(client, backend, &accept_state);
                commit_loss_clear_active_connection(&accept_active_connection);
            }
        });
        Self {
            local_addr,
            state,
            shutdown,
            active_connection,
            accept_handle: Some(accept_handle),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Arms exactly one future `COMMIT` dispatched through this proxy to be
    /// severed at `fault_point`, resetting prior fired/observed flags.
    fn arm(&self, fault_point: CommitFaultPoint) {
        self.state.fault_fired.store(false, Ordering::SeqCst);
        self.state
            .backend_commit_accepted
            .store(false, Ordering::SeqCst);
        *self.state.armed.lock().unwrap() = Some(fault_point);
    }

    fn fault_fired(&self) -> bool {
        self.state.fault_fired.load(Ordering::SeqCst)
    }

    fn backend_commit_accepted(&self) -> bool {
        self.state.backend_commit_accepted.load(Ordering::SeqCst)
    }
}

impl Drop for CommitLossProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Sever the one active physical connection directly, if any, rather
        // than waiting for the pool's own client to close its side. The
        // accept thread can be blocked for the life of this connection
        // inside `commit_loss_handle_connection`, never returning to
        // `accept()` on its own; without this, `join` below would wait for
        // that connection's relay threads to hit `COMMIT_LOSS_IO_TIMEOUT`.
        if let Some(active) = commit_loss_lock_active_connection(&self.active_connection).take() {
            commit_loss_shutdown_both(&active.client, &active.backend);
        }
        // Unblock a pending `accept()` so the listener thread observes the
        // shutdown flag and exits instead of blocking indefinitely.
        let _ = TcpStream::connect(self.local_addr);
        if let Some(handle) = self.accept_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Clones both sockets for the paired relay threads, or `None` if either
/// clone fails.
fn commit_loss_clone_relay_pair(
    client: &TcpStream,
    backend: &TcpStream,
) -> Option<(TcpStream, TcpStream)> {
    let client_reader = client.try_clone().ok()?;
    let backend_writer = backend.try_clone().ok()?;
    Some((client_reader, backend_writer))
}

fn commit_loss_handle_connection(
    mut client: TcpStream,
    mut backend: TcpStream,
    state: &Arc<CommitLossProxyState>,
) {
    let _ = client.set_read_timeout(Some(COMMIT_LOSS_IO_TIMEOUT));
    let _ = client.set_write_timeout(Some(COMMIT_LOSS_IO_TIMEOUT));
    let _ = backend.set_read_timeout(Some(COMMIT_LOSS_IO_TIMEOUT));
    let _ = backend.set_write_timeout(Some(COMMIT_LOSS_IO_TIMEOUT));
    // Disable Nagle's algorithm on both legs. Every relayed message is
    // forwarded as one or two small writes; combined with the peer's
    // delayed-ACK timer, leaving Nagle enabled serializes each one behind a
    // multi-hundred-millisecond wait and compounds across the many messages
    // in one transaction into multi-second per-operation latency.
    let _ = client.set_nodelay(true);
    let _ = backend.set_nodelay(true);

    if commit_loss_relay_startup_message(&mut client, &mut backend).is_err() {
        let _ = client.shutdown(Shutdown::Both);
        let _ = backend.shutdown(Shutdown::Both);
        return;
    }

    let Some((client_reader, backend_writer)) = commit_loss_clone_relay_pair(&client, &backend)
    else {
        return;
    };
    let awaiting_ack = Arc::new(AtomicBool::new(false));

    let forward_state = Arc::clone(state);
    let forward_awaiting_ack = Arc::clone(&awaiting_ack);
    let forward_handle = thread::spawn(move || {
        commit_loss_client_to_backend(
            client_reader,
            backend_writer,
            &forward_state,
            &forward_awaiting_ack,
        );
    });

    let reverse_state = Arc::clone(state);
    let reverse_awaiting_ack = Arc::clone(&awaiting_ack);
    let reverse_handle = thread::spawn(move || {
        commit_loss_backend_to_client(backend, client, &reverse_state, &reverse_awaiting_ack);
    });

    let _ = forward_handle.join();
    let _ = reverse_handle.join();
}

/// Relays the untyped, length-prefixed frontend `StartupMessage` verbatim.
/// Every later frontend/backend message uses the typed frame this proxy
/// inspects; only this first client-to-backend message lacks a type byte.
fn commit_loss_relay_startup_message(
    client: &mut TcpStream,
    backend: &mut TcpStream,
) -> io::Result<()> {
    let mut length_bytes = [0_u8; 4];
    client.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes);
    let payload_len = length.checked_sub(4).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "startup message length below minimum",
        )
    })?;
    if payload_len > COMMIT_LOSS_MAX_INSPECTED_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "startup message exceeds bounded size",
        ));
    }
    let mut payload = vec![0_u8; payload_len as usize];
    client.read_exact(&mut payload)?;
    // Written as one buffer, not two, so it cannot land as separate small
    // TCP segments subject to Nagle/delayed-ACK interaction.
    let mut message = Vec::with_capacity(length_bytes.len() + payload.len());
    message.extend_from_slice(&length_bytes);
    message.extend_from_slice(&payload);
    backend.write_all(&message)?;
    backend.flush()
}

/// Reads one typed message header, returning `Ok(None)` on a clean EOF.
fn commit_loss_read_header(reader: &mut TcpStream) -> io::Result<Option<(u8, u32)>> {
    let mut type_byte = [0_u8; 1];
    match reader.read_exact(&mut type_byte) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes);
    let payload_len = length.checked_sub(4).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "message length below minimum")
    })?;
    Ok(Some((type_byte[0], payload_len)))
}

fn commit_loss_forward_message(
    writer: &mut TcpStream,
    message_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(payload.len() + 4)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large to forward"))?;
    // Written as one buffer, not three, so it cannot land as separate small
    // TCP segments subject to Nagle/delayed-ACK interaction.
    let mut message = Vec::with_capacity(1 + 4 + payload.len());
    message.push(message_type);
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(payload);
    writer.write_all(&message)?;
    writer.flush()
}

fn commit_loss_forward_header(
    writer: &mut TcpStream,
    message_type: u8,
    payload_len: u32,
) -> io::Result<()> {
    let length = payload_len
        .checked_add(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "message length overflow"))?;
    let mut header = [0_u8; 5];
    header[0] = message_type;
    header[1..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header)
}

fn commit_loss_stream_copy(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    mut remaining: u64,
) -> io::Result<()> {
    let mut buffer = [0_u8; COMMIT_LOSS_COPY_CHUNK_BYTES];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..chunk])?;
        writer.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;
    }
    writer.flush()
}

fn commit_loss_drain(reader: &mut TcpStream, mut remaining: u64) -> io::Result<()> {
    let mut buffer = [0_u8; COMMIT_LOSS_COPY_CHUNK_BYTES];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..chunk])?;
        remaining -= chunk as u64;
    }
    Ok(())
}

fn commit_loss_is_commit_query(payload: &[u8]) -> bool {
    payload == b"COMMIT\0"
}

fn commit_loss_shutdown_both(a: &TcpStream, b: &TcpStream) {
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}

/// Relays client-to-backend traffic, injecting [`CommitFaultPoint::BeforeCommitDispatch`]
/// by dropping the `COMMIT` message instead of forwarding it, or arming the
/// paired `backend_to_client` relay to intercept the response for
/// [`CommitFaultPoint::AfterBackendCommitAccepted`].
///
/// Every exit path, including a clean EOF or a forwarding failure, shuts
/// down both directions of this physical connection immediately so the
/// paired relay thread never idles until [`COMMIT_LOSS_IO_TIMEOUT`] elapses.
fn commit_loss_client_to_backend(
    mut reader: TcpStream,
    mut writer: TcpStream,
    state: &Arc<CommitLossProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) {
    commit_loss_client_to_backend_loop(&mut reader, &mut writer, state, awaiting_ack);
    commit_loss_shutdown_both(&reader, &writer);
}

fn commit_loss_client_to_backend_loop(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    state: &Arc<CommitLossProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) {
    loop {
        let (message_type, payload_len) = match commit_loss_read_header(reader) {
            Ok(Some(header)) => header,
            Ok(None) | Err(_) => return,
        };
        if message_type == b'Q' && payload_len <= COMMIT_LOSS_MAX_INSPECTED_MESSAGE_BYTES {
            let mut payload = vec![0_u8; payload_len as usize];
            if reader.read_exact(&mut payload).is_err() {
                return;
            }
            if commit_loss_is_commit_query(&payload) {
                let armed_point = state.armed.lock().unwrap().take();
                match armed_point {
                    Some(CommitFaultPoint::BeforeCommitDispatch) => {
                        state.fault_fired.store(true, Ordering::SeqCst);
                        return;
                    }
                    Some(CommitFaultPoint::AfterBackendCommitAccepted) => {
                        // Commit the paired relay to withholding *before* the
                        // COMMIT bytes can possibly reach the backend and
                        // produce a response. Setting this after forwarding
                        // would race a fast local reply: the paired thread
                        // could observe and forward the acknowledgement
                        // before seeing the arm.
                        awaiting_ack.store(true, Ordering::SeqCst);
                        if commit_loss_forward_message(writer, message_type, &payload).is_err() {
                            return;
                        }
                        continue;
                    }
                    None => {
                        if commit_loss_forward_message(writer, message_type, &payload).is_err() {
                            return;
                        }
                        continue;
                    }
                }
            }
            if commit_loss_forward_message(writer, message_type, &payload).is_err() {
                return;
            }
            continue;
        }
        if commit_loss_forward_header(writer, message_type, payload_len).is_err() {
            return;
        }
        if commit_loss_stream_copy(reader, writer, u64::from(payload_len)).is_err() {
            return;
        }
    }
}

/// Relays backend-to-client traffic. Once armed by
/// [`commit_loss_client_to_backend`] for
/// [`CommitFaultPoint::AfterBackendCommitAccepted`], this withholds every
/// message of the `COMMIT` response instead of forwarding it, recording
/// whether the backend actually sent a successful `CommandComplete("COMMIT")`
/// before the paired `ReadyForQuery` proves the round trip finished.
///
/// Every exit path, including a clean EOF or a forwarding failure, shuts
/// down both directions of this physical connection immediately so the
/// paired relay thread never idles until [`COMMIT_LOSS_IO_TIMEOUT`] elapses.
fn commit_loss_backend_to_client(
    mut reader: TcpStream,
    mut writer: TcpStream,
    state: &Arc<CommitLossProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) {
    commit_loss_backend_to_client_loop(&mut reader, &mut writer, state, awaiting_ack);
    commit_loss_shutdown_both(&reader, &writer);
}

fn commit_loss_backend_to_client_loop(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    state: &Arc<CommitLossProxyState>,
    awaiting_ack: &Arc<AtomicBool>,
) {
    let mut commit_complete_seen = false;
    loop {
        let (message_type, payload_len) = match commit_loss_read_header(reader) {
            Ok(Some(header)) => header,
            Ok(None) | Err(_) => return,
        };
        if awaiting_ack.load(Ordering::SeqCst) {
            if payload_len > COMMIT_LOSS_MAX_INSPECTED_MESSAGE_BYTES {
                if commit_loss_drain(reader, u64::from(payload_len)).is_err() {
                    return;
                }
                continue;
            }
            let mut payload = vec![0_u8; payload_len as usize];
            if reader.read_exact(&mut payload).is_err() {
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
            // Any other message while awaiting (for example an unexpected
            // ErrorResponse) is dropped too: the fault always severs the
            // connection once armed, and only a genuine
            // `CommandComplete("COMMIT")` before `ReadyForQuery` is reported
            // as a backend acceptance.
            continue;
        }
        if commit_loss_forward_header(writer, message_type, payload_len).is_err() {
            return;
        }
        if commit_loss_stream_copy(reader, writer, u64::from(payload_len)).is_err() {
            return;
        }
    }
}

/// Resolves the exact TCP address the proxy must dial for one PostgreSQL
/// connection string.
fn commit_loss_backend_addr(database_url: &str) -> SocketAddr {
    let config: Config = database_url.parse().unwrap();
    let host = match config.get_hosts().first() {
        Some(Host::Tcp(host)) => host.clone(),
        _ => panic!("commit-loss proxy requires a TCP host"),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    (host.as_str(), port)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
}

/// Builds a `NoTls`, `SslMode::Disable` config pointed at the proxy instead
/// of the real backend, preserving only the credentials/database identity
/// needed to authenticate.
fn commit_loss_proxied_config(database_url: &str, proxy_addr: SocketAddr) -> Config {
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
        .host(&proxy_addr.ip().to_string())
        .port(proxy_addr.port())
        .ssl_mode(SslMode::Disable)
        .application_name("sunrise-edge-pr76-commit-loss");
    proxied
}

struct CommitLossPostgresFixture {
    store: Arc<PostgresDurableStore<TestPostgresManager>>,
    namespace: PostgresNamespace,
    operator: Mutex<Client>,
    initial_fence: WriterFenceGeneration,
    proxy: CommitLossProxy,
}

impl DurableStoreFixture for CommitLossPostgresFixture {
    type Store = PostgresDurableStore<TestPostgresManager>;

    fn store(&self) -> Arc<Self::Store> {
        Arc::clone(&self.store)
    }

    fn domain(&self) -> AtomicityDomainId {
        self.namespace.domain()
    }

    fn initial_writer_fence(&self) -> WriterFenceGeneration {
        self.initial_fence
    }

    fn live_context(
        &self,
        writer_fence: WriterFenceGeneration,
        correlation_byte: u8,
        budget: Duration,
    ) -> ConformanceResult<DurableOperationContext> {
        let now_millis: u64 = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| ConformanceFailure::new("commit-loss-fixture", error.to_string()))?
                .as_millis(),
        )
        .map_err(|_| ConformanceFailure::new("commit-loss-fixture", "clock exceeds u64"))?;
        let budget_millis: u64 = u64::try_from(budget.as_millis())
            .map_err(|_| ConformanceFailure::new("commit-loss-fixture", "budget exceeds u64"))?;
        let deadline: u64 = now_millis.checked_add(budget_millis).ok_or_else(|| {
            ConformanceFailure::new("commit-loss-fixture", "deadline exceeds u64")
        })?;
        Ok(DurableOperationContext::new(
            writer_fence,
            StorageDeadline::new(deadline).ok_or_else(|| {
                ConformanceFailure::new("commit-loss-fixture", "deadline must be non-zero")
            })?,
            StorageCorrelationId::new([correlation_byte; 16]).ok_or_else(|| {
                ConformanceFailure::new("commit-loss-fixture", "correlation ID must be non-zero")
            })?,
        ))
    }

    fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> ConformanceResult<()> {
        let mut operator = self.operator.lock().map_err(|_| {
            ConformanceFailure::new("commit-loss-fixture", "operator client lock poisoned")
        })?;
        let metadata =
            advance_postgres_writer_fence(&mut operator, &self.namespace, expected, next).map_err(
                |error| ConformanceFailure::new("commit-loss-fixture", error.to_string()),
            )?;
        if metadata.writer_fence() != next {
            return Err(ConformanceFailure::new(
                "commit-loss-fixture",
                "operator fence advance returned the wrong generation",
            ));
        }
        Ok(())
    }
}

impl CommitLossFixture for CommitLossPostgresFixture {
    fn arm_commit_loss(&self, fault_point: CommitFaultPoint) -> ConformanceResult<()> {
        self.proxy.arm(fault_point);
        Ok(())
    }

    fn commit_loss_fired(&self) -> ConformanceResult<bool> {
        Ok(self.proxy.fault_fired())
    }

    fn backend_commit_accepted(&self) -> ConformanceResult<bool> {
        Ok(self.proxy.backend_commit_accepted())
    }
}

struct PostgresConformanceFixture {
    store: Arc<PostgresDurableStore<TestPostgresManager>>,
    namespace: PostgresNamespace,
    operator: Mutex<Client>,
    initial_fence: WriterFenceGeneration,
}

impl DurableStoreFixture for PostgresConformanceFixture {
    type Store = PostgresDurableStore<TestPostgresManager>;

    fn store(&self) -> Arc<Self::Store> {
        Arc::clone(&self.store)
    }

    fn domain(&self) -> AtomicityDomainId {
        self.namespace.domain()
    }

    fn initial_writer_fence(&self) -> WriterFenceGeneration {
        self.initial_fence
    }

    fn live_context(
        &self,
        writer_fence: WriterFenceGeneration,
        correlation_byte: u8,
        budget: Duration,
    ) -> ConformanceResult<DurableOperationContext> {
        let now_millis: u64 = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| ConformanceFailure::new("postgres-fixture", error.to_string()))?
                .as_millis(),
        )
        .map_err(|_| ConformanceFailure::new("postgres-fixture", "clock exceeds u64"))?;
        let budget_millis: u64 = u64::try_from(budget.as_millis())
            .map_err(|_| ConformanceFailure::new("postgres-fixture", "budget exceeds u64"))?;
        let deadline: u64 = now_millis
            .checked_add(budget_millis)
            .ok_or_else(|| ConformanceFailure::new("postgres-fixture", "deadline exceeds u64"))?;
        Ok(DurableOperationContext::new(
            writer_fence,
            StorageDeadline::new(deadline).ok_or_else(|| {
                ConformanceFailure::new("postgres-fixture", "deadline must be non-zero")
            })?,
            StorageCorrelationId::new([correlation_byte; 16]).ok_or_else(|| {
                ConformanceFailure::new("postgres-fixture", "correlation ID must be non-zero")
            })?,
        ))
    }

    fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> ConformanceResult<()> {
        let mut operator = self.operator.lock().map_err(|_| {
            ConformanceFailure::new("postgres-fixture", "operator client lock poisoned")
        })?;
        let metadata =
            advance_postgres_writer_fence(&mut operator, &self.namespace, expected, next)
                .map_err(|error| ConformanceFailure::new("postgres-fixture", error.to_string()))?;
        if metadata.writer_fence() != next {
            return Err(ConformanceFailure::new(
                "postgres-fixture",
                "operator fence advance returned the wrong generation",
            ));
        }
        Ok(())
    }
}

impl SchemaSkewFixture for PostgresConformanceFixture {
    fn install_unsupported_schema(&self) -> ConformanceResult<()> {
        let unsupported_generation: u64 = POSTGRES_SCHEMA_GENERATION
            .get()
            .checked_add(1)
            .ok_or_else(|| {
                ConformanceFailure::new("postgres-fixture", "schema generation overflow")
            })?;
        self.set_schema_generation(unsupported_generation)
    }

    fn restore_supported_schema(&self) -> ConformanceResult<()> {
        self.set_schema_generation(POSTGRES_SCHEMA_GENERATION.get())
    }
}

impl PostgresConformanceFixture {
    fn set_schema_generation(&self, generation: u64) -> ConformanceResult<()> {
        let mut operator = self.operator.lock().map_err(|_| {
            ConformanceFailure::new("postgres-fixture", "operator client lock poisoned")
        })?;
        let updated: u64 = operator
            .execute(
                "UPDATE sunrise_edge.storage_metadata
                 SET schema_generation = CAST(CAST($1 AS TEXT) AS NUMERIC),
                     compatibility_min_generation = CAST(CAST($1 AS TEXT) AS NUMERIC),
                     compatibility_max_generation = CAST(CAST($1 AS TEXT) AS NUMERIC)
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4",
                &[
                    &generation.to_string(),
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                ],
            )
            .map_err(|error| ConformanceFailure::new("postgres-fixture", error.to_string()))?;
        if updated != 1 {
            return Err(ConformanceFailure::new(
                "postgres-fixture",
                "schema generation update did not affect exactly one namespace",
            ));
        }
        Ok(())
    }

    fn set_migration_phase(&self, phase: i16) -> ConformanceResult<()> {
        let mut operator = self.operator.lock().map_err(|_| {
            ConformanceFailure::new("postgres-fixture", "operator client lock poisoned")
        })?;
        let updated: u64 = operator
            .execute(
                "UPDATE sunrise_edge.storage_metadata
                 SET migration_phase_id = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4",
                &[
                    &phase,
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                ],
            )
            .map_err(|error| ConformanceFailure::new("postgres-fixture", error.to_string()))?;
        if updated != 1 {
            return Err(ConformanceFailure::new(
                "postgres-fixture",
                "migration phase update did not affect exactly one namespace",
            ));
        }
        Ok(())
    }
}

fn postgres_conformance_fixture(
    database_url: &str,
    pool: Pool<TestPostgresManager>,
    namespace: PostgresNamespace,
    initial_fence: WriterFenceGeneration,
) -> PostgresConformanceFixture {
    let mut operator = Client::connect(database_url, NoTls).unwrap();
    bootstrap_namespace(
        &mut operator,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        initial_fence,
    )
    .unwrap();
    PostgresConformanceFixture {
        store: Arc::new(PostgresDurableStore::new(
            pool,
            namespace.clone(),
            PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
        )),
        namespace,
        operator: Mutex::new(operator),
        initial_fence,
    }
}

#[test]
fn postgres_schema_and_durable_store_conformance() {
    let Some(url) = std::env::var_os("SUNRISE_EDGE_TEST_POSTGRES_URL") else {
        eprintln!("skipping live PostgreSQL conformance: SUNRISE_EDGE_TEST_POSTGRES_URL is unset");
        return;
    };
    let mut client = Client::connect(&url.to_string_lossy(), NoTls).unwrap();
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, TEST_DATABASE,
        "refusing to reset a non-test database"
    );
    client
        .batch_execute("DROP SCHEMA IF EXISTS sunrise_edge CASCADE")
        .unwrap();

    client
        .batch_execute(
            "CREATE SCHEMA sunrise_edge;
             CREATE TABLE sunrise_edge.unclaimed (value INTEGER NOT NULL);",
        )
        .unwrap();
    assert!(matches!(
        apply_initial_schema(&mut client),
        Err(PostgresSchemaError::SchemaNotApplied)
    ));
    let unclaimed_still_exists: bool = client
        .query_one(
            "SELECT to_regclass('sunrise_edge.unclaimed') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(unclaimed_still_exists);
    client
        .batch_execute("DROP SCHEMA sunrise_edge CASCADE")
        .unwrap();

    apply_initial_schema(&mut client).unwrap();
    apply_initial_schema(&mut client).unwrap();
    verify_initial_schema(&mut client).unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new("postgres-conformance").unwrap(),
        ValidatorId::new([0x11; 32]),
        AtomicityDomainId::new([0x22; 32]).unwrap(),
    )
    .unwrap();
    let initial_fence = WriterFenceGeneration::new(7).unwrap();
    let metadata = bootstrap_namespace(
        &mut client,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        initial_fence,
    )
    .unwrap();
    assert_eq!(metadata.writer_fence(), initial_fence);
    assert_eq!(metadata.commit_sequence(), 0);
    assert_eq!(
        inspect_namespace(&mut client, &namespace).unwrap(),
        Some(metadata)
    );

    assert!(matches!(
        bootstrap_namespace(
            &mut client,
            &namespace,
            POSTGRES_SCHEMA_GENERATION,
            WriterFenceGeneration::new(8).unwrap(),
        ),
        Err(PostgresSchemaError::NamespaceMetadataMismatch)
    ));

    let tables: Vec<String> = client
        .query(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema = 'sunrise_edge' ORDER BY table_name",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        tables,
        vec![
            "checkpoints",
            "migration_jobs",
            "object_heads",
            "object_versions",
            "outbox_batches",
            "outbox_delivery",
            "outbox_delivery_attempts",
            "outbox_messages",
            "request_receipts",
            "schema_migrations",
            "state_records",
            "storage_metadata",
        ]
    );
    let due_index: bool = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE schemaname = 'sunrise_edge' AND indexname = 'outbox_delivery_due'
            )",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(due_index);

    let over_u64 = client.execute(
        "UPDATE sunrise_edge.storage_metadata
         SET writer_fence_generation = CAST(CAST($1 AS TEXT) AS NUMERIC)
         WHERE chain_id_bytes = $2 AND validator_id = $3 AND atomicity_domain_id = $4",
        &[
            &"18446744073709551616",
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
        ],
    );
    assert_eq!(
        over_u64.unwrap_err().code(),
        Some(&SqlState::CHECK_VIOLATION)
    );

    let zero_domain = [0_u8; 32];
    let zero_domain_insert = client.execute(
        "INSERT INTO sunrise_edge.storage_metadata (
             chain_id_bytes, validator_id, atomicity_domain_id, schema_identity,
             schema_generation, migration_phase_id, compatibility_min_generation,
             compatibility_max_generation, writer_fence_generation, commit_sequence
         ) SELECT
             $1, $2, $3, schema_identity, 1, 5, 1, 1, 1, 0
         FROM sunrise_edge.schema_migrations WHERE migration_id = 1",
        &[
            &b"zero-domain".as_slice(),
            &&namespace.validator_id().as_bytes()[..],
            &&zero_domain[..],
        ],
    );
    assert_eq!(
        zero_domain_insert.unwrap_err().code(),
        Some(&SqlState::CHECK_VIOLATION)
    );

    let request_id = [0x33_u8; 32];
    let event_digest = [0x44_u8; 32];
    client
        .execute(
            "INSERT INTO sunrise_edge.request_receipts (
                 chain_id_bytes, validator_id, atomicity_domain_id, request_id,
                 event_digest_algorithm_id, event_digest_bytes, terminal_result_id,
                 canonical_response_bytes, commit_sequence
             ) VALUES ($1, $2, $3, $4, 1, $5, 1, $6, 1)",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&request_id[..],
                &&event_digest[..],
                &b"response".as_slice(),
            ],
        )
        .unwrap();
    let mismatched_event_digest = [0x45_u8; 32];
    let mismatched_batch = client.execute(
        "INSERT INTO sunrise_edge.outbox_batches (
             chain_id_bytes, validator_id, atomicity_domain_id, request_id,
             event_digest_algorithm_id, event_digest_bytes, message_count,
             creation_commit_sequence
         ) VALUES ($1, $2, $3, $4, 1, $5, 0, 1)",
        &[
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
            &&request_id[..],
            &&mismatched_event_digest[..],
        ],
    );
    assert_eq!(
        mismatched_batch.unwrap_err().code(),
        Some(&SqlState::FOREIGN_KEY_VIOLATION)
    );

    let object_id = [0x55_u8; 32];
    let object_digest = [0x66_u8; 32];
    client
        .execute(
            "INSERT INTO sunrise_edge.object_versions (
                 chain_id_bytes, validator_id, atomicity_domain_id, object_id,
                 object_version, digest_algorithm_id, digest_bytes, schema_version,
                 type_id, created_checkpoint, inline_canonical_bytes
             ) VALUES ($1, $2, $3, $4, 1, 1, $5, 1, 1, 0, $6)",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&object_id[..],
                &&object_digest[..],
                &b"object".as_slice(),
            ],
        )
        .unwrap();
    let mismatched_object_digest = [0x67_u8; 32];
    let mismatched_head = client.execute(
        "INSERT INTO sunrise_edge.object_heads (
             chain_id_bytes, validator_id, atomicity_domain_id, object_id,
             current_version, digest_algorithm_id, digest_bytes, revision, tombstone
         ) VALUES ($1, $2, $3, $4, 1, 1, $5, 1, FALSE)",
        &[
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
            &&object_id[..],
            &&mismatched_object_digest[..],
        ],
    );
    assert_eq!(
        mismatched_head.unwrap_err().code(),
        Some(&SqlState::FOREIGN_KEY_VIOLATION)
    );

    let mut database_config: Config = url.to_string_lossy().parse().unwrap();
    database_config.application_name("sunrise-edge-pr72-test");
    let pool = build_postgres_pool(
        database_config,
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(1).unwrap(),
            Duration::from_secs(2),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();
    let store = Arc::new(PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    ));
    let now_millis = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let context = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(now_millis + 60_000).unwrap(),
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    );
    let state_key = b"application/state".to_vec();
    let missing = store
        .get_versioned_durable(&context, namespace.domain(), &state_key)
        .unwrap();
    assert_eq!(missing.revision(), StateRevision::INITIAL);
    assert_eq!(missing.value(), None);

    let state_only_key = b"state-only".to_vec();
    let state_only = AtomicStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(state_only_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                state_only_key.clone(),
                StateMutation::Put(b"state-only-value".to_vec()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, state_only),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, namespace.domain(), &state_only_key)
            .unwrap()
            .value(),
        Some(b"state-only-value".as_slice())
    );

    let durable_request_id = DurableRequestId::new([0x71; 32]).unwrap();
    let durable_event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x72; 32]);
    let receipt = DurableRequestReceipt::new(
        durable_request_id,
        durable_event_digest,
        b"canonical-receipt".to_vec(),
    )
    .unwrap();
    let message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0x73; 32]),
        b"canonical-outbound-event".to_vec(),
    )
    .unwrap();
    let state = DurableStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(state_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(state_key.clone(), StateMutation::Put(b"state-v1".to_vec()))
                .unwrap(),
        ],
    )
    .unwrap();
    let invocation = DurableInvocationTransaction::new(
        namespace.domain(),
        Some(state),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(
            DurableOutboxBatch::new(durable_request_id, durable_event_digest, vec![message])
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, invocation.clone()),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.commit_invocation(&context, invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    let committed_state = store
        .get_versioned_durable(&context, namespace.domain(), &state_key)
        .unwrap();
    assert_eq!(committed_state.revision(), StateRevision::new(1));
    assert_eq!(committed_state.value(), Some(b"state-v1".as_slice()));
    assert_eq!(
        store
            .get_request_receipt(&context, namespace.domain(), durable_request_id)
            .unwrap(),
        Some(receipt)
    );

    let conflict_request_id = DurableRequestId::new([0x74; 32]).unwrap();
    let conflict_invocation = DurableInvocationTransaction::new(
        namespace.domain(),
        Some(
            DurableStateTransaction::new(
                namespace.domain(),
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(state_key.clone(), StateRevision::INITIAL).unwrap(),
                ])
                .unwrap(),
                vec![
                    StateMutationEntry::new(
                        state_key.clone(),
                        StateMutation::Put(b"must-not-commit".to_vec()),
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        ),
        DurableObjectChanges::empty(),
        DurableRequestReceipt::new(
            conflict_request_id,
            Digest32::new(HashAlgorithmId::Sha2_256, [0x75; 32]),
            b"conflicting-receipt".to_vec(),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    assert!(matches!(
        store.commit_invocation(&context, conflict_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            current_revision,
            ..
        }) if current_revision == StateRevision::new(1)
    ));
    assert_eq!(
        store
            .get_request_receipt(&context, namespace.domain(), conflict_request_id)
            .unwrap(),
        None
    );

    let read_only_request_id = DurableRequestId::new([0x76; 32]).unwrap();
    let read_only_invocation = DurableInvocationTransaction::new(
        namespace.domain(),
        Some(
            DurableStateTransaction::new(
                namespace.domain(),
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(state_key.clone(), StateRevision::new(1)).unwrap(),
                ])
                .unwrap(),
                Vec::new(),
            )
            .unwrap(),
        ),
        DurableObjectChanges::empty(),
        DurableRequestReceipt::new(
            read_only_request_id,
            Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]),
            b"read-only-receipt".to_vec(),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, read_only_invocation),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, namespace.domain(), &state_key)
            .unwrap()
            .revision(),
        StateRevision::new(1)
    );

    let stale_context = DurableOperationContext::new(
        WriterFenceGeneration::new(initial_fence.get() + 1).unwrap(),
        StorageDeadline::new(now_millis + 60_000).unwrap(),
        StorageCorrelationId::new([0x62; 16]).unwrap(),
    );
    assert!(matches!(
        store.get_versioned_durable(&stale_context, namespace.domain(), &state_key),
        Err(DurableReadError::WriterFenced { active_generation })
            if active_generation == initial_fence
    ));
    let expired_context = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(now_millis.saturating_sub(1)).unwrap(),
        StorageCorrelationId::new([0x63; 16]).unwrap(),
    );
    assert!(matches!(
        store.get_request_receipt(&expired_context, namespace.domain(), durable_request_id),
        Err(DurableReadError::DeadlineExceeded)
    ));

    let persisted_counts_row = client
        .query_one(
            "SELECT
                 (SELECT COUNT(*) FROM sunrise_edge.state_records
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND state_key = $4),
                 (SELECT COUNT(*) FROM sunrise_edge.request_receipts
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND request_id IN ($5, $6)),
                 (SELECT COUNT(*) FROM sunrise_edge.outbox_messages
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND request_id = $5),
                 (SELECT COUNT(*) FROM sunrise_edge.outbox_delivery
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND request_id = $5)",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &state_key.as_slice(),
                &&durable_request_id.as_bytes()[..],
                &&read_only_request_id.as_bytes()[..],
            ],
        )
        .unwrap();
    let persisted_counts = (
        persisted_counts_row.get::<_, i64>(0),
        persisted_counts_row.get::<_, i64>(1),
        persisted_counts_row.get::<_, i64>(2),
        persisted_counts_row.get::<_, i64>(3),
    );
    assert_eq!(persisted_counts, (1, 2, 1, 1));

    let mut pooled = pool.get().unwrap();
    let statement_timeout: String = pooled
        .query_one("SHOW statement_timeout", &[])
        .unwrap()
        .get(0);
    let lock_timeout: String = pooled.query_one("SHOW lock_timeout", &[]).unwrap().get(0);
    assert_eq!(statement_timeout, "0");
    assert_eq!(lock_timeout, "0");
    drop(pooled);

    let held_pool_connection = pool.get().unwrap();
    let pool_wait_now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let pool_wait_context: DurableOperationContext = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(pool_wait_now.checked_add(100).unwrap()).unwrap(),
        StorageCorrelationId::new([0x64; 16]).unwrap(),
    );
    assert_eq!(
        store.get_versioned_durable(
            &pool_wait_context,
            namespace.domain(),
            b"pool-wait-deadline",
        ),
        Err(DurableReadError::DeadlineExceeded)
    );
    drop(held_pool_connection);

    let mut locker = Client::connect(&url.to_string_lossy(), NoTls).unwrap();
    let mut locker_transaction = locker.transaction().unwrap();
    locker_transaction
        .execute(
            "UPDATE sunrise_edge.storage_metadata
             SET operator_metadata = operator_metadata
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();
    let lock_deadline_key: Vec<u8> = b"lock-wait-deadline".to_vec();
    let lock_wait_now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let lock_wait_context: DurableOperationContext = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(lock_wait_now.checked_add(100).unwrap()).unwrap(),
        StorageCorrelationId::new([0x65; 16]).unwrap(),
    );
    let lock_wait_transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(lock_deadline_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                lock_deadline_key.clone(),
                StateMutation::Put(b"must-not-commit".to_vec()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&lock_wait_context, lock_wait_transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
    let retry_key = b"serialization-retry".to_vec();
    let retry_transaction = AtomicStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(retry_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(retry_key.clone(), StateMutation::Put(b"retried".to_vec()))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let retry_store = Arc::clone(&store);
    let retry_context = context;
    let retry_handle =
        thread::spawn(move || retry_store.commit_durable(&retry_context, retry_transaction));
    let mut observed_lock_wait = false;
    for _ in 0..2_000 {
        observed_lock_wait = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                     WHERE application_name = 'sunrise-edge-pr72-test'
                       AND wait_event_type = 'Lock'
                 )",
                &[],
            )
            .unwrap()
            .get(0);
        if observed_lock_wait {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        observed_lock_wait,
        "adapter never reached the fenced metadata lock"
    );
    locker_transaction.commit().unwrap();
    assert_eq!(
        retry_handle.join().unwrap(),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, namespace.domain(), &retry_key)
            .unwrap()
            .value(),
        Some(b"retried".as_slice())
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, namespace.domain(), &lock_deadline_key)
            .unwrap(),
        runtime::VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
    );

    let commit_outbox = |request_byte: u8, payloads: &[&[u8]]| -> DurableRequestId {
        let request_id = DurableRequestId::new([request_byte; 32]).unwrap();
        let event_digest = Digest32::new(
            HashAlgorithmId::Sha2_256,
            [request_byte.wrapping_add(1); 32],
        );
        let messages: Vec<DurableOutboxMessage> = payloads
            .iter()
            .enumerate()
            .map(|(index, payload)| {
                let index_byte = u8::try_from(index).unwrap();
                DurableOutboxMessage::new(
                    Digest32::new(
                        HashAlgorithmId::Sha3_256,
                        [request_byte.wrapping_add(index_byte).wrapping_add(2); 32],
                    ),
                    payload.to_vec(),
                )
                .unwrap()
            })
            .collect();
        let invocation = DurableInvocationTransaction::new(
            namespace.domain(),
            None,
            DurableObjectChanges::empty(),
            DurableRequestReceipt::new(request_id, event_digest, vec![request_byte]).unwrap(),
            Some(DurableOutboxBatch::new(request_id, event_digest, messages).unwrap()),
        )
        .unwrap();
        assert_eq!(
            store.commit_invocation(&context, invocation),
            DurableCommitOutcome::Committed
        );
        request_id
    };
    let lease =
        |byte: u8| -> DurableOutboxLeaseId { DurableOutboxLeaseId::new([byte; 32]).unwrap() };

    let preexisting_lease = lease(0x8f);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                durable_request_id,
                1_000,
                preexisting_lease,
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                durable_request_id,
                0,
                preexisting_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let older_request = commit_outbox(0x80, &[b"older-due"]);
    let exact_request = commit_outbox(0x81, &[b"exact-request"]);
    let exact_lease = lease(0x90);
    let exact_claim_request = RequestOutboxClaimRequest::new(
        namespace.domain(),
        exact_request,
        1_000,
        exact_lease,
        2_000,
    )
    .unwrap();
    let exact_claim = match store.claim_request_outbox(&context, exact_claim_request) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("exact request claim failed: {outcome:?}"),
    };
    assert_eq!(exact_claim.request_id(), exact_request);
    assert_eq!(exact_claim.message_index(), 0);
    assert_eq!(exact_claim.canonical_payload(), b"exact-request");
    let reconciled_claim = store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            namespace.domain(),
            exact_request,
            1_001,
            exact_lease,
            3_000,
        )
        .unwrap(),
    );
    assert_eq!(
        reconciled_claim,
        DurableOutboxClaimOutcome::Claimed(exact_claim.clone())
    );
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                older_request,
                1_001,
                exact_lease,
                3_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );
    let other_domain = AtomicityDomainId::new([0x23; 32]).unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(other_domain, exact_request, 1_001, exact_lease, 3_000,)
                .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse)
    );
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(namespace.domain(), exact_request, 0, exact_lease,),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let older_lease = lease(0x91);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                older_request,
                1_000,
                older_lease,
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(namespace.domain(), older_request, 0, older_lease,),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let later_ordered_request = commit_outbox(0x84, &[b"later-ordered"]);
    let first_ordered_request = commit_outbox(0x83, &[b"first-ordered"]);
    let first_ordered_lease = lease(0x92);
    let first_ordered_claim = match store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(namespace.domain(), 1_000, first_ordered_lease, 2_000).unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("stable due claim failed: {outcome:?}"),
    };
    assert_eq!(first_ordered_claim.request_id(), first_ordered_request);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                first_ordered_request,
                0,
                first_ordered_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    let later_ordered_lease = lease(0x93);
    let later_ordered_claim = match store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(namespace.domain(), 1_000, later_ordered_lease, 2_000).unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("second stable due claim failed: {outcome:?}"),
    };
    assert_eq!(later_ordered_claim.request_id(), later_ordered_request);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                later_ordered_request,
                0,
                later_ordered_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let multi_request = commit_outbox(0x85, &[b"multi-0", b"multi-1"]);
    let first_multi_lease = lease(0x94);
    let first_multi_claim = match store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            namespace.domain(),
            multi_request,
            1_000,
            first_multi_lease,
            2_000,
        )
        .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("first multi-message claim failed: {outcome:?}"),
    };
    assert_eq!(first_multi_claim.message_index(), 0);
    let first_multi_acknowledgement =
        DurableOutboxAcknowledgement::new(namespace.domain(), multi_request, 0, first_multi_lease);
    assert_eq!(
        store.acknowledge_outbox(&context, first_multi_acknowledgement),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    let second_multi_lease = lease(0x95);
    let second_multi_claim = match store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            namespace.domain(),
            multi_request,
            1_000,
            second_multi_lease,
            2_000,
        )
        .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("second multi-message claim failed: {outcome:?}"),
    };
    assert_eq!(second_multi_claim.message_index(), 1);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                multi_request,
                1,
                second_multi_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    assert_eq!(
        store.acknowledge_outbox(&context, first_multi_acknowledgement),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    let completed_row = client
        .query_one(
            "SELECT next_message_index, state_id
             FROM sunrise_edge.outbox_delivery
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&multi_request.as_bytes()[..],
            ],
        )
        .unwrap();
    assert_eq!(completed_row.get::<_, i32>(0), 2);
    assert_eq!(completed_row.get::<_, i16>(1), 2);
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                multi_request,
                1_000,
                lease(0x96),
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    let expiry_request = commit_outbox(0x86, &[b"expiry"]);
    let expired_lease = lease(0x97);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                expiry_request,
                1_000,
                expired_lease,
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    let replacement_lease = lease(0x98);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                expiry_request,
                2_000,
                replacement_lease,
                3_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    let expired_attempt_state: i16 = client
        .query_one(
            "SELECT state_id FROM sunrise_edge.outbox_delivery_attempts
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND lease_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&expired_lease.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(expired_attempt_state, 3);
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                expiry_request,
                0,
                replacement_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let serialization_request = commit_outbox(0x8b, &[b"claim-serialization-retry"]);
    let mut outbox_locker = Client::connect(&url.to_string_lossy(), NoTls).unwrap();
    let mut outbox_locker_transaction = outbox_locker.transaction().unwrap();
    outbox_locker_transaction
        .execute(
            "UPDATE sunrise_edge.outbox_delivery
             SET last_error_class_id = last_error_class_id
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&serialization_request.as_bytes()[..],
            ],
        )
        .unwrap();
    let serialization_store = Arc::clone(&store);
    let serialization_context = context;
    let serialization_domain = namespace.domain();
    let serialization_lease = lease(0x9f);
    let serialization_handle = thread::spawn(move || {
        serialization_store.claim_request_outbox(
            &serialization_context,
            RequestOutboxClaimRequest::new(
                serialization_domain,
                serialization_request,
                1_000,
                serialization_lease,
                2_000,
            )
            .unwrap(),
        )
    });
    let mut observed_outbox_lock_wait = false;
    for _ in 0..2_000 {
        observed_outbox_lock_wait = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                     WHERE application_name = 'sunrise-edge-pr72-test'
                       AND wait_event_type = 'Lock'
                 )",
                &[],
            )
            .unwrap()
            .get(0);
        if observed_outbox_lock_wait {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        observed_outbox_lock_wait,
        "adapter never reached the outbox delivery lock"
    );
    outbox_locker_transaction.commit().unwrap();
    assert!(matches!(
        serialization_handle.join().unwrap(),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                serialization_request,
                0,
                serialization_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let authority_request = commit_outbox(0x87, &[b"authority"]);
    assert!(matches!(
        store.claim_request_outbox(
            &stale_context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                authority_request,
                1_000,
                lease(0x99),
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::WriterFenced {
            active_generation
        }) if active_generation == initial_fence
    ));
    assert_eq!(
        store.claim_request_outbox(
            &expired_context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                authority_request,
                1_000,
                lease(0x9a),
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(
            DurableOutboxClaimRejection::DeadlineExceededBeforeCommit
        )
    );
    let authority_row = client
        .query_one(
            "SELECT active_lease_id, attempt_count::TEXT, revision::TEXT
             FROM sunrise_edge.outbox_delivery
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&authority_request.as_bytes()[..],
            ],
        )
        .unwrap();
    assert_eq!(authority_row.get::<_, Option<Vec<u8>>>(0), None);
    assert_eq!(authority_row.get::<_, String>(1), "0");
    assert_eq!(authority_row.get::<_, String>(2), "1");
    let authority_lease = lease(0x9b);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                authority_request,
                1_000,
                authority_lease,
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    let authority_ack = DurableOutboxAcknowledgement::new(
        namespace.domain(),
        authority_request,
        0,
        authority_lease,
    );
    assert!(matches!(
        store.acknowledge_outbox(&stale_context, authority_ack),
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::WriterFenced { active_generation }
        ) if active_generation == initial_fence
    ));
    assert_eq!(
        store.acknowledge_outbox(&expired_context, authority_ack),
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit
        )
    );
    assert_eq!(
        store.acknowledge_outbox(&context, authority_ack),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let attempt_overflow_request = commit_outbox(0x88, &[b"attempt-overflow"]);
    client
        .execute(
            "UPDATE sunrise_edge.outbox_delivery
             SET attempt_count = 18446744073709551615
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&attempt_overflow_request.as_bytes()[..],
            ],
        )
        .unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                attempt_overflow_request,
                1_000,
                lease(0x9c),
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::ArithmeticOverflow)
    );
    let overflow_attempt_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sunrise_edge.outbox_delivery_attempts
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&attempt_overflow_request.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(overflow_attempt_count, 0);

    let revision_overflow_request = commit_outbox(0x89, &[b"revision-overflow"]);
    client
        .execute(
            "UPDATE sunrise_edge.outbox_delivery
             SET revision = 18446744073709551615
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&revision_overflow_request.as_bytes()[..],
            ],
        )
        .unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                revision_overflow_request,
                1_000,
                lease(0x9d),
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::ArithmeticOverflow)
    );
    let overflow_revision_attempt_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM sunrise_edge.outbox_delivery_attempts
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&revision_overflow_request.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(overflow_revision_attempt_count, 0);

    let acknowledgement_overflow_request = commit_outbox(0x8a, &[b"ack-overflow"]);
    let acknowledgement_overflow_lease = lease(0x9e);
    assert!(matches!(
        store.claim_request_outbox(
            &context,
            RequestOutboxClaimRequest::new(
                namespace.domain(),
                acknowledgement_overflow_request,
                1_000,
                acknowledgement_overflow_lease,
                2_000,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    client
        .execute(
            "UPDATE sunrise_edge.outbox_delivery
             SET revision = 18446744073709551615
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&acknowledgement_overflow_request.as_bytes()[..],
            ],
        )
        .unwrap();
    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(
                namespace.domain(),
                acknowledgement_overflow_request,
                0,
                acknowledgement_overflow_lease,
            ),
        ),
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::ArithmeticOverflow
        )
    );
    let overflow_ack_attempt_state: i16 = client
        .query_one(
            "SELECT state_id FROM sunrise_edge.outbox_delivery_attempts
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3 AND lease_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&acknowledgement_overflow_lease.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(overflow_ack_attempt_state, 1);

    let mut pooled_after_outbox = pool.get().unwrap();
    let statement_timeout_after_outbox: String = pooled_after_outbox
        .query_one("SHOW statement_timeout", &[])
        .unwrap()
        .get(0);
    let lock_timeout_after_outbox: String = pooled_after_outbox
        .query_one("SHOW lock_timeout", &[])
        .unwrap()
        .get(0);
    assert_eq!(statement_timeout_after_outbox, "0");
    assert_eq!(lock_timeout_after_outbox, "0");
    drop(pooled_after_outbox);

    client
        .execute(
            "UPDATE sunrise_edge.storage_metadata
             SET commit_sequence = 18446744073709551615
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();
    let overflow_key = b"commit-sequence-overflow".to_vec();
    let overflow_transaction = AtomicStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(overflow_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                overflow_key,
                StateMutation::Put(b"must-not-commit".to_vec()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, overflow_transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::CommitSequenceOverflow)
    );

    let database_url: String = url.to_string_lossy().into_owned();
    let mut conformance_config: Config = database_url.parse().unwrap();
    conformance_config.application_name("sunrise-edge-pr74-conformance");
    let conformance_pool: Pool<TestPostgresManager> = build_postgres_pool(
        conformance_config,
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(4).unwrap(),
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();

    let conformance_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-shared-conformance").unwrap(),
        ValidatorId::new([0xA1; 32]),
        AtomicityDomainId::new([0xA2; 32]).unwrap(),
    )
    .unwrap();
    let conformance_fence = WriterFenceGeneration::new(31).unwrap();
    let missing_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-missing-fence-namespace").unwrap(),
        ValidatorId::new([0xAF; 32]),
        AtomicityDomainId::new([0xB0; 32]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        advance_postgres_writer_fence(
            &mut client,
            &missing_namespace,
            conformance_fence,
            WriterFenceGeneration::new(32).unwrap(),
        ),
        Err(PostgresSchemaError::NamespaceMetadataMismatch)
    ));
    let conformance_fixture = postgres_conformance_fixture(
        &database_url,
        conformance_pool.clone(),
        conformance_namespace,
        conformance_fence,
    );
    {
        let mut conformance_operator = conformance_fixture.operator.lock().unwrap();
        assert!(matches!(
            advance_postgres_writer_fence(
                &mut conformance_operator,
                &conformance_fixture.namespace,
                conformance_fence,
                conformance_fence,
            ),
            Err(PostgresSchemaError::WriterFenceNotAdvanced { .. })
        ));
        assert!(matches!(
            advance_postgres_writer_fence(
                &mut conformance_operator,
                &conformance_fixture.namespace,
                WriterFenceGeneration::new(30).unwrap(),
                WriterFenceGeneration::new(32).unwrap(),
            ),
            Err(PostgresSchemaError::WriterFenceMismatch {
                expected,
                actual,
            }) if expected == WriterFenceGeneration::new(30).unwrap()
                && actual == conformance_fence
        ));
    }
    run_durable_store_conformance(&conformance_fixture).unwrap();

    let object_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-object-conformance").unwrap(),
        ValidatorId::new([0xC1; 32]),
        AtomicityDomainId::new([0xC2; 32]).unwrap(),
    )
    .unwrap();
    let object_fence = WriterFenceGeneration::new(71).unwrap();
    let object_fixture = postgres_conformance_fixture(
        &database_url,
        conformance_pool.clone(),
        object_namespace,
        object_fence,
    );
    run_durable_object_conformance(&object_fixture).unwrap();
    let object_context = object_fixture
        .live_context(object_fence, 0xC3, Duration::from_secs(60))
        .unwrap();
    let lifecycle_object_id = ObjectId::new([0x51; 32]);
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        let history_count: i64 = object_operator
            .query_one(
                "SELECT COUNT(*)
                 FROM sunrise_edge.object_versions
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap()
            .get(0);
        assert_eq!(history_count, 3);
        let tombstone = object_operator
            .query_one(
                "SELECT current_version IS NULL,
                        digest_algorithm_id IS NULL,
                        digest_bytes IS NULL,
                        owner_projection IS NULL,
                        routing_projection IS NULL,
                        revision::TEXT,
                        tombstone
                 FROM sunrise_edge.object_heads
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        assert!(tombstone.get::<usize, bool>(0));
        assert!(tombstone.get::<usize, bool>(1));
        assert!(tombstone.get::<usize, bool>(2));
        assert!(tombstone.get::<usize, bool>(3));
        assert!(tombstone.get::<usize, bool>(4));
        assert_eq!(tombstone.get::<usize, String>(5), "5");
        assert!(tombstone.get::<usize, bool>(6));
    }

    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET type_id = 0
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4
                   AND object_version = 3",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }
    assert_eq!(
        object_fixture.store.get_object_head(
            &object_context,
            object_fixture.namespace.domain(),
            lifecycle_object_id,
        ),
        Err(DurableReadError::InvalidPersistedState)
    );
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET type_id = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4
                   AND object_id = $5
                   AND object_version = 3",
                &[
                    &i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID),
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }
    assert!(matches!(
        object_fixture
            .store
            .get_object_head(
                &object_context,
                object_fixture.namespace.domain(),
                lifecycle_object_id,
            )
            .unwrap(),
        DurableObjectHead::Tombstoned {
            last_object_version,
            ..
        } if last_object_version == DurableObjectVersion::new(3).unwrap()
    ));

    let correct_owner_projection: Vec<u8> =
        encode_owner(&Owner::Address(Address::new([0x33; 32]))).unwrap();
    let (version_three_algorithm, version_three_digest, version_three_bytes): (
        i32,
        Vec<u8>,
        Vec<u8>,
    ) = {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        let row = object_operator
            .query_one(
                "SELECT digest_algorithm_id, digest_bytes, inline_canonical_bytes
                 FROM sunrise_edge.object_versions
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4
                   AND object_version = 3",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    {
        let malformed_inline_bytes: Vec<u8> = vec![0xFF];
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET inline_canonical_bytes = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4
                   AND object_id = $5
                   AND object_version = 3",
                &[
                    &malformed_inline_bytes,
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }
    assert!(matches!(
        object_fixture
            .store
            .get_object_head(
                &object_context,
                object_fixture.namespace.domain(),
                lifecycle_object_id,
            )
            .unwrap(),
        DurableObjectHead::Tombstoned {
            last_object_version,
            ..
        } if last_object_version == DurableObjectVersion::new(3).unwrap()
    ));
    assert_eq!(
        object_fixture.store.get_object_version(
            &object_context,
            object_fixture.namespace.domain(),
            lifecycle_object_id,
            DurableObjectVersion::new(3).unwrap(),
        ),
        Err(DurableReadError::InvalidPersistedState)
    );
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET inline_canonical_bytes = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4
                   AND object_id = $5
                   AND object_version = 3",
                &[
                    &version_three_bytes,
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }

    let future_object: Object = Object {
        id: lifecycle_object_id,
        version: 4,
        owner: Owner::Address(Address::new([0x44; 32])),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x45; 32]),
        schema_version: 0x44,
        data: vec![0x46],
    };
    let future_canonical_bytes: Vec<u8> = encode_object(&future_object).unwrap();
    let future_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x47; 32]);
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_heads
                 SET current_version = 3,
                     digest_algorithm_id = $1,
                     digest_bytes = $2,
                     owner_projection = $3,
                     routing_projection = NULL,
                     tombstone = FALSE
                 WHERE chain_id_bytes = $4
                   AND validator_id = $5
                   AND atomicity_domain_id = $6
                   AND object_id = $7",
                &[
                    &version_three_algorithm,
                    &version_three_digest,
                    &correct_owner_projection,
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        object_operator
            .execute(
                "INSERT INTO sunrise_edge.object_versions (
                     chain_id_bytes, validator_id, atomicity_domain_id, object_id,
                     object_version, digest_algorithm_id, digest_bytes,
                     schema_version, type_id, created_checkpoint,
                     inline_canonical_bytes,
                     blob_digest_algorithm_id, blob_digest_bytes
                 ) VALUES ($1, $2, $3, $4, 4, $5, $6, $7, $8, 13, $9, NULL, NULL)",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                    &i32::from(future_digest.algorithm().as_u16()),
                    &&future_digest.bytes()[..],
                    &i64::from(future_object.schema_version),
                    &i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID),
                    &future_canonical_bytes,
                ],
            )
            .unwrap();
    }
    assert_eq!(
        object_fixture.store.get_object_head(
            &object_context,
            object_fixture.namespace.domain(),
            lifecycle_object_id,
        ),
        Err(DurableReadError::InvalidPersistedState)
    );
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "DELETE FROM sunrise_edge.object_versions
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4
                   AND object_version = 4",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_heads
                 SET current_version = NULL,
                     digest_algorithm_id = NULL,
                     digest_bytes = NULL,
                     owner_projection = NULL,
                     routing_projection = NULL,
                     tombstone = TRUE
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&lifecycle_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }
    assert!(matches!(
        object_fixture
            .store
            .get_object_head(
                &object_context,
                object_fixture.namespace.domain(),
                lifecycle_object_id,
            )
            .unwrap(),
        DurableObjectHead::Tombstoned {
            last_object_version,
            ..
        } if last_object_version == DurableObjectVersion::new(3).unwrap()
    ));

    let blob_object_id = ObjectId::new([0x61; 32]);
    let blob_version = DurableObjectVersionRecord::from_blob_reference(
        blob_object_id,
        DurableObjectVersion::FIRST,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x62; 32]),
        9,
        10,
        Digest32::new(HashAlgorithmId::Sha3_256, [0x63; 32]),
    );
    let blob_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            blob_object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            blob_object_id,
            DurableObjectMutation::Create {
                version: blob_version.clone(),
                owner_projection: runtime::DurableObjectOwnerProjection::default(),
                routing_projection: runtime::DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let blob_request_id = DurableRequestId::new([0x64; 32]).unwrap();
    let blob_event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x65; 32]);
    let blob_invocation = DurableInvocationTransaction::new(
        object_fixture.namespace.domain(),
        None,
        blob_changes,
        DurableRequestReceipt::new(blob_request_id, blob_event_digest, vec![0x66]).unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(
        object_fixture
            .store
            .commit_invocation(&object_context, blob_invocation),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        object_fixture
            .store
            .get_object_version(
                &object_context,
                object_fixture.namespace.domain(),
                blob_object_id,
                DurableObjectVersion::FIRST,
            )
            .unwrap(),
        Some(blob_version.clone())
    );
    assert!(matches!(
        object_fixture
            .store
            .get_object_head(
                &object_context,
                object_fixture.namespace.domain(),
                blob_object_id,
            )
            .unwrap(),
        DurableObjectHead::Current {
            head_revision,
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } if head_revision == runtime::ObjectHeadRevision::FIRST
            && object_version == DurableObjectVersion::FIRST
            && digest == Digest32::new(HashAlgorithmId::Sha2_256, [0x62; 32])
            && owner_projection.bytes().is_none()
            && routing_projection.bytes().is_none()
    ));
    assert!(matches!(
        blob_version.payload(),
        DurableObjectPayload::BlobReference(digest)
            if *digest == Digest32::new(HashAlgorithmId::Sha3_256, [0x63; 32])
    ));
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        let blob_row = object_operator
            .query_one(
                "SELECT inline_canonical_bytes IS NULL,
                        blob_digest_algorithm_id,
                        blob_digest_bytes,
                        type_id
                 FROM sunrise_edge.object_versions
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4
                   AND object_version = 1",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&blob_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        assert!(blob_row.get::<usize, bool>(0));
        assert_eq!(blob_row.get::<usize, i32>(1), 2);
        assert_eq!(blob_row.get::<usize, Vec<u8>>(2), vec![0x63; 32]);
        assert_eq!(
            blob_row.get::<usize, i64>(3),
            i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID)
        );
        let current_head = object_operator
            .query_one(
                "SELECT current_version::TEXT,
                        digest_algorithm_id,
                        digest_bytes,
                        owner_projection IS NULL,
                        routing_projection IS NULL,
                        revision::TEXT,
                        tombstone
                 FROM sunrise_edge.object_heads
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&blob_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
        assert_eq!(current_head.get::<usize, String>(0), "1");
        assert_eq!(current_head.get::<usize, i32>(1), 1);
        assert_eq!(current_head.get::<usize, Vec<u8>>(2), vec![0x62; 32]);
        assert!(current_head.get::<usize, bool>(3));
        assert!(current_head.get::<usize, bool>(4));
        assert_eq!(current_head.get::<usize, String>(5), "1");
        assert!(!current_head.get::<usize, bool>(6));

        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET type_id = 0
                 WHERE chain_id_bytes = $1
                   AND validator_id = $2
                   AND atomicity_domain_id = $3
                   AND object_id = $4
                   AND object_version = 1",
                &[
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&blob_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }
    assert_eq!(
        object_fixture.store.get_object_version(
            &object_context,
            object_fixture.namespace.domain(),
            blob_object_id,
            DurableObjectVersion::FIRST,
        ),
        Err(DurableReadError::InvalidPersistedState)
    );
    assert_eq!(
        object_fixture.store.get_object_head(
            &object_context,
            object_fixture.namespace.domain(),
            blob_object_id,
        ),
        Err(DurableReadError::InvalidPersistedState)
    );
    {
        let mut object_operator = object_fixture.operator.lock().unwrap();
        object_operator
            .execute(
                "UPDATE sunrise_edge.object_versions
                 SET type_id = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4
                   AND object_id = $5
                   AND object_version = 1",
                &[
                    &i64::from(runtime::DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID),
                    &object_fixture.namespace.chain_id_bytes(),
                    &&object_fixture.namespace.validator_id().as_bytes()[..],
                    &&object_fixture.namespace.domain().as_bytes()[..],
                    &&blob_object_id.as_bytes()[..],
                ],
            )
            .unwrap();
    }

    let schema_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-schema-skew-conformance").unwrap(),
        ValidatorId::new([0xA3; 32]),
        AtomicityDomainId::new([0xA4; 32]).unwrap(),
    )
    .unwrap();
    let schema_fixture = postgres_conformance_fixture(
        &database_url,
        conformance_pool.clone(),
        schema_namespace,
        WriterFenceGeneration::new(41).unwrap(),
    );
    schema_fixture.set_migration_phase(4).unwrap();
    let phase_context = schema_fixture
        .live_context(
            WriterFenceGeneration::new(41).unwrap(),
            0xA8,
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(
        schema_fixture.store.get_versioned_durable(
            &phase_context,
            schema_fixture.namespace.domain(),
            b"migration-phase-skew",
        ),
        Err(DurableReadError::SchemaMismatch)
    );
    {
        let mut schema_operator = schema_fixture.operator.lock().unwrap();
        assert!(matches!(
            advance_postgres_writer_fence(
                &mut schema_operator,
                &schema_fixture.namespace,
                WriterFenceGeneration::new(41).unwrap(),
                WriterFenceGeneration::new(42).unwrap(),
            ),
            Err(PostgresSchemaError::SchemaMismatch)
        ));
    }
    schema_fixture.set_migration_phase(5).unwrap();
    schema_fixture.install_unsupported_schema().unwrap();
    {
        let mut schema_operator = schema_fixture.operator.lock().unwrap();
        assert!(matches!(
            advance_postgres_writer_fence(
                &mut schema_operator,
                &schema_fixture.namespace,
                WriterFenceGeneration::new(41).unwrap(),
                WriterFenceGeneration::new(42).unwrap(),
            ),
            Err(PostgresSchemaError::SchemaMismatch)
        ));
    }
    schema_fixture.restore_supported_schema().unwrap();
    run_schema_skew_conformance(&schema_fixture).unwrap();

    let serialization_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-serialization-exhaustion").unwrap(),
        ValidatorId::new([0xA5; 32]),
        AtomicityDomainId::new([0xA6; 32]).unwrap(),
    )
    .unwrap();
    let serialization_fence = WriterFenceGeneration::new(51).unwrap();
    bootstrap_namespace(
        &mut client,
        &serialization_namespace,
        POSTGRES_SCHEMA_GENERATION,
        serialization_fence,
    )
    .unwrap();
    let serialization_store = Arc::new(PostgresDurableStore::new(
        conformance_pool,
        serialization_namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    ));
    let serialization_now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let serialization_context = DurableOperationContext::new(
        serialization_fence,
        StorageDeadline::new(serialization_now.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([0xA7; 16]).unwrap(),
    );
    let serialization_key = b"serialization-exhaustion".to_vec();
    let serialization_transaction = AtomicStateTransaction::new(
        serialization_namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(serialization_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                serialization_key.clone(),
                StateMutation::Put(b"must-not-commit".to_vec()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let mut serialization_locker = Client::connect(&database_url, NoTls).unwrap();
    let mut serialization_locker_transaction = serialization_locker.transaction().unwrap();
    serialization_locker_transaction
        .execute(
            "UPDATE sunrise_edge.storage_metadata
             SET operator_metadata = operator_metadata
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3",
            &[
                &serialization_namespace.chain_id_bytes(),
                &&serialization_namespace.validator_id().as_bytes()[..],
                &&serialization_namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();
    let serialization_store_for_thread = Arc::clone(&serialization_store);
    let serialization_handle = thread::spawn(move || {
        serialization_store_for_thread
            .commit_durable(&serialization_context, serialization_transaction)
    });
    let mut observed_serialization_wait = false;
    for _ in 0..10_000 {
        observed_serialization_wait = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                     WHERE application_name = 'sunrise-edge-pr74-conformance'
                       AND wait_event_type = 'Lock'
                 )",
                &[],
            )
            .unwrap()
            .get(0);
        if observed_serialization_wait {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        observed_serialization_wait,
        "adapter never reached the serialization-exhaustion metadata lock"
    );
    serialization_locker_transaction.commit().unwrap();
    assert_eq!(
        serialization_handle.join().unwrap(),
        DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure)
    );
    assert_eq!(
        serialization_store
            .get_versioned_durable(
                &serialization_context,
                serialization_namespace.domain(),
                &serialization_key,
            )
            .unwrap(),
        runtime::VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None).unwrap()
    );

    let commit_loss_namespace = PostgresNamespace::new(
        &ChainId::new("postgres-commit-loss-conformance").unwrap(),
        ValidatorId::new([0xB1; 32]),
        AtomicityDomainId::new([0xB2; 32]).unwrap(),
    )
    .unwrap();
    let commit_loss_fence = WriterFenceGeneration::new(61).unwrap();
    let mut commit_loss_operator = Client::connect(&database_url, NoTls).unwrap();
    bootstrap_namespace(
        &mut commit_loss_operator,
        &commit_loss_namespace,
        POSTGRES_SCHEMA_GENERATION,
        commit_loss_fence,
    )
    .unwrap();
    let commit_loss_proxy = CommitLossProxy::spawn(commit_loss_backend_addr(&database_url));
    let commit_loss_pool: Pool<TestPostgresManager> = build_postgres_pool(
        commit_loss_proxied_config(&database_url, commit_loss_proxy.local_addr()),
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(1).unwrap(),
            Duration::from_secs(10),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();
    let commit_loss_fixture = CommitLossPostgresFixture {
        store: Arc::new(PostgresDurableStore::new(
            commit_loss_pool,
            commit_loss_namespace.clone(),
            PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
        )),
        namespace: commit_loss_namespace,
        operator: Mutex::new(commit_loss_operator),
        initial_fence: commit_loss_fence,
        proxy: commit_loss_proxy,
    };
    run_commit_loss_conformance(&commit_loss_fixture).unwrap();
}
