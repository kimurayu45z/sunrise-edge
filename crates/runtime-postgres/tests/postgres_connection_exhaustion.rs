//! Live bounded server connection-exhaustion test for the PostgreSQL durable
//! store.
//!
//! This is a separate test binary from every other live test in this crate
//! because it starts and destroys its own disposable container with a tiny,
//! exact `max_connections` cap (see `support::ConnectionExhaustionPostgresContainer`);
//! it still takes `support::LiveTestLock` before any container work, so it
//! never runs concurrently with another live test in this crate. Capability
//! resolution (skip vs. run vs. fail on partial/invalid configuration) is
//! `support::resolve_connection_exhaustion_scenario`; see that function's doc
//! comment for the exact rules.
//!
//! Scope: unlike the disk-full and WAL-full scenarios, which fault a
//! filesystem, this scenario faults the server's own connection-slot
//! capacity. An already-open operator connection bootstraps the disposable
//! namespace and stays open for the whole scenario. Immediately after the
//! short-lived admin client that created the disposable database is
//! dropped, this test boundedly polls through the operator connection until
//! exactly one active client backend (the operator's own) is visible —
//! `Client::drop` only requests connection teardown asynchronously, so
//! without this poll the admin client's backend could still transiently
//! count against capacity right as the blocker loop below starts. This poll
//! is safe, unlike the later transient-count poll this design deliberately
//! avoids after releasing a blocker (see below): no `r2d2` pool exists yet
//! at this point, and nothing else this test has started can spontaneously
//! open or close a connection on its own, so the target count of exactly
//! one, once reached, is stable rather than a value some independent
//! background task could immediately overwrite. A small, exactly bounded
//! number of direct blocker connections then saturate every remaining slot
//! configured by `max_connections` (with `superuser_reserved_connections=0`
//! and PostgreSQL 16+'s separate `reserved_connections=0` so no role gets a
//! capacity carve-out this scenario's counting would need to special-case).
//! `autovacuum` is disabled on this scenario's container too, but only as
//! optional quiescence during the bounded window: autovacuum workers and the
//! autovacuum launcher are accounted from their own separate budget
//! (`autovacuum_max_workers`, alongside `max_worker_processes` and
//! `max_wal_senders`), not carved out of `max_connections`, and every count
//! this scenario asserts is already filtered to
//! `backend_type = 'client backend'`, which excludes them regardless. One
//! further direct connection attempt is live, ground-truth evidence that the
//! server is genuinely out of
//! connection slots: SQLSTATE `53300` (`too_many_connections`) at `FATAL`
//! severity. With capacity still fully exhausted, a freshly built, max-size-one
//! adapter pool — proven to hold zero physical connections before its first
//! checkout — drives one bounded structured invocation commit. Live evidence,
//! not an assumption: the adapter's own pool never gets to observe a raw
//! `53300` at all, because `r2d2`'s `Pool::get_timeout` only ever returns
//! once it either succeeds or its *entire* requested wait elapses — it does
//! not return early on a connection refusal — so by the time this crate's
//! `acquire()` helper re-checks the caller's [`DurableOperationContext`]
//! deadline to classify the failure, that deadline has, by construction,
//! also just elapsed. Pool exhaustion and deadline exhaustion therefore
//! collapse into the same observable outcome here: the definite pre-commit
//! `Rejected(DeadlineExceededBeforeCommit)`, not `UnavailableBeforeCommit`
//! (which this adapter reserves for a fault surfacing *after* a connection
//! and transaction are already open, as in the disk-full/WAL-full
//! scenarios). This crate's own `retry_serializable` never retries this
//! outcome (it only re-attempts on `Rejected(SerializationFailure)`), so
//! `commit_invocation` makes exactly one such attempt; `r2d2` may still make
//! its own bounded, unspecified number of internal connection attempts on a
//! short backoff while satisfying that one `pool.get_timeout` wait, which
//! this test does not, and does not need to, count. This is proven bounded
//! from both directions, not merely assumed: the observed wall-clock
//! duration of that one call is asserted to track its configured context
//! deadline both from below (it did not return near-instantly) and from
//! above (it did not run away past it). Non-publication of state,
//! receipt, commit sequence, and outbox rows is proven through the
//! still-open operator connection while capacity remains exhausted (the
//! adapter pool cannot open a new connection to check this itself). The
//! rejected attempt's own internal connection attempt does not simply give
//! up once `commit_invocation` returns: `r2d2` keeps retrying it,
//! independently and indefinitely, on its own short backoff, until it either
//! succeeds or the pool itself is dropped. This means the freed slot from
//! releasing exactly one blocker connection can be reclaimed by that
//! still-running background task at any time, not necessarily by any
//! particular call this test makes — so this test does not poll for a
//! transient server-side count after releasing the blocker (racing that
//! independent background task with a poll would be flaky by construction).
//! It instead proves recovery deterministically: the next
//! `commit_invocation` call must succeed once capacity is available however
//! it became available, and the post-recovery, steady-state server-side
//! connection counts (through the same still-open operator connection) prove
//! specifically that the adapter pool's own connection, identified by its
//! distinct `application_name`, is the one that reclaimed it. This test also
//! proves the exact replay/claim/acknowledgement behavior and pool usability
//! afterward. It does **not** prove real-device resource exhaustion,
//! load/soak capacity, connection-pool behavior under a provider-managed
//! pooler (e.g. PgBouncer), TLS-path connection loss, real writer failover,
//! provider certification, or production readiness.

use postgres::{Client, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::PostgresConnectionManager;
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableOperationContext,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome, DurableOutboxBatch,
    DurableOutboxClaimOutcome, DurableOutboxLeaseId, DurableOutboxMessage, DurableRequestId,
    DurableRequestReceipt, DurableStateTransaction, IndexedOutboxRepository,
    RequestOutboxClaimRequest, StateMutation, StateMutationEntry, StateReadAssertion,
    StateRevision, StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
    WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, apply_initial_schema, bootstrap_namespace, build_postgres_pool,
    inspect_namespace, verify_initial_schema,
};
use std::{
    num::NonZeroU32,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod support;

/// Disposable database this scenario creates on its own container, never the
/// shared CI service database and never another scenario's own database.
const CONNECTION_EXHAUSTION_DATABASE: &str = "sunrise_edge_connection_exhaustion";

/// Size of the state payload driven through the adapter's structured
/// invocation. Small and unremarkable: this scenario's fault is connection
/// capacity, not payload size, so nothing here needs to be large.
const STATE_PAYLOAD_BYTES: usize = 256;

/// `application_name` set on the adapter pool's own PostgreSQL connections.
/// Distinct from every direct client this scenario opens (none of which set
/// an `application_name`), so `pg_stat_activity` can identify the adapter
/// pool's own connection, specifically, after recovery.
const ADAPTER_POOL_APPLICATION_NAME: &str = "sunrise-edge-pr88-connection-exhaustion";

type TestPostgresManager = PostgresConnectionManager<NoTls>;

fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A value unique to this process and this instant, mixed into the test's
/// chain ID so repeated runs never collide with a previous run's namespace.
fn unique_run_suffix() -> u128 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos ^ u128::from(std::process::id())
}

/// Deterministic xorshift64* byte stream, used only so the state payload is
/// not a suspiciously uniform buffer; this scenario has no compression- or
/// WAL-crossing requirement on it.
fn xorshift64_star_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// Connect timeout applied to every direct probe/blocker/operator client this
/// scenario opens against its own disposable container.
const DIRECT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-level user timeout mirrored onto every direct client, so a connection
/// that stalls after the TCP handshake against the disposable container is
/// bounded the same way as a slow connect.
const DIRECT_CLIENT_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Session `statement_timeout` applied to every direct client. Generous
/// relative to this scenario's own bounded work, but far below the outer test
/// process's own deadline, so a wedged connection fails loudly instead of
/// hanging the test.
const DIRECT_CLIENT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a bounded [`postgres::Config`] for a direct client against this
/// scenario's disposable container: an explicit connect timeout, TCP user
/// timeout, and session `statement_timeout`, so no direct connection this
/// scenario opens can inherit the driver's unbounded defaults.
fn bounded_direct_client_config(url: &str) -> postgres::Config {
    let mut config: postgres::Config = url.parse().unwrap_or_else(|error| {
        panic!("failed to parse disposable-container database URL: {error}")
    });
    let statement_timeout_millis: u64 =
        u64::try_from(DIRECT_CLIENT_STATEMENT_TIMEOUT.as_millis()).unwrap();
    config.connect_timeout(DIRECT_CLIENT_CONNECT_TIMEOUT);
    config.tcp_user_timeout(DIRECT_CLIENT_TCP_USER_TIMEOUT);
    config.options(&format!("-c statement_timeout={statement_timeout_millis}"));
    config
}

/// Connects a direct client through [`bounded_direct_client_config`]. `label`
/// identifies the connection in a failure message only; it never includes the
/// URL itself, since the URL carries the generated container password.
fn connect_bounded(url: &str, label: &str) -> Client {
    bounded_direct_client_config(url)
        .connect(NoTls)
        .unwrap_or_else(|error| panic!("bounded connect to {label} failed: {error}"))
}

/// Exact count of regular client-backend connections currently open on the
/// server, through `client`'s own already-open session. Filtered to
/// `backend_type = 'client backend'` so auxiliary processes (the
/// checkpointer, walwriter, the autovacuum launcher, and any autovacuum
/// worker) never perturb the count. This filter alone is sufficient: those
/// processes are accounted from their own separate budgets
/// (`autovacuum_max_workers`, `max_worker_processes`, `max_wal_senders`),
/// never carved out of the `max_connections` budget this scenario saturates,
/// so `autovacuum=off` on this scenario's container is only optional
/// quiescence against unrelated background activity during the bounded
/// window, not a requirement for this count to be exact.
fn active_client_backend_count(client: &mut Client) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'",
            &[],
        )
        .unwrap()
        .get(0)
}

/// Bound on how long [`wait_until_solely_operator_connection`] waits for the
/// admin client's connection teardown to be reflected server-side.
const ADMIN_TEARDOWN_POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for [`ADMIN_TEARDOWN_POLL_TIMEOUT`] to elapse.
const ADMIN_TEARDOWN_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Boundedly polls [`active_client_backend_count`] through `client` (the
/// operator connection) until it reports exactly one active client backend:
/// the operator connection's own. Dropping a `postgres::Client` only
/// requests connection teardown; it does not wait for the server to have
/// processed it, so without this poll the admin client that created the
/// disposable database could still transiently count against capacity right
/// as the blocker loop that follows starts opening connections, throwing off
/// its exact accounting by one.
///
/// This is safe to poll for, unlike the later transient server-side count
/// this design deliberately does not poll for after releasing a blocker
/// connection (see this file's module docs): at this point in the scenario
/// no `r2d2` pool exists yet, and nothing else this test has started can
/// spontaneously open or close a connection on its own, so the target count
/// of exactly one, once reached, is stable — not a value some independent,
/// already-running background retry could immediately overwrite before this
/// poll (or its caller) observes it.
fn wait_until_solely_operator_connection(client: &mut Client) {
    let deadline = Instant::now() + ADMIN_TEARDOWN_POLL_TIMEOUT;
    loop {
        let observed = active_client_backend_count(client);
        if observed == 1 {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "expected exactly one active client backend (the operator connection) within \
                 {ADMIN_TEARDOWN_POLL_TIMEOUT:?} after dropping the admin client, still observed \
                 {observed}"
            );
        }
        thread::sleep(ADMIN_TEARDOWN_POLL_INTERVAL);
    }
}

fn deadline(budget_millis: u64) -> StorageDeadline {
    StorageDeadline::new(now_millis().checked_add(budget_millis).unwrap()).unwrap()
}

/// Bounded budget for the adapter's exhaustion-probe [`DurableOperationContext`].
/// The adapter pool cannot succeed while the server is saturated, so
/// `store.commit_invocation` genuinely blocks for close to this whole budget
/// (retrying its own connection attempt on a short internal backoff) before
/// returning the definite rejection; this is intentionally short (seconds,
/// not this crate's usual 240-second phase budget) so the bounded wait stays
/// fast without masking a real connection-exhaustion result behind an
/// unrelated deadline.
const EXHAUSTION_PROBE_BUDGET_MILLIS: u64 = 8_000;

/// Upper-bound headroom added to [`EXHAUSTION_PROBE_BUDGET_MILLIS`] when
/// bounding the observed wall-clock time of the exhaustion-probe commit
/// attempt: proof that call resolved from a single bounded
/// connection-acquisition wait, not an unbounded retry loop that kept going
/// well past its own deadline.
const EXHAUSTION_PROBE_ELAPSED_UPPER_HEADROOM: Duration = Duration::from_secs(5);

/// Lower-bound tolerance subtracted from [`EXHAUSTION_PROBE_BUDGET_MILLIS`]
/// when bounding the observed wall-clock time of the exhaustion-probe commit
/// attempt from below: proof the call genuinely consumed close to its whole
/// bounded connection-acquisition wait rather than returning near-instantly
/// (which would mean the rejection did not actually come from exhausting
/// that wait). Generous enough to tolerate CI scheduling jitter without
/// being so loose it would accept a near-immediate return.
const EXHAUSTION_PROBE_ELAPSED_LOWER_TOLERANCE: Duration = Duration::from_secs(3);

/// Generous budget for every context after capacity is released, where the
/// adapter pool can genuinely succeed quickly.
const RECOVERY_BUDGET_MILLIS: u64 = 60_000;

#[test]
fn postgres_connection_exhaustion_bounded_server_capacity() {
    let image = match support::resolve_connection_exhaustion_scenario() {
        support::ConnectionExhaustionScenario::Skip => {
            eprintln!(
                "skipping live PostgreSQL connection-exhaustion scenario: neither {} nor {} is \
                 configured",
                support::CONNECTION_EXHAUSTION_IMAGE_ENV,
                support::CONNECTION_EXHAUSTION_REQUIRED_ENV
            );
            return;
        }
        support::ConnectionExhaustionScenario::Run(image) => image,
    };

    // Acquired before any container work, and declared before `container`
    // below, so that on unwind locals drop in reverse declaration order:
    // `container` (panic-safe force-remove) drops first, and only then is
    // the lock released for the next live test.
    let _live_test_lock = support::LiveTestLock::acquire();

    let container = support::ConnectionExhaustionPostgresContainer::start(&image);

    // --- Provision the disposable database ----------------------------------

    let mut admin_client = connect_bounded(&container.url("postgres"), "postgres (admin)");
    admin_client
        .execute(
            &format!("CREATE DATABASE {CONNECTION_EXHAUSTION_DATABASE}"),
            &[],
        )
        .unwrap();
    drop(admin_client);

    // The operator connection: opened once, before any blocker session, and
    // kept open for the whole scenario. It bootstraps the namespace, reads
    // server-side capacity configuration, and — critically — remains usable
    // to prove non-publication while the server has zero spare capacity for
    // any *new* connection, including one the adapter pool would need.
    let mut operator_client = connect_bounded(
        &container.url(CONNECTION_EXHAUSTION_DATABASE),
        CONNECTION_EXHAUSTION_DATABASE,
    );

    let database: String = operator_client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, CONNECTION_EXHAUSTION_DATABASE,
        "refusing to run the connection-exhaustion scenario against a non-disposable database"
    );

    // The admin client above only requested its own teardown by dropping;
    // wait for the server to have actually processed it before this
    // scenario starts opening exactly-counted blocker connections. See
    // `wait_until_solely_operator_connection`'s doc comment for why polling
    // here (unlike later in this scenario) is safe.
    wait_until_solely_operator_connection(&mut operator_client);

    apply_initial_schema(&mut operator_client).unwrap();
    verify_initial_schema(&mut operator_client).unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!(
            "postgres-connection-exhaustion-{}",
            unique_run_suffix()
        ))
        .unwrap(),
        ValidatorId::new([0xe1; 32]),
        AtomicityDomainId::new([0xe2; 32]).unwrap(),
    )
    .unwrap();
    let domain = namespace.domain();
    let initial_fence = WriterFenceGeneration::new(1).unwrap();
    let metadata = bootstrap_namespace(
        &mut operator_client,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        initial_fence,
    )
    .unwrap();
    assert_eq!(metadata.writer_fence(), initial_fence);
    assert_eq!(metadata.commit_sequence(), 0);

    // --- Server-side capacity ground truth, through the operator connection -

    let configured_settings_row = operator_client
        .query_one(
            "SELECT current_setting('max_connections')::int, \
             current_setting('superuser_reserved_connections')::int, \
             current_setting('reserved_connections')::int",
            &[],
        )
        .unwrap();
    let configured_max_connections: i32 = configured_settings_row.get(0);
    let configured_superuser_reserved: i32 = configured_settings_row.get(1);
    let configured_reserved_connections: i32 = configured_settings_row.get(2);
    assert_eq!(
        configured_max_connections,
        i32::try_from(support::CONNECTION_EXHAUSTION_MAX_CONNECTIONS).unwrap(),
        "the disposable container did not apply the configured max_connections; refusing to \
         treat a shared/default-capacity server as genuinely exhausted"
    );
    assert_eq!(
        configured_superuser_reserved,
        i32::try_from(support::CONNECTION_EXHAUSTION_SUPERUSER_RESERVED_CONNECTIONS).unwrap(),
        "the disposable container did not apply the configured superuser_reserved_connections"
    );
    // PostgreSQL 16+ reserves a second, independent pool of slots for roles
    // with the `pg_use_reserved_connections` predefined role, distinct from
    // `superuser_reserved_connections` above. Pinned to zero and read back
    // here for the same reason: any non-zero carve-out would mean this
    // scenario's exact blocker/slot accounting no longer matches the
    // server's real capacity.
    assert_eq!(
        configured_reserved_connections,
        i32::try_from(support::CONNECTION_EXHAUSTION_RESERVED_CONNECTIONS).unwrap(),
        "the disposable container did not apply the configured reserved_connections"
    );

    // --- Fill every remaining slot with bounded direct blocker sessions -----
    //
    // The operator connection above already holds one slot; open exactly
    // enough further direct blocker connections to bring the server to full,
    // exact capacity.
    let blocker_count: u32 = support::CONNECTION_EXHAUSTION_MAX_CONNECTIONS - 1;
    let mut blockers: Vec<Client> = Vec::with_capacity(blocker_count as usize);
    for index in 0..blocker_count {
        blockers.push(connect_bounded(
            &container.url(CONNECTION_EXHAUSTION_DATABASE),
            &format!("blocker[{index}]"),
        ));
    }

    let saturated_backend_count = active_client_backend_count(&mut operator_client);
    assert_eq!(
        saturated_backend_count,
        i64::from(support::CONNECTION_EXHAUSTION_MAX_CONNECTIONS),
        "expected exactly max_connections active client backends (the operator connection plus \
         every blocker); the server is not genuinely saturated"
    );

    // Ground-truth fault probe: one further direct connection attempt,
    // independent of the adapter.
    let probe_result =
        bounded_direct_client_config(&container.url(CONNECTION_EXHAUSTION_DATABASE)).connect(NoTls);
    // `postgres::Client` does not implement `Debug`, so `Result::expect_err`
    // (which would need to format the `Ok` value on failure) cannot be used
    // here; match explicitly instead.
    let probe_error = match probe_result {
        Err(error) => error,
        Ok(_client) => panic!("expected the server to be genuinely out of connection slots"),
    };
    assert_eq!(
        probe_error.code().map(postgres::error::SqlState::code),
        Some("53300"),
        "expected SQLSTATE 53300 (too_many_connections), got {probe_error:?}"
    );
    let probe_db_error = probe_error
        .as_db_error()
        .unwrap_or_else(|| panic!("expected a database error response, got {probe_error:?}"));
    assert_eq!(
        probe_db_error.parsed_severity(),
        Some(postgres::error::Severity::Fatal),
        "expected FATAL severity (a connection-establishment failure, never PANIC/ERROR), got \
         {probe_db_error:?}"
    );

    // --- A max-size-one adapter pool, proven to hold zero physical connections

    let mut pool_config: postgres::Config = container
        .url(CONNECTION_EXHAUSTION_DATABASE)
        .parse()
        .unwrap();
    pool_config.application_name(ADAPTER_POOL_APPLICATION_NAME);
    let pool = build_postgres_pool(
        pool_config,
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
    let pool_state_before_attempt = pool.state();
    assert_eq!(
        pool_state_before_attempt.connections, 0,
        "expected the freshly built max-size-one pool to hold zero physical connections before \
         its first checkout"
    );
    assert_eq!(pool_state_before_attempt.idle_connections, 0);

    let store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );

    // --- Build the fault invocation (not yet committed) ----------------------

    let request_id = DurableRequestId::new([0xea; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xeb; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"connection-exhaustion-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0xec; 32]),
        b"connection-exhaustion-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"connection-exhaustion/state".to_vec();
    let state_value = xorshift64_star_payload(STATE_PAYLOAD_BYTES, 0x9E37_79B9_7F4A_7C15);
    let state_transaction = DurableStateTransaction::new(
        domain,
        runtime::AtomicStateReadSet::new(vec![
            StateReadAssertion::new(state_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(state_key.clone(), StateMutation::Put(state_value.clone()))
                .unwrap(),
        ],
    )
    .unwrap();
    let fault_invocation = DurableInvocationTransaction::new(
        domain,
        Some(state_transaction),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox_batch),
    )
    .unwrap();

    // --- Without releasing capacity, drive one bounded adapter invocation ---

    let exhaustion_context = DurableOperationContext::new(
        initial_fence,
        deadline(EXHAUSTION_PROBE_BUDGET_MILLIS),
        StorageCorrelationId::new([0xed; 16]).unwrap(),
    );
    let attempt_started = Instant::now();
    let exhaustion_outcome = store.commit_invocation(&exhaustion_context, fault_invocation.clone());
    let attempt_elapsed = attempt_started.elapsed();
    eprintln!(
        "connection-exhaustion adapter outcome: {exhaustion_outcome:?} after {attempt_elapsed:?}"
    );
    // Live evidence, not the naively assumed `UnavailableBeforeCommit`: the
    // adapter's own attempt to open a new physical connection fails the same
    // way the direct probe above did, but it never surfaces as a raw
    // `postgres::Error` this crate could classify by SQLSTATE — `acquire()`
    // only learns the pool's `get_timeout` failed, then re-checks the
    // caller's deadline to decide between `Deadline` and `Unavailable`.
    // Because `get_timeout` (see this file's module docs) never returns
    // early on a connection refusal, that re-check reliably observes the
    // deadline as having also just elapsed, so pool exhaustion is classified
    // as the definite pre-commit `Rejected(DeadlineExceededBeforeCommit)`.
    assert_eq!(
        exhaustion_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::DeadlineExceededBeforeCommit)
    );
    // No higher-level retry storm at the `commit_invocation` level:
    // `retry_serializable` only re-attempts the whole `acquire`-through-commit
    // closure on `Rejected(SerializationFailure)`, never on this outcome, so
    // this call makes exactly one such attempt. Within that one attempt,
    // `pool.get_timeout` (an `r2d2` internal, not this crate's own retry
    // logic) may itself make a bounded, unspecified number of internal
    // connection attempts on its own short backoff while waiting out this
    // context's deadline; this test does not — and should not — assert an
    // exact TCP-connect attempt count, only that the whole call's observed
    // duration tracks a single bounded wait rather than compounding across
    // multiple such waits. A lower bound proves the call did not return
    // near-instantly (which would mean this outcome did not genuinely come
    // from exhausting that wait); an upper bound proves it did not run away
    // past it.
    let exhaustion_probe_budget = Duration::from_millis(EXHAUSTION_PROBE_BUDGET_MILLIS);
    assert!(
        attempt_elapsed + EXHAUSTION_PROBE_ELAPSED_LOWER_TOLERANCE >= exhaustion_probe_budget,
        "commit_invocation returned after only {attempt_elapsed:?}, well short of its \
         {EXHAUSTION_PROBE_BUDGET_MILLIS}ms bounded deadline minus tolerance; this suggests the \
         rejection did not genuinely come from exhausting the bounded connection-acquisition wait"
    );
    assert!(
        attempt_elapsed <= exhaustion_probe_budget + EXHAUSTION_PROBE_ELAPSED_UPPER_HEADROOM,
        "commit_invocation took {attempt_elapsed:?}, well beyond its \
         {EXHAUSTION_PROBE_BUDGET_MILLIS}ms bounded deadline plus headroom; this suggests an \
         unbounded retry loop rather than a single bounded connection-acquisition wait"
    );

    let pool_state_after_attempt = pool.state();
    assert_eq!(
        pool_state_after_attempt.connections, 0,
        "a rejected connection attempt must not leave a phantom connection recorded in the pool"
    );
    assert_eq!(pool_state_after_attempt.idle_connections, 0);

    // --- Prove non-publication through the still-open operator connection ---

    let non_publication_row = operator_client
        .query_one(
            "SELECT
                 (SELECT COUNT(*) FROM sunrise_edge.state_records
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND state_key = $4),
                 (SELECT COUNT(*) FROM sunrise_edge.request_receipts
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND request_id = $5),
                 (SELECT COUNT(*) FROM sunrise_edge.outbox_messages
                  WHERE chain_id_bytes = $1 AND validator_id = $2
                    AND atomicity_domain_id = $3 AND request_id = $5)",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &state_key.as_slice(),
                &&request_id.as_bytes()[..],
            ],
        )
        .unwrap();
    let state_row_count: i64 = non_publication_row.get(0);
    let receipt_row_count: i64 = non_publication_row.get(1);
    let outbox_row_count: i64 = non_publication_row.get(2);
    assert_eq!(
        state_row_count, 0,
        "the rejected attempt must not have published a state row"
    );
    assert_eq!(
        receipt_row_count, 0,
        "the rejected attempt must not have published a receipt row"
    );
    assert_eq!(
        outbox_row_count, 0,
        "the rejected attempt must not have published an outbox row"
    );
    assert_eq!(
        inspect_namespace(&mut operator_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        0,
        "the rejected attempt must not have advanced the commit sequence"
    );

    // --- Release exactly one blocker slot ------------------------------------
    //
    // Deliberately not followed by a poll for a transient server-side count:
    // the earlier rejected attempt left `r2d2` with its own still-active,
    // independently retrying background reconnect task (see this file's
    // module docs), which can claim the freed slot on its own, at any time,
    // without this test ever driving it. Racing that background task with a
    // poll for an intermediate count is inherently flaky — the freed slot can
    // be reclaimed before a poll ever observes the transient drop, or
    // in between two poll iterations. Recovery is instead proven
    // deterministically below: the very next `commit_invocation` call must
    // succeed once capacity is available (however it became available), and
    // the post-recovery, steady-state server-side counts prove exactly which
    // connection reclaimed it.

    let released_blocker = blockers
        .pop()
        .expect("expected at least one blocker connection to release");
    drop(released_blocker);
    assert_eq!(
        blockers.len(),
        (blocker_count - 1) as usize,
        "expected exactly one blocker connection to have been released client-side"
    );

    // --- Recovery: the identical invocation now commits through the same
    //     pool and store ------------------------------------------------------

    let recovery_context = DurableOperationContext::new(
        initial_fence,
        deadline(RECOVERY_BUDGET_MILLIS),
        StorageCorrelationId::new([0xee; 16]).unwrap(),
    );
    assert_eq!(
        store.commit_invocation(&recovery_context, fault_invocation.clone()),
        DurableCommitOutcome::Committed
    );

    let pool_state_after_recovery = pool.state();
    assert_eq!(
        pool_state_after_recovery.connections, 1,
        "expected the max-size-one pool to hold exactly one physical connection after a \
         successful commit"
    );

    // Steady-state proof, through the still-open operator connection, that
    // the released slot was reclaimed by the adapter pool specifically: the
    // successful commit above already proves *some* connection became
    // available, but not, by itself, which one. By this point every
    // connection attempt this scenario could trigger has already resolved
    // (the commit above only returns once its own connection is fully
    // established and has committed), so these counts are no longer subject
    // to the race described above.
    let post_recovery_counts_row = operator_client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'),
                 (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'
                  AND application_name = $1)",
            &[&ADAPTER_POOL_APPLICATION_NAME],
        )
        .unwrap();
    let post_recovery_total_backends: i64 = post_recovery_counts_row.get(0);
    let post_recovery_adapter_backends: i64 = post_recovery_counts_row.get(1);
    assert_eq!(
        post_recovery_total_backends,
        i64::from(support::CONNECTION_EXHAUSTION_MAX_CONNECTIONS),
        "expected exactly max_connections active client backends after recovery (the operator \
         connection, every remaining blocker, and the adapter pool's one connection)"
    );
    assert_eq!(
        post_recovery_adapter_backends, 1,
        "expected exactly one active client backend carrying the adapter pool's \
         application_name after a successful recovery commit, proving the released slot was \
         reclaimed by the adapter pool itself"
    );

    let recovered_state = store
        .get_versioned_durable(&recovery_context, domain, &state_key)
        .unwrap();
    assert_eq!(recovered_state.revision(), StateRevision::new(1));
    assert_eq!(recovered_state.value(), Some(state_value.as_slice()));
    assert_eq!(
        store
            .get_request_receipt(&recovery_context, domain, request_id)
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store.commit_invocation(&recovery_context, fault_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0xef; 32]).unwrap();
    let claim_window: u64 = now_millis();
    let claim_expiry: u64 = claim_window.checked_add(60_000).unwrap();
    let claim = match store.claim_request_outbox(
        &recovery_context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("expected the recovered outbox message to be claimable, got {outcome:?}"),
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(
        claim.canonical_payload(),
        b"connection-exhaustion-outbound-event"
    );

    assert_eq!(
        store.acknowledge_outbox(
            &recovery_context,
            DurableOutboxAcknowledgement::new(domain, request_id, 0, claim_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let no_due_work_window: u64 = now_millis();
    let no_due_work_expiry: u64 = no_due_work_window.checked_add(60_000).unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &recovery_context,
            RequestOutboxClaimRequest::new(
                domain,
                request_id,
                no_due_work_window,
                DurableOutboxLeaseId::new([0xf0; 32]).unwrap(),
                no_due_work_expiry,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    assert_eq!(
        inspect_namespace(&mut operator_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );
}
