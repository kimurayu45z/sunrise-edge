//! Live bounded PgBouncer transaction-pooling rehearsal for the PostgreSQL
//! durable store.
//!
//! This is a separate test binary from every other live test in this crate;
//! it takes `support::LiveTestLock` before any container work, so it never
//! runs concurrently with another live test in this crate. Capability
//! resolution (skip vs. run vs. fail on partial/invalid configuration) is
//! `support::resolve_pgbouncer_scenario`; see that function's doc comment for
//! the exact rules.
//!
//! Scope: unlike every other scenario in this crate, which drives the
//! adapter straight against PostgreSQL, this scenario puts a real,
//! digest-pinned `ghcr.io/icoretech/pgbouncer-docker` 1.25.2 proxy, running
//! in transaction-pooling mode with exactly one backend connection for the
//! tested database/user pool, between the adapter and a real, digest-pinned
//! PostgreSQL 18.6. Both containers run on one isolated, freshly generated
//! Docker network (`support::DockerNetwork`); PgBouncer resolves PostgreSQL
//! by its network alias, never a host-published address. This test's own
//! direct verification connections (schema bootstrap, ground-truth reads)
//! bypass the proxy entirely and talk straight to PostgreSQL's own separately
//! published port, so they are never subject to the proxy's single-backend
//! contention this scenario deliberately creates.
//!
//! The live evidence proven, in order: (1) PgBouncer's own admin console
//! (`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`, asserted directly, never
//! inferred from client behavior) confirms `pool_mode = transaction`, a
//! nonzero `max_prepared_statements`, a bounded `query_wait_timeout`, and
//! that `default_pool_size`, `max_db_connections`, `max_user_connections`,
//! and the tested database's own `SHOW DATABASES` `pool_size` are each
//! exactly one; (2) two simultaneously open, distinct client connections
//! each complete a sequential transaction, and `SHOW SERVERS` proves both
//! were served by the exact same PostgreSQL backend process (`remote_pid`),
//! i.e. transaction pooling actually reused one backend rather than opening
//! a second; (3) the real `runtime-postgres` adapter (a genuine `r2d2` pool
//! plus `PostgresDurableStore`) is pointed at the proxy, not PostgreSQL
//! directly; (4) while a direct client (bypassing the adapter, but still
//! through the proxy) holds the pool's only backend inside an open
//! transaction — proven by `SHOW SERVERS`' sole row for that database
//! reporting PgBouncer's own `active` state, not merely existing — one
//! adapter structured invocation gets a bounded, definite pre-commit
//! rejection whose timing tracks PgBouncer's own `query_wait_timeout`, not
//! this test's own outer deadline, with no state/receipt/outbox row
//! published (checked through the direct, proxy-bypassing verification
//! connection, which the proxy's contention cannot affect); (5) after
//! releasing the blocking transaction, the identical invocation commits
//! through the same adapter pool/store — `SHOW SERVERS`' `remote_pid`,
//! read again, proves the recovered commit was served by the exact same
//! sole backend the two synthetic clients observed in (2), and `SHOW
//! CLIENTS`, filtered by the adapter pool's own `application_name`, proves
//! specifically that the adapter's own proxy connection is the one that
//! reclaimed the freed backend — a replay returns exact
//! `RequestAlreadyCommitted`, the exact outbox message is claimed and
//! acknowledged, a further claim attempt returns `NoDueWork`, and the pool
//! remains usable.
//!
//! This is explicitly a bounded local PgBouncer transaction-pooling
//! rehearsal, not provider-managed pooler service certification, load/soak
//! testing, failover, or TLS evidence: PgBouncer and PostgreSQL both run as
//! disposable local containers this test starts and destroys, the client
//! leg is plaintext, and nothing here exercises PgBouncer's own high
//! availability, connection draining, TLS termination, or a hosted
//! provider's operational surface.

use postgres::{Client, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::PostgresConnectionManager;
use runtime::{
    AtomicStateReadSet, DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
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
    inspect_namespace,
};
use std::{
    num::NonZeroU32,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod support;

/// Disposable database this scenario creates on its own backend container,
/// never the shared CI service database and never another scenario's own
/// database.
const PGBOUNCER_DATABASE: &str = "sunrise_edge_pgbouncer";

/// Size of the state payload driven through the adapter's structured
/// invocation. Small and unremarkable: this scenario's fault is a proxy
/// queue timeout, not payload size.
const STATE_PAYLOAD_BYTES: usize = 256;

/// `application_name` set on the adapter pool's own PostgreSQL connections
/// (relayed by PgBouncer to `SHOW CLIENTS`), distinct from every direct
/// client this scenario opens, so PgBouncer's own admin console can identify
/// the adapter pool's connection specifically after recovery.
const ADAPTER_POOL_APPLICATION_NAME: &str = "sunrise-edge-pr97-pgbouncer";

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
/// not a suspiciously uniform buffer.
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

/// Connect timeout applied to every direct/proxied client this scenario
/// opens.
const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-level user timeout mirrored onto every client this scenario opens.
const CLIENT_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Session `statement_timeout` applied to every direct (proxy-bypassing)
/// client. Not applied to proxied clients: PgBouncer's `query_wait_timeout`
/// is the bound under test for those, and a session-level `statement_timeout`
/// startup option would be a second, redundant bound competing with it.
const DIRECT_CLIENT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a bounded [`postgres::Config`] for a direct, proxy-bypassing client
/// against this scenario's own PostgreSQL container.
fn bounded_direct_client_config(url: &str) -> postgres::Config {
    let mut config: postgres::Config = url
        .parse()
        .unwrap_or_else(|error| panic!("failed to parse direct database URL: {error}"));
    let statement_timeout_millis: u64 =
        u64::try_from(DIRECT_CLIENT_STATEMENT_TIMEOUT.as_millis()).unwrap();
    config.connect_timeout(CLIENT_CONNECT_TIMEOUT);
    config.tcp_user_timeout(CLIENT_TCP_USER_TIMEOUT);
    config.options(&format!("-c statement_timeout={statement_timeout_millis}"));
    config
}

fn connect_direct(url: &str, label: &str) -> Client {
    bounded_direct_client_config(url)
        .connect(NoTls)
        .unwrap_or_else(|error| panic!("bounded direct connect to {label} failed: {error}"))
}

/// Builds a bounded [`postgres::Config`] for a client routed through the
/// PgBouncer proxy. No `statement_timeout` startup option: see
/// [`DIRECT_CLIENT_STATEMENT_TIMEOUT`]'s doc comment.
fn bounded_proxied_client_config(url: &str) -> postgres::Config {
    let mut config: postgres::Config = url
        .parse()
        .unwrap_or_else(|error| panic!("failed to parse proxied database URL: {error}"));
    config.connect_timeout(CLIENT_CONNECT_TIMEOUT);
    config.tcp_user_timeout(CLIENT_TCP_USER_TIMEOUT);
    config
}

fn connect_proxied(url: &str, label: &str) -> Client {
    bounded_proxied_client_config(url)
        .connect(NoTls)
        .unwrap_or_else(|error| panic!("bounded proxied connect to {label} failed: {error}"))
}

/// PgBouncer's admin console (`dbname=pgbouncer`) only answers `SHOW ...`
/// commands over the simple query protocol, not the extended (`Parse`/
/// `Bind`/`Execute`) protocol `postgres::Client::query` always uses, so every
/// admin-console call in this scenario goes through `simple_query` and this
/// helper instead. Every regular data query against the tested database
/// (through the proxy's pooled connection) is unaffected: PgBouncer's
/// extended-protocol/prepared-statement support is exactly what
/// `max_prepared_statements` governs for those.
fn admin_show_rows(admin: &mut Client, command: &str) -> Vec<postgres::SimpleQueryRow> {
    admin
        .simple_query(command)
        .unwrap_or_else(|error| panic!("{command} failed: {error}"))
        .into_iter()
        .filter_map(|message| match message {
            postgres::SimpleQueryMessage::Row(row) => Some(row),
            _ => None,
        })
        .collect()
}

fn simple_row_get<'a>(row: &'a postgres::SimpleQueryRow, column: &str) -> &'a str {
    row.get(column)
        .unwrap_or_else(|| panic!("admin console row had no {column:?} column"))
}

/// Reads the single PostgreSQL backend PID PgBouncer reports as currently
/// serving `database` through `admin`'s `SHOW SERVERS` admin-console
/// evidence. Panics unless there is exactly one such server row: this
/// scenario's `pool_size=1` makes that the only correct steady state whenever
/// this is called.
fn sole_backend_remote_pid(admin: &mut Client, database: &str) -> i32 {
    let rows = admin_show_rows(admin, "SHOW SERVERS");
    let matching: Vec<&postgres::SimpleQueryRow> = rows
        .iter()
        .filter(|row| simple_row_get(row, "database") == database)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one PgBouncer server (backend) connection for database {database:?}, \
         got {}",
        matching.len()
    );
    simple_row_get(matching[0], "remote_pid")
        .parse()
        .unwrap_or_else(|error| panic!("SHOW SERVERS remote_pid was not an integer: {error}"))
}

fn deadline(budget_millis: u64) -> StorageDeadline {
    StorageDeadline::new(now_millis().checked_add(budget_millis).unwrap()).unwrap()
}

/// Bounded budget for the adapter's blocked-proxy [`DurableOperationContext`].
/// Deliberately generous relative to PgBouncer's own configured
/// `query_wait_timeout` (`support::PGBOUNCER_QUERY_WAIT_TIMEOUT_SECS`), so the
/// observed rejection is proven to come from PgBouncer's own bounded queue
/// timeout, not from this context's deadline running out first.
const BLOCKED_PROBE_BUDGET_MILLIS: u64 = 15_000;

/// Upper-bound headroom, added to PgBouncer's own configured
/// `query_wait_timeout`, when bounding the observed wall-clock time of the
/// blocked-proxy commit attempt: proof PgBouncer's own timeout fired, not an
/// unbounded wait.
const BLOCKED_PROBE_ELAPSED_UPPER_HEADROOM: Duration = Duration::from_secs(5);

/// Lower-bound tolerance subtracted from PgBouncer's own configured
/// `query_wait_timeout` when bounding the observed wall-clock time from
/// below: proof the call did not return near-instantly (which would mean the
/// rejection did not genuinely come from exhausting PgBouncer's queue wait).
const BLOCKED_PROBE_ELAPSED_LOWER_TOLERANCE: Duration = Duration::from_secs(2);

/// Generous budget for every context after the blocking transaction is
/// released, where the adapter pool can genuinely succeed quickly.
const RECOVERY_BUDGET_MILLIS: u64 = 60_000;

#[test]
fn postgres_pgbouncer_transaction_pooling_rehearsal() {
    let (postgres_image, pgbouncer_image) = match support::resolve_pgbouncer_scenario() {
        support::PgBouncerScenario::Skip => {
            eprintln!(
                "skipping live PgBouncer rehearsal: neither {} nor {} is configured and {} is unset",
                support::PGBOUNCER_POSTGRES_IMAGE_ENV,
                support::PGBOUNCER_IMAGE_ENV,
                support::PGBOUNCER_REQUIRED_ENV
            );
            return;
        }
        support::PgBouncerScenario::Run {
            postgres_image,
            pgbouncer_image,
        } => (postgres_image, pgbouncer_image),
    };

    // Acquired before any container/network work, and declared before every
    // guard below, so that on unwind locals drop in reverse declaration
    // order: the proxy container drops first, then the PostgreSQL container,
    // then the network (Docker refuses to remove a network with live
    // attachments), and only then is the lock released for the next live
    // test.
    let _live_test_lock = support::LiveTestLock::acquire();

    let network = support::DockerNetwork::create();
    let postgres_container = support::PgBouncerPostgresContainer::start(&postgres_image, &network);

    // --- Provision the disposable database and pool credentials -------------

    let mut admin_client = connect_direct(&postgres_container.url("postgres"), "postgres (admin)");
    admin_client
        .execute(&format!("CREATE DATABASE {PGBOUNCER_DATABASE}"), &[])
        .unwrap();
    drop(admin_client);

    // The direct, proxy-bypassing operator connection: opened once and kept
    // open for the whole scenario. It bootstraps the namespace, reads
    // ground-truth server-side state, and — critically — remains fully
    // usable even while PgBouncer's single backend is held by a blocking
    // transaction, since it never goes through the proxy.
    let mut direct_operator = connect_direct(
        &postgres_container.url(PGBOUNCER_DATABASE),
        PGBOUNCER_DATABASE,
    );
    let database: String = direct_operator
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, PGBOUNCER_DATABASE,
        "refusing to run the PgBouncer rehearsal against a non-disposable database"
    );

    let pool_password = postgres_container.password().to_owned();
    direct_operator
        .execute(
            &format!("ALTER ROLE postgres PASSWORD '{pool_password}'"),
            &[],
        )
        .unwrap();
    let credential_hash: String = direct_operator
        .query_one(
            "SELECT rolpassword FROM pg_authid WHERE rolname = 'postgres'",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        credential_hash.starts_with("md5") && credential_hash.len() == 35,
        "expected PostgreSQL to have stored an md5<32 hex> credential hash for the pool role \
         (password_encryption=md5 is set on this disposable container), got {credential_hash:?}"
    );

    apply_initial_schema(&mut direct_operator).unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!("postgres-pgbouncer-{}", unique_run_suffix())).unwrap(),
        ValidatorId::new([0xf1; 32]),
        AtomicityDomainId::new([0xf2; 32]).unwrap(),
    )
    .unwrap();
    let domain = namespace.domain();
    let initial_fence = WriterFenceGeneration::new(1).unwrap();
    let metadata = bootstrap_namespace(
        &mut direct_operator,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        initial_fence,
    )
    .unwrap();
    assert_eq!(metadata.writer_fence(), initial_fence);
    assert_eq!(metadata.commit_sequence(), 0);

    // --- Start the PgBouncer proxy, wired to the backend by network alias ---

    let proxy = support::PgBouncerProxyContainer::start(
        &pgbouncer_image,
        &network,
        PGBOUNCER_DATABASE,
        "postgres",
        &pool_password,
        &credential_hash,
    );
    let mut admin = connect_proxied(&proxy.admin_url(), "pgbouncer admin console");

    // --- Assert PgBouncer admin pool evidence for configured transaction mode

    let config_rows = admin_show_rows(&mut admin, "SHOW CONFIG");
    let config_value = |key: &str| -> String {
        let row = config_rows
            .iter()
            .find(|row| simple_row_get(row, "key") == key)
            .unwrap_or_else(|| panic!("SHOW CONFIG did not return a {key:?} row"));
        simple_row_get(row, "value").to_owned()
    };
    assert_eq!(config_value("pool_mode"), "transaction");
    let configured_max_prepared_statements: u32 =
        config_value("max_prepared_statements").parse().unwrap();
    assert_eq!(
        configured_max_prepared_statements,
        support::PGBOUNCER_MAX_PREPARED_STATEMENTS
    );
    assert!(
        configured_max_prepared_statements > 0,
        "max_prepared_statements must be nonzero"
    );
    let configured_query_wait_timeout: u32 = config_value("query_wait_timeout").parse().unwrap();
    assert_eq!(
        configured_query_wait_timeout,
        support::PGBOUNCER_QUERY_WAIT_TIMEOUT_SECS
    );
    // Exactly one backend connection for the tested database/user pool is
    // not just `pool_size` in the rendered ini: read back every PgBouncer
    // setting that could independently cap or override it, directly through
    // the admin console, never inferred from `pool_size` alone.
    let configured_default_pool_size: u32 = config_value("default_pool_size").parse().unwrap();
    assert_eq!(configured_default_pool_size, support::PGBOUNCER_POOL_SIZE);
    let configured_max_db_connections: u32 = config_value("max_db_connections").parse().unwrap();
    assert_eq!(configured_max_db_connections, support::PGBOUNCER_POOL_SIZE);
    let configured_max_user_connections: u32 =
        config_value("max_user_connections").parse().unwrap();
    assert_eq!(
        configured_max_user_connections,
        support::PGBOUNCER_POOL_SIZE
    );

    // `SHOW DATABASES` carries the per-database `pool_size` PgBouncer
    // actually loaded from the `[databases]` section for the tested
    // database specifically (as opposed to `SHOW CONFIG`'s `[pgbouncer]`
    // section defaults above), so this is independent evidence, not a
    // restatement of the same setting.
    let database_rows = admin_show_rows(&mut admin, "SHOW DATABASES");
    let app_database_row = database_rows
        .iter()
        .find(|row| simple_row_get(row, "name") == PGBOUNCER_DATABASE)
        .unwrap_or_else(|| panic!("SHOW DATABASES did not return a row for {PGBOUNCER_DATABASE}"));
    let configured_database_pool_size: u32 = simple_row_get(app_database_row, "pool_size")
        .parse()
        .unwrap();
    assert_eq!(configured_database_pool_size, support::PGBOUNCER_POOL_SIZE);

    // --- Two simultaneously open, distinct client connections reuse exactly
    //     one PostgreSQL backend across sequential transactions ------------
    //
    // `SHOW POOLS` only lists a pool once some client has connected to that
    // database at least once, so the `pool_mode` cross-check against it
    // happens after client A's first transaction rather than before either
    // client connects.

    let mut client_a = connect_proxied(&proxy.url(PGBOUNCER_DATABASE), "proxied client A");
    let mut client_b = connect_proxied(&proxy.url(PGBOUNCER_DATABASE), "proxied client B");

    {
        let mut transaction_a = client_a.transaction().unwrap();
        transaction_a.query_one("SELECT 1", &[]).unwrap();
        transaction_a.commit().unwrap();
    }
    let remote_pid_after_a = sole_backend_remote_pid(&mut admin, PGBOUNCER_DATABASE);

    let pool_rows = admin_show_rows(&mut admin, "SHOW POOLS");
    let app_pool_row = pool_rows
        .iter()
        .find(|row| simple_row_get(row, "database") == PGBOUNCER_DATABASE)
        .unwrap_or_else(|| panic!("SHOW POOLS did not return a row for {PGBOUNCER_DATABASE}"));
    assert_eq!(simple_row_get(app_pool_row, "pool_mode"), "transaction");

    {
        let mut transaction_b = client_b.transaction().unwrap();
        transaction_b.query_one("SELECT 1", &[]).unwrap();
        transaction_b.commit().unwrap();
    }
    let remote_pid_after_b = sole_backend_remote_pid(&mut admin, PGBOUNCER_DATABASE);

    assert_eq!(
        remote_pid_after_a, remote_pid_after_b,
        "expected both distinct, simultaneously open client connections to reuse the exact same \
         PostgreSQL backend process across their sequential transactions"
    );
    drop(client_a);
    drop(client_b);

    // --- The real runtime-postgres adapter, pointed at the proxy -----------

    // `connect_timeout`/`tcp_user_timeout` are deliberately not set here:
    // `build_postgres_pool` always overwrites both from the
    // `PostgresPoolConfig` below (its own `connection_timeout` argument), so
    // setting them on this `Config` first would be dead code silently
    // discarded, not the effective value.
    let mut pool_config: postgres::Config = proxy.url(PGBOUNCER_DATABASE).parse().unwrap();
    pool_config.application_name(ADAPTER_POOL_APPLICATION_NAME);
    let pool = build_postgres_pool(
        pool_config,
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(1).unwrap(),
            Duration::from_secs(BLOCKED_PROBE_BUDGET_MILLIS / 1000 + 5),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap();
    let store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );

    // --- Build the invocation (not yet committed) ---------------------------

    let request_id = DurableRequestId::new([0xf3; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xf4; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"pgbouncer-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0xf5; 32]),
        b"pgbouncer-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"pgbouncer/state".to_vec();
    let state_value = xorshift64_star_payload(STATE_PAYLOAD_BYTES, 0x9E37_79B9_7F4A_7C15);
    let state_transaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(state_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(state_key.clone(), StateMutation::Put(state_value.clone()))
                .unwrap(),
        ],
    )
    .unwrap();
    let invocation = DurableInvocationTransaction::new(
        domain,
        Some(state_transaction),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox_batch),
    )
    .unwrap();

    // --- While a direct proxied client holds the only backend in an open
    //     transaction, drive one bounded adapter invocation ------------------

    let mut blocker = connect_proxied(&proxy.url(PGBOUNCER_DATABASE), "proxied blocker");
    let mut blocker_transaction = blocker.transaction().unwrap();
    blocker_transaction.query_one("SELECT 1", &[]).unwrap();
    // `blocker_transaction` is deliberately left open (neither committed nor
    // rolled back) across the blocked-proxy probe below: PgBouncer keeps this
    // client's backend assignment for as long as its transaction remains
    // open, which is what makes the adapter's own attempt queue.

    let blocked_server_rows: Vec<postgres::SimpleQueryRow> =
        admin_show_rows(&mut admin, "SHOW SERVERS")
            .into_iter()
            .filter(|row| simple_row_get(row, "database") == PGBOUNCER_DATABASE)
            .collect();
    assert_eq!(
        blocked_server_rows.len(),
        1,
        "expected the blocking transaction to hold exactly the one configured backend"
    );
    // Not just that the one row exists, but that it is genuinely occupied by
    // the blocker's open transaction (`state = active`), not merely present
    // and idle: `active` is PgBouncer's own admin-console evidence that this
    // backend is currently linked to a client, which is exactly what makes
    // the adapter's own attempt queue below.
    assert_eq!(
        simple_row_get(&blocked_server_rows[0], "state"),
        "active",
        "expected the sole backend to be in PgBouncer's `active` state while the blocker's \
         transaction is open"
    );

    let blocked_context = DurableOperationContext::new(
        initial_fence,
        deadline(BLOCKED_PROBE_BUDGET_MILLIS),
        StorageCorrelationId::new([0xf6; 16]).unwrap(),
    );
    let attempt_started = Instant::now();
    let blocked_outcome = store.commit_invocation(&blocked_context, invocation.clone());
    let attempt_elapsed = attempt_started.elapsed();
    eprintln!("pgbouncer-blocked adapter outcome: {blocked_outcome:?} after {attempt_elapsed:?}");
    // Live evidence, not an assumed classification: PgBouncer's own
    // `query_wait_timeout` surfaces as a definite PostgreSQL-protocol
    // `ErrorResponse` (SQLSTATE 08P01, message `query_wait_timeout`) on the
    // adapter's first statement (the transaction-opening `BEGIN`) once the
    // proxy gives up waiting for a free backend — never a raw connection
    // refusal, since PgBouncer always accepts and authenticates the client
    // TCP connection itself before it ever tries to pair it with a backend.
    // This crate's `PreCommitFailure::from_sqlstate` has no dedicated arm for
    // class `08` (connection exception), so it falls through to its default
    // `Unavailable` bucket, i.e. a definite pre-commit rejection, never the
    // `Indeterminate`/`Deadline` outcomes this crate reserves for a
    // definitively lost connection or an exhausted caller-side deadline.
    assert_eq!(
        blocked_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
    );
    // Bounded from both directions around PgBouncer's own configured
    // `query_wait_timeout`, not this probe's much larger context budget:
    // proof the rejection's timing tracks the proxy's own queue timeout, not
    // this test's outer deadline or an unbounded wait.
    let configured_query_wait =
        Duration::from_secs(u64::from(support::PGBOUNCER_QUERY_WAIT_TIMEOUT_SECS));
    assert!(
        attempt_elapsed + BLOCKED_PROBE_ELAPSED_LOWER_TOLERANCE >= configured_query_wait,
        "commit_invocation returned after only {attempt_elapsed:?}, well short of PgBouncer's own \
         {configured_query_wait:?} query_wait_timeout minus tolerance; this suggests the rejection \
         did not genuinely come from exhausting PgBouncer's queue wait"
    );
    assert!(
        attempt_elapsed <= configured_query_wait + BLOCKED_PROBE_ELAPSED_UPPER_HEADROOM,
        "commit_invocation took {attempt_elapsed:?}, well beyond PgBouncer's own \
         {configured_query_wait:?} query_wait_timeout plus headroom; this suggests the rejection \
         came from this probe's own much larger context deadline instead of PgBouncer's queue \
         timeout"
    );
    assert!(
        attempt_elapsed < Duration::from_millis(BLOCKED_PROBE_BUDGET_MILLIS),
        "commit_invocation took {attempt_elapsed:?}, which did not leave any margin below this \
         probe's {BLOCKED_PROBE_BUDGET_MILLIS}ms context deadline; the rejection must be caused by \
         PgBouncer's own shorter query_wait_timeout, not this probe's deadline"
    );

    // --- Prove non-publication through the direct, proxy-bypassing operator
    //     connection, unaffected by the proxy's contention -------------------

    let non_publication_row = direct_operator
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
        inspect_namespace(&mut direct_operator, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        0,
        "the rejected attempt must not have advanced the commit sequence"
    );

    // --- Release the blocking transaction, then recover through the same
    //     adapter pool/store -------------------------------------------------

    blocker_transaction.commit().unwrap();
    drop(blocker);

    let recovery_context = DurableOperationContext::new(
        initial_fence,
        deadline(RECOVERY_BUDGET_MILLIS),
        StorageCorrelationId::new([0xf7; 16]).unwrap(),
    );
    // Bounded, documented tolerance for one specific, live-verified transient:
    // r2d2 checks `Client::is_closed()` on the *previous* (blocked-probe)
    // connection the instant its `PooledConnection` guard drops, to decide
    // whether to recycle it into the idle pool or evict it. `tokio-postgres`
    // only learns a peer-closed TCP connection is dead once its background
    // connection-driving task processes that close, asynchronously and
    // slightly after PgBouncer's FATAL closes the socket — so `is_closed()`
    // can occasionally still read `false` at that exact instant, and r2d2
    // recycles the now-actually-dead connection instead of evicting it. This
    // scenario's own next `pool.get_timeout()` (here) can then be handed that
    // exact stale connection and fail near-instantly (a local broken-pipe/
    // reset I/O error, not a PostgreSQL `ErrorResponse`, so
    // `PreCommitFailure::from_sqlstate` classifies it the same as any other
    // unclassified failure: `Rejected(UnavailableBeforeCommit)`) — live-
    // verified at sub-millisecond elapsed time, sharply distinct from a
    // genuine PgBouncer queue rejection's multi-second elapsed time. This
    // retry only tolerates that exact narrow shape (`UnavailableBeforeCommit`
    // resolved in under one second); the final assertion after the loop still
    // requires the identical invocation to reach `Committed`, and any other
    // outcome fails the test immediately rather than being retried away.
    const RECOVERY_STALE_CONNECTION_RETRY_ATTEMPTS: u32 = 5;
    const RECOVERY_STALE_CONNECTION_ELAPSED_CEILING: Duration = Duration::from_secs(1);
    // Seeded with a rejection, never `Committed`: if a future edit ever
    // shrinks `RECOVERY_STALE_CONNECTION_RETRY_ATTEMPTS` to `0`, this loop
    // runs zero iterations and the final `assert_eq!` below must fail loudly
    // on this seed instead of vacuously passing on an outcome `commit_invocation`
    // never actually produced.
    let mut recovery_outcome =
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit);
    for attempt in 1..=RECOVERY_STALE_CONNECTION_RETRY_ATTEMPTS {
        let attempt_started = Instant::now();
        recovery_outcome = store.commit_invocation(&recovery_context, invocation.clone());
        let attempt_elapsed = attempt_started.elapsed();
        match recovery_outcome {
            DurableCommitOutcome::Committed => break,
            DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
                if attempt_elapsed < RECOVERY_STALE_CONNECTION_ELAPSED_CEILING
                    && attempt < RECOVERY_STALE_CONNECTION_RETRY_ATTEMPTS =>
            {
                eprintln!(
                    "recovery attempt {attempt} hit the known stale-recycled-connection race \
                     ({attempt_elapsed:?} elapsed); retrying"
                );
            }
            _ => break,
        }
    }
    assert_eq!(recovery_outcome, DurableCommitOutcome::Committed);

    // Admin evidence, not inferred: the exact same backend-PID probe used
    // for the two synthetic clients above, called again now, proves the
    // recovered adapter commit was served by that identical physical
    // PostgreSQL backend (`remote_pid_after_a == remote_pid_after_b`
    // already proved above), not a new or different backend process that
    // PgBouncer happened to open after the blocking transaction released.
    let remote_pid_after_recovery = sole_backend_remote_pid(&mut admin, PGBOUNCER_DATABASE);
    assert_eq!(
        remote_pid_after_recovery, remote_pid_after_b,
        "expected the adapter's recovered commit to have been served by the exact same sole \
         PostgreSQL backend the two synthetic clients observed, not a different backend process"
    );

    // Admin evidence, not inferred: PgBouncer's own `SHOW CLIENTS`, filtered
    // by the adapter pool's distinguishing `application_name`, proves
    // specifically that the adapter pool's own proxy connection is the one
    // that reclaimed the freed backend.
    let adapter_client_rows = admin_show_rows(&mut admin, "SHOW CLIENTS");
    let adapter_client_count = adapter_client_rows
        .iter()
        .filter(|row| {
            simple_row_get(row, "database") == PGBOUNCER_DATABASE
                && simple_row_get(row, "application_name") == ADAPTER_POOL_APPLICATION_NAME
        })
        .count();
    assert_eq!(
        adapter_client_count, 1,
        "expected exactly one PgBouncer client carrying the adapter pool's application_name after \
         a successful recovery commit"
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
        store.commit_invocation(&recovery_context, invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0xf8; 32]).unwrap();
    let claim_window: u64 = now_millis();
    let claim_expiry: u64 = claim_window.checked_add(60_000).unwrap();
    let claim = match store.claim_request_outbox(
        &recovery_context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("expected the committed outbox message to be claimable, got {outcome:?}"),
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.canonical_payload(), b"pgbouncer-outbound-event");

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
                DurableOutboxLeaseId::new([0xf9; 32]).unwrap(),
                no_due_work_expiry,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    assert_eq!(
        inspect_namespace(&mut direct_operator, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );

    // Pool usability after the whole rehearsal: one further trivial adapter
    // read through the same store/pool.
    assert_eq!(
        store
            .get_versioned_durable(&recovery_context, domain, &state_key)
            .unwrap()
            .revision(),
        StateRevision::new(1)
    );
}
