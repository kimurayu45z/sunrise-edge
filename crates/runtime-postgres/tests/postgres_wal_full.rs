//! Live bounded WAL-filesystem exhaustion test for the PostgreSQL durable
//! store.
//!
//! This is a separate test binary from every other live test in this crate
//! because it starts and destroys its own disposable container with a
//! non-default entrypoint (see `support::WalFullPostgresContainer`); it still
//! takes `support::LiveTestLock` before any container work, so it never runs
//! concurrently with another live test in this crate. Capability resolution
//! (skip vs. run vs. fail on partial/invalid configuration) is
//! `support::resolve_wal_full_scenario`; see that function's doc comment for
//! the exact rules.
//!
//! Scope: like the disk-full scenario's data-tablespace `ENOSPC`, a real
//! write failure on the filesystem holding `pg_wal` still returns SQLSTATE
//! `53100` (disk_full) to the client — but at `PANIC` severity, not PR86's
//! plain `ERROR`. A `PANIC` response is PostgreSQL's own signal that it is
//! about to terminate every backend and crash-restart the whole postmaster
//! (its own follow-on automatic crash-recovery attempt fails the same way,
//! since it also needs to write WAL, bringing the whole server down a second
//! time). This test runs two independent WAL-fill cycles against the same
//! container. Cycle 1 is a direct ground-truth probe: a direct client write
//! that crosses a WAL segment boundary on a nearly-full, dedicated WAL tmpfs
//! gets SQLSTATE `53100` at `PANIC` severity, immediately followed by the
//! connection itself closing, then recovers in place. Cycle 2 independently
//! refills the same WAL mount and drives the adapter's own structured
//! invocation commit — using a bounded incompressible state payload, not the
//! direct probe — as the write that itself crosses the WAL segment boundary
//! and crashes PostgreSQL; the actually observed adapter outcome is asserted
//! (a definite `Rejected(UnavailableBeforeCommit)`, live evidence, not an
//! assumption carried over from cycle 1), and only then does this test
//! reconcile exact non-publication, a second strictly-advanced
//! `pg_postmaster_start_time()`, and an identical replay/receipt/outbox
//! claim/acknowledgement through the same pool/store. Because the whole
//! server (not just one connection) goes down on either cycle, both recover
//! by freeing WAL space and restarting postgres *in place* inside the same,
//! still-running container (never `docker start`, which would recreate every
//! tmpfs mount empty and destroy the evidence). It does **not** prove
//! commit-boundary `ENOSPC` for WAL or data exhaustion: neither this test nor
//! PR86's disk-full scenario has live evidence for a fault at the literal
//! `COMMIT` statement itself (as opposed to an earlier statement in the same
//! transaction), so that case remains open and must be treated
//! conservatively until such evidence exists. It also does not prove
//! real-device `ENOSPC`,
//! block-device behavior (write cache, torn writes, media faults), the
//! shared CI database's behavior under WAL pressure, connection exhaustion,
//! backup/restore, capacity/load/soak, TLS-path connection loss, real writer
//! failover, provider certification, or production readiness.

use postgres::{Client, Config, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::PostgresConnectionManager;
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableOperationContext,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome, DurableOutboxBatch,
    DurableOutboxClaimOutcome, DurableOutboxLeaseId, DurableOutboxMessage, DurableReadError,
    DurableRequestId, DurableRequestReceipt, DurableStateTransaction, IndexedOutboxRepository,
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

/// Disposable database this scenario creates on its own container, never the
/// shared CI service database and never PR86's disk-full database. Uses the
/// container's unbounded default tablespace: unlike the disk-full scenario,
/// this test never needs a custom tablespace, since WAL (not a relation
/// tablespace) is the filesystem under test.
const WAL_FULL_DATABASE: &str = "sunrise_edge_wal_full";

/// Lower/upper bound, in KiB, that `df -P -k` on [`support::WAL_FULL_WAL_MOUNT`]
/// must report as total capacity: proof the 64 MiB tmpfs cap this scenario
/// configured for `pg_wal` is the filesystem actually in effect.
const WAL_TMPFS_MIN_TOTAL_KIB: u64 = 60_000;
const WAL_TMPFS_MAX_TOTAL_KIB: u64 = 65_536;

/// Lower/upper bound, in KiB, that `df -P -k` on `SHOW data_directory` must
/// report as total capacity: proof the 512 MiB tmpfs cap this scenario
/// configures for PGDATA (excluding `pg_wal`) is the filesystem actually in
/// effect, not some larger inherited mount. This filesystem is never
/// intentionally filled, so unlike the WAL bound above it is a much wider,
/// symmetric-in-kind sanity range around the configured 512 MiB
/// (524,288 KiB) cap.
const PGDATA_TMPFS_MIN_TOTAL_KIB: u64 = 500_000;
const PGDATA_TMPFS_MAX_TOTAL_KIB: u64 = 524_288;

/// Upper bound, in KiB, on WAL-mount available space immediately after the
/// filler write: headroom for tmpfs bookkeeping, not a measured budget.
const POST_FILL_MAX_AVAILABLE_KIB: u64 = 1536;

/// Lower bound, in KiB, on WAL-mount available space immediately after the
/// filler file is removed: proof space was genuinely freed.
const POST_CLEANUP_MIN_AVAILABLE_KIB: u64 = 32_768;

/// KiB of headroom left unfilled by the `dd` write, so early, small WAL
/// activity (schema DDL, the baseline commit) still succeeds before the
/// filesystem is considered full.
const FILL_HEADROOM_KIB: u64 = 1024;

/// Size of the incompressible payload driven through both the direct
/// ground-truth probe (cycle 1) and the adapter's own state mutation
/// (cycle 2). This test cluster fixes WAL segments at 2 MiB during `initdb`;
/// the payload is
/// comfortably larger so the write's WAL record reliably crosses into a new
/// segment (which needs a fresh, zero-filled segment file the nearly-full WAL
/// tmpfs cannot supply) regardless of exactly how much of the current
/// segment is already used. Enforced below to stay well inside
/// `runtime::MAX_STATE_VALUE_BYTES` (32 MiB), since cycle 2 drives this
/// exact byte count through a real `DurableStateTransaction`.
const WAL_SEGMENT_CROSSING_PAYLOAD_BYTES: usize = 24 * 1024 * 1024;

const _: () = assert!(WAL_SEGMENT_CROSSING_PAYLOAD_BYTES <= runtime::MAX_STATE_VALUE_BYTES);

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

/// Deterministic xorshift64* byte stream: `pglz`/LZ4 TOAST compression cannot
/// shrink it, so the WAL record backing it is guaranteed to need genuine new
/// WAL bytes, not merely a large logical value that compresses away.
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

fn data_directory(client: &mut Client) -> String {
    client.query_one("SHOW data_directory", &[]).unwrap().get(0)
}

/// Projects `pg_postmaster_start_time()` as an exact integer count of
/// microseconds since the Unix epoch, exactly as DR-0069's crash-recovery
/// test does: `EXTRACT(EPOCH FROM ...)` returns `numeric` (exact decimal), so
/// multiplying by `1000000` and casting to `bigint` never lets a float enter
/// either the SQL computation or the Rust decode.
const POSTMASTER_START_TIME_MICROS_SQL: &str =
    "SELECT (EXTRACT(EPOCH FROM pg_postmaster_start_time()) * 1000000)::bigint";

fn postmaster_start_time_micros(client: &mut Client) -> i64 {
    client
        .query_one(POSTMASTER_START_TIME_MICROS_SQL, &[])
        .unwrap()
        .get(0)
}

/// Connect timeout applied to every direct probe/DDL client this scenario
/// opens against its own disposable container.
const DIRECT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-level user timeout mirrored onto every direct probe/DDL client, so a
/// connection that stalls after the TCP handshake against the disposable
/// container is bounded the same way as a slow connect.
const DIRECT_CLIENT_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Session `statement_timeout` applied to every direct probe/DDL client.
/// Generous relative to this scenario's own bounded work, but far below the
/// outer test process's own deadline, so a wedged connection fails loudly
/// instead of hanging the test. The WAL-exhaustion probe statement itself
/// never reaches this timeout: it fails immediately with a closed connection,
/// not a slow query.
const DIRECT_CLIENT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a bounded [`Config`] for a direct probe/DDL client against this
/// scenario's disposable container: an explicit connect timeout, TCP user
/// timeout, and session `statement_timeout`, so no direct query this scenario
/// issues can inherit the driver's unbounded defaults.
fn bounded_direct_client_config(url: &str) -> Config {
    let mut config: Config = url.parse().unwrap_or_else(|error| {
        panic!("failed to parse disposable-container database URL: {error}")
    });
    let statement_timeout_millis: u64 =
        u64::try_from(DIRECT_CLIENT_STATEMENT_TIMEOUT.as_millis()).unwrap();
    config.connect_timeout(DIRECT_CLIENT_CONNECT_TIMEOUT);
    config.tcp_user_timeout(DIRECT_CLIENT_TCP_USER_TIMEOUT);
    config.options(&format!("-c statement_timeout={statement_timeout_millis}"));
    config
}

/// Connects a direct probe/DDL client through [`bounded_direct_client_config`].
/// `label` identifies the target database in a failure message only; it never
/// includes the URL itself, since the URL carries the generated container
/// password.
fn connect_bounded(url: &str, label: &str) -> Client {
    bounded_direct_client_config(url)
        .connect(NoTls)
        .unwrap_or_else(|error| panic!("bounded connect to {label} failed: {error}"))
}

#[test]
fn postgres_wal_full_bounded_wal_exhaustion() {
    let image = match support::resolve_wal_full_scenario() {
        support::WalFullScenario::Skip => {
            eprintln!(
                "skipping live PostgreSQL WAL-exhaustion scenario: neither {} nor {} is configured",
                support::WAL_FULL_IMAGE_ENV,
                support::WAL_FULL_REQUIRED_ENV
            );
            return;
        }
        support::WalFullScenario::Run(image) => image,
    };

    // Acquired before any container work, and declared before `container`
    // below, so that on unwind locals drop in reverse declaration order:
    // `container` (panic-safe force-remove) drops first, and only then is
    // the lock released for the next live test.
    let _live_test_lock = support::LiveTestLock::acquire();

    let container = support::WalFullPostgresContainer::start(&image);

    // --- Provision the disposable database -----------------------------------

    let identity_marker = support::random_hex_token(32);
    let identity_file = format!("identity-{identity_marker}");
    container
        .exec(&[
            "touch",
            &format!("{}/{identity_file}", support::WAL_FULL_WAL_MOUNT),
        ])
        .unwrap_or_else(|error| panic!("touch identity marker failed: {error}"));

    let mut admin_client = connect_bounded(&container.url("postgres"), "postgres (admin)");
    admin_client
        .execute(&format!("CREATE DATABASE {WAL_FULL_DATABASE}"), &[])
        .unwrap();
    drop(admin_client);

    let mut client = connect_bounded(&container.url(WAL_FULL_DATABASE), WAL_FULL_DATABASE);

    // --- Phase 0: identity, before any fault ---------------------------------

    let ls_entries: Vec<String> = client
        .query("SELECT pg_ls_dir($1)", &[&support::WAL_FULL_WAL_MOUNT])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        ls_entries.contains(&identity_file),
        "expected {identity_file:?} in {}, found {ls_entries:?}; the SQL connection and the \
         docker exec target are not the same container/mount",
        support::WAL_FULL_WAL_MOUNT
    );

    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, WAL_FULL_DATABASE,
        "refusing to run the WAL-exhaustion scenario against a non-disposable database"
    );

    let pgdata = data_directory(&mut client);
    let pg_wal_target = container
        .exec(&["readlink", "-f", &format!("{pgdata}/pg_wal")])
        .unwrap_or_else(|error| panic!("readlink -f {pgdata}/pg_wal failed: {error}"));
    assert_eq!(
        pg_wal_target.trim(),
        support::WAL_FULL_WAL_DIRECTORY,
        "pg_wal must resolve to the dedicated WAL tmpfs, not stay inside PGDATA"
    );

    let pgdata_device = support::parse_device_id(
        &container
            .exec(&["stat", "-c", "%d", &pgdata])
            .unwrap_or_else(|error| panic!("stat {pgdata} failed: {error}")),
    );
    let wal_device = support::parse_device_id(
        &container
            .exec(&["stat", "-c", "%d", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| panic!("stat {} failed: {error}", support::WAL_FULL_WAL_MOUNT)),
    );
    assert_ne!(
        pgdata_device, wal_device,
        "PGDATA and the dedicated WAL mount must live on different filesystems, or filling the \
         WAL mount could also exhaust PGDATA and the single-outcome oracle below would not be \
         sound"
    );

    let (wal_total_kib, _wal_available_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    assert!(
        (WAL_TMPFS_MIN_TOTAL_KIB..=WAL_TMPFS_MAX_TOTAL_KIB).contains(&wal_total_kib),
        "expected {} total capacity in [{WAL_TMPFS_MIN_TOTAL_KIB}, {WAL_TMPFS_MAX_TOTAL_KIB}] \
         KiB, got {wal_total_kib} KiB",
        support::WAL_FULL_WAL_MOUNT
    );

    let (pgdata_total_kib, _pgdata_available_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", &pgdata])
            .unwrap_or_else(|error| panic!("df -P -k {pgdata} failed: {error}")),
    );
    assert!(
        (PGDATA_TMPFS_MIN_TOTAL_KIB..=PGDATA_TMPFS_MAX_TOTAL_KIB).contains(&pgdata_total_kib),
        "expected {pgdata} total capacity in [{PGDATA_TMPFS_MIN_TOTAL_KIB}, \
         {PGDATA_TMPFS_MAX_TOTAL_KIB}] KiB, got {pgdata_total_kib} KiB"
    );

    apply_initial_schema(&mut client).unwrap();
    verify_initial_schema(&mut client).unwrap();
    client
        .execute(
            "CREATE TABLE public.wal_full_probe (payload BYTEA NOT NULL)",
            &[],
        )
        .unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!("postgres-wal-full-{}", unique_run_suffix())).unwrap(),
        ValidatorId::new([0xfe; 32]),
        AtomicityDomainId::new([0xfd; 32]).unwrap(),
    )
    .unwrap();
    let domain = namespace.domain();
    let initial_fence = WriterFenceGeneration::new(1).unwrap();
    let metadata = bootstrap_namespace(
        &mut client,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        initial_fence,
    )
    .unwrap();
    assert_eq!(metadata.writer_fence(), initial_fence);
    assert_eq!(metadata.commit_sequence(), 0);

    let mut pool_config: postgres::Config = container.url(WAL_FULL_DATABASE).parse().unwrap();
    pool_config.application_name("sunrise-edge-pr87-wal-full");
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
    let store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );

    /// Builds a fresh [`DurableOperationContext`] with a deadline computed
    /// from the current instant, never reused across phases: this scenario
    /// spans two full WAL-fill/crash/in-place-restart cycles, each involving
    /// several bounded but real `docker exec`/`pg_ctl` round trips, so a
    /// single context created once at the top of the test could have its
    /// deadline elapse by the time a later phase runs, making
    /// `DeadlineExceededBeforeCommit`/`Indeterminate(DeadlineExceeded)`
    /// (rather than the WAL-exhaustion fault under test) responsible for
    /// whatever outcome resulted. `correlation_seed` only fills every byte of
    /// the correlation ID, distinguishing phases in a failure message.
    fn bounded_context(
        fence: WriterFenceGeneration,
        budget_millis: u64,
        correlation_seed: u8,
    ) -> DurableOperationContext {
        DurableOperationContext::new(
            fence,
            StorageDeadline::new(now_millis().checked_add(budget_millis).unwrap()).unwrap(),
            StorageCorrelationId::new([correlation_seed; 16]).unwrap(),
        )
    }

    /// Generous per-phase deadline budget: this scenario's own bounded work
    /// (container exec, `dd`, `pg_ctl`) always completes in well under this,
    /// so a real WAL-exhaustion result is never confused with a timeout.
    const PHASE_BUDGET_MILLIS: u64 = 240_000;

    // --- Phase 1: healthy baseline, and pre-warm the max-1 connection pool -

    let baseline_key = b"wal-full/baseline".to_vec();
    let baseline_transaction = DurableStateTransaction::new(
        domain,
        runtime::AtomicStateReadSet::new(vec![
            StateReadAssertion::new(baseline_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(baseline_key, StateMutation::Put(b"baseline-value".to_vec()))
                .unwrap(),
        ],
    )
    .unwrap();
    let baseline_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0xf1; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xf2; 32]),
        b"wal-full-baseline-receipt".to_vec(),
    )
    .unwrap();
    let baseline_invocation = DurableInvocationTransaction::new(
        domain,
        Some(baseline_transaction),
        DurableObjectChanges::empty(),
        baseline_receipt,
        None,
    )
    .unwrap();
    let baseline_context = bounded_context(initial_fence, PHASE_BUDGET_MILLIS, 0xb1);
    assert_eq!(
        store.commit_invocation(&baseline_context, baseline_invocation),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        inspect_namespace(&mut client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );

    // === Cycle 1: direct ground-truth probe ==================================
    //
    // Fills the WAL mount and forces the PANIC/crash/in-place-restart cycle
    // through a direct client write, independent of the adapter. This
    // establishes the raw fault mechanics (exact SQLSTATE, severity,
    // connection behavior, whole-server crash, in-place recovery) before
    // cycle 2 below asks the adapter's own commit to be the operation that
    // triggers an identical crash.

    // Captured immediately before the fault: proof, once compared after
    // restart, that postgres genuinely crashed and restarted rather than
    // this scenario merely reconnecting to a server that was never actually
    // interrupted.
    let pre_cycle1_postmaster_start_micros = postmaster_start_time_micros(&mut client);

    let (_, available_before_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    let fill_count_kib = available_before_fill_kib.saturating_sub(FILL_HEADROOM_KIB);
    container
        .exec(&[
            "dd",
            "if=/dev/zero",
            &format!("of={}/filler", support::WAL_FULL_WAL_MOUNT),
            "bs=1024",
            &format!("count={fill_count_kib}"),
        ])
        .unwrap_or_else(|error| panic!("dd filler write failed: {error}"));
    let (_, available_after_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    assert!(
        available_after_fill_kib <= POST_FILL_MAX_AVAILABLE_KIB,
        "expected {} available space <= {POST_FILL_MAX_AVAILABLE_KIB} KiB after filling, got \
         {available_after_fill_kib} KiB",
        support::WAL_FULL_WAL_MOUNT
    );

    // Ground-truth fault probe: a direct client insert large enough to force
    // a new WAL segment on the nearly-full WAL filesystem. Live evidence
    // (not a guess): the backend still returns SQLSTATE 53100 (disk_full,
    // the same code PR86's data-ENOSPC probe observes), but at `PANIC`
    // severity rather than PR86's plain `ERROR`. A `PANIC` response is
    // PostgreSQL's own signal that it is about to terminate every backend
    // and crash-restart the whole postmaster, which the follow-up query
    // below confirms by observing the same connection is now closed.
    let probe_payload =
        xorshift64_star_payload(WAL_SEGMENT_CROSSING_PAYLOAD_BYTES, 0xD1B5_4A32_D192_ED03);
    let probe_error = client
        .execute(
            "INSERT INTO public.wal_full_probe (payload) VALUES ($1)",
            &[&probe_payload],
        )
        .expect_err("expected the bounded WAL filesystem to be genuinely out of space");
    assert_eq!(
        probe_error.code().map(postgres::error::SqlState::code),
        Some("53100"),
        "expected SQLSTATE 53100 (disk_full), got {probe_error:?}"
    );
    let probe_db_error = probe_error
        .as_db_error()
        .unwrap_or_else(|| panic!("expected a database error response, got {probe_error:?}"));
    assert_eq!(
        probe_db_error.parsed_severity(),
        Some(postgres::error::Severity::Panic),
        "expected PANIC severity (PostgreSQL's own signal that it is about to crash-restart the \
         whole server), got {probe_db_error:?}"
    );

    // The PANIC response above is immediately followed by the backend
    // terminating every server process; this second query on the same,
    // still-open `client` handle proves the connection itself is now closed,
    // not merely that one statement failed.
    let post_panic_error = client
        .simple_query("SELECT 1")
        .expect_err("expected the connection to be closed after the WAL-exhaustion PANIC");
    assert!(
        post_panic_error.is_closed(),
        "expected the connection to report closed after the WAL-exhaustion PANIC, got \
         {post_panic_error:?}"
    );

    // The container's own PID 1 (the supervisor script) survives the fault;
    // only the postgres server process inside it does not. This is the key
    // difference from PR86's disk-full scenario and from DR-0069's SIGKILL
    // scenario: a WAL write failure is fatal to the whole database cluster,
    // not just the one statement or one connection.
    assert!(
        container.is_running(),
        "the disposable container itself must survive cycle 1's WAL-exhaustion fault"
    );
    container.wait_until_postgres_down(&pgdata);

    container
        .exec(&["rm", &format!("{}/filler", support::WAL_FULL_WAL_MOUNT)])
        .unwrap_or_else(|error| {
            panic!("rm {}/filler failed: {error}", support::WAL_FULL_WAL_MOUNT)
        });
    let (_, available_after_cycle1_cleanup_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    assert!(
        available_after_cycle1_cleanup_kib >= POST_CLEANUP_MIN_AVAILABLE_KIB,
        "expected {} available space >= {POST_CLEANUP_MIN_AVAILABLE_KIB} KiB after removing the \
         filler, got {available_after_cycle1_cleanup_kib} KiB",
        support::WAL_FULL_WAL_MOUNT
    );

    // Never `docker start`: this restarts postgres in place via `pg_ctl`,
    // preserving the same, never-torn-down tmpfs mounts.
    container.restart_postgres_in_place(&pgdata, WAL_FULL_DATABASE);

    let mut fresh_client = connect_bounded(&container.url(WAL_FULL_DATABASE), WAL_FULL_DATABASE);
    let post_cycle1_postmaster_start_micros = postmaster_start_time_micros(&mut fresh_client);
    assert!(
        post_cycle1_postmaster_start_micros > pre_cycle1_postmaster_start_micros,
        "postmaster start time did not strictly advance across cycle 1's WAL-exhaustion \
         crash/restart (pre-fault {pre_cycle1_postmaster_start_micros}us, post-fault \
         {post_cycle1_postmaster_start_micros}us); this scenario's restart must be a genuine \
         crash/recovery cycle, not a reconnect to a server that never actually went down"
    );

    // Through the same pool and store: cycle 1 involved no adapter commit
    // attempt at all, so the pool's single connection — checked back in
    // healthy after the baseline commit and never touched again until now —
    // is still the pre-crash socket, which the crash killed without this
    // pool ever finding out (`test_on_check_out(false)` never validates it on
    // checkout). Live evidence: the first call through the pool after
    // restart discovers and evicts that stale connection (`has_broken` on
    // drop) but itself still reports the failure it hit; only the next call
    // succeeds against a freshly established connection to the restarted
    // server. This is expected, sound pool behavior, not a bug under test.
    let cycle1_recheck_context = bounded_context(initial_fence, PHASE_BUDGET_MILLIS, 0xc1);
    let stale_pool_connection_error = store
        .get_versioned_durable(&cycle1_recheck_context, domain, b"wal-full/baseline")
        .expect_err(
            "expected the pool's pre-crash idle connection to still be stale immediately after \
             cycle 1's restart",
        );
    assert_eq!(stale_pool_connection_error, DurableReadError::Unavailable);

    let baseline_after_cycle1 = store
        .get_versioned_durable(&cycle1_recheck_context, domain, b"wal-full/baseline")
        .unwrap();
    assert_eq!(baseline_after_cycle1.revision(), StateRevision::new(1));
    assert_eq!(
        baseline_after_cycle1.value(),
        Some(b"baseline-value".as_slice())
    );
    assert_eq!(
        inspect_namespace(&mut fresh_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );

    // === Cycle 2: the adapter's own commit crosses the WAL segment ==========
    //
    // Independently refills the same, now-recovered WAL mount, then drives
    // `store.commit_invocation` with a bounded incompressible state payload
    // large enough to itself force a new WAL segment: this time the
    // adapter's own write is the operation that crashes PostgreSQL, not an
    // already-broken connection to an already-down server.

    let request_id = DurableRequestId::new([0xfa; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xfb; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"wal-full-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0xf3; 32]),
        b"wal-full-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"wal-full/state".to_vec();
    let state_value =
        xorshift64_star_payload(WAL_SEGMENT_CROSSING_PAYLOAD_BYTES, 0x9E37_79B9_7F4A_7C15);
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

    let pre_cycle2_postmaster_start_micros = postmaster_start_time_micros(&mut fresh_client);

    let (_, available_before_cycle2_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    let cycle2_fill_count_kib = available_before_cycle2_fill_kib.saturating_sub(FILL_HEADROOM_KIB);
    container
        .exec(&[
            "dd",
            "if=/dev/zero",
            &format!("of={}/filler", support::WAL_FULL_WAL_MOUNT),
            "bs=1024",
            &format!("count={cycle2_fill_count_kib}"),
        ])
        .unwrap_or_else(|error| panic!("dd filler write failed: {error}"));
    let (_, available_after_cycle2_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    assert!(
        available_after_cycle2_fill_kib <= POST_FILL_MAX_AVAILABLE_KIB,
        "expected {} available space <= {POST_FILL_MAX_AVAILABLE_KIB} KiB after cycle 2's \
         filling, got {available_after_cycle2_fill_kib} KiB",
        support::WAL_FULL_WAL_MOUNT
    );

    // The adapter's own structured invocation commit is the operation that
    // crosses the WAL segment boundary this time. A fresh context, built
    // right before this call, so a stale deadline from an earlier phase
    // (each of which involved real, bounded `docker exec`/`pg_ctl` round
    // trips) could never be what actually determines this outcome.
    let cycle2_fault_context = bounded_context(initial_fence, PHASE_BUDGET_MILLIS, 0xc2);
    let cycle2_outcome = store.commit_invocation(&cycle2_fault_context, fault_invocation.clone());
    eprintln!("cycle 2 observed adapter outcome: {cycle2_outcome:?}");
    // Live evidence, not an assumption carried over from cycle 1: the
    // adapter's own pre-`COMMIT` state mutation is the operation that fills
    // WAL, the server goes down, and the public adapter API reports
    // `UnavailableBeforeCommit`. The adapter intentionally does not expose
    // its raw database error, so only cycle 1 claims the exact SQLSTATE and
    // severity. The definite rejection is sound because this failure is
    // observed before the adapter dispatches its own `COMMIT`; no partial
    // effect of this invocation can have reached durable storage.
    assert_eq!(
        cycle2_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit),
    );

    assert!(
        container.is_running(),
        "the disposable container itself must survive cycle 2's WAL-exhaustion fault"
    );
    container.wait_until_postgres_down(&pgdata);

    // --- Reconcile after cycle 2: free space and restart in place again -----

    container
        .exec(&["rm", &format!("{}/filler", support::WAL_FULL_WAL_MOUNT)])
        .unwrap_or_else(|error| {
            panic!("rm {}/filler failed: {error}", support::WAL_FULL_WAL_MOUNT)
        });
    let (_, available_after_cycle2_cleanup_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", support::WAL_FULL_WAL_MOUNT])
            .unwrap_or_else(|error| {
                panic!("df -P -k {} failed: {error}", support::WAL_FULL_WAL_MOUNT)
            }),
    );
    assert!(
        available_after_cycle2_cleanup_kib >= POST_CLEANUP_MIN_AVAILABLE_KIB,
        "expected {} available space >= {POST_CLEANUP_MIN_AVAILABLE_KIB} KiB after removing the \
         filler, got {available_after_cycle2_cleanup_kib} KiB",
        support::WAL_FULL_WAL_MOUNT
    );

    container.restart_postgres_in_place(&pgdata, WAL_FULL_DATABASE);

    let mut fresh_client = connect_bounded(&container.url(WAL_FULL_DATABASE), WAL_FULL_DATABASE);
    let post_cycle2_postmaster_start_micros = postmaster_start_time_micros(&mut fresh_client);
    assert!(
        post_cycle2_postmaster_start_micros > pre_cycle2_postmaster_start_micros,
        "postmaster start time did not strictly advance across cycle 2's WAL-exhaustion \
         crash/restart (pre-fault {pre_cycle2_postmaster_start_micros}us, post-fault \
         {post_cycle2_postmaster_start_micros}us); this scenario's restart must be a genuine \
         crash/recovery cycle, not a reconnect to a server that never actually went down"
    );

    // Through the same pool and store: nothing from cycle 2's rejected
    // attempt was published, and the pool itself recovered a working
    // connection against the freshly restarted server a second time.
    let reconcile_context = bounded_context(initial_fence, PHASE_BUDGET_MILLIS, 0xc3);
    let recovered_state = store
        .get_versioned_durable(&reconcile_context, domain, &state_key)
        .unwrap();
    assert_eq!(recovered_state.revision(), StateRevision::INITIAL);
    assert_eq!(recovered_state.value(), None);
    assert_eq!(
        store
            .get_request_receipt(&reconcile_context, domain, request_id)
            .unwrap(),
        None
    );
    assert_eq!(
        inspect_namespace(&mut fresh_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );

    // A second, independent proof of non-publication: re-committing the
    // identical invocation asserts `StateRevision::INITIAL` in its read set
    // and the same `DurableRequestId` in its receipt, so a partial earlier
    // commit would have produced `Rejected(Conflict)` or
    // `Rejected(RequestAlreadyCommitted)` instead of `Committed`.
    let replay_context = bounded_context(initial_fence, PHASE_BUDGET_MILLIS, 0xc4);
    assert_eq!(
        store.commit_invocation(&replay_context, fault_invocation.clone()),
        DurableCommitOutcome::Committed
    );

    let post_recovery_state = store
        .get_versioned_durable(&replay_context, domain, &state_key)
        .unwrap();
    assert_eq!(post_recovery_state.revision(), StateRevision::new(1));
    assert_eq!(post_recovery_state.value(), Some(state_value.as_slice()));
    assert_eq!(
        store
            .get_request_receipt(&replay_context, domain, request_id)
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store.commit_invocation(&replay_context, fault_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0xfd; 32]).unwrap();
    let claim_window: u64 = now_millis();
    let claim_expiry: u64 = claim_window.checked_add(60_000).unwrap();
    let claim = match store.claim_request_outbox(
        &replay_context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("expected the recovered outbox message to be claimable, got {outcome:?}"),
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.canonical_payload(), b"wal-full-outbound-event");

    assert_eq!(
        store.acknowledge_outbox(
            &replay_context,
            DurableOutboxAcknowledgement::new(domain, request_id, 0, claim_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let no_due_work_window: u64 = now_millis();
    let no_due_work_expiry: u64 = no_due_work_window.checked_add(60_000).unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &replay_context,
            RequestOutboxClaimRequest::new(
                domain,
                request_id,
                no_due_work_window,
                DurableOutboxLeaseId::new([0xfe; 32]).unwrap(),
                no_due_work_expiry,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    assert_eq!(
        inspect_namespace(&mut fresh_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        2
    );
}
