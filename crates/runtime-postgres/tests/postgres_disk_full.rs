//! Live bounded-tablespace `ENOSPC` (disk-full) test for the PostgreSQL
//! durable store.
//!
//! This is a separate test binary from `postgres_schema.rs` and
//! `postgres_crash_recovery.rs` because it starts and destroys its own
//! disposable container rather than touching the shared CI service
//! container; it still takes `support::LiveTestLock` before any container
//! work, so it never runs concurrently with another live test in this crate.
//! Capability resolution (skip vs. run vs. fail on partial/invalid
//! configuration) is `support::resolve_disk_full_scenario`; see that
//! function's doc comment for the exact rules.
//!
//! Scope: this proves that a real `ENOSPC` on the real filesystem holding the
//! adapter's own heap/index/TOAST relations produces SQLSTATE `53100`, which
//! the adapter classifies as the definite
//! `Rejected(DurableCommitRejection::UnavailableBeforeCommit)`; that nothing
//! from the rejected attempt is published; and that after space is freed the
//! same pool, store, and identical invocation commit and reconcile exactly.
//! It does **not** prove WAL-filesystem exhaustion (deliberately left on an
//! unfilled filesystem), commit-boundary `ENOSPC`, block-device behavior
//! (write cache, torn writes, media faults, fsync-time `ENOSPC`, delayed
//! allocation timing), the shared CI database's behavior under disk
//! pressure, connection exhaustion, backup/restore, capacity/load/soak,
//! TLS-path connection loss, real writer failover, provider certification,
//! or production readiness.

use postgres::{Client, Config, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::PostgresConnectionManager;
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableOperationContext, DurableOutboxAcknowledgement,
    DurableOutboxAcknowledgementOutcome, DurableOutboxBatch, DurableOutboxClaimOutcome,
    DurableOutboxLeaseId, DurableOutboxMessage, DurableRequestId, DurableRequestReceipt,
    DurableStateTransaction, IndexedOutboxRepository, RequestOutboxClaimRequest, StateMutation,
    StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
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
/// shared CI service database.
const DISK_FULL_DATABASE: &str = "sunrise_edge_disk_full";

/// Tablespace holding every adapter relation, backed by the 64 MiB `/bounded`
/// tmpfs mount.
const BOUNDED_TABLESPACE: &str = "se_bounded";

/// Directory the bounded tablespace is created at, inside the `/bounded`
/// tmpfs mount.
const BOUNDED_TABLESPACE_LOCATION: &str = "/bounded/ts";

/// Lower/upper bound, in KiB, that `df -P -k /bounded` must report as total
/// capacity: proof the 64 MiB tmpfs cap this scenario configured is the
/// filesystem actually in effect, not some larger inherited mount.
const BOUNDED_TMPFS_MIN_TOTAL_KIB: u64 = 60_000;
const BOUNDED_TMPFS_MAX_TOTAL_KIB: u64 = 65_536;

/// Lower/upper bound, in KiB, that `df -P -k` on `SHOW data_directory` must
/// report as total capacity: proof the 512 MiB tmpfs cap this scenario
/// configures for PGDATA is the filesystem actually in effect, not some
/// larger inherited mount. Symmetric in kind with the `/bounded` assertion
/// above, scaled to the configured 512 MiB (524,288 KiB) PGDATA tmpfs.
const PGDATA_TMPFS_MIN_TOTAL_KIB: u64 = 500_000;
const PGDATA_TMPFS_MAX_TOTAL_KIB: u64 = 524_288;

/// Upper bound, in KiB, on `/bounded` available space immediately after the
/// filler write: headroom for tmpfs bookkeeping, not a measured budget.
const POST_FILL_MAX_AVAILABLE_KIB: u64 = 1536;

/// Lower bound, in KiB, on `/bounded` available space immediately after the
/// filler file is removed: proof space was genuinely freed.
const POST_CLEANUP_MIN_AVAILABLE_KIB: u64 = 32_768;

/// KiB of headroom left unfilled by the `dd` write, so the write itself
/// always succeeds before the filesystem is considered full.
const FILL_HEADROOM_KIB: u64 = 1024;

/// Size of the incompressible payload driven through both the direct
/// ground-truth probe and the adapter's own commit path. Well inside
/// `runtime::MAX_STATE_VALUE_BYTES` (32 MiB) and the schema's
/// 33,554,432-byte `canonical_bytes` CHECK, but large enough to force many
/// new TOAST pages on the bounded tablespace.
const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

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

/// Deterministic xorshift64* byte stream: `pglz`/LZ4 TOAST compression
/// cannot shrink it, so the row it backs is guaranteed to need genuine new
/// TOAST pages on disk, not merely a large logical value.
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

/// Connect timeout applied to every direct probe/DDL client this scenario
/// opens against its own disposable container.
const DIRECT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-level user timeout mirrored onto every direct probe/DDL client, so a
/// connection that stalls after the TCP handshake against the disposable
/// container is bounded the same way as a slow connect.
const DIRECT_CLIENT_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Session `statement_timeout` applied to every direct probe/DDL client.
/// Generous relative to this scenario's own bounded work (tablespace/database
/// DDL, small catalog probes, and the multi-megabyte filler insert), but far
/// below the outer test process's own deadline, so a wedged connection to the
/// disposable container fails loudly instead of hanging the test.
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
fn postgres_disk_full_bounded_tablespace_enospc() {
    let image = match support::resolve_disk_full_scenario() {
        support::DiskFullScenario::Skip => {
            eprintln!(
                "skipping live PostgreSQL disk-full scenario: neither {} nor {} is configured",
                support::DISK_FULL_IMAGE_ENV,
                support::DISK_FULL_REQUIRED_ENV
            );
            return;
        }
        support::DiskFullScenario::Run(image) => image,
    };

    // Acquired before any container work, and declared before `container`
    // below, so that on unwind locals drop in reverse declaration order:
    // `container` (panic-safe force-remove) drops first, and only then is
    // the lock released for the next live test.
    let _live_test_lock = support::LiveTestLock::acquire();

    let container = support::DisposablePostgresContainer::start(&image);

    // --- Provision the bounded tablespace and disposable database ----------

    container
        .exec(&["mkdir", "-m", "700", BOUNDED_TABLESPACE_LOCATION])
        .unwrap_or_else(|error| panic!("mkdir {BOUNDED_TABLESPACE_LOCATION} failed: {error}"));

    let identity_marker = support::random_hex_token(32);
    let identity_file = format!("identity-{identity_marker}");
    container
        .exec(&["touch", &format!("/bounded/{identity_file}")])
        .unwrap_or_else(|error| panic!("touch identity marker failed: {error}"));

    let mut admin_client = connect_bounded(&container.url("postgres"), "postgres (admin)");
    admin_client
        .execute(
            &format!(
                "CREATE TABLESPACE {BOUNDED_TABLESPACE} LOCATION '{BOUNDED_TABLESPACE_LOCATION}'"
            ),
            &[],
        )
        .unwrap();
    admin_client
        .execute(
            &format!("CREATE DATABASE {DISK_FULL_DATABASE} TABLESPACE {BOUNDED_TABLESPACE}"),
            &[],
        )
        .unwrap();
    drop(admin_client);

    let mut client = connect_bounded(&container.url(DISK_FULL_DATABASE), DISK_FULL_DATABASE);

    // --- Phase 0: identity, before any fault ---------------------------------

    let ls_entries: Vec<String> = client
        .query("SELECT pg_ls_dir('/bounded')", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        ls_entries.contains(&identity_file),
        "expected {identity_file:?} in /bounded, found {ls_entries:?}; the SQL connection and \
         the docker exec target are not the same container/mount"
    );

    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, DISK_FULL_DATABASE,
        "refusing to run the disk-full scenario against a non-disposable database"
    );

    let database_tablespace: String = client
        .query_one(
            "SELECT t.spcname FROM pg_database d
             JOIN pg_tablespace t ON t.oid = d.dattablespace
             WHERE d.datname = current_database()",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(database_tablespace, BOUNDED_TABLESPACE);
    let tablespace_location: String = client
        .query_one(
            "SELECT pg_tablespace_location(oid) FROM pg_tablespace WHERE spcname = $1",
            &[&BOUNDED_TABLESPACE],
        )
        .unwrap()
        .get(0);
    assert_eq!(tablespace_location, BOUNDED_TABLESPACE_LOCATION);

    let pgdata = data_directory(&mut client);
    let bounded_device = support::parse_device_id(
        &container
            .exec(&["stat", "-c", "%d", "/bounded"])
            .unwrap_or_else(|error| panic!("stat /bounded failed: {error}")),
    );
    let pgdata_device = support::parse_device_id(
        &container
            .exec(&["stat", "-c", "%d", &pgdata])
            .unwrap_or_else(|error| panic!("stat {pgdata} failed: {error}")),
    );
    let pgdata_wal_device = support::parse_device_id(
        &container
            .exec(&["stat", "-c", "%d", &format!("{pgdata}/pg_wal")])
            .unwrap_or_else(|error| panic!("stat {pgdata}/pg_wal failed: {error}")),
    );
    assert_ne!(
        bounded_device, pgdata_device,
        "the bounded tablespace and PGDATA must live on different filesystems, or WAL could \
         also run out of space and the single-outcome oracle below would not be sound"
    );
    assert_eq!(
        pgdata_wal_device, pgdata_device,
        "pg_wal must live on the same (unbounded) filesystem as PGDATA"
    );

    let (bounded_total_kib, _bounded_available_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", "/bounded"])
            .unwrap_or_else(|error| panic!("df -P -k /bounded failed: {error}")),
    );
    assert!(
        (BOUNDED_TMPFS_MIN_TOTAL_KIB..=BOUNDED_TMPFS_MAX_TOTAL_KIB).contains(&bounded_total_kib),
        "expected /bounded total capacity in [{BOUNDED_TMPFS_MIN_TOTAL_KIB}, \
         {BOUNDED_TMPFS_MAX_TOTAL_KIB}] KiB, got {bounded_total_kib} KiB"
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
            "CREATE TABLE public.disk_full_probe (payload BYTEA NOT NULL)",
            &[],
        )
        .unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!("postgres-disk-full-{}", unique_run_suffix())).unwrap(),
        ValidatorId::new([0xf7; 32]),
        AtomicityDomainId::new([0xf8; 32]).unwrap(),
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

    let mut pool_config: postgres::Config = container.url(DISK_FULL_DATABASE).parse().unwrap();
    pool_config.application_name("sunrise-edge-pr86-disk-full");
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

    fn deadline(budget_millis: u64) -> StorageDeadline {
        StorageDeadline::new(now_millis().checked_add(budget_millis).unwrap()).unwrap()
    }
    let context = DurableOperationContext::new(
        initial_fence,
        deadline(240_000),
        StorageCorrelationId::new([0xf9; 16]).unwrap(),
    );

    // --- Phase 1: healthy baseline, and pre-warm the max-1 connection pool -

    let baseline_key = b"disk-full/baseline".to_vec();
    let baseline_transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(baseline_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(baseline_key, StateMutation::Put(b"baseline-value".to_vec()))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, baseline_transaction),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        inspect_namespace(&mut client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        1
    );

    // --- Build the fault invocation (not yet committed) ---------------------

    let request_id = DurableRequestId::new([0xfa; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xfb; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"disk-full-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0xfc; 32]),
        b"disk-full-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"disk-full/state".to_vec();
    let state_value = xorshift64_star_payload(PAYLOAD_BYTES, 0x9E37_79B9_7F4A_7C15);
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
    let fault_invocation = DurableInvocationTransaction::new(
        domain,
        Some(state_transaction),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox_batch),
    )
    .unwrap();

    // --- Phase 2: the fault instant ------------------------------------------

    let (_, available_before_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", "/bounded"])
            .unwrap_or_else(|error| panic!("df -P -k /bounded failed: {error}")),
    );
    let fill_count_kib = available_before_fill_kib.saturating_sub(FILL_HEADROOM_KIB);
    container
        .exec(&[
            "dd",
            "if=/dev/zero",
            "of=/bounded/filler",
            "bs=1024",
            &format!("count={fill_count_kib}"),
        ])
        .unwrap_or_else(|error| panic!("dd filler write failed: {error}"));
    let (_, available_after_fill_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", "/bounded"])
            .unwrap_or_else(|error| panic!("df -P -k /bounded failed: {error}")),
    );
    assert!(
        available_after_fill_kib <= POST_FILL_MAX_AVAILABLE_KIB,
        "expected /bounded available space <= {POST_FILL_MAX_AVAILABLE_KIB} KiB after filling, \
         got {available_after_fill_kib} KiB"
    );

    // Ground-truth fault probe: a direct client insert on the same bounded
    // filesystem, independent of the adapter, whose `DurableCommitOutcome`
    // erases the SQLSTATE.
    let probe_payload = xorshift64_star_payload(PAYLOAD_BYTES, 0xD1B5_4A32_D192_ED03);
    let probe_error = client
        .execute(
            "INSERT INTO public.disk_full_probe (payload) VALUES ($1)",
            &[&probe_payload],
        )
        .expect_err("expected the bounded tablespace to be genuinely out of space");
    assert_eq!(
        probe_error.code().map(postgres::error::SqlState::code),
        Some("53100"),
        "expected SQLSTATE 53100 (disk_full), got {probe_error:?}"
    );

    // The exact fault instant is a relation extension inside the pre-COMMIT
    // TOAST insert, so this must be a strict equality, not a disjunction.
    assert_eq!(
        store.commit_invocation(&context, fault_invocation.clone()),
        DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit),
    );

    // --- Phase 3: reconcile ground truth after freeing space -----------------

    container
        .exec(&["rm", "/bounded/filler"])
        .unwrap_or_else(|error| panic!("rm /bounded/filler failed: {error}"));
    let (_, available_after_cleanup_kib) = support::parse_df_kib(
        &container
            .exec(&["df", "-P", "-k", "/bounded"])
            .unwrap_or_else(|error| panic!("df -P -k /bounded failed: {error}")),
    );
    assert!(
        available_after_cleanup_kib >= POST_CLEANUP_MIN_AVAILABLE_KIB,
        "expected /bounded available space >= {POST_CLEANUP_MIN_AVAILABLE_KIB} KiB after \
         removing the filler, got {available_after_cleanup_kib} KiB"
    );

    // Through the same pool and store: nothing from the rejected attempt was
    // published, and the pool itself recovered.
    let recovered_state = store
        .get_versioned_durable(&context, domain, &state_key)
        .unwrap();
    assert_eq!(recovered_state.revision(), StateRevision::INITIAL);
    assert_eq!(recovered_state.value(), None);
    assert_eq!(
        store
            .get_request_receipt(&context, domain, request_id)
            .unwrap(),
        None
    );
    assert_eq!(
        inspect_namespace(&mut client, &namespace)
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
    assert_eq!(
        store.commit_invocation(&context, fault_invocation.clone()),
        DurableCommitOutcome::Committed
    );

    let post_recovery_state = store
        .get_versioned_durable(&context, domain, &state_key)
        .unwrap();
    assert_eq!(post_recovery_state.revision(), StateRevision::new(1));
    assert_eq!(post_recovery_state.value(), Some(state_value.as_slice()));
    assert_eq!(
        store
            .get_request_receipt(&context, domain, request_id)
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store.commit_invocation(&context, fault_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0xfd; 32]).unwrap();
    let claim_window: u64 = now_millis();
    let claim_expiry: u64 = claim_window.checked_add(60_000).unwrap();
    let claim = match store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("expected the recovered outbox message to be claimable, got {outcome:?}"),
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.canonical_payload(), b"disk-full-outbound-event");

    assert_eq!(
        store.acknowledge_outbox(
            &context,
            DurableOutboxAcknowledgement::new(domain, request_id, 0, claim_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let no_due_work_window: u64 = now_millis();
    let no_due_work_expiry: u64 = no_due_work_window.checked_add(60_000).unwrap();
    assert_eq!(
        store.claim_request_outbox(
            &context,
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
        inspect_namespace(&mut client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        2
    );
}
