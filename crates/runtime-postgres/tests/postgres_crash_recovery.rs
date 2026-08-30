//! Live SIGKILL crash-recovery test for the PostgreSQL durable store.
//!
//! This is a separate test binary from `postgres_schema.rs` because it kills
//! the whole database-service container, not just a connection: every other
//! live test in this crate must be quiescent for the duration, which is what
//! `support::LiveTestLock` enforces. Capability resolution (skip vs. run vs.
//! fail on partial/invalid configuration) is `support::resolve_crash_scenario`;
//! see that function's doc comment for the exact rules.
//!
//! Scope: this proves PostgreSQL database-process SIGKILL and WAL recovery
//! on a live host with a live page cache. It does not prove abrupt
//! host/power loss, storage write-cache flush/torn-write/media/filesystem
//! faults, disk-full/WAL exhaustion, TLS-path behavior, backup/restore,
//! capacity/load/soak, writer failover, provider certification, or
//! production readiness.

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
    verify_initial_schema,
};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

const TEST_DATABASE: &str = "sunrise_edge_test";

/// Projects `pg_postmaster_start_time()` as an exact integer count of
/// microseconds since the Unix epoch. `EXTRACT(EPOCH FROM ...)` returns
/// `numeric` (exact decimal), not `double precision`, so multiplying by
/// `1000000` and casting to `bigint` is exact decimal arithmetic with no
/// floating-point rounding anywhere in the computation, and the driver
/// decodes the result as a plain `i64` with no float ever entering the Rust
/// side either.
const POSTMASTER_START_TIME_MICROS_SQL: &str =
    "SELECT (EXTRACT(EPOCH FROM pg_postmaster_start_time()) * 1000000)::bigint";

/// Queries [`POSTMASTER_START_TIME_MICROS_SQL`] on `client`. Used once
/// before the durable commit and once again after `guard.restart_and_wait_ready()`
/// through a fresh connection, so the test can assert the value strictly
/// advanced — proof that the *database process this client is actually
/// talking to* really was killed and restarted, not merely that some
/// container (possibly the wrong one, if `SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID`
/// is misconfigured to a valid-but-unrelated container) was.
fn postmaster_start_time_micros(client: &mut Client) -> i64 {
    client
        .query_one(POSTMASTER_START_TIME_MICROS_SQL, &[])
        .unwrap()
        .get(0)
}

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
/// chain ID so repeated runs against the same long-lived `sunrise_edge_test`
/// database (this test never resets the schema) always bootstrap a brand
/// new namespace instead of colliding with a previous run's leftover rows.
fn unique_run_suffix() -> u128 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos ^ u128::from(std::process::id())
}

#[test]
fn postgres_crash_recovery_sigkill_and_wal_replay() {
    let url = std::env::var_os(support::LIVE_POSTGRES_URL_ENV);
    let live_url_configured = url.is_some();
    let container_id = match support::resolve_crash_scenario(live_url_configured) {
        support::CrashScenario::Skip => {
            eprintln!(
                "skipping live PostgreSQL crash recovery: neither {} nor {} is configured",
                support::LIVE_POSTGRES_URL_ENV,
                support::CRASH_CONTAINER_ID_ENV
            );
            return;
        }
        support::CrashScenario::Run(container_id) => container_id,
    };
    let url: String = url
        .expect("resolve_crash_scenario only returns Run when the live URL is configured")
        .to_string_lossy()
        .into_owned();

    // Acquired before any live database work, and before constructing the
    // guard below: this test kills the whole database-service container, so
    // it must never run concurrently with any other live test in this
    // crate. Declared before `guard` so that on unwind, locals drop in
    // reverse declaration order — `guard` drops first (best-effort restart,
    // waiting for readiness) and only then does this lock drop and let
    // another live test proceed against the container.
    let _live_test_lock = support::LiveTestLock::acquire();

    let mut guard = support::DockerCrashGuard::new(container_id, url.clone());

    let mut client = Client::connect(&url, NoTls).unwrap();
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, TEST_DATABASE,
        "refusing to run the crash scenario against a non-test database"
    );

    let fsync: String = client.query_one("SHOW fsync", &[]).unwrap().get(0);
    assert_eq!(
        fsync, "on",
        "fsync must be enabled or a SIGKILL proves nothing about WAL durability"
    );
    let synchronous_commit: String = client
        .query_one("SHOW synchronous_commit", &[])
        .unwrap()
        .get(0);
    assert!(
        synchronous_commit == "on" || synchronous_commit == "remote_apply",
        "synchronous_commit must guarantee the WAL record reached durable storage before COMMIT \
         acknowledgement, got {synchronous_commit}"
    );

    // `apply_initial_schema`/`verify_initial_schema` are idempotent: this
    // test does not reset the schema first, since it must not destroy any
    // other live test's data, only its own uniquely named namespace.
    apply_initial_schema(&mut client).unwrap();
    verify_initial_schema(&mut client).unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!("postgres-crash-recovery-{}", unique_run_suffix())).unwrap(),
        ValidatorId::new([0xc7; 32]),
        AtomicityDomainId::new([0xc8; 32]).unwrap(),
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

    let mut database_config: Config = url.parse().unwrap();
    database_config.application_name("sunrise-edge-pr85-crash-recovery-pre");
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
    let store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );

    let pre_crash_deadline: u64 = now_millis().checked_add(60_000).unwrap();
    let pre_crash_context = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(pre_crash_deadline).unwrap(),
        StorageCorrelationId::new([0xc9; 16]).unwrap(),
    );

    let request_id = DurableRequestId::new([0xd1; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xd2; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"crash-recovery-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0xd3; 32]),
        b"crash-recovery-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"crash-recovery/state".to_vec();
    let state_value = b"crash-recovery-state-v1".to_vec();
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
    let replay_invocation = invocation.clone();

    // Captured here, before the commit, so that the commit -> `sigkill()`
    // sequence immediately below stays adjacent with no intervening SQL.
    let pre_crash_postmaster_start_micros = postmaster_start_time_micros(&mut client);

    // From here until the confirmed `guard.sigkill()` immediately below, no
    // further SQL or database operation may run: the whole point of this
    // scenario is that nothing happens between the driver observing
    // `Committed` and the container dying.
    let commit_outcome = store.commit_invocation(&pre_crash_context, invocation);
    assert_eq!(commit_outcome, DurableCommitOutcome::Committed);
    guard.sigkill();

    // Only after the confirmed kill do the pre-crash store/pool/client go
    // away; nothing above depended on this ordering, but it keeps the "old"
    // and "fresh" halves of the test unambiguous.
    drop(store);
    drop(pool);
    drop(client);

    guard.restart_and_wait_ready();

    let mut fresh_client = Client::connect(&url, NoTls).unwrap();
    let fresh_database: String = fresh_client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(fresh_database, TEST_DATABASE);

    let post_crash_postmaster_start_micros = postmaster_start_time_micros(&mut fresh_client);
    assert!(
        post_crash_postmaster_start_micros > pre_crash_postmaster_start_micros,
        "postmaster start time did not strictly advance across the SIGKILL/restart \
         (pre-crash {pre_crash_postmaster_start_micros}us, post-crash \
         {post_crash_postmaster_start_micros}us); this means {} does not actually name the \
         database-service container this test's client is talking to (for example, a valid but \
         unrelated container), since killing and restarting the right container always advances \
         its postmaster start time",
        support::CRASH_CONTAINER_ID_ENV
    );

    let mut fresh_database_config: Config = url.parse().unwrap();
    fresh_database_config.application_name("sunrise-edge-pr85-crash-recovery-post");
    let fresh_pool = build_postgres_pool(
        fresh_database_config,
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
    let fresh_store: PostgresDurableStore<TestPostgresManager> = PostgresDurableStore::new(
        fresh_pool,
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    );

    let post_crash_deadline: u64 = now_millis().checked_add(60_000).unwrap();
    let post_crash_context = DurableOperationContext::new(
        initial_fence,
        StorageDeadline::new(post_crash_deadline).unwrap(),
        StorageCorrelationId::new([0xca; 16]).unwrap(),
    );

    let recovered_state = fresh_store
        .get_versioned_durable(&post_crash_context, domain, &state_key)
        .unwrap();
    assert_eq!(recovered_state.revision(), StateRevision::new(1));
    assert_eq!(recovered_state.value(), Some(state_value.as_slice()));
    assert_eq!(
        fresh_store
            .get_request_receipt(&post_crash_context, domain, request_id)
            .unwrap(),
        Some(receipt)
    );

    assert_eq!(
        fresh_store.commit_invocation(&post_crash_context, replay_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0xe1; 32]).unwrap();
    let claim_window: u64 = now_millis();
    let claim_expiry: u64 = claim_window.checked_add(60_000).unwrap();
    let claim = match fresh_store.claim_request_outbox(
        &post_crash_context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => {
            panic!("expected the recovered outbox message to be claimable, got {outcome:?}")
        }
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.canonical_payload(), b"crash-recovery-outbound-event");

    assert_eq!(
        fresh_store.acknowledge_outbox(
            &post_crash_context,
            DurableOutboxAcknowledgement::new(domain, request_id, 0, claim_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let no_due_work_window: u64 = now_millis();
    let no_due_work_expiry: u64 = no_due_work_window.checked_add(60_000).unwrap();
    assert_eq!(
        fresh_store.claim_request_outbox(
            &post_crash_context,
            RequestOutboxClaimRequest::new(
                domain,
                request_id,
                no_due_work_window,
                DurableOutboxLeaseId::new([0xe2; 32]).unwrap(),
                no_due_work_expiry,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    let post_recovery_key = b"crash-recovery/post-recovery".to_vec();
    let post_recovery_transaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(post_recovery_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                post_recovery_key,
                StateMutation::Put(b"post-recovery-value".to_vec()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        fresh_store.commit_durable(&post_crash_context, post_recovery_transaction),
        DurableCommitOutcome::Committed
    );
}
