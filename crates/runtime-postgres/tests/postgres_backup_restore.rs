//! Live bounded PostgreSQL database-snapshot restore rehearsal for the
//! durable store.
//!
//! This is a separate test binary from every other live test in this crate
//! because it starts and destroys two of its own disposable containers (a
//! source and a fully separate, isolated target) rather than touching the
//! shared CI service container or another scenario's own container; it still
//! takes `support::LiveTestLock` before any container work, so it never runs
//! concurrently with another live test in this crate. Capability resolution
//! (skip vs. run vs. fail on partial/invalid configuration) is
//! `support::resolve_backup_restore_scenario`; see that function's doc
//! comment for the exact rules.
//!
//! Scope, precisely: this proves a bounded `pg_dump`-based database-snapshot
//! restore rehearsal only. It commits one structured invocation (state,
//! receipt, one outbox message) on a source container, takes a plain-text
//! `pg_dump --inserts` snapshot of that one database, removes PostgreSQL 18's
//! `psql`-only restrict markers, and applies the remaining SQL
//! to a freshly created, empty database on a second, fully separate,
//! independently started PostgreSQL container — a different container
//! process, a different generated password, and a different published host
//! port, not merely a second database inside the source's own server. It then
//! proves exact schema identity (`verify_initial_schema`) and exact restored
//! durable ground truth (the namespace metadata row plus the committed state
//! and receipt through the normal adapter read path) before the
//! rehearsal's fence-promotion step;
//! advances the restored namespace's writer fence through the operator-only
//! `advance_writer_fence` seam; proves the stale pre-backup writer context
//! (still carrying the old fence) is rejected as `WriterFenced` against the
//! restored target; and proves a fresh context carrying the new fence
//! reconciles the exact restored receipt/state, claims and acknowledges the
//! restored pending outbox payload, and then commits genuinely new work. A
//! separate, deterministic negative case restores a snapshot truncated to
//! exactly half its captured byte length into a third, empty database on the
//! same target container (not a third container, since the fault here is
//! snapshot content, not server isolation) and proves the same rehearsal
//! verification gate — schema identity plus restored state/receipt ground
//! truth read through the adapter — never passes against it. The truncated
//! restore execution itself must also fail loudly.
//!
//! This is a database-snapshot restore rehearsal only, not a production
//! backup/restore capability, and does **not** prove: point-in-time
//! recovery, continuous WAL archiving/shipping, a hot/consistent backup taken
//! under concurrent write load, `pg_basebackup`/replication-based backup,
//! backup encryption or off-host storage, retention/rotation policy, restore
//! automation, checkpoint publication (the schema has no implemented
//! checkpoint-publication path; `sunrise_edge.checkpoints` is not written or
//! read by anything in this crate), blob-manifest verification, state-root
//! verification, or encryption-key verification — the normalized schema and
//! this adapter implement none of those, so this scenario invents no
//! evidence for them. It also does not prove multi-database/whole-cluster
//! backup, backup under concurrent adapter write traffic, real storage-device
//! or off-host transfer faults, capacity/load/soak, TLS-path connection loss,
//! real writer failover beyond the one bounded target fence advance proven
//! here (that copied-row update does not fence or stop the independently
//! running source database), or production certification.

use postgres::{Client, Config, NoTls};
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
    PostgresSchemaMetadata, PostgresTransactionPolicy, advance_writer_fence, apply_initial_schema,
    bootstrap_namespace, build_postgres_pool, inspect_namespace, verify_initial_schema,
};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

/// Disposable database created on the source container.
const SOURCE_DATABASE: &str = "sunrise_edge_backup_restore_source";

/// Disposable database created on the target container to receive the
/// transformed snapshot SQL.
const TARGET_DATABASE: &str = "sunrise_edge_backup_restore_target";

/// A second, separate disposable database on the same target container
/// (never the good-restore database above) that only ever receives the
/// deterministically truncated, corrupted snapshot.
const CORRUPT_DATABASE: &str = "sunrise_edge_backup_restore_corrupt";

/// Size of the state payload driven through the adapter's structured
/// invocation. Small and unremarkable: this scenario's evidence is about
/// snapshot/restore correctness, not payload size, and a small payload keeps
/// the `pg_dump` snapshot itself small.
const STATE_PAYLOAD_BYTES: usize = 256;

/// Upper bound on the plain-text `pg_dump --inserts` snapshot this scenario
/// captures. The fixed generation-one schema DDL is tens of KiB and the
/// seeded payload is deliberately tiny, so this is generous headroom, not a
/// measured budget; a snapshot exceeding it fails the capture loudly instead
/// of silently truncating.
const DUMP_MAX_BYTES: u64 = 1024 * 1024;

/// Lower bound on the same snapshot: proof it genuinely contains the full
/// normalized schema plus seeded data, not an empty or truncated capture.
const DUMP_MIN_BYTES: u64 = 4 * 1024;

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
/// size-driven fault requirement on it.
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

fn deadline(budget_millis: u64) -> StorageDeadline {
    StorageDeadline::new(now_millis().checked_add(budget_millis).unwrap()).unwrap()
}

/// Connect timeout applied to every direct probe/admin client this scenario
/// opens against either of its own disposable containers.
const DIRECT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-level user timeout mirrored onto every direct client, so a connection
/// that stalls after the TCP handshake against a disposable container is
/// bounded the same way as a slow connect.
const DIRECT_CLIENT_TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);

/// Session `statement_timeout` applied to every direct client. Generous
/// relative to this scenario's own bounded work (DDL, small catalog probes,
/// and one bounded `batch_execute` of the captured snapshot), but far below
/// the outer test process's own deadline, so a wedged connection fails
/// loudly instead of hanging the test.
const DIRECT_CLIENT_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Builds a bounded [`Config`] for a direct client against either disposable
/// container: an explicit connect timeout, TCP user timeout, and session
/// `statement_timeout`, so no direct connection this scenario opens can
/// inherit the driver's unbounded defaults.
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

/// Connects a direct client through [`bounded_direct_client_config`]. `label`
/// identifies the connection in a failure message only; it never includes the
/// URL itself, since the URL carries the generated container password.
fn connect_bounded(url: &str, label: &str) -> Client {
    bounded_direct_client_config(url)
        .connect(NoTls)
        .unwrap_or_else(|error| panic!("bounded connect to {label} failed: {error}"))
}

/// Builds a small, bounded adapter pool/store against `database` on
/// `container`, distinguished from every other pool this scenario opens by
/// its own `application_name`.
fn build_store(
    container: &support::BackupRestorePostgresContainer,
    database: &str,
    namespace: &PostgresNamespace,
    application_name: &str,
) -> PostgresDurableStore<TestPostgresManager> {
    let mut pool_config: Config = container.url(database).parse().unwrap_or_else(|error| {
        panic!("failed to parse disposable-container database URL: {error}")
    });
    pool_config.application_name(application_name);
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
    .unwrap_or_else(|error| panic!("failed to build a bounded pool for {database}: {error}"));
    PostgresDurableStore::new(
        pool,
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    )
}

/// The bounded rehearsal gate that must pass before this test advances the
/// copied namespace fence: exact schema
/// identity, an exact namespace metadata match against `expected_metadata`,
/// and the exact restored state/receipt ground truth, all read through the
/// normal adapter read path (never by inferring row contents from raw SQL).
/// Every failure mode returns `false` rather than panicking, so the same
/// function proves both the positive (must pass) and negative (must not
/// pass) cases in this scenario.
#[allow(clippy::too_many_arguments)]
fn restore_passes_rehearsal_gate(
    store: &PostgresDurableStore<TestPostgresManager>,
    client: &mut Client,
    namespace: &PostgresNamespace,
    domain: AtomicityDomainId,
    context: &DurableOperationContext,
    expected_metadata: PostgresSchemaMetadata,
    expected_state_key: &[u8],
    expected_state_value: &[u8],
    expected_request_id: DurableRequestId,
    expected_receipt: &DurableRequestReceipt,
) -> bool {
    if verify_initial_schema(client).is_err() {
        return false;
    }
    let Ok(Some(metadata)) = inspect_namespace(client, namespace) else {
        return false;
    };
    if metadata != expected_metadata {
        return false;
    }
    let Ok(state) = store.get_versioned_durable(context, domain, expected_state_key) else {
        return false;
    };
    if state.revision() != StateRevision::new(1) || state.value() != Some(expected_state_value) {
        return false;
    }
    let Ok(receipt) = store.get_request_receipt(context, domain, expected_request_id) else {
        return false;
    };
    receipt.as_ref() == Some(expected_receipt)
}

/// Truncates `text` to at most `max_bytes`, backing off to the nearest
/// earlier UTF-8 character boundary if `max_bytes` would otherwise split a
/// multi-byte character. The captured snapshot is plain-ASCII SQL, so this
/// backoff is never expected to move more than a few bytes; it exists only so
/// this deterministic corruption can never itself panic on a boundary it does
/// not control.
fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Removes `pg_dump`'s `\restrict <key>` / `\unrestrict <key>` bracketing
/// lines from a captured plain-SQL snapshot.
///
/// PostgreSQL 18's `pg_dump` wraps plain-text output in these two lines by
/// default as a `psql`-only safety meta-command pair (`psql` refuses to run
/// anything between them under a different, mismatched, or absent
/// `\restrict`/`\unrestrict` key). They are not SQL, are meaningless outside
/// `psql`'s own reader, and the server rejects them as a syntax error if sent
/// verbatim over the wire — which is exactly what happens here, since this
/// scenario restores by executing the captured text directly through
/// [`postgres::Client::batch_execute`], deliberately bypassing `psql`, rather
/// than by invoking `psql` as a subprocess. Stripping these two fixed lines
/// is a well-understood, deterministic transform of a format detail specific
/// to *how* this scenario applies the snapshot; it is not a content
/// corruption of the schema or data the snapshot represents.
fn strip_psql_restrict_meta_commands(dump: &str) -> String {
    dump.lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("\\restrict ") || trimmed.starts_with("\\unrestrict "))
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

#[test]
fn postgres_backup_restore_rehearsal() {
    let image = match support::resolve_backup_restore_scenario() {
        support::BackupRestoreScenario::Skip => {
            eprintln!(
                "skipping live PostgreSQL backup-restore scenario: neither {} nor {} is configured",
                support::BACKUP_RESTORE_IMAGE_ENV,
                support::BACKUP_RESTORE_REQUIRED_ENV
            );
            return;
        }
        support::BackupRestoreScenario::Run(image) => image,
    };

    // Acquired before any container work, and declared before the
    // containers below, so that on unwind locals drop in reverse declaration
    // order: the containers (panic-safe force-remove) drop first, and only
    // then is the lock released for the next live test.
    let _live_test_lock = support::LiveTestLock::acquire();

    let source = support::BackupRestorePostgresContainer::start(&image, "source");
    let target = support::BackupRestorePostgresContainer::start(&image, "target");
    assert_ne!(
        source.container_id(),
        target.container_id(),
        "the source and target must be two genuinely separate containers"
    );

    // --- Provision the source namespace and commit durable ground truth ----

    let mut source_admin = connect_bounded(&source.url("postgres"), "postgres (source admin)");
    source_admin
        .execute(&format!("CREATE DATABASE {SOURCE_DATABASE}"), &[])
        .unwrap();
    drop(source_admin);

    let mut source_client = connect_bounded(&source.url(SOURCE_DATABASE), SOURCE_DATABASE);
    apply_initial_schema(&mut source_client).unwrap();
    verify_initial_schema(&mut source_client).unwrap();

    let namespace = PostgresNamespace::new(
        &ChainId::new(format!("postgres-backup-restore-{}", unique_run_suffix())).unwrap(),
        ValidatorId::new([0x21; 32]),
        AtomicityDomainId::new([0x22; 32]).unwrap(),
    )
    .unwrap();
    let domain = namespace.domain();
    let source_fence = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(
        &mut source_client,
        &namespace,
        POSTGRES_SCHEMA_GENERATION,
        source_fence,
    )
    .unwrap();

    let source_store = build_store(
        &source,
        SOURCE_DATABASE,
        &namespace,
        "sunrise-edge-pr89-backup-restore-source",
    );
    let source_context = DurableOperationContext::new(
        source_fence,
        deadline(240_000),
        StorageCorrelationId::new([0x23; 16]).unwrap(),
    );

    let request_id = DurableRequestId::new([0x24; 32]).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x25; 32]);
    let receipt = DurableRequestReceipt::new(
        request_id,
        event_digest,
        b"backup-restore-canonical-receipt".to_vec(),
    )
    .unwrap();
    let outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0x26; 32]),
        b"backup-restore-outbound-event".to_vec(),
    )
    .unwrap();
    let outbox_batch =
        DurableOutboxBatch::new(request_id, event_digest, vec![outbox_message]).unwrap();
    let state_key = b"backup-restore/state".to_vec();
    let state_value = xorshift64_star_payload(STATE_PAYLOAD_BYTES, 0x1234_5678_9abc_def0);
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
    let baseline_invocation = DurableInvocationTransaction::new(
        domain,
        Some(state_transaction),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox_batch),
    )
    .unwrap();
    let replay_invocation = baseline_invocation.clone();

    // Deliberately left claimed by nothing: the outbox message stays pending
    // through the backup, so reconciliation after restore proves an exact
    // claim/acknowledgement, not merely a read.
    assert_eq!(
        source_store.commit_invocation(&source_context, baseline_invocation),
        DurableCommitOutcome::Committed
    );

    let pre_backup_metadata = inspect_namespace(&mut source_client, &namespace)
        .unwrap()
        .unwrap();
    assert_eq!(pre_backup_metadata.writer_fence(), source_fence);
    assert_eq!(pre_backup_metadata.commit_sequence(), 1);

    // --- Take a bounded pg_dump snapshot of the source database ------------

    // `--inserts` avoids `COPY ... FROM stdin` embedded data blocks, whose
    // "data follows in the same script" convention is implemented by `psql`
    // itself, not the wire protocol; a plain literal-`INSERT`-only snapshot
    // is a fully self-contained SQL script this scenario can apply directly
    // through `postgres::Client::batch_execute` over its own bounded
    // connection, with no intermediate file or extra process.
    let raw_dump_text = source
        .exec_capped(
            &[
                "pg_dump",
                "-d",
                SOURCE_DATABASE,
                "--no-owner",
                "--no-privileges",
                "--inserts",
            ],
            DUMP_MAX_BYTES,
        )
        .unwrap_or_else(|error| panic!("pg_dump on the source container failed: {error}"));
    let dump_text = strip_psql_restrict_meta_commands(&raw_dump_text);
    assert!(
        (DUMP_MIN_BYTES as usize..=DUMP_MAX_BYTES as usize).contains(&dump_text.len()),
        "expected the pg_dump snapshot to be between {DUMP_MIN_BYTES} and {DUMP_MAX_BYTES} \
         bytes, got {} bytes",
        dump_text.len()
    );
    assert!(
        dump_text.contains("sunrise_edge.storage_metadata"),
        "expected the pg_dump snapshot to include the sunrise_edge.storage_metadata table"
    );

    // --- Restore the exact snapshot into a separate, fully isolated target -

    let mut target_admin = connect_bounded(&target.url("postgres"), "postgres (target admin)");
    target_admin
        .execute(&format!("CREATE DATABASE {TARGET_DATABASE}"), &[])
        .unwrap();
    drop(target_admin);

    let mut target_client = connect_bounded(&target.url(TARGET_DATABASE), TARGET_DATABASE);
    target_client
        .batch_execute(&dump_text)
        .unwrap_or_else(|error| {
            panic!("restoring the pg_dump snapshot into the target failed: {error}")
        });

    // --- Verify exact schema identity and ground truth before fence promotion

    let target_store = build_store(
        &target,
        TARGET_DATABASE,
        &namespace,
        "sunrise-edge-pr89-backup-restore-target",
    );
    let stale_context = DurableOperationContext::new(
        source_fence,
        deadline(240_000),
        StorageCorrelationId::new([0x27; 16]).unwrap(),
    );
    assert!(
        restore_passes_rehearsal_gate(
            &target_store,
            &mut target_client,
            &namespace,
            domain,
            &stale_context,
            pre_backup_metadata,
            &state_key,
            &state_value,
            request_id,
            &receipt,
        ),
        "the restored target must pass the exact schema-identity and durable ground-truth \
         rehearsal gate before fence promotion"
    );

    // --- Advance the restored namespace writer fence (operator-only) -------

    let promoted_fence = WriterFenceGeneration::new(2).unwrap();
    let advanced_metadata =
        advance_writer_fence(&mut target_client, &namespace, source_fence, promoted_fence).unwrap();
    assert_eq!(advanced_metadata.writer_fence(), promoted_fence);
    assert_eq!(
        advanced_metadata.commit_sequence(),
        pre_backup_metadata.commit_sequence()
    );
    let source_metadata_after_target_promotion = inspect_namespace(&mut source_client, &namespace)
        .unwrap()
        .unwrap();
    assert_eq!(
        source_metadata_after_target_promotion.writer_fence(),
        source_fence,
        "advancing the copied target row must not be misrepresented as fencing the independent source database"
    );

    // --- The stale pre-backup writer context is now fenced ------------------

    let fresh_request_id = DurableRequestId::new([0x28; 32]).unwrap();
    let fresh_event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x29; 32]);
    let fresh_receipt = DurableRequestReceipt::new(
        fresh_request_id,
        fresh_event_digest,
        b"backup-restore-fresh-canonical-receipt".to_vec(),
    )
    .unwrap();
    let fresh_outbox_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha3_256, [0x2a; 32]),
        b"backup-restore-fresh-outbound-event".to_vec(),
    )
    .unwrap();
    let fresh_outbox_batch = DurableOutboxBatch::new(
        fresh_request_id,
        fresh_event_digest,
        vec![fresh_outbox_message],
    )
    .unwrap();
    let fresh_state_key = b"backup-restore/fresh-state".to_vec();
    let fresh_state_value = xorshift64_star_payload(STATE_PAYLOAD_BYTES, 0xfedc_ba98_7654_3210);
    let fresh_state_transaction = DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(fresh_state_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(
                fresh_state_key.clone(),
                StateMutation::Put(fresh_state_value.clone()),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let fresh_invocation = DurableInvocationTransaction::new(
        domain,
        Some(fresh_state_transaction),
        DurableObjectChanges::empty(),
        fresh_receipt,
        Some(fresh_outbox_batch),
    )
    .unwrap();

    assert_eq!(
        target_store.commit_invocation(&stale_context, fresh_invocation.clone()),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: promoted_fence,
        })
    );
    // Nothing from the fenced attempt was published.
    assert_eq!(
        inspect_namespace(&mut target_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        pre_backup_metadata.commit_sequence()
    );

    // --- A fresh context reconciles exact restored ground truth, then commits fresh work

    let fresh_context = DurableOperationContext::new(
        promoted_fence,
        deadline(240_000),
        StorageCorrelationId::new([0x2b; 16]).unwrap(),
    );

    let reconciled_state = target_store
        .get_versioned_durable(&fresh_context, domain, &state_key)
        .unwrap();
    assert_eq!(reconciled_state.revision(), StateRevision::new(1));
    assert_eq!(reconciled_state.value(), Some(state_value.as_slice()));
    let reconciled_receipt = target_store
        .get_request_receipt(&fresh_context, domain, request_id)
        .unwrap();
    assert_eq!(reconciled_receipt, Some(receipt.clone()));
    assert_eq!(
        target_store.commit_invocation(&fresh_context, replay_invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    let claim_lease = DurableOutboxLeaseId::new([0x2c; 32]).unwrap();
    let claim_window = now_millis();
    let claim_expiry = claim_window.checked_add(60_000).unwrap();
    let claim = match target_store.claim_request_outbox(
        &fresh_context,
        RequestOutboxClaimRequest::new(domain, request_id, claim_window, claim_lease, claim_expiry)
            .unwrap(),
    ) {
        DurableOutboxClaimOutcome::Claimed(claim) => claim,
        outcome => panic!("expected the restored outbox message to be claimable, got {outcome:?}"),
    };
    assert_eq!(claim.request_id(), request_id);
    assert_eq!(claim.message_index(), 0);
    assert_eq!(claim.lease_id(), claim_lease);
    assert_eq!(claim.lease_expires_at_unix_millis(), claim_expiry);
    assert_eq!(claim.canonical_payload(), b"backup-restore-outbound-event");

    assert_eq!(
        target_store.acknowledge_outbox(
            &fresh_context,
            DurableOutboxAcknowledgement::new(domain, request_id, 0, claim_lease),
        ),
        DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    let no_due_work_window = now_millis();
    let no_due_work_expiry = no_due_work_window.checked_add(60_000).unwrap();
    assert_eq!(
        target_store.claim_request_outbox(
            &fresh_context,
            RequestOutboxClaimRequest::new(
                domain,
                request_id,
                no_due_work_window,
                DurableOutboxLeaseId::new([0x2d; 32]).unwrap(),
                no_due_work_expiry,
            )
            .unwrap(),
        ),
        DurableOutboxClaimOutcome::NoDueWork
    );

    assert_eq!(
        target_store.commit_invocation(&fresh_context, fresh_invocation),
        DurableCommitOutcome::Committed
    );
    let fresh_committed_state = target_store
        .get_versioned_durable(&fresh_context, domain, &fresh_state_key)
        .unwrap();
    assert_eq!(fresh_committed_state.revision(), StateRevision::new(1));
    assert_eq!(
        fresh_committed_state.value(),
        Some(fresh_state_value.as_slice())
    );
    // Only structured invocation commits allocate a new commit sequence;
    // claim and acknowledgement do not, so the restored baseline's sequence
    // (from `pre_backup_metadata`) advances by exactly one more here, for
    // this one fresh commit.
    assert_eq!(
        inspect_namespace(&mut target_client, &namespace)
            .unwrap()
            .unwrap()
            .commit_sequence(),
        pre_backup_metadata
            .commit_sequence()
            .checked_add(1)
            .unwrap()
    );

    // --- Negative case: a truncated snapshot never passes the rehearsal gate

    let mut corrupt_admin =
        connect_bounded(&target.url("postgres"), "postgres (target admin, corrupt)");
    corrupt_admin
        .execute(&format!("CREATE DATABASE {CORRUPT_DATABASE}"), &[])
        .unwrap();
    drop(corrupt_admin);
    let mut corrupt_client = connect_bounded(&target.url(CORRUPT_DATABASE), CORRUPT_DATABASE);

    let truncated_dump = truncate_at_char_boundary(&dump_text, dump_text.len() / 2);
    assert!(
        !truncated_dump.is_empty() && truncated_dump.len() < dump_text.len(),
        "the truncated snapshot must be strictly shorter than the captured snapshot"
    );
    corrupt_client
        .batch_execute(truncated_dump)
        .expect_err("the deterministically truncated snapshot must fail loudly during restore");

    let corrupt_store = build_store(
        &target,
        CORRUPT_DATABASE,
        &namespace,
        "sunrise-edge-pr89-backup-restore-corrupt",
    );
    assert!(
        !restore_passes_rehearsal_gate(
            &corrupt_store,
            &mut corrupt_client,
            &namespace,
            domain,
            &stale_context,
            pre_backup_metadata,
            &state_key,
            &state_value,
            request_id,
            &receipt,
        ),
        "a deterministically truncated (half-length) snapshot must never pass the rehearsal \
         gate, but schema identity and durable ground truth both verified"
    );
}
