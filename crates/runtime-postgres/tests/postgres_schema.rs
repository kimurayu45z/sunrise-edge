use postgres::{Client, Config, NoTls, error::SqlState};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableOperationContext, DurableOutboxBatch, DurableOutboxMessage,
    DurableReadError, DurableRequestId, DurableRequestReceipt, DurableStateTransaction,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId,
    StorageDeadline, StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresSchemaError, PostgresTransactionPolicy, apply_initial_schema, bootstrap_namespace,
    build_postgres_pool, inspect_namespace, verify_initial_schema,
};
use std::{
    num::NonZeroU32,
    sync::Arc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const TEST_DATABASE: &str = "sunrise_edge_test";

#[test]
fn normalized_schema_bootstrap_and_constraints_hold_in_postgres() {
    let Some(url) = std::env::var_os("SUNRISE_EDGE_TEST_POSTGRES_URL") else {
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
}
