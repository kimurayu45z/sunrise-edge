//! Shared durable conformance evidence and restart-persistence tests for the
//! local-only, non-production [`SqliteDurableStore`].

use hashing::{BuiltinHashFunction, HashFunction};
use objects::{Address, Object, Owner};
use protocol_types::{ChainId, ProtocolVersion, ValidatorId};
use runtime::conformance::{
    ConformanceFailure, ConformanceResult, DurableStoreFixture, SchemaSkewFixture,
    run_durable_object_conformance, run_durable_store_conformance, run_schema_skew_conformance,
};
use runtime::{
    AtomicStateReadSet, AtomicityDomainId, DueOutboxClaimRequest, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectRoutingProjection, DurableObjectVersion, DurableObjectVersionRecord,
    DurableOperationContext, DurableOutboxAcknowledgement, DurableOutboxBatch,
    DurableOutboxClaimOutcome, DurableOutboxClaimRejection, DurableOutboxLeaseId,
    DurableOutboxMessage, DurableReadError, DurableRequestReceipt, DurableStateTransaction,
    IndexedOutboxRepository, ObjectId, OutboxRequestId, RequestOutboxClaimRequest, StateMutation,
    StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use runtime_sqlite::{
    SQLITE_STRUCTURED_SCHEMA_IDENTITY, SqliteDurableStore, SqliteDurableStoreError, SqliteNamespace,
};
use rusqlite::{Connection, params};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

/// A private temporary SQLite database file, removed (with its WAL/SHM
/// siblings) when dropped.
struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let nonce = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sunrise-edge-sqlite-structured-{}-{nanos}-{nonce}.db",
            std::process::id()
        ));
        Self { path }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.as_os_str().to_owned();
            path.push(suffix);
            let path = PathBuf::from(path);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}

fn namespace(chain: &str, validator_byte: u8, domain_byte: u8) -> SqliteNamespace {
    SqliteNamespace::new(
        ChainId::new(chain).unwrap(),
        ValidatorId::new([validator_byte; 32]),
        AtomicityDomainId::new([domain_byte; 32]).unwrap(),
    )
}

struct SqliteConformanceFixture {
    _database: TestDatabase,
    path: PathBuf,
    store: Arc<SqliteDurableStore>,
    namespace: SqliteNamespace,
    initial_fence: WriterFenceGeneration,
}

impl SqliteConformanceFixture {
    fn new(
        chain: &str,
        validator_byte: u8,
        domain_byte: u8,
        initial_fence: WriterFenceGeneration,
    ) -> Self {
        let database = TestDatabase::new();
        let namespace = namespace(chain, validator_byte, domain_byte);
        let store =
            SqliteDurableStore::open(&database.path, namespace.clone(), initial_fence).unwrap();
        Self {
            path: database.path.clone(),
            _database: database,
            store: Arc::new(store),
            namespace,
            initial_fence,
        }
    }

    fn admin_connection(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
}

impl DurableStoreFixture for SqliteConformanceFixture {
    type Store = SqliteDurableStore;

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
                .map_err(|error| ConformanceFailure::new("sqlite-fixture", error.to_string()))?
                .as_millis(),
        )
        .map_err(|_| ConformanceFailure::new("sqlite-fixture", "clock exceeds u64"))?;
        let budget_millis: u64 = u64::try_from(budget.as_millis())
            .map_err(|_| ConformanceFailure::new("sqlite-fixture", "budget exceeds u64"))?;
        let deadline: u64 = now_millis
            .checked_add(budget_millis)
            .ok_or_else(|| ConformanceFailure::new("sqlite-fixture", "deadline exceeds u64"))?;
        Ok(DurableOperationContext::new(
            writer_fence,
            StorageDeadline::new(deadline).ok_or_else(|| {
                ConformanceFailure::new("sqlite-fixture", "deadline must be non-zero")
            })?,
            StorageCorrelationId::new([correlation_byte; 16]).ok_or_else(|| {
                ConformanceFailure::new("sqlite-fixture", "correlation ID must be non-zero")
            })?,
        ))
    }

    fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> ConformanceResult<()> {
        let advanced = self
            .store
            .advance_writer_fence(expected, next)
            .map_err(|error| ConformanceFailure::new("sqlite-fixture", error.to_string()))?;
        if advanced != next {
            return Err(ConformanceFailure::new(
                "sqlite-fixture",
                "operator fence advance returned the wrong generation",
            ));
        }
        Ok(())
    }

    fn object_provenance_chain_id(&self) -> ConformanceResult<ChainId> {
        Ok(self.namespace.chain_id().clone())
    }
}

impl SchemaSkewFixture for SqliteConformanceFixture {
    fn install_unsupported_schema(&self) -> ConformanceResult<()> {
        self.set_schema_identity(b"sunrise-edge/sqlite/structured/schema/unsupported")
    }

    fn restore_supported_schema(&self) -> ConformanceResult<()> {
        self.set_schema_identity(SQLITE_STRUCTURED_SCHEMA_IDENTITY)
    }
}

impl SqliteConformanceFixture {
    fn set_schema_identity(&self, identity: &[u8]) -> ConformanceResult<()> {
        let connection = self.admin_connection();
        let updated = connection
            .execute(
                "UPDATE durable_metadata SET schema_identity = ?1 WHERE id = 1",
                params![identity],
            )
            .map_err(|error| ConformanceFailure::new("sqlite-fixture", error.to_string()))?;
        if updated != 1 {
            return Err(ConformanceFailure::new(
                "sqlite-fixture",
                "schema identity update did not affect exactly one namespace row",
            ));
        }
        Ok(())
    }
}

#[test]
fn sqlite_structured_durable_store_conformance() {
    let fixture = SqliteConformanceFixture::new(
        "sqlite-structured-conformance",
        0xA0,
        0xA1,
        WriterFenceGeneration::new(7).unwrap(),
    );
    run_durable_store_conformance(&fixture).unwrap();
}

#[test]
fn sqlite_structured_object_conformance() {
    let fixture = SqliteConformanceFixture::new(
        "sqlite-object-conformance",
        0xA0,
        0xA2,
        WriterFenceGeneration::new(9).unwrap(),
    );
    run_durable_object_conformance(&fixture).unwrap();
}

#[test]
fn sqlite_structured_schema_skew_conformance() {
    let fixture = SqliteConformanceFixture::new(
        "sqlite-schema-skew-conformance",
        0xA0,
        0xA3,
        WriterFenceGeneration::new(11).unwrap(),
    );
    run_schema_skew_conformance(&fixture).unwrap();
}

fn build_object_version(
    chain_id: &ChainId,
    object_id: ObjectId,
    version: u64,
    byte: u8,
    checkpoint: u64,
) -> DurableObjectVersionRecord {
    let object = Object {
        id: object_id,
        version,
        owner: Owner::Address(Address::new([byte; 32])),
        type_hash: protocol_types::Digest32::new(
            protocol_types::HashAlgorithmId::Sha2_256,
            [byte.wrapping_add(1); 32],
        ),
        schema_version: u32::from(byte),
        data: vec![byte.wrapping_add(2)],
    };
    let canonical_bytes = objects::encode_object(&object).unwrap();
    let protocol_version = ProtocolVersion::new(1);
    let digest = BuiltinHashFunction::new(protocol_types::HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            protocol_version,
            chain_id,
            &canonical_bytes,
        )
        .unwrap();
    let provenance = DurableObjectProvenance::new(chain_id.clone(), protocol_version);
    DurableObjectVersionRecord::from_inline_object(object, digest, provenance, checkpoint).unwrap()
}

fn live_context(fence: WriterFenceGeneration, correlation_byte: u8) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now + 60_000).unwrap(),
        StorageCorrelationId::new([correlation_byte; 16]).unwrap(),
    )
}

/// Restarts a fresh process-local [`SqliteDurableStore`] against the same
/// file to prove durable state, immutable object versions, receipts, and
/// outbox delivery/claim/acknowledgement survive a close and reopen; that
/// exact request replay after reopen returns `RequestAlreadyCommitted`
/// without reapplying effects; that acknowledgement remains idempotent after
/// reopen; and that the persisted writer fence, not anything held in process
/// memory, fences a stale context.
#[test]
fn sqlite_structured_restart_persists_state_objects_receipts_and_outbox() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-restart", 0xB0, 0xB1);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0x22; 32]);
    let state_key = b"restart/counter".to_vec();
    let initial_fence = WriterFenceGeneration::new(3).unwrap();
    let context = live_context(initial_fence, 0x01);
    let request_id = OutboxRequestId::new([0x55; 32]).unwrap();
    let lease_id = DurableOutboxLeaseId::new([0x5A; 32]).unwrap();

    let version = build_object_version(&chain_id, object_id, 1, 0x33, 100);
    let owner_projection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new([0x33; 32]))).unwrap();
    let routing_projection = DurableObjectRoutingProjection::new(Some(vec![0x44])).unwrap();
    let object_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            },
        )],
    )
    .unwrap();

    let state = DurableStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(state_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![StateMutationEntry::new(state_key.clone(), StateMutation::Put(vec![0x99])).unwrap()],
    )
    .unwrap();

    let event_digest =
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x56; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![0x57]).unwrap();
    let message = DurableOutboxMessage::new(
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha3_256, [0x58; 32]),
        vec![0x59],
    )
    .unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();

    let invocation = DurableInvocationTransaction::new(
        namespace.domain(),
        Some(state),
        object_changes,
        receipt,
        Some(outbox),
    )
    .unwrap();

    {
        let store =
            SqliteDurableStore::open(&database.path, namespace.clone(), initial_fence).unwrap();

        let outcome = store.commit_invocation(&context, invocation.clone());
        assert_eq!(outcome, DurableCommitOutcome::Committed);

        // Claim (but do not acknowledge) the sole outbox message before restart.
        let claim_outcome = store.claim_due_outbox(
            &context,
            DueOutboxClaimRequest::new(namespace.domain(), 0, lease_id, 60_000).unwrap(),
        );
        assert!(matches!(
            claim_outcome,
            DurableOutboxClaimOutcome::Claimed(_)
        ));
    }

    // Reopen a fresh store instance against the same file.
    let store = SqliteDurableStore::open(&database.path, namespace.clone(), initial_fence).unwrap();

    let state_value = store
        .get_versioned_durable(&context, namespace.domain(), &state_key)
        .unwrap();
    assert_eq!(state_value.value(), Some([0x99].as_slice()));
    assert_eq!(state_value.revision(), StateRevision::new(1));

    let head = store
        .get_object_head(&context, namespace.domain(), object_id)
        .unwrap();
    let DurableObjectHead::Current {
        object_version,
        digest,
        ..
    } = head
    else {
        panic!("expected a current object head after restart, got {head:?}");
    };
    assert_eq!(object_version, DurableObjectVersion::new(1).unwrap());

    let version_record = store
        .get_object_version(
            &context,
            namespace.domain(),
            object_id,
            DurableObjectVersion::new(1).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(version_record.digest(), digest);
    assert_eq!(version_record.created_checkpoint(), 100);

    let receipt = store
        .get_request_receipt(&context, namespace.domain(), request_id)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.canonical_bytes(), &[0x57]);

    // Exact request replay after reopen must not reapply any effect: the
    // persisted receipt alone is authoritative, not anything held in memory.
    let replay_outcome = store.commit_invocation(&context, invocation);
    assert_eq!(
        replay_outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );

    // The lease claimed before restart is still active and still reconciles
    // to the identical claim.
    let claim_outcome = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(namespace.domain(), 0, lease_id, 60_000).unwrap(),
    );
    let DurableOutboxClaimOutcome::Claimed(claim) = claim_outcome else {
        panic!("expected the pre-restart lease to reconcile, got {claim_outcome:?}");
    };
    assert_eq!(claim.canonical_payload(), &[0x59]);

    let acknowledgement =
        DurableOutboxAcknowledgement::new(namespace.domain(), request_id, 0, lease_id);
    let ack_outcome = store.acknowledge_outbox(&context, acknowledgement);
    assert_eq!(
        ack_outcome,
        runtime::DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    // Acknowledging the exact same lease/index a second time after reopen
    // must remain idempotent rather than erroring or skipping a message.
    let repeated_ack_outcome = store.acknowledge_outbox(&context, acknowledgement);
    assert_eq!(
        repeated_ack_outcome,
        runtime::DurableOutboxAcknowledgementOutcome::Acknowledged
    );

    // The next due claim after restart must observe NoDueWork: acknowledgement
    // is idempotent and no work is left.
    let no_more_work = store.claim_due_outbox(
        &context,
        DueOutboxClaimRequest::new(
            namespace.domain(),
            0,
            DurableOutboxLeaseId::new([0x5B; 32]).unwrap(),
            60_000,
        )
        .unwrap(),
    );
    assert_eq!(no_more_work, DurableOutboxClaimOutcome::NoDueWork);

    // The persisted writer fence survives restart: a stale in-memory context
    // is fenced out even though the process never observed the operator's
    // advance.
    let advanced = store
        .advance_writer_fence(initial_fence, WriterFenceGeneration::new(4).unwrap())
        .unwrap();
    assert_eq!(advanced, WriterFenceGeneration::new(4).unwrap());
    let stale_read = store.get_object_head(&context, namespace.domain(), object_id);
    assert_eq!(
        stale_read,
        Err(DurableReadError::WriterFenced {
            active_generation: WriterFenceGeneration::new(4).unwrap(),
        })
    );

    let restarted_store =
        SqliteDurableStore::open(&database.path, namespace.clone(), initial_fence).unwrap();
    let fresh_context = live_context(WriterFenceGeneration::new(4).unwrap(), 0x02);
    let refreshed_head = restarted_store
        .get_object_head(&fresh_context, namespace.domain(), object_id)
        .unwrap();
    assert!(matches!(refreshed_head, DurableObjectHead::Current { .. }));
}

#[test]
fn sqlite_structured_open_rejects_mismatched_namespace() {
    let database = TestDatabase::new();
    let first = namespace("sqlite-namespace-a", 0xC0, 0xC1);
    let second = namespace("sqlite-namespace-b", 0xC0, 0xC1);
    let fence = WriterFenceGeneration::new(1).unwrap();

    SqliteDurableStore::open(&database.path, first, fence).unwrap();
    let reopened = SqliteDurableStore::open(&database.path, second, fence);
    assert!(matches!(
        reopened,
        Err(SqliteDurableStoreError::NamespaceMismatch)
    ));
}

#[test]
fn sqlite_structured_open_rejects_mismatched_validator_id() {
    let database = TestDatabase::new();
    let first = namespace("sqlite-namespace-validator", 0xC2, 0xC3);
    let second = namespace("sqlite-namespace-validator", 0xC4, 0xC3);
    let fence = WriterFenceGeneration::new(1).unwrap();

    SqliteDurableStore::open(&database.path, first, fence).unwrap();
    let reopened = SqliteDurableStore::open(&database.path, second, fence);
    assert!(matches!(
        reopened,
        Err(SqliteDurableStoreError::NamespaceMismatch)
    ));
}

#[test]
fn sqlite_structured_request_path_rejects_tampered_validator_id() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-request-path-validator-corruption", 0xC5, 0xC6);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x0A);

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();

    // Tamper with the persisted validator_id directly, bypassing `open`'s
    // check entirely: every later request-path operation must still fail
    // closed, not just the constructor.
    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_metadata SET validator_id = ?1 WHERE id = 1",
            params![[0xC7_u8; 32].as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_versioned_durable(&context, namespace.domain(), b"any-key");
    assert_eq!(result, Err(DurableReadError::SchemaMismatch));
}

#[test]
fn sqlite_structured_open_rejects_unclaimed_database_with_existing_schema() {
    let database = TestDatabase::new();
    let connection = Connection::open(&database.path).unwrap();
    connection
        .execute("CREATE TABLE foreign_data (id INTEGER)", [])
        .unwrap();
    drop(connection);

    let result = SqliteDurableStore::open(
        &database.path,
        namespace("sqlite-unclaimed", 0xD0, 0xD1),
        WriterFenceGeneration::new(1).unwrap(),
    );
    assert!(matches!(
        result,
        Err(SqliteDurableStoreError::UnclaimedDatabase)
    ));
}

/// Commits one owned `Create` for `object_id` with no state or outbox
/// section, so corruption tests have a real object-version row to tamper
/// with directly through a raw admin connection.
fn commit_one_object(
    store: &SqliteDurableStore,
    context: &DurableOperationContext,
    namespace: &SqliteNamespace,
    chain_id: &ChainId,
    object_id: ObjectId,
    request_id: OutboxRequestId,
) {
    let version = build_object_version(chain_id, object_id, 1, 0x11, 5);
    let owner_projection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new([0x11; 32]))).unwrap();
    let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
    let object_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            },
        )],
    )
    .unwrap();
    let event_digest =
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x12; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![0x13]).unwrap();
    let invocation =
        DurableInvocationTransaction::new(namespace.domain(), None, object_changes, receipt, None)
            .unwrap();
    let outcome = store.commit_invocation(context, invocation);
    assert_eq!(outcome, DurableCommitOutcome::Committed);
}

#[test]
fn sqlite_structured_object_head_rejects_mismatched_digest_columns() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-head-digest-corruption", 0xE0, 0xE1);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0xE2; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x03);
    let request_id = OutboxRequestId::new([0xE3; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    commit_one_object(
        &store, &context, &namespace, &chain_id, object_id, request_id,
    );

    // Null out digest_bytes while leaving digest_algorithm set: exactly one
    // of the pair is present, which must never be silently treated as absent.
    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_object_heads SET digest_bytes = NULL WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_object_head(&context, namespace.domain(), object_id);
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn sqlite_structured_object_head_rejects_tombstone_with_current_only_columns() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-head-tombstone-corruption", 0xE4, 0xE5);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0xE6; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x04);
    let request_id = OutboxRequestId::new([0xE7; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    commit_one_object(
        &store, &context, &namespace, &chain_id, object_id, request_id,
    );

    // Mark the head tombstoned but leave a current-only column populated:
    // a genuine tombstone must never carry any current-only column.
    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_object_heads SET status = 2 WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_object_head(&context, namespace.domain(), object_id);
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn sqlite_structured_object_version_rejects_unknown_digest_algorithm() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-version-digest-corruption", 0xE8, 0xE9);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0xEA; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x05);
    let request_id = OutboxRequestId::new([0xEB; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    commit_one_object(
        &store, &context, &namespace, &chain_id, object_id, request_id,
    );

    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_object_versions SET digest_algorithm = 9999 WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_object_version(
        &context,
        namespace.domain(),
        object_id,
        DurableObjectVersion::new(1).unwrap(),
    );
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn sqlite_structured_object_version_rejects_type_id_mismatch() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-version-type-id-corruption", 0xEC, 0xED);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0xEE; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x06);
    let request_id = OutboxRequestId::new([0xEF; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    commit_one_object(
        &store, &context, &namespace, &chain_id, object_id, request_id,
    );

    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_object_versions SET type_id = 777 WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_object_version(
        &context,
        namespace.domain(),
        object_id,
        DurableObjectVersion::new(1).unwrap(),
    );
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn sqlite_structured_object_version_rejects_persisted_chain_mismatch() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-version-chain-corruption", 0xF0, 0xF1);
    let chain_id = namespace.chain_id().clone();
    let object_id = ObjectId::new([0xF2; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x07);
    let request_id = OutboxRequestId::new([0xF3; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    commit_one_object(
        &store, &context, &namespace, &chain_id, object_id, request_id,
    );

    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_object_versions SET created_chain_id = 'some-other-chain'
             WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let result = store.get_object_version(
        &context,
        namespace.domain(),
        object_id,
        DurableObjectVersion::new(1).unwrap(),
    );
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
}

#[test]
fn sqlite_structured_commit_rejects_object_version_provenance_chain_mismatch() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-commit-chain-mismatch", 0xF4, 0xF5);
    let other_chain_id = ChainId::new("sqlite-commit-chain-mismatch-wrong-chain").unwrap();
    let object_id = ObjectId::new([0xF6; 32]);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x08);
    let request_id = OutboxRequestId::new([0xF7; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();

    // The version's own provenance chain differs from the namespace's bound
    // chain: commit must reject before ever writing a row.
    let version = build_object_version(&other_chain_id, object_id, 1, 0x11, 5);
    let owner_projection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new([0x11; 32]))).unwrap();
    let routing_projection = DurableObjectRoutingProjection::new(None).unwrap();
    let object_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            },
        )],
    )
    .unwrap();
    let event_digest =
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x12; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![0x13]).unwrap();
    let invocation =
        DurableInvocationTransaction::new(namespace.domain(), None, object_changes, receipt, None)
            .unwrap();
    let outcome = store.commit_invocation(&context, invocation);
    assert_eq!(
        outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );

    let head = store
        .get_object_head(&context, namespace.domain(), object_id)
        .unwrap();
    assert_eq!(head, DurableObjectHead::Absent);
}

#[test]
fn sqlite_structured_outbox_claim_rejects_non_boolean_completed() {
    let database = TestDatabase::new();
    let namespace = namespace("sqlite-outbox-completed-corruption", 0xF8, 0xF9);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let context = live_context(fence, 0x09);
    let request_id = OutboxRequestId::new([0xFA; 32]).unwrap();

    let store = SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    let event_digest =
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0xFB; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![0xFC]).unwrap();
    let message = DurableOutboxMessage::new(
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha3_256, [0xFD; 32]),
        vec![0xFE],
    )
    .unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
    let invocation = DurableInvocationTransaction::new(
        namespace.domain(),
        None,
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap();
    let outcome = store.commit_invocation(&context, invocation);
    assert_eq!(outcome, DurableCommitOutcome::Committed);

    let admin = Connection::open(&database.path).unwrap();
    let updated = admin
        .execute(
            "UPDATE durable_outbox_delivery SET completed = 2 WHERE request_id = ?1",
            params![request_id.as_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(updated, 1);
    drop(admin);

    let claim_outcome = store.claim_request_outbox(
        &context,
        RequestOutboxClaimRequest::new(
            namespace.domain(),
            request_id,
            0,
            DurableOutboxLeaseId::new([0xFF; 32]).unwrap(),
            60_000,
        )
        .unwrap(),
    );
    assert_eq!(
        claim_outcome,
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::InvalidPersistedState)
    );
}
