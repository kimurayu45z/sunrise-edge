//! Local-only, non-production SQLite implementation of the structured durable
//! runtime contracts.
//!
//! [`SqliteDurableStore`] implements [`StructuredDurableDomainStateStore`] and
//! [`IndexedOutboxRepository`] using its own tables and its own SQLite
//! `PRAGMA application_id`, separate from the opaque legacy
//! [`crate::SqliteStateStore`]. Because `application_id`/`user_version` are
//! whole-file SQLite properties, this store and the legacy opaque store
//! cannot share one database file: each must open its own file. This store
//! never reinterprets the legacy store's opaque state-key prefixes; it
//! normalizes application state, immutable object versions, completed-request
//! receipts, and the outbox into their own tables, matching the normalized
//! `runtime-postgres` schema at the level of this contract (not its SQL
//! dialect, pooling, or multi-tenant hardening).
//!
//! This adapter is for the single-node Developer MVP only. It is bound at
//! construction to exactly one trusted `(chain, validator, atomicity domain)`
//! namespace, and serializes every operation behind one process-local
//! [`Mutex`] plus one SQLite transaction: a `Deferred` transaction wraps each
//! multi-statement read (the metadata/fence check and the requested payload
//! are observed from one consistent snapshot, then explicitly rolled back),
//! and a `BEGIN IMMEDIATE` transaction wraps each write (the writer fence is
//! validated once, right after the write lock is acquired, and stays valid
//! through `COMMIT` because that lock excludes any other writer from
//! advancing it meanwhile; only the deadline is rechecked immediately before
//! `COMMIT`). The caller's remaining `DurableOperationContext` deadline is
//! propagated into that connection's SQLite `busy_timeout`, clamped to
//! `[1ms, 5000ms]`, immediately before each transaction is acquired, so a
//! blocked write fails closed near the caller's own deadline instead of
//! always waiting the fixed default. This adapter has none of
//! `runtime-postgres`'s connection pooling, serialization-conflict retries,
//! or live fault-injected evidence. It is not suitable for multi-writer or
//! production deployments.

use crate::{decode_u64, encode_u64};
use protocol_types::{ChainId, Digest32, HashAlgorithmId, ProtocolVersion, ValidatorId};
use runtime::{
    AtomicStateTransaction, AtomicityDomainId, DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID,
    DueOutboxClaimRequest, DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectHeadSummary, DurableObjectMutation, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaim, DurableOutboxClaimOutcome,
    DurableOutboxClaimRejection, DurableOutboxLeaseId, DurableReadError, DurableRequestId,
    DurableRequestReceipt, IndeterminateCommitReason, IndexedOutboxRepository, ObjectHeadRevision,
    ObjectId, OutboxRequestId, RequestOutboxClaimRequest, RuntimeError, StateMutation,
    StateMutationEntry, StateReadAssertion, StateRevision, StructuredDurableDomainStateStore,
    VersionedStateValue, WriterFenceGeneration,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const STRUCTURED_APPLICATION_ID: i64 = 0x5352_4453;
const STRUCTURED_SCHEMA_VERSION: i64 = 1;
const STRUCTURED_MAX_BUSY_TIMEOUT_MILLIS: u64 = 5_000;
const STRUCTURED_BUSY_TIMEOUT: Duration = Duration::from_millis(STRUCTURED_MAX_BUSY_TIMEOUT_MILLIS);

/// Stable identity of the local-only structured SQLite schema, generation one.
///
/// A future additive migration bumps [`STRUCTURED_SCHEMA_VERSION`] and this
/// identity together; a database claimed by an unsupported identity or
/// version fails closed rather than being silently reinterpreted.
pub const SQLITE_STRUCTURED_SCHEMA_IDENTITY: &[u8] = b"sunrise-edge/sqlite/structured/schema/v1";

const OBJECT_HEAD_STATUS_CURRENT: i64 = 1;
const OBJECT_HEAD_STATUS_TOMBSTONED: i64 = 2;

const OUTBOX_ATTEMPT_CLAIMED: i64 = 1;
const OUTBOX_ATTEMPT_ACKNOWLEDGED: i64 = 2;
const OUTBOX_ATTEMPT_EXPIRED: i64 = 3;

/// Typed, strictly decoded status of one `durable_outbox_attempts` row.
///
/// Any persisted value other than the three known statuses is corruption,
/// never coerced to one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboxAttemptStatus {
    Claimed,
    Acknowledged,
    Expired,
}

impl OutboxAttemptStatus {
    fn decode(value: i64) -> Result<Self, SqlitePreCommitFailure> {
        match value {
            OUTBOX_ATTEMPT_CLAIMED => Ok(Self::Claimed),
            OUTBOX_ATTEMPT_ACKNOWLEDGED => Ok(Self::Acknowledged),
            OUTBOX_ATTEMPT_EXPIRED => Ok(Self::Expired),
            _ => Err(SqlitePreCommitFailure::InvalidPersistedState),
        }
    }

    const fn encode(self) -> i64 {
        match self {
            Self::Claimed => OUTBOX_ATTEMPT_CLAIMED,
            Self::Acknowledged => OUTBOX_ATTEMPT_ACKNOWLEDGED,
            Self::Expired => OUTBOX_ATTEMPT_EXPIRED,
        }
    }
}

/// The exact trusted `(chain, validator, atomicity domain)` namespace one
/// local SQLite structured database file is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqliteNamespace {
    chain_id: ChainId,
    validator_id: ValidatorId,
    domain: AtomicityDomainId,
}

impl SqliteNamespace {
    /// Binds one trusted chain, validator identity, and logical atomicity
    /// domain.
    #[must_use]
    pub const fn new(
        chain_id: ChainId,
        validator_id: ValidatorId,
        domain: AtomicityDomainId,
    ) -> Self {
        Self {
            chain_id,
            validator_id,
            domain,
        }
    }

    /// Returns the trusted chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the trusted validator identity this database file serves.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Returns the one logical atomicity domain this database file serves.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }
}

/// Fail-closed errors opening, bootstrapping, or operating a structured
/// SQLite database outside the request-path traits.
#[derive(Debug)]
pub enum SqliteDurableStoreError {
    /// SQLite rejected an operation.
    Database(rusqlite::Error),
    /// The database could not enter WAL mode.
    UnsupportedJournalMode(String),
    /// The database belongs to another application.
    ApplicationId(i64),
    /// An unclaimed database already contained unrelated schema objects.
    UnclaimedDatabase,
    /// The database schema version is not supported by this binary.
    SchemaVersion(i64),
    /// The persisted schema identity does not match this binary.
    SchemaIdentityMismatch,
    /// The persisted namespace differs from the requested chain, validator,
    /// or domain.
    NamespaceMismatch,
    /// The namespace metadata row is missing or malformed.
    InvalidPersistedMetadata,
    /// A persisted writer fence was zero.
    ZeroWriterFence,
    /// The expected writer fence was no longer active when advancing it.
    WriterFenceMismatch {
        /// Generation the operator expected to replace.
        expected: WriterFenceGeneration,
        /// Generation actually persisted.
        actual: WriterFenceGeneration,
    },
    /// A requested writer generation did not strictly advance the active one.
    WriterFenceNotAdvanced {
        /// Current generation supplied by the operator.
        current: WriterFenceGeneration,
        /// Requested replacement generation.
        requested: WriterFenceGeneration,
    },
    /// Another thread panicked while holding the connection.
    ConnectionPoisoned,
}

impl fmt::Display for SqliteDurableStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "SQLite operation failed: {error}"),
            Self::UnsupportedJournalMode(mode) => {
                write!(f, "SQLite journal mode is {mode}, expected wal")
            }
            Self::ApplicationId(id) => write!(
                f,
                "SQLite application id is {id:#x}, expected {STRUCTURED_APPLICATION_ID:#x}"
            ),
            Self::UnclaimedDatabase => {
                f.write_str("unclaimed SQLite database already contains schema objects")
            }
            Self::SchemaVersion(version) => write!(
                f,
                "SQLite structured schema version is {version}, expected {STRUCTURED_SCHEMA_VERSION}"
            ),
            Self::SchemaIdentityMismatch => {
                f.write_str("SQLite structured schema identity is unsupported")
            }
            Self::NamespaceMismatch => {
                f.write_str("SQLite database already has a different bound chain/validator/domain")
            }
            Self::InvalidPersistedMetadata => {
                f.write_str("SQLite structured metadata row is missing or malformed")
            }
            Self::ZeroWriterFence => f.write_str("SQLite writer fence must be non-zero"),
            Self::WriterFenceMismatch { expected, actual } => write!(
                f,
                "SQLite writer fence changed: expected {}, found {}",
                expected.get(),
                actual.get()
            ),
            Self::WriterFenceNotAdvanced { current, requested } => write!(
                f,
                "SQLite writer fence must advance: current {}, requested {}",
                current.get(),
                requested.get()
            ),
            Self::ConnectionPoisoned => f.write_str("SQLite connection lock is poisoned"),
        }
    }
}

impl Error for SqliteDurableStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteDurableStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

/// Local-only, single-writer structured durable store backed by one SQLite
/// file.
///
/// See the module documentation for the exact scope and limits. Callers must
/// run this synchronous interface behind bounded blocking isolation when used
/// from an asynchronous request runtime.
#[derive(Debug)]
pub struct SqliteDurableStore {
    connection: Mutex<Connection>,
    namespace: SqliteNamespace,
}

impl SqliteDurableStore {
    /// Opens or bootstraps a local structured durable database.
    ///
    /// `initial_writer_fence` is used only the first time this namespace is
    /// bootstrapped; a later open with the same file ignores it and reads the
    /// persisted fence. This auto-bootstrap-on-open behavior (unlike
    /// `runtime-postgres`'s explicit operator-only bootstrap) is acceptable
    /// only because the file is local, single-tenant, and non-production.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
        initial_writer_fence: WriterFenceGeneration,
    ) -> Result<Self, SqliteDurableStoreError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteDurableStoreError::UnsupportedJournalMode(
                journal_mode,
            ));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;

        initialize_structured_schema(&mut connection, &namespace, initial_writer_fence)?;
        Ok(Self {
            connection: Mutex::new(connection),
            namespace,
        })
    }

    /// Returns the exact namespace this database file is bound to.
    #[must_use]
    pub const fn namespace(&self) -> &SqliteNamespace {
        &self.namespace
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, SqliteDurableStoreError> {
        self.connection
            .lock()
            .map_err(|_| SqliteDurableStoreError::ConnectionPoisoned)
    }

    fn domain_is_bound(&self, domain: AtomicityDomainId) -> bool {
        domain == self.namespace.domain()
    }

    /// Atomically advances the persisted writer fence.
    ///
    /// This is an explicit operator-only failover seam, not part of any
    /// runtime trait. Request handling must never be able to reach it. Unlike
    /// the request path, this method carries no `DurableOperationContext`
    /// deadline, so it resets the connection's SQLite `busy_timeout` back to
    /// the fixed operator default before acquiring `BEGIN IMMEDIATE`: a
    /// previous request-path operation may have left a much shorter budget
    /// installed on this shared connection.
    pub fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        if next.get() <= expected.get() {
            return Err(SqliteDurableStoreError::WriterFenceNotAdvanced {
                current: expected,
                requested: next,
            });
        }
        let mut connection = self.connection()?;
        connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Revalidate the exact schema identity and chain/validator/domain
        // namespace inside the write lock, before trusting or mutating the
        // fence: a namespace check performed before BEGIN IMMEDIATE would not
        // be held by that lock and could be stale by the time the fence is
        // read.
        verify_namespace(&transaction, &self.namespace)?;
        let actual = read_writer_fence(&transaction)?;
        if actual != expected {
            return Err(SqliteDurableStoreError::WriterFenceMismatch { expected, actual });
        }
        let updated = transaction.execute(
            "UPDATE durable_metadata SET writer_fence = ?1 WHERE id = 1",
            params![encode_u64(next.get()).as_slice()],
        )?;
        if updated != 1 {
            return Err(SqliteDurableStoreError::InvalidPersistedMetadata);
        }
        transaction.commit()?;
        Ok(next)
    }

    /// Reads the currently persisted writer fence.
    ///
    /// This is an explicit operator-only accessor, not part of any runtime
    /// trait; request handling must never be able to reach it. Like
    /// [`SqliteDurableStore::advance_writer_fence`], it carries no
    /// `DurableOperationContext` deadline, so it resets the connection's
    /// SQLite `busy_timeout` back to the fixed operator default before
    /// acquiring a transaction. It revalidates the exact schema identity and
    /// chain/validator/domain namespace and reads the writer fence from one
    /// consistent `Deferred` snapshot, then rolls the read-only transaction
    /// back (equivalent to a commit here, since nothing was written).
    pub fn writer_fence(&self) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        let mut connection = self.connection()?;
        connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        verify_namespace(&transaction, &self.namespace)?;
        let fence = read_writer_fence(&transaction)?;
        transaction.rollback()?;
        Ok(fence)
    }
}

fn structured_schema_ddl() -> String {
    format!(
        "CREATE TABLE durable_metadata (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             schema_identity BLOB NOT NULL,
             chain_id TEXT NOT NULL,
             validator_id BLOB NOT NULL CHECK(length(validator_id) = 32),
             domain BLOB NOT NULL CHECK(length(domain) = 32),
             writer_fence BLOB NOT NULL CHECK(length(writer_fence) = 8)
         );

         CREATE TABLE durable_state (
             key BLOB PRIMARY KEY NOT NULL,
             revision BLOB NOT NULL CHECK(length(revision) = 8),
             value BLOB NULL
         ) WITHOUT ROWID;

         CREATE TABLE durable_object_heads (
             object_id BLOB PRIMARY KEY NOT NULL CHECK(length(object_id) = 32),
             status INTEGER NOT NULL,
             head_revision BLOB NOT NULL CHECK(length(head_revision) = 8),
             object_version BLOB NULL CHECK(object_version IS NULL OR length(object_version) = 8),
             digest_algorithm INTEGER NULL,
             digest_bytes BLOB NULL CHECK(digest_bytes IS NULL OR length(digest_bytes) = 32),
             owner_projection BLOB NULL,
             routing_projection BLOB NULL
         ) WITHOUT ROWID;

         CREATE TABLE durable_object_versions (
             object_id BLOB NOT NULL CHECK(length(object_id) = 32),
             object_version BLOB NOT NULL CHECK(length(object_version) = 8),
             digest_algorithm INTEGER NOT NULL,
             digest_bytes BLOB NOT NULL CHECK(length(digest_bytes) = 32),
             schema_version INTEGER NOT NULL,
             type_id INTEGER NOT NULL,
             created_chain_id TEXT NOT NULL,
             created_protocol_version INTEGER NOT NULL,
             created_checkpoint BLOB NOT NULL CHECK(length(created_checkpoint) = 8),
             inline_canonical_bytes BLOB NULL,
             blob_digest_algorithm INTEGER NULL,
             blob_digest_bytes BLOB NULL CHECK(blob_digest_bytes IS NULL OR length(blob_digest_bytes) = 32),
             PRIMARY KEY (object_id, object_version)
         ) WITHOUT ROWID;

         CREATE TABLE durable_receipts (
             request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 32),
             event_digest_algorithm INTEGER NOT NULL,
             event_digest_bytes BLOB NOT NULL CHECK(length(event_digest_bytes) = 32),
             canonical_bytes BLOB NOT NULL
         ) WITHOUT ROWID;

         CREATE TABLE durable_outbox_messages (
             request_id BLOB NOT NULL CHECK(length(request_id) = 32),
             message_index INTEGER NOT NULL,
             payload_digest_algorithm INTEGER NOT NULL,
             payload_digest_bytes BLOB NOT NULL CHECK(length(payload_digest_bytes) = 32),
             canonical_payload BLOB NOT NULL,
             PRIMARY KEY (request_id, message_index)
         ) WITHOUT ROWID;

         CREATE TABLE durable_outbox_delivery (
             request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 32),
             message_count INTEGER NOT NULL,
             next_message_index INTEGER NOT NULL,
             completed INTEGER NOT NULL,
             available_at_unix_millis BLOB NOT NULL CHECK(length(available_at_unix_millis) = 8),
             active_lease_id BLOB NULL CHECK(active_lease_id IS NULL OR length(active_lease_id) = 32),
             lease_expires_at_unix_millis BLOB NULL
                 CHECK(lease_expires_at_unix_millis IS NULL OR length(lease_expires_at_unix_millis) = 8),
             attempt_count BLOB NOT NULL CHECK(length(attempt_count) = 8)
         ) WITHOUT ROWID;

         CREATE INDEX durable_outbox_due_idx
             ON durable_outbox_delivery(available_at_unix_millis, request_id)
             WHERE completed = 0;

         CREATE TABLE durable_outbox_attempts (
             lease_id BLOB PRIMARY KEY NOT NULL CHECK(length(lease_id) = 32),
             request_id BLOB NOT NULL CHECK(length(request_id) = 32),
             message_index INTEGER NOT NULL,
             lease_expires_at_unix_millis BLOB NOT NULL CHECK(length(lease_expires_at_unix_millis) = 8),
             status INTEGER NOT NULL
         ) WITHOUT ROWID;

         PRAGMA application_id = {STRUCTURED_APPLICATION_ID};
         PRAGMA user_version = {STRUCTURED_SCHEMA_VERSION};"
    )
}

fn initialize_structured_schema(
    connection: &mut Connection,
    namespace: &SqliteNamespace,
    initial_writer_fence: WriterFenceGeneration,
) -> Result<(), SqliteDurableStoreError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 && application_id != STRUCTURED_APPLICATION_ID {
        return Err(SqliteDurableStoreError::ApplicationId(application_id));
    }
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != 0 && schema_version != STRUCTURED_SCHEMA_VERSION {
        return Err(SqliteDurableStoreError::SchemaVersion(schema_version));
    }

    if application_id == STRUCTURED_APPLICATION_ID && schema_version == STRUCTURED_SCHEMA_VERSION {
        return verify_namespace(connection, namespace);
    }
    if application_id != 0 {
        return Err(SqliteDurableStoreError::SchemaVersion(schema_version));
    }
    if schema_version != 0 {
        return Err(SqliteDurableStoreError::ApplicationId(application_id));
    }
    let schema_objects: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if schema_objects != 0 {
        return Err(SqliteDurableStoreError::UnclaimedDatabase);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(&structured_schema_ddl())?;
    transaction.execute(
        "INSERT INTO durable_metadata (id, schema_identity, chain_id, validator_id, domain, writer_fence)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            SQLITE_STRUCTURED_SCHEMA_IDENTITY,
            namespace.chain_id().as_str(),
            namespace.validator_id().as_bytes().as_slice(),
            namespace.domain().as_bytes().as_slice(),
            encode_u64(initial_writer_fence.get()).as_slice(),
        ],
    )?;
    transaction.commit()?;
    verify_namespace(connection, namespace)
}

/// One raw `durable_metadata` row, aliased so `clippy::type_complexity` does
/// not flag the inline tuple used only to shuttle query results.
type NamespaceRow = (Vec<u8>, String, Vec<u8>, Vec<u8>);

fn verify_namespace(
    connection: &Connection,
    namespace: &SqliteNamespace,
) -> Result<(), SqliteDurableStoreError> {
    let row: Option<NamespaceRow> = connection
        .query_row(
            "SELECT schema_identity, chain_id, validator_id, domain FROM durable_metadata WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((schema_identity, chain_id, validator_id, domain)) = row else {
        return Err(SqliteDurableStoreError::InvalidPersistedMetadata);
    };
    if schema_identity != SQLITE_STRUCTURED_SCHEMA_IDENTITY {
        return Err(SqliteDurableStoreError::SchemaIdentityMismatch);
    }
    if chain_id != namespace.chain_id().as_str()
        || validator_id.as_slice() != namespace.validator_id().as_bytes().as_slice()
        || domain.as_slice() != namespace.domain().as_bytes().as_slice()
    {
        return Err(SqliteDurableStoreError::NamespaceMismatch);
    }
    Ok(())
}

fn read_writer_fence(
    connection: &Connection,
) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
    let bytes: Vec<u8> = connection.query_row(
        "SELECT writer_fence FROM durable_metadata WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    decode_u64(&bytes)
        .and_then(WriterFenceGeneration::new)
        .ok_or(SqliteDurableStoreError::ZeroWriterFence)
}

/// Pre-commit classification of one failed SQLite read/write attempt,
/// analogous to `runtime-postgres`'s `PreCommitFailure` but without a
/// serialization-retry branch: the process-local mutex plus one `BEGIN
/// IMMEDIATE` transaction already serializes every operation.
#[derive(Debug)]
enum SqlitePreCommitFailure {
    Deadline,
    WriterFenced(WriterFenceGeneration),
    SchemaMismatch,
    InvalidPersistedState,
    Unavailable,
}

impl SqlitePreCommitFailure {
    fn into_read_error(self) -> DurableReadError {
        match self {
            Self::Deadline => DurableReadError::DeadlineExceeded,
            Self::WriterFenced(active_generation) => {
                DurableReadError::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableReadError::SchemaMismatch,
            Self::InvalidPersistedState => DurableReadError::InvalidPersistedState,
            Self::Unavailable => DurableReadError::Unavailable,
        }
    }

    fn into_commit_rejection(self) -> DurableCommitRejection {
        match self {
            Self::Deadline => DurableCommitRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableCommitRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableCommitRejection::SchemaMismatch,
            Self::InvalidPersistedState => DurableCommitRejection::InvalidPersistedState,
            Self::Unavailable => DurableCommitRejection::UnavailableBeforeCommit,
        }
    }

    fn into_claim_rejection(self) -> DurableOutboxClaimRejection {
        match self {
            Self::Deadline => DurableOutboxClaimRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxClaimRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableOutboxClaimRejection::SchemaMismatch,
            Self::InvalidPersistedState => DurableOutboxClaimRejection::InvalidPersistedState,
            Self::Unavailable => DurableOutboxClaimRejection::UnavailableBeforeCommit,
        }
    }

    fn into_acknowledgement_rejection(self) -> DurableOutboxAcknowledgementRejection {
        match self {
            Self::Deadline => DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxAcknowledgementRejection::WriterFenced { active_generation }
            }
            Self::SchemaMismatch => DurableOutboxAcknowledgementRejection::SchemaMismatch,
            Self::InvalidPersistedState => {
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            }
            Self::Unavailable => DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
        }
    }
}

fn database_unavailable(_error: rusqlite::Error) -> SqlitePreCommitFailure {
    SqlitePreCommitFailure::Unavailable
}

fn now_unix_millis() -> Result<u64, SqlitePreCommitFailure> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SqlitePreCommitFailure::Unavailable)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| SqlitePreCommitFailure::Unavailable)
}

fn check_deadline(context: &DurableOperationContext) -> Result<(), SqlitePreCommitFailure> {
    let now = now_unix_millis()?;
    if context.deadline().is_expired_at(now) {
        return Err(SqlitePreCommitFailure::Deadline);
    }
    Ok(())
}

/// Computes the exact remaining wall-clock budget until `context`'s
/// deadline, clamped to `[1ms, STRUCTURED_MAX_BUSY_TIMEOUT_MILLIS]`.
///
/// An already-expired deadline is a definite pre-commit rejection here, not a
/// zero-length busy wait: SQLite would otherwise interpret a zero timeout as
/// "return immediately on any contention" rather than "the caller is out of
/// budget," which are different failures.
fn remaining_busy_timeout(
    context: &DurableOperationContext,
) -> Result<Duration, SqlitePreCommitFailure> {
    let now = now_unix_millis()?;
    let remaining_millis = context
        .deadline()
        .unix_millis()
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(SqlitePreCommitFailure::Deadline)?;
    Ok(Duration::from_millis(
        remaining_millis.clamp(1, STRUCTURED_MAX_BUSY_TIMEOUT_MILLIS),
    ))
}

/// Propagates `context`'s remaining deadline into this connection's SQLite
/// `busy_timeout` immediately before acquiring a transaction, so a lock wait
/// (for example another connection holding `BEGIN IMMEDIATE`) cannot block
/// past the caller's own deadline even though the connection-level default
/// set at [`SqliteDurableStore::open`] is a fixed five seconds.
fn apply_busy_timeout(
    connection: &Connection,
    context: &DurableOperationContext,
) -> Result<(), SqlitePreCommitFailure> {
    let timeout = remaining_busy_timeout(context)?;
    connection
        .busy_timeout(timeout)
        .map_err(database_unavailable)
}

struct SqliteNamespaceMetadata {
    writer_fence: WriterFenceGeneration,
}

/// One raw `durable_metadata` row, aliased so `clippy::type_complexity` does
/// not flag the inline tuple used only to shuttle query results.
type MetadataRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_metadata(
    connection: &Connection,
    namespace: &SqliteNamespace,
) -> Result<SqliteNamespaceMetadata, SqlitePreCommitFailure> {
    let row: Option<MetadataRow> = connection
        .query_row(
            "SELECT schema_identity, chain_id, validator_id, domain, writer_fence
             FROM durable_metadata WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((schema_identity, chain_id, validator_id, domain, writer_fence)) = row else {
        return Err(SqlitePreCommitFailure::SchemaMismatch);
    };
    if schema_identity != SQLITE_STRUCTURED_SCHEMA_IDENTITY
        || chain_id != namespace.chain_id().as_str()
        || validator_id.as_slice() != namespace.validator_id().as_bytes().as_slice()
        || domain.as_slice() != namespace.domain().as_bytes().as_slice()
    {
        return Err(SqlitePreCommitFailure::SchemaMismatch);
    }
    let writer_fence = decode_u64(&writer_fence)
        .and_then(WriterFenceGeneration::new)
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    Ok(SqliteNamespaceMetadata { writer_fence })
}

fn validate_authority(
    metadata: &SqliteNamespaceMetadata,
    context: &DurableOperationContext,
) -> Result<(), SqlitePreCommitFailure> {
    if metadata.writer_fence != context.writer_fence() {
        return Err(SqlitePreCommitFailure::WriterFenced(metadata.writer_fence));
    }
    check_deadline(context)
}

/// Runs one multi-statement read operation inside a single SQLite `Deferred`
/// transaction, so the metadata/fence check and the requested payload are
/// observed from one consistent snapshot instead of two independent
/// autocommit statements that another connection could interleave a write
/// between. The transaction is explicitly rolled back (read-only, so this is
/// exactly equivalent to a commit) and any rollback failure is propagated
/// rather than silently dropped.
fn read_in_snapshot<T>(
    connection: &mut Connection,
    namespace: &SqliteNamespace,
    context: &DurableOperationContext,
    load: impl FnOnce(&Transaction<'_>) -> Result<T, SqlitePreCommitFailure>,
) -> Result<T, SqlitePreCommitFailure> {
    apply_busy_timeout(connection, context)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(database_unavailable)?;
    let metadata = load_metadata(&transaction, namespace)?;
    validate_authority(&metadata, context)?;
    let value = load(&transaction)?;
    check_deadline(context)?;
    transaction.rollback().map_err(database_unavailable)?;
    Ok(value)
}

/// Strictly decodes one required `(algorithm, bytes)` digest column pair.
///
/// An unknown algorithm ID or a byte length other than 32 is persisted
/// corruption, not an absent value, and is always `InvalidPersistedState`.
fn decode_required_digest(
    algorithm: i64,
    bytes: &[u8],
) -> Result<Digest32, SqlitePreCommitFailure> {
    let algorithm: HashAlgorithmId = u16::try_from(algorithm)
        .ok()
        .and_then(|value| HashAlgorithmId::try_from(value).ok())
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    Ok(Digest32::new(algorithm, bytes))
}

/// Strictly decodes one optional `(algorithm, bytes)` digest column pair.
///
/// Only both columns null means the digest is genuinely absent. Exactly one
/// column null, an unknown algorithm ID, or a malformed byte length is
/// persisted corruption and is always `InvalidPersistedState`, never
/// silently treated as absent.
fn decode_optional_digest(
    algorithm: Option<i64>,
    bytes: Option<&[u8]>,
) -> Result<Option<Digest32>, SqlitePreCommitFailure> {
    match (algorithm, bytes) {
        (None, None) => Ok(None),
        (Some(algorithm), Some(bytes)) => decode_required_digest(algorithm, bytes).map(Some),
        (None, Some(_)) | (Some(_), None) => Err(SqlitePreCommitFailure::InvalidPersistedState),
    }
}

/// Strictly decodes one `0`/`1` `INTEGER` column as a boolean.
///
/// Any other stored value is persisted corruption, not truthy/falsy
/// coercion, and is always `InvalidPersistedState`.
fn decode_bool(value: i64) -> Result<bool, SqlitePreCommitFailure> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SqlitePreCommitFailure::InvalidPersistedState),
    }
}

fn load_state_value(
    connection: &Connection,
    key: &[u8],
) -> Result<VersionedStateValue, SqlitePreCommitFailure> {
    let row: Option<(Vec<u8>, Option<Vec<u8>>)> = connection
        .query_row(
            "SELECT revision, value FROM durable_state WHERE key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((revision, value)) = row else {
        return VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
            .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState);
    };
    let revision = decode_u64(&revision)
        .map(StateRevision::new)
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    if revision == StateRevision::INITIAL {
        return Err(SqlitePreCommitFailure::InvalidPersistedState);
    }
    VersionedStateValue::from_persisted_parts(revision, value)
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)
}

fn upsert_state(
    transaction: &Transaction<'_>,
    key: &[u8],
    revision: StateRevision,
    value: Option<&[u8]>,
) -> Result<(), SqlitePreCommitFailure> {
    transaction
        .execute(
            "INSERT INTO durable_state (key, revision, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET revision = excluded.revision, value = excluded.value",
            params![key, encode_u64(revision.get()).as_slice(), value],
        )
        .map_err(database_unavailable)?;
    Ok(())
}

fn validate_state_reads(
    connection: &Connection,
    reads: &[StateReadAssertion],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current = load_state_value(connection, read.key())
            .map_err(SqlitePreCommitFailure::into_commit_rejection)?;
        if current.revision() != read.expected_revision() {
            return Err(DurableCommitRejection::Conflict {
                key: read.key().to_vec(),
                current_revision: current.revision(),
            });
        }
    }
    Ok(())
}

fn apply_state_mutations(
    transaction: &Transaction<'_>,
    reads: &[StateReadAssertion],
    mutations: &[StateMutationEntry],
) -> Result<(), DurableCommitRejection> {
    for mutation in mutations {
        let expected_revision = reads
            .iter()
            .find(|read| read.key() == mutation.key())
            .map(StateReadAssertion::expected_revision)
            .ok_or(DurableCommitRejection::InvalidPersistedState)?;
        let next = expected_revision
            .checked_next()
            .map_err(|_| DurableCommitRejection::StateRevisionOverflow)?;
        match mutation.mutation() {
            StateMutation::Put(value) => {
                upsert_state(transaction, mutation.key(), next, Some(value))
            }
            StateMutation::Delete => upsert_state(transaction, mutation.key(), next, None),
            StateMutation::Assert => return Err(DurableCommitRejection::InvalidPersistedState),
        }
        .map_err(SqlitePreCommitFailure::into_commit_rejection)?;
    }
    Ok(())
}

/// Returns the maximum retained immutable object version for `object_id`, or
/// `None` if no version row exists.
///
/// This only resolves which version number to look up next; it does not
/// substitute for the full validation `load_object_version` performs on the
/// row it names.
fn max_object_version(
    connection: &Connection,
    object_id: ObjectId,
) -> Result<Option<DurableObjectVersion>, SqlitePreCommitFailure> {
    let max_version: Option<Vec<u8>> = connection
        .query_row(
            "SELECT MAX(object_version) FROM durable_object_versions WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(database_unavailable)?;
    let Some(max_version) = max_version else {
        return Ok(None);
    };
    let max_version = decode_u64(&max_version)
        .and_then(DurableObjectVersion::new)
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    Ok(Some(max_version))
}

/// Reads and cross-validates one object head against its exact immutable
/// version history.
///
/// This function never calls itself, directly or indirectly: it may call
/// [`load_object_version`], but that function never calls back into this one,
/// so there is no recursion. A `Current` head is trusted only after the
/// object version it names is loaded through the fully validated
/// [`load_object_version`] path (digest, canonical-record-type ID, and
/// creating-chain checks included) and confirmed to be the maximum retained
/// version, with its digest matching the head row's own digest columns. A
/// `Tombstoned` head resolves its last version through that same fully
/// validated path rather than trusting the raw `MAX(object_version)` value.
fn load_object_head(
    connection: &Connection,
    namespace: &SqliteNamespace,
    object_id: ObjectId,
) -> Result<DurableObjectHead, SqlitePreCommitFailure> {
    type HeadRow = (
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let row: Option<HeadRow> = connection
        .query_row(
            "SELECT status, head_revision, object_version, digest_algorithm, digest_bytes,
                    owner_projection, routing_projection
             FROM durable_object_heads WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((
        status,
        head_revision,
        object_version,
        digest_algorithm,
        digest_bytes,
        owner_projection,
        routing_projection,
    )) = row
    else {
        let retained_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM durable_object_versions WHERE object_id = ?1)",
                params![object_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(database_unavailable)?;
        if retained_exists {
            return Err(SqlitePreCommitFailure::InvalidPersistedState);
        }
        return Ok(DurableObjectHead::Absent);
    };
    let head_revision = decode_u64(&head_revision)
        .and_then(ObjectHeadRevision::new)
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    match status {
        OBJECT_HEAD_STATUS_TOMBSTONED => {
            // A tombstoned head must carry no current-only columns; any of
            // them present is persisted corruption, not a partial tombstone.
            if object_version.is_some()
                || digest_algorithm.is_some()
                || digest_bytes.is_some()
                || owner_projection.is_some()
                || routing_projection.is_some()
            {
                return Err(SqlitePreCommitFailure::InvalidPersistedState);
            }
            let last_object_version = max_object_version(connection, object_id)?
                .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            // Resolve the retained last version through the same fully
            // validated read path a direct lookup would use, rather than
            // trusting the raw MAX() value's row shape.
            let last_object_version_record =
                load_object_version(connection, namespace, object_id, last_object_version)?
                    .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            Ok(DurableObjectHead::Tombstoned {
                head_revision,
                last_object_version: last_object_version_record.object_version(),
            })
        }
        OBJECT_HEAD_STATUS_CURRENT => {
            let object_version = object_version
                .as_deref()
                .and_then(decode_u64)
                .and_then(DurableObjectVersion::new)
                .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            let digest = decode_optional_digest(digest_algorithm, digest_bytes.as_deref())?
                .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            // Cross-check against the exact validated immutable version: its
            // digest must match, and it must be the maximum retained version
            // for this object, or the head is not trustworthy.
            let version_record =
                load_object_version(connection, namespace, object_id, object_version)?
                    .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            if version_record.digest() != digest {
                return Err(SqlitePreCommitFailure::InvalidPersistedState);
            }
            let max_version = max_object_version(connection, object_id)?
                .ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
            if max_version != object_version {
                return Err(SqlitePreCommitFailure::InvalidPersistedState);
            }
            let owner_projection =
                DurableObjectOwnerProjection::from_canonical_bytes(owner_projection)
                    .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
            let routing_projection = DurableObjectRoutingProjection::new(routing_projection)
                .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
            Ok(DurableObjectHead::Current {
                head_revision,
                object_version,
                digest,
                owner_projection,
                routing_projection,
            })
        }
        _ => Err(SqlitePreCommitFailure::InvalidPersistedState),
    }
}

/// One raw `durable_object_versions` row, aliased so `clippy::type_complexity`
/// does not flag the inline tuple used only to shuttle query results.
type VersionRow = (
    i64,
    Vec<u8>,
    i64,
    i64,
    String,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
);

fn load_object_version(
    connection: &Connection,
    namespace: &SqliteNamespace,
    object_id: ObjectId,
    object_version: DurableObjectVersion,
) -> Result<Option<DurableObjectVersionRecord>, SqlitePreCommitFailure> {
    let row: Option<VersionRow> = connection
        .query_row(
            "SELECT digest_algorithm, digest_bytes, schema_version, type_id, created_chain_id,
                    created_protocol_version, created_checkpoint, inline_canonical_bytes,
                    blob_digest_algorithm, blob_digest_bytes
             FROM durable_object_versions WHERE object_id = ?1 AND object_version = ?2",
            params![
                object_id.as_bytes().as_slice(),
                encode_u64(object_version.get()).as_slice()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((
        digest_algorithm,
        digest_bytes,
        schema_version,
        type_id,
        created_chain_id,
        created_protocol_version,
        created_checkpoint,
        inline_bytes,
        blob_algorithm,
        blob_bytes,
    )) = row
    else {
        return Ok(None);
    };
    let digest = decode_required_digest(digest_algorithm, &digest_bytes)?;
    let schema_version =
        u32::try_from(schema_version).map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let type_id =
        u32::try_from(type_id).map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    if type_id != DURABLE_OBJECT_CANONICAL_RECORD_TYPE_ID {
        return Err(SqlitePreCommitFailure::InvalidPersistedState);
    }
    let created_chain_id = ChainId::new(created_chain_id)
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    if &created_chain_id != namespace.chain_id() {
        return Err(SqlitePreCommitFailure::InvalidPersistedState);
    }
    let created_protocol_version = ProtocolVersion::new(
        u32::try_from(created_protocol_version)
            .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?,
    );
    let provenance = DurableObjectProvenance::new(created_chain_id, created_protocol_version);
    let created_checkpoint =
        decode_u64(&created_checkpoint).ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    let blob_digest = decode_optional_digest(blob_algorithm, blob_bytes.as_deref())?;
    let record = match (inline_bytes, blob_digest) {
        (Some(inline_bytes), None) => DurableObjectVersionRecord::from_inline_canonical_bytes(
            inline_bytes,
            digest,
            provenance,
            created_checkpoint,
        )
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?,
        (None, Some(blob_digest)) => DurableObjectVersionRecord::from_blob_reference(
            object_id,
            object_version,
            digest,
            schema_version,
            provenance,
            created_checkpoint,
            blob_digest,
        ),
        (None, None) | (Some(_), Some(_)) => {
            return Err(SqlitePreCommitFailure::InvalidPersistedState);
        }
    };
    if record.object_id() != object_id
        || record.object_version() != object_version
        || record.schema_version() != schema_version
        || record.canonical_record_type_id() != type_id
    {
        return Err(SqlitePreCommitFailure::InvalidPersistedState);
    }
    Ok(Some(record))
}

/// One raw `durable_receipts` row, aliased so `clippy::type_complexity` does
/// not flag the inline tuple used only to shuttle query results.
type ReceiptRow = (i64, Vec<u8>, Vec<u8>);

fn load_receipt(
    connection: &Connection,
    request_id: DurableRequestId,
) -> Result<Option<DurableRequestReceipt>, SqlitePreCommitFailure> {
    let row: Option<ReceiptRow> = connection
        .query_row(
            "SELECT event_digest_algorithm, event_digest_bytes, canonical_bytes
             FROM durable_receipts WHERE request_id = ?1",
            params![request_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((algorithm, digest_bytes, canonical_bytes)) = row else {
        return Ok(None);
    };
    let event_digest = decode_required_digest(algorithm, &digest_bytes)?;
    let receipt = DurableRequestReceipt::new(request_id, event_digest, canonical_bytes)
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    Ok(Some(receipt))
}

fn receipt_exists(
    connection: &Connection,
    request_id: DurableRequestId,
) -> Result<bool, SqlitePreCommitFailure> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM durable_receipts WHERE request_id = ?1)",
            params![request_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(database_unavailable)
}

fn validate_object_reads(
    connection: &Connection,
    namespace: &SqliteNamespace,
    reads: &[DurableObjectHeadRead],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        let current = load_object_head(connection, namespace, read.object_id())
            .map_err(SqlitePreCommitFailure::into_commit_rejection)?;
        if &current != read.expected() {
            return Err(DurableCommitRejection::ObjectConflict {
                object_id: read.object_id(),
                current: DurableObjectHeadSummary::from(&current),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PreparedObjectMutation {
    object_id: ObjectId,
    next_head_revision: ObjectHeadRevision,
}

fn prepare_object_mutations(
    connection: &Connection,
    changes: &DurableObjectChanges,
) -> Result<Vec<PreparedObjectMutation>, DurableCommitRejection> {
    let mut prepared = Vec::with_capacity(changes.mutations().len());
    for mutation in changes.mutations() {
        let read_index = changes
            .reads()
            .binary_search_by_key(&mutation.object_id(), DurableObjectHeadRead::object_id)
            .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let expected = changes.reads()[read_index].expected();
        let next_head_revision = match expected.head_revision() {
            Some(revision) => revision
                .checked_next()
                .ok_or(DurableCommitRejection::InvalidPersistedState)?,
            None => ObjectHeadRevision::FIRST,
        };
        if let Some(version) = mutation.mutation().version() {
            let existing: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM durable_object_versions
                     WHERE object_id = ?1 AND object_version = ?2)",
                    params![
                        mutation.object_id().as_bytes().as_slice(),
                        encode_u64(version.object_version().get()).as_slice()
                    ],
                    |row| row.get(0),
                )
                .map_err(|error| database_unavailable(error).into_commit_rejection())?;
            if existing {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
        }
        prepared.push(PreparedObjectMutation {
            object_id: mutation.object_id(),
            next_head_revision,
        });
    }
    Ok(prepared)
}

/// Bounded inline-versus-blob payload columns for one `durable_object_versions`
/// insert, aliased so `clippy::type_complexity` does not flag the inline
/// tuple used only to shuttle these three columns.
type ObjectPayloadColumns<'a> = (Option<&'a [u8]>, Option<i64>, Option<[u8; 32]>);

fn insert_object_version(
    transaction: &Transaction<'_>,
    namespace: &SqliteNamespace,
    version: &DurableObjectVersionRecord,
) -> Result<(), DurableCommitRejection> {
    if version.provenance().chain_id() != namespace.chain_id() {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    let (inline_bytes, blob_algorithm, blob_bytes): ObjectPayloadColumns<'_> =
        match version.payload() {
            DurableObjectPayload::Inline(inline) => (Some(inline.canonical_bytes()), None, None),
            DurableObjectPayload::BlobReference(blob_digest) => (
                None,
                Some(i64::from(blob_digest.algorithm().as_u16())),
                Some(blob_digest.bytes()),
            ),
        };
    let digest = version.digest();
    let inserted = transaction
        .execute(
            "INSERT INTO durable_object_versions (
                 object_id, object_version, digest_algorithm, digest_bytes, schema_version,
                 type_id, created_chain_id, created_protocol_version, created_checkpoint,
                 inline_canonical_bytes, blob_digest_algorithm, blob_digest_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                version.object_id().as_bytes().as_slice(),
                encode_u64(version.object_version().get()).as_slice(),
                i64::from(digest.algorithm().as_u16()),
                digest.bytes().as_slice(),
                i64::from(version.schema_version()),
                i64::from(version.canonical_record_type_id()),
                version.provenance().chain_id().as_str(),
                i64::from(version.provenance().protocol_version().get()),
                encode_u64(version.created_checkpoint()).as_slice(),
                inline_bytes,
                blob_algorithm,
                blob_bytes.as_ref().map(<[u8; 32]>::as_slice),
            ],
        )
        .map_err(|error| database_unavailable(error).into_commit_rejection())?;
    if inserted != 1 {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    Ok(())
}

fn apply_object_mutations(
    transaction: &Transaction<'_>,
    namespace: &SqliteNamespace,
    changes: &DurableObjectChanges,
    prepared: &[PreparedObjectMutation],
) -> Result<(), DurableCommitRejection> {
    if changes.mutations().len() != prepared.len() {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    for (mutation, prepared) in changes.mutations().iter().zip(prepared) {
        if mutation.object_id() != prepared.object_id {
            return Err(DurableCommitRejection::InvalidPersistedState);
        }
        match mutation.mutation() {
            DurableObjectMutation::Create {
                version,
                owner_projection,
                routing_projection,
            }
            | DurableObjectMutation::Update {
                version,
                owner_projection,
                routing_projection,
            } => {
                insert_object_version(transaction, namespace, version)?;
                let digest = version.digest();
                let updated = transaction
                    .execute(
                        "INSERT INTO durable_object_heads (
                             object_id, status, head_revision, object_version,
                             digest_algorithm, digest_bytes, owner_projection, routing_projection
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                         ON CONFLICT(object_id) DO UPDATE SET
                             status = excluded.status,
                             head_revision = excluded.head_revision,
                             object_version = excluded.object_version,
                             digest_algorithm = excluded.digest_algorithm,
                             digest_bytes = excluded.digest_bytes,
                             owner_projection = excluded.owner_projection,
                             routing_projection = excluded.routing_projection",
                        params![
                            mutation.object_id().as_bytes().as_slice(),
                            OBJECT_HEAD_STATUS_CURRENT,
                            encode_u64(prepared.next_head_revision.get()).as_slice(),
                            encode_u64(version.object_version().get()).as_slice(),
                            i64::from(digest.algorithm().as_u16()),
                            digest.bytes().as_slice(),
                            owner_projection.bytes(),
                            routing_projection.bytes(),
                        ],
                    )
                    .map_err(|error| database_unavailable(error).into_commit_rejection())?;
                if updated != 1 {
                    return Err(DurableCommitRejection::InvalidPersistedState);
                }
            }
            DurableObjectMutation::Delete => {
                let updated = transaction
                    .execute(
                        "UPDATE durable_object_heads SET
                             status = ?1, head_revision = ?2, object_version = NULL,
                             digest_algorithm = NULL, digest_bytes = NULL,
                             owner_projection = NULL, routing_projection = NULL
                         WHERE object_id = ?3",
                        params![
                            OBJECT_HEAD_STATUS_TOMBSTONED,
                            encode_u64(prepared.next_head_revision.get()).as_slice(),
                            mutation.object_id().as_bytes().as_slice(),
                        ],
                    )
                    .map_err(|error| database_unavailable(error).into_commit_rejection())?;
                if updated != 1 {
                    return Err(DurableCommitRejection::InvalidPersistedState);
                }
            }
        }
    }
    Ok(())
}

fn insert_structured_invocation(
    transaction: &Transaction<'_>,
    invocation: &DurableInvocationTransaction,
) -> Result<(), DurableCommitRejection> {
    let receipt = invocation.receipt();
    let event_digest = receipt.event_digest();
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO durable_receipts (
                 request_id, event_digest_algorithm, event_digest_bytes, canonical_bytes
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.request_id().as_bytes().as_slice(),
                i64::from(event_digest.algorithm().as_u16()),
                event_digest.bytes().as_slice(),
                receipt.canonical_bytes(),
            ],
        )
        .map_err(|error| database_unavailable(error).into_commit_rejection())?;
    if inserted != 1 {
        return Err(DurableCommitRejection::RequestAlreadyCommitted);
    }

    let Some(outbox) = invocation.outbox() else {
        return Ok(());
    };
    let message_count = i64::try_from(outbox.messages().len())
        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
    for (index, message) in outbox.messages().iter().enumerate() {
        let message_index =
            i64::try_from(index).map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let payload_digest = message.payload_digest();
        transaction
            .execute(
                "INSERT INTO durable_outbox_messages (
                     request_id, message_index, payload_digest_algorithm,
                     payload_digest_bytes, canonical_payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    outbox.request_id().as_bytes().as_slice(),
                    message_index,
                    i64::from(payload_digest.algorithm().as_u16()),
                    payload_digest.bytes().as_slice(),
                    message.canonical_payload(),
                ],
            )
            .map_err(|error| database_unavailable(error).into_commit_rejection())?;
    }
    let completed = i64::from(outbox.messages().is_empty());
    transaction
        .execute(
            "INSERT INTO durable_outbox_delivery (
                 request_id, message_count, next_message_index, completed,
                 available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis,
                 attempt_count
             ) VALUES (?1, ?2, 0, ?3, ?4, NULL, NULL, ?4)",
            params![
                outbox.request_id().as_bytes().as_slice(),
                message_count,
                completed,
                encode_u64(0).as_slice(),
            ],
        )
        .map_err(|error| database_unavailable(error).into_commit_rejection())?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxAttempt {
    request_id: OutboxRequestId,
    message_index: u32,
    lease_expires_at_unix_millis: u64,
    status: OutboxAttemptStatus,
}

/// One raw `durable_outbox_attempts` row, aliased so `clippy::type_complexity`
/// does not flag the inline tuple used only to shuttle query results.
type AttemptRow = (Vec<u8>, i64, Vec<u8>, i64);

fn load_outbox_attempt(
    connection: &Connection,
    lease_id: DurableOutboxLeaseId,
) -> Result<Option<PersistedOutboxAttempt>, SqlitePreCommitFailure> {
    let row: Option<AttemptRow> = connection
        .query_row(
            "SELECT request_id, message_index, lease_expires_at_unix_millis, status
             FROM durable_outbox_attempts WHERE lease_id = ?1",
            params![lease_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((request_id, message_index, lease_expires, status)) = row else {
        return Ok(None);
    };
    let request_id: [u8; 32] = request_id
        .try_into()
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let request_id = OutboxRequestId::new(request_id)
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let message_index =
        u32::try_from(message_index).map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let lease_expires_at_unix_millis =
        decode_u64(&lease_expires).ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    let status = OutboxAttemptStatus::decode(status)?;
    Ok(Some(PersistedOutboxAttempt {
        request_id,
        message_index,
        lease_expires_at_unix_millis,
        status,
    }))
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxDelivery {
    request_id: OutboxRequestId,
    next_message_index: u32,
    message_count: u32,
    completed: bool,
    available_at_unix_millis: u64,
    active_lease_id: Option<DurableOutboxLeaseId>,
    lease_expires_at_unix_millis: Option<u64>,
    attempt_count: u64,
}

fn load_outbox_delivery(
    connection: &Connection,
    request_id: OutboxRequestId,
) -> Result<Option<PersistedOutboxDelivery>, SqlitePreCommitFailure> {
    type DeliveryRow = (
        i64,
        i64,
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
    );
    let row: Option<DeliveryRow> = connection
        .query_row(
            "SELECT next_message_index, message_count, completed, available_at_unix_millis,
                    active_lease_id, lease_expires_at_unix_millis, attempt_count
             FROM durable_outbox_delivery WHERE request_id = ?1",
            params![request_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some((
        next_index,
        message_count,
        completed,
        available_at,
        lease_id,
        lease_expires,
        attempt_count,
    )) = row
    else {
        return Ok(None);
    };
    let next_message_index =
        u32::try_from(next_index).map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let message_count =
        u32::try_from(message_count).map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let available_at_unix_millis =
        decode_u64(&available_at).ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    let active_lease_id = lease_id
        .map(
            |bytes| -> Result<DurableOutboxLeaseId, SqlitePreCommitFailure> {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
                DurableOutboxLeaseId::new(bytes)
                    .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)
            },
        )
        .transpose()?;
    let lease_expires_at_unix_millis = lease_expires
        .map(|bytes| decode_u64(&bytes).ok_or(SqlitePreCommitFailure::InvalidPersistedState))
        .transpose()?;
    if active_lease_id.is_some() != lease_expires_at_unix_millis.is_some() {
        return Err(SqlitePreCommitFailure::InvalidPersistedState);
    }
    let attempt_count =
        decode_u64(&attempt_count).ok_or(SqlitePreCommitFailure::InvalidPersistedState)?;
    Ok(Some(PersistedOutboxDelivery {
        request_id,
        next_message_index,
        message_count,
        completed: decode_bool(completed)?,
        available_at_unix_millis,
        active_lease_id,
        lease_expires_at_unix_millis,
        attempt_count,
    }))
}

fn load_due_outbox_delivery(
    connection: &Connection,
    now_unix_millis: u64,
) -> Result<Option<PersistedOutboxDelivery>, SqlitePreCommitFailure> {
    let request_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT request_id FROM durable_outbox_delivery
             WHERE completed = 0 AND available_at_unix_millis <= ?1
             ORDER BY available_at_unix_millis, request_id
             LIMIT 1",
            params![encode_u64(now_unix_millis).as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_unavailable)?;
    let Some(request_id) = request_id else {
        return Ok(None);
    };
    let request_id: [u8; 32] = request_id
        .try_into()
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    let request_id = OutboxRequestId::new(request_id)
        .map_err(|_| SqlitePreCommitFailure::InvalidPersistedState)?;
    load_outbox_delivery(connection, request_id)
}

fn load_outbox_payload(
    connection: &Connection,
    request_id: OutboxRequestId,
    message_index: u32,
) -> Result<Vec<u8>, SqlitePreCommitFailure> {
    connection
        .query_row(
            "SELECT canonical_payload FROM durable_outbox_messages
             WHERE request_id = ?1 AND message_index = ?2",
            params![request_id.as_bytes().as_slice(), i64::from(message_index)],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_unavailable)?
        .ok_or(SqlitePreCommitFailure::InvalidPersistedState)
}

fn reconcile_outbox_claim(
    connection: &Connection,
    lease_id: DurableOutboxLeaseId,
    attempt: PersistedOutboxAttempt,
    now_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if attempt.status != OutboxAttemptStatus::Claimed
        || attempt.lease_expires_at_unix_millis <= now_unix_millis
    {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    let delivery = load_outbox_delivery(connection, attempt.request_id)
        .map_err(SqlitePreCommitFailure::into_claim_rejection)?
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    if delivery.completed
        || delivery.next_message_index != attempt.message_index
        || delivery.active_lease_id != Some(lease_id)
        || delivery.lease_expires_at_unix_millis != Some(attempt.lease_expires_at_unix_millis)
        || delivery.available_at_unix_millis != attempt.lease_expires_at_unix_millis
    {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    let payload = load_outbox_payload(connection, attempt.request_id, attempt.message_index)
        .map_err(SqlitePreCommitFailure::into_claim_rejection)?;
    DurableOutboxClaim::from_parts(
        attempt.request_id,
        attempt.message_index,
        lease_id,
        attempt.lease_expires_at_unix_millis,
        payload,
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)
}

fn install_outbox_claim(
    transaction: &Transaction<'_>,
    delivery: PersistedOutboxDelivery,
    now_unix_millis: u64,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if delivery.completed || delivery.available_at_unix_millis > now_unix_millis {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    if delivery.next_message_index >= delivery.message_count {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    match (
        delivery.active_lease_id,
        delivery.lease_expires_at_unix_millis,
    ) {
        (Some(expired_lease_id), Some(expired_at)) if expired_at <= now_unix_millis => {
            if delivery.available_at_unix_millis != expired_at {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
            let expired_attempt = load_outbox_attempt(transaction, expired_lease_id)
                .map_err(SqlitePreCommitFailure::into_claim_rejection)?
                .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
            if expired_attempt.request_id != delivery.request_id
                || expired_attempt.message_index != delivery.next_message_index
                || expired_attempt.lease_expires_at_unix_millis != expired_at
                || expired_attempt.status != OutboxAttemptStatus::Claimed
            {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
            let updated = transaction
                .execute(
                    "UPDATE durable_outbox_attempts SET status = ?1 WHERE lease_id = ?2 AND status = ?3",
                    params![
                        OutboxAttemptStatus::Expired.encode(),
                        expired_lease_id.as_bytes().as_slice(),
                        OutboxAttemptStatus::Claimed.encode()
                    ],
                )
                .map_err(|error| database_unavailable(error).into_claim_rejection())?;
            if updated != 1 {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
        }
        (None, None) => {}
        (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
            return Err(DurableOutboxClaimRejection::InvalidPersistedState);
        }
    }

    let attempt_count = delivery
        .attempt_count
        .checked_add(1)
        .ok_or(DurableOutboxClaimRejection::ArithmeticOverflow)?;
    let payload = load_outbox_payload(
        transaction,
        delivery.request_id,
        delivery.next_message_index,
    )
    .map_err(SqlitePreCommitFailure::into_claim_rejection)?;
    let claim = DurableOutboxClaim::from_parts(
        delivery.request_id,
        delivery.next_message_index,
        lease_id,
        lease_expires_at_unix_millis,
        payload,
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)?;
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO durable_outbox_attempts (
                 lease_id, request_id, message_index, lease_expires_at_unix_millis, status
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                lease_id.as_bytes().as_slice(),
                delivery.request_id.as_bytes().as_slice(),
                i64::from(delivery.next_message_index),
                encode_u64(lease_expires_at_unix_millis).as_slice(),
                OutboxAttemptStatus::Claimed.encode(),
            ],
        )
        .map_err(|error| database_unavailable(error).into_claim_rejection())?;
    if inserted != 1 {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    let updated = transaction
        .execute(
            "UPDATE durable_outbox_delivery SET
                 active_lease_id = ?1, lease_expires_at_unix_millis = ?2,
                 available_at_unix_millis = ?2, attempt_count = ?3
             WHERE request_id = ?4",
            params![
                lease_id.as_bytes().as_slice(),
                encode_u64(lease_expires_at_unix_millis).as_slice(),
                encode_u64(attempt_count).as_slice(),
                delivery.request_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|error| database_unavailable(error).into_claim_rejection())?;
    if updated != 1 {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    Ok(claim)
}

/// A failed `COMMIT` after `BEGIN IMMEDIATE` on an embedded local database has
/// no remote-network analog: the process already holds the exclusive writer
/// lock. This is conservatively still treated as indeterminate rather than a
/// definite rejection, since local storage I/O failure at the commit boundary
/// carries the same fsync ambiguity the shared contract documents for a
/// severed remote connection.
fn finalize_commit(transaction: Transaction<'_>) -> DurableCommitOutcome {
    match transaction.commit() {
        Ok(()) => DurableCommitOutcome::Committed,
        Err(_) => DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
    }
}

fn finalize_outbox_claim(
    transaction: Transaction<'_>,
    claim: DurableOutboxClaim,
) -> DurableOutboxClaimOutcome {
    match transaction.commit() {
        Ok(()) => DurableOutboxClaimOutcome::Claimed(claim),
        Err(_) => {
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        }
    }
}

fn finalize_outbox_acknowledgement(
    transaction: Transaction<'_>,
) -> DurableOutboxAcknowledgementOutcome {
    match transaction.commit() {
        Ok(()) => DurableOutboxAcknowledgementOutcome::Acknowledged,
        Err(_) => DurableOutboxAcknowledgementOutcome::Indeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ),
    }
}

impl DurableDomainStateStore for SqliteDurableStore {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL)
            .map_err(DurableReadError::InvalidRequest)?;
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        check_deadline(context).map_err(SqlitePreCommitFailure::into_read_error)?;
        let mut connection = self
            .connection()
            .map_err(|_| DurableReadError::Unavailable)?;
        read_in_snapshot(&mut connection, &self.namespace, context, |transaction| {
            load_state_value(transaction, key)
        })
        .map_err(SqlitePreCommitFailure::into_read_error)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(transaction.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::UnavailableBeforeCommit,
                );
            }
        };
        if let Err(reason) = apply_busy_timeout(&connection, context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        let sqlite_transaction =
            match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
                Ok(transaction) => transaction,
                Err(_) => {
                    return DurableCommitOutcome::Rejected(
                        DurableCommitRejection::UnavailableBeforeCommit,
                    );
                }
            };
        let metadata = match load_metadata(&sqlite_transaction, &self.namespace) {
            Ok(metadata) => metadata,
            Err(reason) => return DurableCommitOutcome::Rejected(reason.into_commit_rejection()),
        };
        if let Err(reason) = validate_authority(&metadata, context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        if let Err(reason) = validate_state_reads(&sqlite_transaction, transaction.reads()) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = apply_state_mutations(
            &sqlite_transaction,
            transaction.reads(),
            transaction.mutations(),
        ) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        finalize_commit(sqlite_transaction)
    }
}

impl StructuredDurableDomainStateStore for SqliteDurableStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        check_deadline(context).map_err(SqlitePreCommitFailure::into_read_error)?;
        let mut connection = self
            .connection()
            .map_err(|_| DurableReadError::Unavailable)?;
        read_in_snapshot(&mut connection, &self.namespace, context, |transaction| {
            load_object_head(transaction, &self.namespace, object_id)
        })
        .map_err(SqlitePreCommitFailure::into_read_error)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        check_deadline(context).map_err(SqlitePreCommitFailure::into_read_error)?;
        let mut connection = self
            .connection()
            .map_err(|_| DurableReadError::Unavailable)?;
        read_in_snapshot(&mut connection, &self.namespace, context, |transaction| {
            load_object_version(transaction, &self.namespace, object_id, object_version)
        })
        .map_err(SqlitePreCommitFailure::into_read_error)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch,
            ));
        }
        check_deadline(context).map_err(SqlitePreCommitFailure::into_read_error)?;
        let mut connection = self
            .connection()
            .map_err(|_| DurableReadError::Unavailable)?;
        read_in_snapshot(&mut connection, &self.namespace, context, |transaction| {
            load_receipt(transaction, request_id)
        })
        .map_err(SqlitePreCommitFailure::into_read_error)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        invocation: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(invocation.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::UnavailableBeforeCommit,
                );
            }
        };
        if let Err(reason) = apply_busy_timeout(&connection, context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::UnavailableBeforeCommit,
                );
            }
        };
        let metadata = match load_metadata(&transaction, &self.namespace) {
            Ok(metadata) => metadata,
            Err(reason) => return DurableCommitOutcome::Rejected(reason.into_commit_rejection()),
        };
        if let Err(reason) = validate_authority(&metadata, context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        let receipt = invocation.receipt();
        match receipt_exists(&transaction, receipt.request_id()) {
            Ok(true) => {
                return DurableCommitOutcome::Rejected(
                    DurableCommitRejection::RequestAlreadyCommitted,
                );
            }
            Ok(false) => {}
            Err(reason) => return DurableCommitOutcome::Rejected(reason.into_commit_rejection()),
        }
        if let Some(state) = invocation.state()
            && let Err(reason) = validate_state_reads(&transaction, state.reads())
        {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = validate_object_reads(
            &transaction,
            &self.namespace,
            invocation.object_changes().reads(),
        ) {
            return DurableCommitOutcome::Rejected(reason);
        }
        let prepared = match prepare_object_mutations(&transaction, invocation.object_changes()) {
            Ok(prepared) => prepared,
            Err(reason) => return DurableCommitOutcome::Rejected(reason),
        };
        if let Some(state) = invocation.state()
            && let Err(reason) =
                apply_state_mutations(&transaction, state.reads(), state.mutations())
        {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = apply_object_mutations(
            &transaction,
            &self.namespace,
            invocation.object_changes(),
            &prepared,
        ) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = insert_structured_invocation(&transaction, &invocation) {
            return DurableCommitOutcome::Rejected(reason);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
        }
        finalize_commit(transaction)
    }
}

impl IndexedOutboxRepository for SqliteDurableStore {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::UnavailableBeforeCommit,
                );
            }
        };
        if let Err(reason) = apply_busy_timeout(&connection, context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::UnavailableBeforeCommit,
                );
            }
        };
        let metadata = match load_metadata(&transaction, &self.namespace) {
            Ok(metadata) => metadata,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        if let Err(reason) = validate_authority(&metadata, context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let existing = match load_outbox_attempt(&transaction, request.lease_id()) {
            Ok(existing) => existing,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        if let Some(attempt) = existing {
            if attempt.request_id != request.request_id() {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::LeaseIdReuse,
                );
            }
            return match reconcile_outbox_claim(
                &transaction,
                request.lease_id(),
                attempt,
                request.now_unix_millis(),
            ) {
                Ok(claim) => DurableOutboxClaimOutcome::Claimed(claim),
                Err(reason) => DurableOutboxClaimOutcome::Rejected(reason),
            };
        }
        let delivery = match load_outbox_delivery(&transaction, request.request_id()) {
            Ok(Some(delivery)) => delivery,
            Ok(None) => return DurableOutboxClaimOutcome::NoDueWork,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        if delivery.completed
            || delivery.available_at_unix_millis > request.now_unix_millis()
            || delivery
                .lease_expires_at_unix_millis
                .is_some_and(|expires_at| expires_at > request.now_unix_millis())
        {
            return DurableOutboxClaimOutcome::NoDueWork;
        }
        let claim = match install_outbox_claim(
            &transaction,
            delivery,
            request.now_unix_millis(),
            request.lease_id(),
            request.lease_expires_at_unix_millis(),
        ) {
            Ok(claim) => claim,
            Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
        };
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        finalize_outbox_claim(transaction, claim)
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::UnavailableBeforeCommit,
                );
            }
        };
        if let Err(reason) = apply_busy_timeout(&connection, context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => {
                return DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::UnavailableBeforeCommit,
                );
            }
        };
        let metadata = match load_metadata(&transaction, &self.namespace) {
            Ok(metadata) => metadata,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        if let Err(reason) = validate_authority(&metadata, context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        let existing = match load_outbox_attempt(&transaction, request.lease_id()) {
            Ok(existing) => existing,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        if let Some(attempt) = existing {
            return match reconcile_outbox_claim(
                &transaction,
                request.lease_id(),
                attempt,
                request.now_unix_millis(),
            ) {
                Ok(claim) => DurableOutboxClaimOutcome::Claimed(claim),
                Err(reason) => DurableOutboxClaimOutcome::Rejected(reason),
            };
        }
        let delivery = match load_due_outbox_delivery(&transaction, request.now_unix_millis()) {
            Ok(Some(delivery)) => delivery,
            Ok(None) => return DurableOutboxClaimOutcome::NoDueWork,
            Err(reason) => {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        };
        let claim = match install_outbox_claim(
            &transaction,
            delivery,
            request.now_unix_millis(),
            request.lease_id(),
            request.lease_expires_at_unix_millis(),
        ) {
            Ok(claim) => claim,
            Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
        };
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
        }
        finalize_outbox_claim(transaction, claim)
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        if !self.domain_is_bound(acknowledgement.domain()) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                reason.into_acknowledgement_rejection(),
            );
        }
        let mut connection = match self.connection() {
            Ok(connection) => connection,
            Err(_) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
                );
            }
        };
        if let Err(reason) = apply_busy_timeout(&connection, context) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                reason.into_acknowledgement_rejection(),
            );
        }
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
                );
            }
        };
        let metadata = match load_metadata(&transaction, &self.namespace) {
            Ok(metadata) => metadata,
            Err(reason) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
        };
        if let Err(reason) = validate_authority(&metadata, context) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                reason.into_acknowledgement_rejection(),
            );
        }
        let attempt = match load_outbox_attempt(&transaction, acknowledgement.lease_id()) {
            Ok(Some(attempt)) => attempt,
            Ok(None) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::LeaseMismatch,
                );
            }
            Err(reason) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
        };
        if attempt.request_id != acknowledgement.request_id()
            || attempt.message_index != acknowledgement.message_index()
        {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        let delivery = match load_outbox_delivery(&transaction, acknowledgement.request_id()) {
            Ok(Some(delivery)) => delivery,
            Ok(None) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::InvalidPersistedState,
                );
            }
            Err(reason) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
        };
        if attempt.status == OutboxAttemptStatus::Acknowledged {
            if attempt.message_index >= delivery.message_count
                || delivery.next_message_index <= attempt.message_index
                || delivery.next_message_index > delivery.message_count
            {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::InvalidPersistedState,
                );
            }
            return DurableOutboxAcknowledgementOutcome::Acknowledged;
        }
        if attempt.status != OutboxAttemptStatus::Claimed {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        if delivery.next_message_index != acknowledgement.message_index() {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::IndexMismatch,
            );
        }
        if delivery.completed
            || delivery.active_lease_id != Some(acknowledgement.lease_id())
            || delivery.lease_expires_at_unix_millis != Some(attempt.lease_expires_at_unix_millis)
            || delivery.available_at_unix_millis != attempt.lease_expires_at_unix_millis
        {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::LeaseMismatch,
            );
        }
        let next_message_index = match delivery.next_message_index.checked_add(1) {
            Some(index) => index,
            None => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::ArithmeticOverflow,
                );
            }
        };
        if next_message_index > delivery.message_count {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        }
        let attempt_updated = match transaction.execute(
            "UPDATE durable_outbox_attempts SET status = ?1 WHERE lease_id = ?2 AND status = ?3",
            params![
                OutboxAttemptStatus::Acknowledged.encode(),
                acknowledgement.lease_id().as_bytes().as_slice(),
                OutboxAttemptStatus::Claimed.encode()
            ],
        ) {
            Ok(updated) => updated,
            Err(error) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    database_unavailable(error).into_acknowledgement_rejection(),
                );
            }
        };
        if attempt_updated != 1 {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        }
        let completed = i64::from(next_message_index == delivery.message_count);
        let delivery_updated = match transaction.execute(
            "UPDATE durable_outbox_delivery SET
                 next_message_index = ?1, completed = ?2, available_at_unix_millis = ?3,
                 active_lease_id = NULL, lease_expires_at_unix_millis = NULL
             WHERE request_id = ?4",
            params![
                i64::from(next_message_index),
                completed,
                encode_u64(0).as_slice(),
                acknowledgement.request_id().as_bytes().as_slice(),
            ],
        ) {
            Ok(updated) => updated,
            Err(error) => {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    database_unavailable(error).into_acknowledgement_rejection(),
                );
            }
        };
        if delivery_updated != 1 {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            );
        }
        if let Err(reason) = check_deadline(context) {
            return DurableOutboxAcknowledgementOutcome::Rejected(
                reason.into_acknowledgement_rejection(),
            );
        }
        finalize_outbox_acknowledgement(transaction)
    }
}
