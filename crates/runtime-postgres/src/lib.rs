#![forbid(unsafe_code)]

//! Explicit PostgreSQL schema lifecycle for the normalized durable runtime.
//!
//! Request handling never calls the migration or namespace-bootstrap APIs in
//! this crate. Operators apply migrations and bind one logical namespace
//! before a durable adapter is admitted. The schema stores state, receipts,
//! outbox data, objects, checkpoints, and migration jobs in separate relations;
//! it never classifies opaque [`runtime::PersistenceLayout`] keys.

use postgres::{
    Client, Config, GenericClient, IsolationLevel, Socket,
    tls::{MakeTlsConnect, TlsConnect},
};
use protocol_types::{AtomicityDomainId, ChainId, Digest32, HashAlgorithmId, ValidatorId};
use r2d2_postgres::{
    PostgresConnectionManager,
    r2d2::{ManageConnection, Pool},
};
use runtime::{
    AtomicStateTransaction, DueOutboxClaimRequest, DurableCommitOutcome, DurableCommitRejection,
    DurableDomainStateStore, DurableInvocationTransaction, DurableOperationContext,
    DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaim, DurableOutboxClaimOutcome,
    DurableOutboxClaimRejection, DurableOutboxLeaseId, DurableReadError, DurableRequestId,
    DurableRequestReceipt, IndeterminateCommitReason, IndexedOutboxRepository, OutboxRequestId,
    RequestOutboxClaimRequest, StateMutation, StateMutationEntry, StateReadAssertion,
    StateRevision, StructuredDurableDomainStateStore, VersionedStateValue, WriterFenceGeneration,
};
use std::{
    error::Error,
    fmt,
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Exact first migration executed only by an explicit operator action.
pub const INITIAL_MIGRATION_SQL: &str = include_str!("../migrations/0001_initial.sql");

/// Stable identity of the normalized PostgreSQL schema generation one.
pub const POSTGRES_SCHEMA_IDENTITY: [u8; 32] = *b"sunrise-edge/postgres/schema/v1\0";

/// First supported schema generation.
pub const POSTGRES_SCHEMA_GENERATION: SchemaGeneration = SchemaGeneration(NonZeroU64::MIN);

const INITIAL_MIGRATION_ID: i32 = 1;
const MIGRATION_PHASE_ACTIVE: i16 = 5;
const MIGRATION_ADVISORY_LOCK_ID: i64 = 0x5352_5047_0000_0001;
// Closed adapter projection IDs. They classify the structured runtime section;
// they are not protocol canonical type IDs inferred from opaque value bytes.
const STATE_RECORD_KIND_APPLICATION: i32 = 1;
const STATE_RECORD_TYPE_OPAQUE_CANONICAL: i64 = 1;
const STATE_RECORD_ENCODING_VERSION: i64 = 1;
const RECEIPT_TERMINAL_RESULT_COMMITTED: i64 = 1;
const OUTBOX_DELIVERY_PENDING: i16 = 1;
const OUTBOX_DELIVERY_COMPLETED: i16 = 2;
const OUTBOX_ATTEMPT_CLAIMED: i16 = 1;
const OUTBOX_ATTEMPT_ACKNOWLEDGED: i16 = 2;
const OUTBOX_ATTEMPT_EXPIRED: i16 = 3;
const MAX_POSTGRES_TIMEOUT_MILLIS: u64 = i32::MAX as u64;
const MAX_SERIALIZATION_ATTEMPTS: u32 = 16;

/// Explicit bounded connection-pool settings for a PostgreSQL durable store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostgresPoolConfig {
    max_connections: NonZeroU32,
    connection_timeout: Duration,
    idle_timeout: Duration,
    max_lifetime: Duration,
}

impl PostgresPoolConfig {
    /// Creates pool settings whose time bounds must all be non-zero.
    pub fn new(
        max_connections: NonZeroU32,
        connection_timeout: Duration,
        idle_timeout: Duration,
        max_lifetime: Duration,
    ) -> Result<Self, PostgresPoolConfigError> {
        if connection_timeout.is_zero() {
            return Err(PostgresPoolConfigError::ZeroDuration("connection timeout"));
        }
        if idle_timeout.is_zero() {
            return Err(PostgresPoolConfigError::ZeroDuration("idle timeout"));
        }
        if max_lifetime.is_zero() {
            return Err(PostgresPoolConfigError::ZeroDuration("maximum lifetime"));
        }
        Ok(Self {
            max_connections,
            connection_timeout,
            idle_timeout,
            max_lifetime,
        })
    }

    /// Returns the hard upper bound on open connections.
    #[must_use]
    pub const fn max_connections(self) -> NonZeroU32 {
        self.max_connections
    }
}

/// Invalid bounded pool configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresPoolConfigError {
    /// A required operational duration was zero.
    ZeroDuration(&'static str),
}

impl fmt::Display for PostgresPoolConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDuration(field) => write!(f, "PostgreSQL pool {field} must be non-zero"),
        }
    }
}

impl Error for PostgresPoolConfigError {}

/// Invalid bounded transaction policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresTransactionPolicyError {
    /// The requested retry bound exceeded the adapter safety ceiling.
    TooManySerializationAttempts {
        /// Requested total attempts.
        requested: u32,
        /// Maximum permitted total attempts.
        maximum: u32,
    },
}

impl fmt::Display for PostgresTransactionPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManySerializationAttempts { requested, maximum } => write!(
                f,
                "PostgreSQL serialization attempts {requested} exceed maximum {maximum}"
            ),
        }
    }
}

impl Error for PostgresTransactionPolicyError {}

/// Bounded retry policy for one unchanged durable transaction envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostgresTransactionPolicy {
    max_serialization_attempts: NonZeroU32,
}

impl PostgresTransactionPolicy {
    /// Creates an explicit total-attempt bound, including the first attempt.
    pub fn new(
        max_serialization_attempts: NonZeroU32,
    ) -> Result<Self, PostgresTransactionPolicyError> {
        if max_serialization_attempts.get() > MAX_SERIALIZATION_ATTEMPTS {
            return Err(
                PostgresTransactionPolicyError::TooManySerializationAttempts {
                    requested: max_serialization_attempts.get(),
                    maximum: MAX_SERIALIZATION_ATTEMPTS,
                },
            );
        }
        Ok(Self {
            max_serialization_attempts,
        })
    }

    /// Returns the total number of serializable attempts permitted.
    #[must_use]
    pub const fn max_serialization_attempts(self) -> NonZeroU32 {
        self.max_serialization_attempts
    }
}

/// Builds a bounded pool without making TLS policy a protocol concern.
///
/// Production composition supplies its own TLS connector. `NoTls` is suitable
/// only for isolated local tests or a separately secured local transport.
pub fn build_postgres_pool<T>(
    mut config: Config,
    tls_connector: T,
    pool_config: PostgresPoolConfig,
) -> Result<Pool<PostgresConnectionManager<T>>, r2d2_postgres::r2d2::Error>
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    config.connect_timeout(pool_config.connection_timeout);
    config.tcp_user_timeout(pool_config.connection_timeout);
    let manager = PostgresConnectionManager::new(config, tls_connector);
    Pool::builder()
        .max_size(pool_config.max_connections.get())
        .min_idle(Some(0))
        .connection_timeout(pool_config.connection_timeout)
        .idle_timeout(Some(pool_config.idle_timeout))
        .max_lifetime(Some(pool_config.max_lifetime))
        .test_on_check_out(false)
        .build(manager)
}

/// Normalized PostgreSQL durable adapter bound to one validator namespace.
///
/// The logical domain in every operation must equal the namespace domain.
/// Connections are acquired only within the caller's absolute storage
/// deadline; request paths never apply migrations or bootstrap metadata.
pub struct PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error>,
{
    pool: Pool<M>,
    namespace: PostgresNamespace,
    transaction_policy: PostgresTransactionPolicy,
}

impl<M> PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error>,
{
    /// Binds an already configured bounded pool to one exact namespace.
    #[must_use]
    pub const fn new(
        pool: Pool<M>,
        namespace: PostgresNamespace,
        transaction_policy: PostgresTransactionPolicy,
    ) -> Self {
        Self {
            pool,
            namespace,
            transaction_policy,
        }
    }

    /// Returns the exact namespace this adapter is authorized to access.
    #[must_use]
    pub const fn namespace(&self) -> &PostgresNamespace {
        &self.namespace
    }
}

/// Non-zero monotonic PostgreSQL schema generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaGeneration(NonZeroU64);

impl SchemaGeneration {
    /// Creates a non-zero schema generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the SQL representation before checked decimal conversion.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Exact logical namespace bound to one validator-local atomicity domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresNamespace {
    chain_id_bytes: Vec<u8>,
    validator_id: ValidatorId,
    domain: AtomicityDomainId,
}

impl PostgresNamespace {
    /// Validates the SQL namespace projection from protocol identities.
    pub fn new(
        chain_id: &ChainId,
        validator_id: ValidatorId,
        domain: AtomicityDomainId,
    ) -> Result<Self, PostgresSchemaError> {
        let chain_id_bytes = chain_id.as_str().as_bytes().to_vec();
        if !(1..=128).contains(&chain_id_bytes.len()) {
            return Err(PostgresSchemaError::InvalidChainIdLength(
                chain_id_bytes.len(),
            ));
        }
        Ok(Self {
            chain_id_bytes,
            validator_id,
            domain,
        })
    }

    /// Returns the exact validated UTF-8 bytes defining chain identity.
    #[must_use]
    pub fn chain_id_bytes(&self) -> &[u8] {
        &self.chain_id_bytes
    }

    /// Returns the validator identity defining local authority.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Returns the logical protocol-configured atomicity domain.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }
}

/// Validated metadata loaded from one exact namespace row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostgresSchemaMetadata {
    schema_generation: SchemaGeneration,
    writer_fence: WriterFenceGeneration,
    commit_sequence: u64,
}

impl PostgresSchemaMetadata {
    /// Returns the active schema generation.
    #[must_use]
    pub const fn schema_generation(self) -> SchemaGeneration {
        self.schema_generation
    }

    /// Returns the active physical writer generation.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }

    /// Returns the last allocated commit sequence.
    #[must_use]
    pub const fn commit_sequence(self) -> u64 {
        self.commit_sequence
    }
}

/// Fail-closed migration, bootstrap, and schema-inspection failures.
#[derive(Debug)]
pub enum PostgresSchemaError {
    /// PostgreSQL rejected the explicit operator operation.
    Database(postgres::Error),
    /// The validated protocol chain identity cannot fit the fixed SQL bound.
    InvalidChainIdLength(usize),
    /// The initial migration marker is absent.
    SchemaNotApplied,
    /// The migration marker or namespace schema identity is unsupported.
    SchemaMismatch,
    /// Existing namespace metadata differs from the requested bootstrap authority.
    NamespaceMetadataMismatch,
    /// The expected writer fence was no longer active when an operator tried to advance it.
    WriterFenceMismatch {
        /// Generation the operator expected to replace.
        expected: WriterFenceGeneration,
        /// Generation locked from authoritative metadata.
        actual: WriterFenceGeneration,
    },
    /// A requested writer generation did not strictly advance the active generation.
    WriterFenceNotAdvanced {
        /// Current generation supplied by the operator.
        current: WriterFenceGeneration,
        /// Requested replacement generation.
        requested: WriterFenceGeneration,
    },
    /// A stored full-range unsigned value was malformed or outside `u64`.
    InvalidUnsignedValue {
        /// Column whose value failed validation.
        field: &'static str,
        /// Exact decimal value returned by PostgreSQL.
        value: String,
    },
    /// A stored writer fence was zero.
    ZeroWriterFence,
}

impl fmt::Display for PostgresSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "PostgreSQL operation failed: {error}"),
            Self::InvalidChainIdLength(length) => {
                write!(
                    f,
                    "chain identity is {length} bytes, expected 1 through 128"
                )
            }
            Self::SchemaNotApplied => f.write_str("PostgreSQL initial schema is not applied"),
            Self::SchemaMismatch => f.write_str("PostgreSQL schema identity is unsupported"),
            Self::NamespaceMetadataMismatch => {
                f.write_str("PostgreSQL namespace already has different authority metadata")
            }
            Self::WriterFenceMismatch { expected, actual } => write!(
                f,
                "PostgreSQL writer fence changed: expected {}, found {}",
                expected.get(),
                actual.get()
            ),
            Self::WriterFenceNotAdvanced { current, requested } => write!(
                f,
                "PostgreSQL writer fence must advance: current {}, requested {}",
                current.get(),
                requested.get()
            ),
            Self::InvalidUnsignedValue { field, value } => {
                write!(f, "PostgreSQL {field} is not a canonical u64: {value}")
            }
            Self::ZeroWriterFence => f.write_str("PostgreSQL writer fence must be non-zero"),
        }
    }
}

impl Error for PostgresSchemaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<postgres::Error> for PostgresSchemaError {
    fn from(value: postgres::Error) -> Self {
        Self::Database(value)
    }
}

/// Applies and verifies the initial normalized schema in one explicit DDL transaction.
///
/// This function is an operator seam. Durable request handling must only verify
/// the already-applied identity and must never invoke it implicitly.
pub fn apply_initial_schema(client: &mut Client) -> Result<(), PostgresSchemaError> {
    let mut transaction = client.transaction()?;
    transaction.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&MIGRATION_ADVISORY_LOCK_ID],
    )?;
    let schema_exists: bool = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'sunrise_edge')",
            &[],
        )?
        .get(0);
    if schema_exists {
        verify_initial_schema(&mut transaction)?;
        transaction.commit()?;
        return Ok(());
    }
    transaction.batch_execute(INITIAL_MIGRATION_SQL)?;
    transaction.execute(
        "INSERT INTO sunrise_edge.schema_migrations
             (migration_id, schema_identity, schema_generation)
         VALUES ($1, $2, CAST(CAST($3 AS TEXT) AS NUMERIC))
         ",
        &[
            &INITIAL_MIGRATION_ID,
            &&POSTGRES_SCHEMA_IDENTITY[..],
            &POSTGRES_SCHEMA_GENERATION.get().to_string(),
        ],
    )?;
    verify_initial_schema(&mut transaction)?;
    transaction.commit()?;
    Ok(())
}

/// Verifies that the exact supported migration marker already exists.
pub fn verify_initial_schema(client: &mut impl GenericClient) -> Result<(), PostgresSchemaError> {
    let migration_table_exists: bool = client
        .query_one(
            "SELECT to_regclass('sunrise_edge.schema_migrations') IS NOT NULL",
            &[],
        )?
        .get(0);
    if !migration_table_exists {
        return Err(PostgresSchemaError::SchemaNotApplied);
    }
    let row = client.query_opt(
        "SELECT schema_identity, schema_generation::TEXT
         FROM sunrise_edge.schema_migrations
         WHERE migration_id = $1",
        &[&INITIAL_MIGRATION_ID],
    )?;
    let Some(row) = row else {
        return Err(PostgresSchemaError::SchemaNotApplied);
    };
    let identity: Vec<u8> = row.get(0);
    let generation_text: String = row.get(1);
    let generation = parse_u64("schema_generation", generation_text)?;
    if identity.as_slice() != POSTGRES_SCHEMA_IDENTITY
        || generation != POSTGRES_SCHEMA_GENERATION.get()
    {
        return Err(PostgresSchemaError::SchemaMismatch);
    }
    Ok(())
}

/// Creates one namespace metadata row or verifies an identical prior bootstrap.
///
/// Bootstrap never advances an existing generation or writer fence. Failover
/// and migration require separate reviewed operator procedures.
pub fn bootstrap_namespace(
    client: &mut Client,
    namespace: &PostgresNamespace,
    schema_generation: SchemaGeneration,
    writer_fence: WriterFenceGeneration,
) -> Result<PostgresSchemaMetadata, PostgresSchemaError> {
    let mut transaction = client.transaction()?;
    verify_initial_schema(&mut transaction)?;
    let schema_generation_text = schema_generation.get().to_string();
    let writer_fence_text = writer_fence.get().to_string();
    transaction.execute(
        "INSERT INTO sunrise_edge.storage_metadata (
             chain_id_bytes,
             validator_id,
             atomicity_domain_id,
             schema_identity,
             schema_generation,
             migration_phase_id,
             compatibility_min_generation,
             compatibility_max_generation,
             writer_fence_generation,
             commit_sequence
         ) VALUES (
             $1, $2, $3, $4,
             CAST(CAST($5 AS TEXT) AS NUMERIC), $6,
             CAST(CAST($5 AS TEXT) AS NUMERIC), CAST(CAST($5 AS TEXT) AS NUMERIC),
             CAST(CAST($7 AS TEXT) AS NUMERIC), 0
         )
         ON CONFLICT (chain_id_bytes, validator_id, atomicity_domain_id) DO NOTHING",
        &[
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
            &&POSTGRES_SCHEMA_IDENTITY[..],
            &schema_generation_text,
            &MIGRATION_PHASE_ACTIVE,
            &writer_fence_text,
        ],
    )?;
    let metadata = inspect_namespace(&mut transaction, namespace)?
        .ok_or(PostgresSchemaError::NamespaceMetadataMismatch)?;
    if metadata.schema_generation() != schema_generation || metadata.writer_fence() != writer_fence
    {
        return Err(PostgresSchemaError::NamespaceMetadataMismatch);
    }
    transaction.commit()?;
    Ok(metadata)
}

/// Atomically advances one namespace's physical writer generation.
///
/// This is an operator-only failover seam. Request handling must never expose
/// it to transport input. The exact metadata row is locked, its schema identity
/// and current generation are revalidated, and only a strictly greater writer
/// generation may replace the expected value.
pub fn advance_writer_fence(
    client: &mut Client,
    namespace: &PostgresNamespace,
    expected: WriterFenceGeneration,
    next: WriterFenceGeneration,
) -> Result<PostgresSchemaMetadata, PostgresSchemaError> {
    if next.get() <= expected.get() {
        return Err(PostgresSchemaError::WriterFenceNotAdvanced {
            current: expected,
            requested: next,
        });
    }
    let mut transaction = client.transaction()?;
    verify_initial_schema(&mut transaction)?;
    let row = transaction.query_opt(
        "SELECT writer_fence_generation::TEXT
         FROM sunrise_edge.storage_metadata
         WHERE chain_id_bytes = $1
           AND validator_id = $2
           AND atomicity_domain_id = $3
         FOR UPDATE",
        &[
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
        ],
    )?;
    let Some(row) = row else {
        return Err(PostgresSchemaError::NamespaceMetadataMismatch);
    };
    inspect_namespace(&mut transaction, namespace)?
        .ok_or(PostgresSchemaError::NamespaceMetadataMismatch)?;
    let actual_value: u64 = parse_u64("writer_fence_generation", row.get(0))?;
    let actual: WriterFenceGeneration =
        WriterFenceGeneration::new(actual_value).ok_or(PostgresSchemaError::ZeroWriterFence)?;
    if actual != expected {
        return Err(PostgresSchemaError::WriterFenceMismatch { expected, actual });
    }
    let updated: u64 = transaction.execute(
        "UPDATE sunrise_edge.storage_metadata
         SET writer_fence_generation = CAST(CAST($1 AS TEXT) AS NUMERIC)
         WHERE chain_id_bytes = $2
           AND validator_id = $3
           AND atomicity_domain_id = $4
           AND writer_fence_generation = CAST(CAST($5 AS TEXT) AS NUMERIC)",
        &[
            &next.get().to_string(),
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
            &expected.get().to_string(),
        ],
    )?;
    if updated != 1 {
        return Err(PostgresSchemaError::NamespaceMetadataMismatch);
    }
    let metadata: PostgresSchemaMetadata = inspect_namespace(&mut transaction, namespace)?
        .ok_or(PostgresSchemaError::NamespaceMetadataMismatch)?;
    transaction.commit()?;
    Ok(metadata)
}

/// Reads and validates one exact namespace metadata row.
pub fn inspect_namespace(
    client: &mut impl GenericClient,
    namespace: &PostgresNamespace,
) -> Result<Option<PostgresSchemaMetadata>, PostgresSchemaError> {
    let row = client.query_opt(
        "SELECT
             schema_identity,
             schema_generation::TEXT,
             compatibility_min_generation::TEXT,
             compatibility_max_generation::TEXT,
             migration_phase_id,
             writer_fence_generation::TEXT,
             commit_sequence::TEXT
         FROM sunrise_edge.storage_metadata
         WHERE chain_id_bytes = $1
           AND validator_id = $2
           AND atomicity_domain_id = $3",
        &[
            &namespace.chain_id_bytes(),
            &&namespace.validator_id().as_bytes()[..],
            &&namespace.domain().as_bytes()[..],
        ],
    )?;
    let Some(row) = row else {
        return Ok(None);
    };
    let identity: Vec<u8> = row.get(0);
    let generation = parse_u64("schema_generation", row.get(1))?;
    let minimum = parse_u64("compatibility_min_generation", row.get(2))?;
    let maximum = parse_u64("compatibility_max_generation", row.get(3))?;
    let migration_phase: i16 = row.get(4);
    if identity.as_slice() != POSTGRES_SCHEMA_IDENTITY
        || generation != POSTGRES_SCHEMA_GENERATION.get()
        || minimum != generation
        || maximum != generation
        || migration_phase != MIGRATION_PHASE_ACTIVE
    {
        return Err(PostgresSchemaError::SchemaMismatch);
    }
    let writer_fence_value = parse_u64("writer_fence_generation", row.get(5))?;
    let writer_fence = WriterFenceGeneration::new(writer_fence_value)
        .ok_or(PostgresSchemaError::ZeroWriterFence)?;
    let commit_sequence = parse_u64("commit_sequence", row.get(6))?;
    Ok(Some(PostgresSchemaMetadata {
        schema_generation: POSTGRES_SCHEMA_GENERATION,
        writer_fence,
        commit_sequence,
    }))
}

fn parse_u64(field: &'static str, value: String) -> Result<u64, PostgresSchemaError> {
    value
        .parse()
        .map_err(|_| PostgresSchemaError::InvalidUnsignedValue { field, value })
}

#[derive(Debug)]
enum PreCommitFailure {
    Deadline,
    WriterFenced(WriterFenceGeneration),
    Serialization,
    InvalidPersistedState,
    SchemaMismatch,
    Unavailable,
}

impl PreCommitFailure {
    fn from_database(error: &postgres::Error) -> Self {
        match error.code().map(postgres::error::SqlState::code) {
            Some("40001" | "40P01") => Self::Serialization,
            Some("55P03" | "57014") => Self::Deadline,
            Some("3F000" | "42P01" | "42703" | "42883") => Self::SchemaMismatch,
            Some(code) if code.starts_with("22") || code.starts_with("23") => {
                Self::InvalidPersistedState
            }
            _ => Self::Unavailable,
        }
    }

    fn into_read_error(self) -> DurableReadError {
        match self {
            Self::Deadline => DurableReadError::DeadlineExceeded,
            Self::WriterFenced(active_generation) => {
                DurableReadError::WriterFenced { active_generation }
            }
            Self::InvalidPersistedState => DurableReadError::InvalidPersistedState,
            Self::SchemaMismatch => DurableReadError::SchemaMismatch,
            Self::Serialization | Self::Unavailable => DurableReadError::Unavailable,
        }
    }

    fn into_commit_rejection(self) -> DurableCommitRejection {
        match self {
            Self::Deadline => DurableCommitRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableCommitRejection::WriterFenced { active_generation }
            }
            Self::Serialization => DurableCommitRejection::SerializationFailure,
            Self::InvalidPersistedState => DurableCommitRejection::InvalidPersistedState,
            Self::SchemaMismatch => DurableCommitRejection::SchemaMismatch,
            Self::Unavailable => DurableCommitRejection::UnavailableBeforeCommit,
        }
    }

    fn into_claim_rejection(self) -> DurableOutboxClaimRejection {
        match self {
            Self::Deadline => DurableOutboxClaimRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxClaimRejection::WriterFenced { active_generation }
            }
            Self::Serialization => DurableOutboxClaimRejection::SerializationFailure,
            Self::InvalidPersistedState => DurableOutboxClaimRejection::InvalidPersistedState,
            Self::SchemaMismatch => DurableOutboxClaimRejection::SchemaMismatch,
            Self::Unavailable => DurableOutboxClaimRejection::UnavailableBeforeCommit,
        }
    }

    fn into_acknowledgement_rejection(self) -> DurableOutboxAcknowledgementRejection {
        match self {
            Self::Deadline => DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit,
            Self::WriterFenced(active_generation) => {
                DurableOutboxAcknowledgementRejection::WriterFenced { active_generation }
            }
            Self::Serialization => DurableOutboxAcknowledgementRejection::SerializationFailure,
            Self::InvalidPersistedState => {
                DurableOutboxAcknowledgementRejection::InvalidPersistedState
            }
            Self::SchemaMismatch => DurableOutboxAcknowledgementRejection::SchemaMismatch,
            Self::Unavailable => DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
        }
    }
}

fn now_unix_millis() -> Result<u64, PreCommitFailure> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreCommitFailure::Unavailable)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| PreCommitFailure::Unavailable)
}

fn remaining_deadline(context: &DurableOperationContext) -> Result<Duration, PreCommitFailure> {
    let now = now_unix_millis()?;
    let remaining = context
        .deadline()
        .unix_millis()
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(PreCommitFailure::Deadline)?;
    Ok(Duration::from_millis(remaining))
}

fn set_local_timeouts(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
) -> Result<(), PreCommitFailure> {
    let remaining = remaining_deadline(context)?;
    let timeout_millis = u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .clamp(1, MAX_POSTGRES_TIMEOUT_MILLIS);
    let timeout = format!("{timeout_millis}ms");
    transaction
        .query_one(
            "SELECT set_config('lock_timeout', $1, true),
                    set_config('statement_timeout', $1, true)",
            &[&timeout],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MetadataLockMode {
    None,
    Share,
    Update,
}

fn load_namespace_metadata(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    lock_mode: MetadataLockMode,
) -> Result<PostgresSchemaMetadata, PreCommitFailure> {
    let suffix: &str = match lock_mode {
        MetadataLockMode::None => "",
        MetadataLockMode::Share => " FOR SHARE",
        MetadataLockMode::Update => " FOR UPDATE",
    };
    let sql = format!(
        "SELECT
             schema_identity,
             schema_generation::TEXT,
             compatibility_min_generation::TEXT,
             compatibility_max_generation::TEXT,
             migration_phase_id,
             writer_fence_generation::TEXT,
             commit_sequence::TEXT
         FROM sunrise_edge.storage_metadata
         WHERE chain_id_bytes = $1
           AND validator_id = $2
           AND atomicity_domain_id = $3{suffix}"
    );
    let row = transaction
        .query_opt(
            &sql,
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?
        .ok_or(PreCommitFailure::SchemaMismatch)?;
    let identity: Vec<u8> = row
        .try_get(0)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let generation = parse_database_u64(&row, 1)?;
    let minimum = parse_database_u64(&row, 2)?;
    let maximum = parse_database_u64(&row, 3)?;
    let migration_phase: i16 = row
        .try_get(4)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if identity.as_slice() != POSTGRES_SCHEMA_IDENTITY
        || generation != POSTGRES_SCHEMA_GENERATION.get()
        || minimum != generation
        || maximum != generation
        || migration_phase != MIGRATION_PHASE_ACTIVE
    {
        return Err(PreCommitFailure::SchemaMismatch);
    }
    let writer_fence = WriterFenceGeneration::new(parse_database_u64(&row, 5)?)
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    Ok(PostgresSchemaMetadata {
        schema_generation: POSTGRES_SCHEMA_GENERATION,
        writer_fence,
        commit_sequence: parse_database_u64(&row, 6)?,
    })
}

fn parse_database_u64(row: &postgres::Row, index: usize) -> Result<u64, PreCommitFailure> {
    let value: String = row
        .try_get(index)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    value
        .parse()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn validate_operation_authority(
    metadata: PostgresSchemaMetadata,
    context: &DurableOperationContext,
) -> Result<(), PreCommitFailure> {
    if metadata.writer_fence() != context.writer_fence() {
        return Err(PreCommitFailure::WriterFenced(metadata.writer_fence()));
    }
    remaining_deadline(context).map(|_| ())
}

fn load_state_value(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    key: &[u8],
) -> Result<VersionedStateValue, PreCommitFailure> {
    let row = transaction
        .query_opt(
            "SELECT revision::TEXT, canonical_bytes, tombstone
             FROM sunrise_edge.state_records
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND record_kind_id = $4
               AND state_key = $5",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &STATE_RECORD_KIND_APPLICATION,
                &key,
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    let Some(row) = row else {
        return VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
            .map_err(|_| PreCommitFailure::InvalidPersistedState);
    };
    let revision = StateRevision::new(parse_database_u64(&row, 0)?);
    if revision == StateRevision::INITIAL {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let value: Option<Vec<u8>> = row
        .try_get(1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let tombstone: bool = row
        .try_get(2)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if tombstone != value.is_none() {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    VersionedStateValue::from_persisted_parts(revision, value)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn load_receipt(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &PostgresNamespace,
    request_id: DurableRequestId,
) -> Result<Option<DurableRequestReceipt>, PreCommitFailure> {
    let row = transaction
        .query_opt(
            "SELECT event_digest_algorithm_id, event_digest_bytes,
                    terminal_result_id, canonical_response_bytes,
                    commit_sequence::TEXT
             FROM sunrise_edge.request_receipts
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&request_id.as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let algorithm_id: i32 = row
        .try_get(0)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let algorithm = u16::try_from(algorithm_id)
        .ok()
        .and_then(|value| HashAlgorithmId::try_from(value).ok())
        .ok_or(PreCommitFailure::InvalidPersistedState)?;
    let digest_bytes: Vec<u8> = row
        .try_get(1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let digest_bytes: [u8; 32] = digest_bytes
        .try_into()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let terminal_result_id: i64 = row
        .try_get(2)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if terminal_result_id != RECEIPT_TERMINAL_RESULT_COMMITTED || parse_database_u64(&row, 4)? == 0
    {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let canonical_bytes: Vec<u8> = row
        .try_get(3)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    DurableRequestReceipt::new(
        request_id,
        Digest32::new(algorithm, digest_bytes),
        canonical_bytes,
    )
    .map(Some)
    .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn validate_state_reads(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    reads: &[StateReadAssertion],
) -> Result<(), DurableCommitRejection> {
    for read in reads {
        set_local_timeouts(transaction, context)
            .map_err(PreCommitFailure::into_commit_rejection)?;
        let current = load_state_value(transaction, namespace, read.key())
            .map_err(PreCommitFailure::into_commit_rejection)?;
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
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    reads: &[StateReadAssertion],
    mutations: &[StateMutationEntry],
) -> Result<(), DurableCommitRejection> {
    for mutation in mutations {
        set_local_timeouts(transaction, context)
            .map_err(PreCommitFailure::into_commit_rejection)?;
        let read = reads
            .binary_search_by(|read| read.key().cmp(mutation.key()))
            .ok()
            .and_then(|index| reads.get(index))
            .ok_or(DurableCommitRejection::InvalidPersistedState)?;
        let next_revision = read
            .expected_revision()
            .checked_next()
            .map_err(|_| DurableCommitRejection::StateRevisionOverflow)?;
        let (canonical_bytes, tombstone): (Option<&[u8]>, bool) = match mutation.mutation() {
            StateMutation::Put(value) => (Some(value), false),
            StateMutation::Delete => (None, true),
            StateMutation::Assert => {
                return Err(DurableCommitRejection::InvalidPersistedState);
            }
        };
        transaction
            .execute(
                "INSERT INTO sunrise_edge.state_records (
                     chain_id_bytes, validator_id, atomicity_domain_id,
                     record_kind_id, state_key, type_id, encoding_version,
                     revision, canonical_bytes, tombstone
                 ) VALUES (
                     $1, $2, $3, $4, $5, $6, $7,
                     CAST(CAST($8 AS TEXT) AS NUMERIC), $9, $10
                 )
                 ON CONFLICT (
                     chain_id_bytes, validator_id, atomicity_domain_id,
                     record_kind_id, state_key
                 ) DO UPDATE SET
                     type_id = EXCLUDED.type_id,
                     encoding_version = EXCLUDED.encoding_version,
                     revision = EXCLUDED.revision,
                     canonical_bytes = EXCLUDED.canonical_bytes,
                     tombstone = EXCLUDED.tombstone",
                &[
                    &namespace.chain_id_bytes(),
                    &&namespace.validator_id().as_bytes()[..],
                    &&namespace.domain().as_bytes()[..],
                    &STATE_RECORD_KIND_APPLICATION,
                    &mutation.key(),
                    &STATE_RECORD_TYPE_OPAQUE_CANONICAL,
                    &STATE_RECORD_ENCODING_VERSION,
                    &next_revision.get().to_string(),
                    &canonical_bytes,
                    &tombstone,
                ],
            )
            .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    }
    Ok(())
}

fn allocate_commit_sequence(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    current: u64,
) -> Result<u64, DurableCommitRejection> {
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    let next = current
        .checked_add(1)
        .ok_or(DurableCommitRejection::CommitSequenceOverflow)?;
    let updated = transaction
        .execute(
            "UPDATE sunrise_edge.storage_metadata
             SET commit_sequence = CAST(CAST($1 AS TEXT) AS NUMERIC)
             WHERE chain_id_bytes = $2
               AND validator_id = $3
               AND atomicity_domain_id = $4",
            &[
                &next.to_string(),
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    if updated != 1 {
        return Err(DurableCommitRejection::SchemaMismatch);
    }
    Ok(next)
}

fn receipt_already_exists(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    request_id: DurableRequestId,
) -> Result<bool, DurableCommitRejection> {
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    transaction
        .query_opt(
            "SELECT 1
             FROM sunrise_edge.request_receipts
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&request_id.as_bytes()[..],
            ],
        )
        .map(|row| row.is_some())
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())
}

fn insert_structured_invocation(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    invocation: &DurableInvocationTransaction,
    commit_sequence: u64,
) -> Result<(), DurableCommitRejection> {
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    let receipt = invocation.receipt();
    let event_digest = receipt.event_digest();
    let inserted = transaction
        .execute(
            "INSERT INTO sunrise_edge.request_receipts (
                 chain_id_bytes, validator_id, atomicity_domain_id, request_id,
                 event_digest_algorithm_id, event_digest_bytes, terminal_result_id,
                 canonical_response_bytes, commit_sequence
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8,
                 CAST(CAST($9 AS TEXT) AS NUMERIC)
             ) ON CONFLICT (
                 chain_id_bytes, validator_id, atomicity_domain_id, request_id
             ) DO NOTHING",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&receipt.request_id().as_bytes()[..],
                &i32::from(event_digest.algorithm().as_u16()),
                &&event_digest.bytes()[..],
                &RECEIPT_TERMINAL_RESULT_COMMITTED,
                &receipt.canonical_bytes(),
                &commit_sequence.to_string(),
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    if inserted != 1 {
        return Err(DurableCommitRejection::RequestAlreadyCommitted);
    }

    let Some(outbox) = invocation.outbox() else {
        return Ok(());
    };
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    let message_count = i32::try_from(outbox.messages().len())
        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
    transaction
        .execute(
            "INSERT INTO sunrise_edge.outbox_batches (
                 chain_id_bytes, validator_id, atomicity_domain_id, request_id,
                 event_digest_algorithm_id, event_digest_bytes, message_count,
                 creation_commit_sequence
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7,
                 CAST(CAST($8 AS TEXT) AS NUMERIC)
             )",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&outbox.request_id().as_bytes()[..],
                &i32::from(outbox.event_digest().algorithm().as_u16()),
                &&outbox.event_digest().bytes()[..],
                &message_count,
                &commit_sequence.to_string(),
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    for (index, message) in outbox.messages().iter().enumerate() {
        set_local_timeouts(transaction, context)
            .map_err(PreCommitFailure::into_commit_rejection)?;
        let message_index =
            i32::try_from(index).map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
        let payload_digest = message.payload_digest();
        transaction
            .execute(
                "INSERT INTO sunrise_edge.outbox_messages (
                     chain_id_bytes, validator_id, atomicity_domain_id, request_id,
                     message_index, payload_digest_algorithm_id,
                     payload_digest_bytes, canonical_payload
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &namespace.chain_id_bytes(),
                    &&namespace.validator_id().as_bytes()[..],
                    &&namespace.domain().as_bytes()[..],
                    &&outbox.request_id().as_bytes()[..],
                    &message_index,
                    &i32::from(payload_digest.algorithm().as_u16()),
                    &&payload_digest.bytes()[..],
                    &message.canonical_payload(),
                ],
            )
            .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    }
    let delivery_state = if outbox.messages().is_empty() {
        OUTBOX_DELIVERY_COMPLETED
    } else {
        OUTBOX_DELIVERY_PENDING
    };
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    transaction
        .execute(
            "INSERT INTO sunrise_edge.outbox_delivery (
                 chain_id_bytes, validator_id, atomicity_domain_id, request_id,
                 next_message_index, state_id, available_at_ms, attempt_count,
                 revision
             ) VALUES ($1, $2, $3, $4, 0, $5, 0, 0, 1)",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&outbox.request_id().as_bytes()[..],
                &delivery_state,
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?;
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_commit_rejection)?;
    let stored_count: i64 = transaction
        .query_one(
            "SELECT COUNT(*)
             FROM sunrise_edge.outbox_messages
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND request_id = $4",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&outbox.request_id().as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_commit_rejection())?
        .try_get(0)
        .map_err(|_| DurableCommitRejection::InvalidPersistedState)?;
    if stored_count != i64::from(message_count) {
        return Err(DurableCommitRejection::InvalidPersistedState);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxAttempt {
    request_id: OutboxRequestId,
    message_index: u32,
    lease_expires_at_unix_millis: u64,
    state_id: i16,
}

#[derive(Clone, Copy, Debug)]
struct PersistedOutboxDelivery {
    request_id: OutboxRequestId,
    next_message_index: u32,
    state_id: i16,
    available_at_unix_millis: u64,
    active_lease_id: Option<DurableOutboxLeaseId>,
    lease_expires_at_unix_millis: Option<u64>,
    attempt_count: u64,
    revision: u64,
    message_count: u32,
}

fn parse_request_id(
    row: &postgres::Row,
    index: usize,
) -> Result<OutboxRequestId, PreCommitFailure> {
    let bytes: Vec<u8> = row
        .try_get(index)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    OutboxRequestId::new(bytes).map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn parse_lease_id(
    row: &postgres::Row,
    index: usize,
) -> Result<Option<DurableOutboxLeaseId>, PreCommitFailure> {
    let bytes: Option<Vec<u8>> = row
        .try_get(index)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    bytes
        .map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
            DurableOutboxLeaseId::new(bytes).map_err(|_| PreCommitFailure::InvalidPersistedState)
        })
        .transpose()
}

fn load_outbox_attempt(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    lease_id: DurableOutboxLeaseId,
) -> Result<Option<PersistedOutboxAttempt>, PreCommitFailure> {
    set_local_timeouts(transaction, context)?;
    let row = transaction
        .query_opt(
            "SELECT request_id, message_index, lease_expires_at_ms::TEXT, state_id
             FROM sunrise_edge.outbox_delivery_attempts
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND lease_id = $4
             FOR UPDATE",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&lease_id.as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let message_index: i32 = row
        .try_get(1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let message_index =
        u32::try_from(message_index).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let state_id: i16 = row
        .try_get(3)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    if !matches!(
        state_id,
        OUTBOX_ATTEMPT_CLAIMED | OUTBOX_ATTEMPT_ACKNOWLEDGED | OUTBOX_ATTEMPT_EXPIRED
    ) {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    Ok(Some(PersistedOutboxAttempt {
        request_id: parse_request_id(&row, 0)?,
        message_index,
        lease_expires_at_unix_millis: parse_database_u64(&row, 2)?,
        state_id,
    }))
}

fn parse_outbox_delivery(row: &postgres::Row) -> Result<PersistedOutboxDelivery, PreCommitFailure> {
    let next_message_index: i32 = row
        .try_get(1)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let next_message_index =
        u32::try_from(next_message_index).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let state_id: i16 = row
        .try_get(2)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let active_lease_id = parse_lease_id(row, 4)?;
    let lease_expires_at_unix_millis: Option<String> = row
        .try_get(5)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let lease_expires_at_unix_millis = lease_expires_at_unix_millis
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| PreCommitFailure::InvalidPersistedState)
        })
        .transpose()?;
    if active_lease_id.is_some() != lease_expires_at_unix_millis.is_some() {
        return Err(PreCommitFailure::InvalidPersistedState);
    }
    let message_count: i32 = row
        .try_get(8)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    let message_count =
        u32::try_from(message_count).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    Ok(PersistedOutboxDelivery {
        request_id: parse_request_id(row, 0)?,
        next_message_index,
        state_id,
        available_at_unix_millis: parse_database_u64(row, 3)?,
        active_lease_id,
        lease_expires_at_unix_millis,
        attempt_count: parse_database_u64(row, 6)?,
        revision: parse_database_u64(row, 7)?,
        message_count,
    })
}

fn load_exact_outbox_delivery(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    request_id: OutboxRequestId,
) -> Result<Option<PersistedOutboxDelivery>, PreCommitFailure> {
    set_local_timeouts(transaction, context)?;
    let row = transaction
        .query_opt(
            "SELECT delivery.request_id, delivery.next_message_index,
                    delivery.state_id, delivery.available_at_ms::TEXT,
                    delivery.active_lease_id, delivery.lease_expires_at_ms::TEXT,
                    delivery.attempt_count::TEXT, delivery.revision::TEXT,
                    batch.message_count
             FROM sunrise_edge.outbox_delivery AS delivery
             JOIN sunrise_edge.outbox_batches AS batch
               USING (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
             WHERE delivery.chain_id_bytes = $1
               AND delivery.validator_id = $2
               AND delivery.atomicity_domain_id = $3
               AND delivery.request_id = $4
             FOR UPDATE OF delivery",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&request_id.as_bytes()[..],
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    row.as_ref().map(parse_outbox_delivery).transpose()
}

fn load_due_outbox_delivery(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    now_unix_millis: u64,
) -> Result<Option<PersistedOutboxDelivery>, PreCommitFailure> {
    set_local_timeouts(transaction, context)?;
    let now = now_unix_millis.to_string();
    let row = transaction
        .query_opt(
            "SELECT delivery.request_id, delivery.next_message_index,
                    delivery.state_id, delivery.available_at_ms::TEXT,
                    delivery.active_lease_id, delivery.lease_expires_at_ms::TEXT,
                    delivery.attempt_count::TEXT, delivery.revision::TEXT,
                    batch.message_count
             FROM sunrise_edge.outbox_delivery AS delivery
             JOIN sunrise_edge.outbox_batches AS batch
               USING (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
             WHERE delivery.chain_id_bytes = $1
               AND delivery.validator_id = $2
               AND delivery.atomicity_domain_id = $3
               AND delivery.state_id = 1
               AND delivery.available_at_ms <= CAST(CAST($4 AS TEXT) AS NUMERIC)
               AND (
                    delivery.active_lease_id IS NULL
                    OR delivery.lease_expires_at_ms <= CAST(CAST($4 AS TEXT) AS NUMERIC)
               )
             ORDER BY delivery.available_at_ms, delivery.request_id
             LIMIT 1
             FOR UPDATE OF delivery SKIP LOCKED",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &now,
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?;
    row.as_ref().map(parse_outbox_delivery).transpose()
}

fn load_outbox_payload(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    request_id: OutboxRequestId,
    message_index: u32,
) -> Result<Vec<u8>, PreCommitFailure> {
    let message_index =
        i32::try_from(message_index).map_err(|_| PreCommitFailure::InvalidPersistedState)?;
    set_local_timeouts(transaction, context)?;
    transaction
        .query_opt(
            "SELECT canonical_payload
             FROM sunrise_edge.outbox_messages
             WHERE chain_id_bytes = $1
               AND validator_id = $2
               AND atomicity_domain_id = $3
               AND request_id = $4
               AND message_index = $5",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&request_id.as_bytes()[..],
                &message_index,
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error))?
        .ok_or(PreCommitFailure::InvalidPersistedState)?
        .try_get(0)
        .map_err(|_| PreCommitFailure::InvalidPersistedState)
}

fn reconcile_outbox_claim(
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    lease_id: DurableOutboxLeaseId,
    attempt: PersistedOutboxAttempt,
    now_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if attempt.state_id != OUTBOX_ATTEMPT_CLAIMED
        || attempt.lease_expires_at_unix_millis <= now_unix_millis
    {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    let delivery = load_exact_outbox_delivery(transaction, context, namespace, attempt.request_id)
        .map_err(PreCommitFailure::into_claim_rejection)?
        .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
    if delivery.state_id != OUTBOX_DELIVERY_PENDING
        || delivery.next_message_index != attempt.message_index
        || delivery.active_lease_id != Some(lease_id)
        || delivery.lease_expires_at_unix_millis != Some(attempt.lease_expires_at_unix_millis)
        || delivery.available_at_unix_millis != attempt.lease_expires_at_unix_millis
    {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    let payload = load_outbox_payload(
        transaction,
        context,
        namespace,
        attempt.request_id,
        attempt.message_index,
    )
    .map_err(PreCommitFailure::into_claim_rejection)?;
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
    transaction: &mut postgres::Transaction<'_>,
    context: &DurableOperationContext,
    namespace: &PostgresNamespace,
    delivery: PersistedOutboxDelivery,
    now_unix_millis: u64,
    lease_id: DurableOutboxLeaseId,
    lease_expires_at_unix_millis: u64,
) -> Result<DurableOutboxClaim, DurableOutboxClaimRejection> {
    if delivery.state_id != OUTBOX_DELIVERY_PENDING
        || delivery.available_at_unix_millis > now_unix_millis
    {
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
            let expired_attempt =
                load_outbox_attempt(transaction, context, namespace, expired_lease_id)
                    .map_err(PreCommitFailure::into_claim_rejection)?
                    .ok_or(DurableOutboxClaimRejection::InvalidPersistedState)?;
            if expired_attempt.request_id != delivery.request_id
                || expired_attempt.message_index != delivery.next_message_index
                || expired_attempt.lease_expires_at_unix_millis != expired_at
                || expired_attempt.state_id != OUTBOX_ATTEMPT_CLAIMED
            {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
            set_local_timeouts(transaction, context)
                .map_err(PreCommitFailure::into_claim_rejection)?;
            let updated = transaction
                .execute(
                    "UPDATE sunrise_edge.outbox_delivery_attempts
                     SET state_id = $1
                     WHERE chain_id_bytes = $2
                       AND validator_id = $3
                       AND atomicity_domain_id = $4
                       AND lease_id = $5
                       AND state_id = $6",
                    &[
                        &OUTBOX_ATTEMPT_EXPIRED,
                        &namespace.chain_id_bytes(),
                        &&namespace.validator_id().as_bytes()[..],
                        &&namespace.domain().as_bytes()[..],
                        &&expired_lease_id.as_bytes()[..],
                        &OUTBOX_ATTEMPT_CLAIMED,
                    ],
                )
                .map_err(|error| PreCommitFailure::from_database(&error).into_claim_rejection())?;
            if updated != 1 {
                return Err(DurableOutboxClaimRejection::InvalidPersistedState);
            }
        }
        (None, None) => {}
        (Some(_), Some(_)) => return Err(DurableOutboxClaimRejection::InvalidPersistedState),
        _ => return Err(DurableOutboxClaimRejection::InvalidPersistedState),
    }

    let attempt_count = delivery
        .attempt_count
        .checked_add(1)
        .ok_or(DurableOutboxClaimRejection::ArithmeticOverflow)?;
    let revision = delivery
        .revision
        .checked_add(1)
        .ok_or(DurableOutboxClaimRejection::ArithmeticOverflow)?;
    let payload = load_outbox_payload(
        transaction,
        context,
        namespace,
        delivery.request_id,
        delivery.next_message_index,
    )
    .map_err(PreCommitFailure::into_claim_rejection)?;
    let claim = DurableOutboxClaim::from_parts(
        delivery.request_id,
        delivery.next_message_index,
        lease_id,
        lease_expires_at_unix_millis,
        payload,
    )
    .map_err(|_| DurableOutboxClaimRejection::InvalidPersistedState)?;
    let message_index = i32::try_from(delivery.next_message_index)
        .map_err(|_| DurableOutboxClaimRejection::ArithmeticOverflow)?;
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_claim_rejection)?;
    let inserted: u64 = transaction
        .execute(
            "INSERT INTO sunrise_edge.outbox_delivery_attempts (
                 chain_id_bytes, validator_id, atomicity_domain_id, lease_id,
                 request_id, message_index, lease_expires_at_ms, state_id
             ) VALUES (
                 $1, $2, $3, $4, $5, $6,
                 CAST(CAST($7 AS TEXT) AS NUMERIC), $8
             ) ON CONFLICT (
                 chain_id_bytes, validator_id, atomicity_domain_id, lease_id
             ) DO NOTHING",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&lease_id.as_bytes()[..],
                &&delivery.request_id.as_bytes()[..],
                &message_index,
                &lease_expires_at_unix_millis.to_string(),
                &OUTBOX_ATTEMPT_CLAIMED,
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_claim_rejection())?;
    if inserted != 1 {
        return Err(DurableOutboxClaimRejection::LeaseIdReuse);
    }
    set_local_timeouts(transaction, context).map_err(PreCommitFailure::into_claim_rejection)?;
    let updated = transaction
        .execute(
            "UPDATE sunrise_edge.outbox_delivery
             SET active_lease_id = $1,
                 lease_expires_at_ms = CAST(CAST($2 AS TEXT) AS NUMERIC),
                 available_at_ms = CAST(CAST($2 AS TEXT) AS NUMERIC),
                 attempt_count = CAST(CAST($3 AS TEXT) AS NUMERIC),
                 revision = CAST(CAST($4 AS TEXT) AS NUMERIC)
             WHERE chain_id_bytes = $5
               AND validator_id = $6
               AND atomicity_domain_id = $7
               AND request_id = $8
               AND revision = CAST(CAST($9 AS TEXT) AS NUMERIC)",
            &[
                &&lease_id.as_bytes()[..],
                &lease_expires_at_unix_millis.to_string(),
                &attempt_count.to_string(),
                &revision.to_string(),
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &&delivery.request_id.as_bytes()[..],
                &delivery.revision.to_string(),
            ],
        )
        .map_err(|error| PreCommitFailure::from_database(&error).into_claim_rejection())?;
    if updated != 1 {
        return Err(DurableOutboxClaimRejection::InvalidPersistedState);
    }
    Ok(claim)
}

fn finalize_outbox_claim(
    transaction: postgres::Transaction<'_>,
    claim: DurableOutboxClaim,
) -> DurableOutboxClaimOutcome {
    match transaction.commit() {
        Ok(()) => DurableOutboxClaimOutcome::Claimed(claim),
        Err(error) => {
            classify_outbox_claim_commit_error(error.code().map(postgres::error::SqlState::code))
        }
    }
}

fn classify_outbox_claim_commit_error(sqlstate: Option<&str>) -> DurableOutboxClaimOutcome {
    match sqlstate {
        Some("40001" | "40P01") => {
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SerializationFailure)
        }
        Some("3F000" | "42P01" | "42703" | "42883") => {
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SchemaMismatch)
        }
        Some(code) if code.starts_with("22") || code.starts_with("23") => {
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::InvalidPersistedState)
        }
        Some("57014") => {
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        }
        _ => DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
    }
}

fn finalize_outbox_acknowledgement(
    transaction: postgres::Transaction<'_>,
) -> DurableOutboxAcknowledgementOutcome {
    match transaction.commit() {
        Ok(()) => DurableOutboxAcknowledgementOutcome::Acknowledged,
        Err(error) => classify_outbox_acknowledgement_commit_error(
            error.code().map(postgres::error::SqlState::code),
        ),
    }
}

fn classify_outbox_acknowledgement_commit_error(
    sqlstate: Option<&str>,
) -> DurableOutboxAcknowledgementOutcome {
    match sqlstate {
        Some("40001" | "40P01") => DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::SerializationFailure,
        ),
        Some("3F000" | "42P01" | "42703" | "42883") => {
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::SchemaMismatch,
            )
        }
        Some(code) if code.starts_with("22") || code.starts_with("23") => {
            DurableOutboxAcknowledgementOutcome::Rejected(
                DurableOutboxAcknowledgementRejection::InvalidPersistedState,
            )
        }
        Some("57014") => DurableOutboxAcknowledgementOutcome::Indeterminate(
            IndeterminateCommitReason::DeadlineExceeded,
        ),
        _ => DurableOutboxAcknowledgementOutcome::Indeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ),
    }
}

fn finalize_commit(transaction: postgres::Transaction<'_>) -> DurableCommitOutcome {
    match transaction.commit() {
        Ok(()) => DurableCommitOutcome::Committed,
        Err(error) => classify_commit_error(error.code().map(postgres::error::SqlState::code)),
    }
}

fn classify_commit_error(sqlstate: Option<&str>) -> DurableCommitOutcome {
    match sqlstate {
        Some("40001" | "40P01") => {
            DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure)
        }
        Some("3F000" | "42P01" | "42703" | "42883") => {
            DurableCommitOutcome::Rejected(DurableCommitRejection::SchemaMismatch)
        }
        Some(code) if code.starts_with("22") || code.starts_with("23") => {
            DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
        }
        Some("57014") => {
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        }
        _ => DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
    }
}

impl<M> PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn acquire(
        &self,
        context: &DurableOperationContext,
    ) -> Result<r2d2_postgres::r2d2::PooledConnection<M>, PreCommitFailure> {
        let remaining = remaining_deadline(context)?;
        self.pool
            .get_timeout(remaining)
            .map_err(|_| match remaining_deadline(context) {
                Err(reason) => reason,
                Ok(_) => PreCommitFailure::Unavailable,
            })
    }

    fn domain_is_bound(&self, domain: AtomicityDomainId) -> bool {
        domain == self.namespace.domain()
    }

    fn retry_serializable(
        &self,
        context: &DurableOperationContext,
        mut attempt: impl FnMut() -> DurableCommitOutcome,
    ) -> DurableCommitOutcome {
        let maximum = self.transaction_policy.max_serialization_attempts().get();
        for attempt_number in 1..=maximum {
            let outcome = attempt();
            if !matches!(
                outcome,
                DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure)
            ) || attempt_number == maximum
            {
                return outcome;
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
        }
        DurableCommitOutcome::Rejected(DurableCommitRejection::SerializationFailure)
    }

    fn retry_outbox_claim(
        &self,
        context: &DurableOperationContext,
        mut attempt: impl FnMut() -> DurableOutboxClaimOutcome,
    ) -> DurableOutboxClaimOutcome {
        let maximum: u32 = self.transaction_policy.max_serialization_attempts().get();
        for attempt_number in 1..=maximum {
            let outcome: DurableOutboxClaimOutcome = attempt();
            if !matches!(
                outcome,
                DurableOutboxClaimOutcome::Rejected(
                    DurableOutboxClaimRejection::SerializationFailure
                )
            ) || attempt_number == maximum
            {
                return outcome;
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
        }
        DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SerializationFailure)
    }

    fn retry_outbox_acknowledgement(
        &self,
        context: &DurableOperationContext,
        mut attempt: impl FnMut() -> DurableOutboxAcknowledgementOutcome,
    ) -> DurableOutboxAcknowledgementOutcome {
        let maximum: u32 = self.transaction_policy.max_serialization_attempts().get();
        for attempt_number in 1..=maximum {
            let outcome: DurableOutboxAcknowledgementOutcome = attempt();
            if !matches!(
                outcome,
                DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::SerializationFailure
                )
            ) || attempt_number == maximum
            {
                return outcome;
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
        }
        DurableOutboxAcknowledgementOutcome::Rejected(
            DurableOutboxAcknowledgementRejection::SerializationFailure,
        )
    }
}

impl<M> DurableDomainStateStore for PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
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
                runtime::RuntimeError::AtomicityDomainMismatch,
            ));
        }
        let mut client = self
            .acquire(context)
            .map_err(PreCommitFailure::into_read_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(true)
            .start()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        set_local_timeouts(&mut transaction, context).map_err(PreCommitFailure::into_read_error)?;
        let metadata =
            load_namespace_metadata(&mut transaction, &self.namespace, MetadataLockMode::None)
                .map_err(PreCommitFailure::into_read_error)?;
        validate_operation_authority(metadata, context)
            .map_err(PreCommitFailure::into_read_error)?;
        let value = load_state_value(&mut transaction, &self.namespace, key)
            .map_err(PreCommitFailure::into_read_error)?;
        transaction
            .rollback()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        remaining_deadline(context).map_err(PreCommitFailure::into_read_error)?;
        Ok(value)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        state: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(state.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        self.retry_serializable(context, || {
            let mut client = match self.acquire(context) {
                Ok(client) => client,
                Err(reason) => {
                    return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
                }
            };
            let mut transaction = match client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DurableCommitOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_commit_rejection(),
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            let metadata = match load_namespace_metadata(
                &mut transaction,
                &self.namespace,
                MetadataLockMode::Update,
            ) {
                Ok(metadata) => metadata,
                Err(reason) => {
                    return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
                }
            };
            if let Err(reason) = validate_operation_authority(metadata, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            if let Err(reason) =
                validate_state_reads(&mut transaction, context, &self.namespace, state.reads())
            {
                return DurableCommitOutcome::Rejected(reason);
            }
            if let Err(reason) = allocate_commit_sequence(
                &mut transaction,
                context,
                &self.namespace,
                metadata.commit_sequence(),
            ) {
                return DurableCommitOutcome::Rejected(reason);
            }
            if let Err(reason) = apply_state_mutations(
                &mut transaction,
                context,
                &self.namespace,
                state.reads(),
                state.mutations(),
            ) {
                return DurableCommitOutcome::Rejected(reason);
            }
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            if let Err(error) = transaction.batch_execute("SET CONSTRAINTS ALL IMMEDIATE") {
                return DurableCommitOutcome::Rejected(
                    PreCommitFailure::from_database(&error).into_commit_rejection(),
                );
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            finalize_commit(transaction)
        })
    }
}

impl<M> StructuredDurableDomainStateStore for PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        if !self.domain_is_bound(domain) {
            return Err(DurableReadError::InvalidRequest(
                runtime::RuntimeError::AtomicityDomainMismatch,
            ));
        }
        let mut client = self
            .acquire(context)
            .map_err(PreCommitFailure::into_read_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(true)
            .start()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        set_local_timeouts(&mut transaction, context).map_err(PreCommitFailure::into_read_error)?;
        let metadata =
            load_namespace_metadata(&mut transaction, &self.namespace, MetadataLockMode::None)
                .map_err(PreCommitFailure::into_read_error)?;
        validate_operation_authority(metadata, context)
            .map_err(PreCommitFailure::into_read_error)?;
        let receipt = load_receipt(&mut transaction, &self.namespace, request_id)
            .map_err(PreCommitFailure::into_read_error)?;
        transaction
            .rollback()
            .map_err(|error| PreCommitFailure::from_database(&error).into_read_error())?;
        remaining_deadline(context).map_err(PreCommitFailure::into_read_error)?;
        Ok(receipt)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        invocation: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        if !self.domain_is_bound(invocation.domain()) {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::AtomicityDomainMismatch);
        }
        if !invocation.objects().is_empty() {
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        self.retry_serializable(context, || {
            let mut client = match self.acquire(context) {
                Ok(client) => client,
                Err(reason) => {
                    return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
                }
            };
            let mut transaction = match client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DurableCommitOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_commit_rejection(),
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            let metadata = match load_namespace_metadata(
                &mut transaction,
                &self.namespace,
                MetadataLockMode::Update,
            ) {
                Ok(metadata) => metadata,
                Err(reason) => {
                    return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
                }
            };
            if let Err(reason) = validate_operation_authority(metadata, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            let receipt = invocation.receipt();
            match receipt_already_exists(
                &mut transaction,
                context,
                &self.namespace,
                receipt.request_id(),
            ) {
                Ok(true) => {
                    return DurableCommitOutcome::Rejected(
                        DurableCommitRejection::RequestAlreadyCommitted,
                    );
                }
                Ok(false) => {}
                Err(reason) => return DurableCommitOutcome::Rejected(reason),
            }
            if let Some(state) = invocation.state()
                && let Err(reason) =
                    validate_state_reads(&mut transaction, context, &self.namespace, state.reads())
            {
                return DurableCommitOutcome::Rejected(reason);
            }
            let commit_sequence = match allocate_commit_sequence(
                &mut transaction,
                context,
                &self.namespace,
                metadata.commit_sequence(),
            ) {
                Ok(sequence) => sequence,
                Err(reason) => return DurableCommitOutcome::Rejected(reason),
            };
            if let Some(state) = invocation.state()
                && let Err(reason) = apply_state_mutations(
                    &mut transaction,
                    context,
                    &self.namespace,
                    state.reads(),
                    state.mutations(),
                )
            {
                return DurableCommitOutcome::Rejected(reason);
            }
            if let Err(reason) = insert_structured_invocation(
                &mut transaction,
                context,
                &self.namespace,
                &invocation,
                commit_sequence,
            ) {
                return DurableCommitOutcome::Rejected(reason);
            }
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            if let Err(error) = transaction.batch_execute("SET CONSTRAINTS ALL IMMEDIATE") {
                return DurableCommitOutcome::Rejected(
                    PreCommitFailure::from_database(&error).into_commit_rejection(),
                );
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableCommitOutcome::Rejected(reason.into_commit_rejection());
            }
            finalize_commit(transaction)
        })
    }
}

impl<M> IndexedOutboxRepository for PostgresDurableStore<M>
where
    M: ManageConnection<Connection = Client, Error = postgres::Error> + 'static,
{
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        self.retry_outbox_claim(context, || {
            let mut client = match self.acquire(context) {
                Ok(client) => client,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            let mut transaction = match client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DurableOutboxClaimOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_claim_rejection(),
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            let metadata = match load_namespace_metadata(
                &mut transaction,
                &self.namespace,
                MetadataLockMode::Share,
            ) {
                Ok(metadata) => metadata,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            if let Err(reason) = validate_operation_authority(metadata, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            let existing = match load_outbox_attempt(
                &mut transaction,
                context,
                &self.namespace,
                request.lease_id(),
            ) {
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
                    &mut transaction,
                    context,
                    &self.namespace,
                    request.lease_id(),
                    attempt,
                    request.now_unix_millis(),
                ) {
                    Ok(claim) => DurableOutboxClaimOutcome::Claimed(claim),
                    Err(reason) => DurableOutboxClaimOutcome::Rejected(reason),
                };
            }
            let delivery = match load_exact_outbox_delivery(
                &mut transaction,
                context,
                &self.namespace,
                request.request_id(),
            ) {
                Ok(Some(delivery)) => delivery,
                Ok(None) => return DurableOutboxClaimOutcome::NoDueWork,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            if delivery.state_id != OUTBOX_DELIVERY_PENDING
                || delivery.available_at_unix_millis > request.now_unix_millis()
                || delivery
                    .lease_expires_at_unix_millis
                    .is_some_and(|expires_at| expires_at > request.now_unix_millis())
            {
                return DurableOutboxClaimOutcome::NoDueWork;
            }
            let claim = match install_outbox_claim(
                &mut transaction,
                context,
                &self.namespace,
                delivery,
                request.now_unix_millis(),
                request.lease_id(),
                request.lease_expires_at_unix_millis(),
            ) {
                Ok(claim) => claim,
                Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            if let Err(error) = transaction.batch_execute("SET CONSTRAINTS ALL IMMEDIATE") {
                return DurableOutboxClaimOutcome::Rejected(
                    PreCommitFailure::from_database(&error).into_claim_rejection(),
                );
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            finalize_outbox_claim(transaction, claim)
        })
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        if !self.domain_is_bound(request.domain()) {
            return DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::LeaseIdReuse);
        }
        self.retry_outbox_claim(context, || {
            let mut client = match self.acquire(context) {
                Ok(client) => client,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            let mut transaction = match client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DurableOutboxClaimOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_claim_rejection(),
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            let metadata = match load_namespace_metadata(
                &mut transaction,
                &self.namespace,
                MetadataLockMode::Share,
            ) {
                Ok(metadata) => metadata,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            if let Err(reason) = validate_operation_authority(metadata, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            let existing = match load_outbox_attempt(
                &mut transaction,
                context,
                &self.namespace,
                request.lease_id(),
            ) {
                Ok(existing) => existing,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            if let Some(attempt) = existing {
                return match reconcile_outbox_claim(
                    &mut transaction,
                    context,
                    &self.namespace,
                    request.lease_id(),
                    attempt,
                    request.now_unix_millis(),
                ) {
                    Ok(claim) => DurableOutboxClaimOutcome::Claimed(claim),
                    Err(reason) => DurableOutboxClaimOutcome::Rejected(reason),
                };
            }
            let delivery = match load_due_outbox_delivery(
                &mut transaction,
                context,
                &self.namespace,
                request.now_unix_millis(),
            ) {
                Ok(Some(delivery)) => delivery,
                Ok(None) => return DurableOutboxClaimOutcome::NoDueWork,
                Err(reason) => {
                    return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
                }
            };
            let claim = match install_outbox_claim(
                &mut transaction,
                context,
                &self.namespace,
                delivery,
                request.now_unix_millis(),
                request.lease_id(),
                request.lease_expires_at_unix_millis(),
            ) {
                Ok(claim) => claim,
                Err(reason) => return DurableOutboxClaimOutcome::Rejected(reason),
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            if let Err(error) = transaction.batch_execute("SET CONSTRAINTS ALL IMMEDIATE") {
                return DurableOutboxClaimOutcome::Rejected(
                    PreCommitFailure::from_database(&error).into_claim_rejection(),
                );
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableOutboxClaimOutcome::Rejected(reason.into_claim_rejection());
            }
            finalize_outbox_claim(transaction, claim)
        })
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
        self.retry_outbox_acknowledgement(context, || {
            let mut client = match self.acquire(context) {
                Ok(client) => client,
                Err(reason) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        reason.into_acknowledgement_rejection(),
                    );
                }
            };
            let mut transaction = match client
                .build_transaction()
                .isolation_level(IsolationLevel::Serializable)
                .start()
            {
                Ok(transaction) => transaction,
                Err(error) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_acknowledgement_rejection(),
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            let metadata = match load_namespace_metadata(
                &mut transaction,
                &self.namespace,
                MetadataLockMode::Share,
            ) {
                Ok(metadata) => metadata,
                Err(reason) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        reason.into_acknowledgement_rejection(),
                    );
                }
            };
            if let Err(reason) = validate_operation_authority(metadata, context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            let attempt = match load_outbox_attempt(
                &mut transaction,
                context,
                &self.namespace,
                acknowledgement.lease_id(),
            ) {
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
            let delivery = match load_exact_outbox_delivery(
                &mut transaction,
                context,
                &self.namespace,
                acknowledgement.request_id(),
            ) {
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
            if attempt.state_id == OUTBOX_ATTEMPT_ACKNOWLEDGED {
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
            if attempt.state_id != OUTBOX_ATTEMPT_CLAIMED {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::LeaseMismatch,
                );
            }
            if delivery.next_message_index != acknowledgement.message_index() {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::IndexMismatch,
                );
            }
            if delivery.state_id != OUTBOX_DELIVERY_PENDING
                || delivery.active_lease_id != Some(acknowledgement.lease_id())
                || delivery.lease_expires_at_unix_millis
                    != Some(attempt.lease_expires_at_unix_millis)
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
            let revision = match delivery.revision.checked_add(1) {
                Some(revision) => revision,
                None => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        DurableOutboxAcknowledgementRejection::ArithmeticOverflow,
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            let attempt_updated = match transaction.execute(
                "UPDATE sunrise_edge.outbox_delivery_attempts
                 SET state_id = $1
                 WHERE chain_id_bytes = $2
                   AND validator_id = $3
                   AND atomicity_domain_id = $4
                   AND lease_id = $5
                   AND state_id = $6",
                &[
                    &OUTBOX_ATTEMPT_ACKNOWLEDGED,
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                    &&acknowledgement.lease_id().as_bytes()[..],
                    &OUTBOX_ATTEMPT_CLAIMED,
                ],
            ) {
                Ok(updated) => updated,
                Err(error) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_acknowledgement_rejection(),
                    );
                }
            };
            if attempt_updated != 1 {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::InvalidPersistedState,
                );
            }
            let state_id: i16 = if next_message_index == delivery.message_count {
                OUTBOX_DELIVERY_COMPLETED
            } else {
                OUTBOX_DELIVERY_PENDING
            };
            let next_message_index_i32 = match i32::try_from(next_message_index) {
                Ok(index) => index,
                Err(_) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        DurableOutboxAcknowledgementRejection::ArithmeticOverflow,
                    );
                }
            };
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            let delivery_updated = match transaction.execute(
                "UPDATE sunrise_edge.outbox_delivery
                 SET next_message_index = $1,
                     state_id = $2,
                     available_at_ms = 0,
                     active_lease_id = NULL,
                     lease_expires_at_ms = NULL,
                     revision = CAST(CAST($3 AS TEXT) AS NUMERIC)
                 WHERE chain_id_bytes = $4
                   AND validator_id = $5
                   AND atomicity_domain_id = $6
                   AND request_id = $7
                   AND revision = CAST(CAST($8 AS TEXT) AS NUMERIC)",
                &[
                    &next_message_index_i32,
                    &state_id,
                    &revision.to_string(),
                    &self.namespace.chain_id_bytes(),
                    &&self.namespace.validator_id().as_bytes()[..],
                    &&self.namespace.domain().as_bytes()[..],
                    &&acknowledgement.request_id().as_bytes()[..],
                    &delivery.revision.to_string(),
                ],
            ) {
                Ok(updated) => updated,
                Err(error) => {
                    return DurableOutboxAcknowledgementOutcome::Rejected(
                        PreCommitFailure::from_database(&error).into_acknowledgement_rejection(),
                    );
                }
            };
            if delivery_updated != 1 {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    DurableOutboxAcknowledgementRejection::InvalidPersistedState,
                );
            }
            if let Err(reason) = set_local_timeouts(&mut transaction, context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            if let Err(error) = transaction.batch_execute("SET CONSTRAINTS ALL IMMEDIATE") {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    PreCommitFailure::from_database(&error).into_acknowledgement_rejection(),
                );
            }
            if let Err(reason) = remaining_deadline(context) {
                return DurableOutboxAcknowledgementOutcome::Rejected(
                    reason.into_acknowledgement_rejection(),
                );
            }
            finalize_outbox_acknowledgement(transaction)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_identity_is_exact_and_generation_is_non_zero() {
        assert_eq!(POSTGRES_SCHEMA_IDENTITY.len(), 32);
        assert_eq!(POSTGRES_SCHEMA_GENERATION.get(), 1);
        assert!(INITIAL_MIGRATION_SQL.contains("CREATE TABLE sunrise_edge.state_records"));
        assert!(INITIAL_MIGRATION_SQL.contains("CREATE INDEX outbox_delivery_due"));
    }

    #[test]
    fn namespace_rejects_chain_identity_over_sql_bound() {
        let chain_id = ChainId::new("x".repeat(129)).unwrap();
        let domain = AtomicityDomainId::new([0x22; 32]).unwrap();
        assert!(matches!(
            PostgresNamespace::new(&chain_id, ValidatorId::new([0x11; 32]), domain),
            Err(PostgresSchemaError::InvalidChainIdLength(129))
        ));
    }

    #[test]
    fn transaction_policy_rejects_unbounded_serialization_retries() {
        assert!(PostgresTransactionPolicy::new(NonZeroU32::new(16).unwrap()).is_ok());
        assert!(matches!(
            PostgresTransactionPolicy::new(NonZeroU32::new(17).unwrap()),
            Err(
                PostgresTransactionPolicyError::TooManySerializationAttempts {
                    requested: 17,
                    maximum: 16,
                }
            )
        ));
    }

    #[test]
    fn commit_boundary_errors_preserve_deadline_ambiguity() {
        assert_eq!(
            classify_commit_error(Some("57014")),
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        );
        assert_eq!(
            classify_outbox_claim_commit_error(Some("57014")),
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::DeadlineExceeded)
        );
        assert_eq!(
            classify_outbox_acknowledgement_commit_error(Some("57014")),
            DurableOutboxAcknowledgementOutcome::Indeterminate(
                IndeterminateCommitReason::DeadlineExceeded
            )
        );
        assert_eq!(
            classify_outbox_claim_commit_error(None),
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        );
        assert_eq!(
            classify_outbox_claim_commit_error(Some("XX999")),
            DurableOutboxClaimOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        );
        assert_eq!(
            classify_outbox_acknowledgement_commit_error(None),
            DurableOutboxAcknowledgementOutcome::Indeterminate(
                IndeterminateCommitReason::ConnectionLost
            )
        );
        assert_eq!(
            classify_outbox_claim_commit_error(Some("40001")),
            DurableOutboxClaimOutcome::Rejected(DurableOutboxClaimRejection::SerializationFailure)
        );
        assert_eq!(
            classify_commit_error(None),
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        );
    }
}
