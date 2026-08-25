#![forbid(unsafe_code)]

//! Explicit PostgreSQL schema lifecycle for the normalized durable runtime.
//!
//! Request handling never calls the migration or namespace-bootstrap APIs in
//! this crate. Operators apply migrations and bind one logical namespace
//! before a durable adapter is admitted. The schema stores state, receipts,
//! outbox data, objects, checkpoints, and migration jobs in separate relations;
//! it never classifies opaque [`runtime::PersistenceLayout`] keys.

use postgres::{Client, GenericClient};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::WriterFenceGeneration;
use std::{error::Error, fmt, num::NonZeroU64};

/// Exact first migration executed only by an explicit operator action.
pub const INITIAL_MIGRATION_SQL: &str = include_str!("../migrations/0001_initial.sql");

/// Stable identity of the normalized PostgreSQL schema generation one.
pub const POSTGRES_SCHEMA_IDENTITY: [u8; 32] = *b"sunrise-edge/postgres/schema/v1\0";

/// First supported schema generation.
pub const POSTGRES_SCHEMA_GENERATION: SchemaGeneration = SchemaGeneration(NonZeroU64::MIN);

const INITIAL_MIGRATION_ID: i32 = 1;
const MIGRATION_PHASE_ACTIVE: i16 = 5;
const MIGRATION_ADVISORY_LOCK_ID: i64 = 0x5352_5047_0000_0001;

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
    if identity.as_slice() != POSTGRES_SCHEMA_IDENTITY
        || generation != POSTGRES_SCHEMA_GENERATION.get()
        || minimum != generation
        || maximum != generation
    {
        return Err(PostgresSchemaError::SchemaMismatch);
    }
    let writer_fence_value = parse_u64("writer_fence_generation", row.get(4))?;
    let writer_fence = WriterFenceGeneration::new(writer_fence_value)
        .ok_or(PostgresSchemaError::ZeroWriterFence)?;
    let commit_sequence = parse_u64("commit_sequence", row.get(5))?;
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
}
