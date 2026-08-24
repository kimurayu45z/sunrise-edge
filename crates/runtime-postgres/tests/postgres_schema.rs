use postgres::{Client, NoTls, error::SqlState};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::WriterFenceGeneration;
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresNamespace, PostgresSchemaError, apply_initial_schema,
    bootstrap_namespace, inspect_namespace, verify_initial_schema,
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
}
