CREATE SCHEMA sunrise_edge;

CREATE TABLE sunrise_edge.schema_migrations (
    migration_id INTEGER PRIMARY KEY CHECK (migration_id > 0),
    schema_identity BYTEA NOT NULL CHECK (octet_length(schema_identity) = 32),
    schema_generation NUMERIC(20, 0) NOT NULL
        CHECK (schema_generation BETWEEN 1 AND 18446744073709551615),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE sunrise_edge.storage_metadata (
    chain_id_bytes BYTEA NOT NULL
        CHECK (octet_length(chain_id_bytes) BETWEEN 1 AND 128),
    validator_id BYTEA NOT NULL CHECK (octet_length(validator_id) = 32),
    atomicity_domain_id BYTEA NOT NULL
        CHECK (
            octet_length(atomicity_domain_id) = 32
            AND atomicity_domain_id <> decode(repeat('00', 32), 'hex')
        ),
    schema_identity BYTEA NOT NULL CHECK (octet_length(schema_identity) = 32),
    schema_generation NUMERIC(20, 0) NOT NULL
        CHECK (schema_generation BETWEEN 1 AND 18446744073709551615),
    migration_phase_id SMALLINT NOT NULL CHECK (migration_phase_id BETWEEN 1 AND 5),
    compatibility_min_generation NUMERIC(20, 0) NOT NULL
        CHECK (compatibility_min_generation BETWEEN 1 AND 18446744073709551615),
    compatibility_max_generation NUMERIC(20, 0) NOT NULL
        CHECK (compatibility_max_generation BETWEEN 1 AND 18446744073709551615),
    writer_fence_generation NUMERIC(20, 0) NOT NULL
        CHECK (writer_fence_generation BETWEEN 1 AND 18446744073709551615),
    commit_sequence NUMERIC(20, 0) NOT NULL
        CHECK (commit_sequence BETWEEN 0 AND 18446744073709551615),
    last_verified_checkpoint NUMERIC(20, 0) NULL
        CHECK (last_verified_checkpoint BETWEEN 0 AND 18446744073709551615),
    operator_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (pg_column_size(operator_metadata) <= 65536),
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id),
    CHECK (compatibility_min_generation <= schema_generation),
    CHECK (schema_generation <= compatibility_max_generation)
);

CREATE TABLE sunrise_edge.state_records (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    record_kind_id INTEGER NOT NULL CHECK (record_kind_id BETWEEN 0 AND 2147483647),
    state_key BYTEA NOT NULL CHECK (octet_length(state_key) BETWEEN 1 AND 1048576),
    type_id BIGINT NOT NULL CHECK (type_id BETWEEN 0 AND 4294967295),
    encoding_version BIGINT NOT NULL CHECK (encoding_version BETWEEN 0 AND 4294967295),
    revision NUMERIC(20, 0) NOT NULL
        CHECK (revision BETWEEN 1 AND 18446744073709551615),
    canonical_bytes BYTEA NULL CHECK (
        canonical_bytes IS NULL OR octet_length(canonical_bytes) <= 33554432
    ),
    tombstone BOOLEAN NOT NULL,
    PRIMARY KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, record_kind_id, state_key
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (tombstone = (canonical_bytes IS NULL))
);

CREATE TABLE sunrise_edge.object_versions (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id) = 32),
    object_version NUMERIC(20, 0) NOT NULL
        CHECK (object_version BETWEEN 1 AND 18446744073709551615),
    digest_algorithm_id INTEGER NOT NULL CHECK (digest_algorithm_id BETWEEN 0 AND 65535),
    digest_bytes BYTEA NOT NULL CHECK (octet_length(digest_bytes) = 32),
    schema_version BIGINT NOT NULL CHECK (schema_version BETWEEN 0 AND 4294967295),
    type_id BIGINT NOT NULL CHECK (type_id BETWEEN 0 AND 4294967295),
    created_chain_id_bytes BYTEA NOT NULL
        CHECK (octet_length(created_chain_id_bytes) BETWEEN 1 AND 128),
    created_protocol_version BIGINT NOT NULL
        CONSTRAINT object_versions_created_protocol_version_range
        CHECK (created_protocol_version BETWEEN 0 AND 4294967295),
    created_checkpoint NUMERIC(20, 0) NOT NULL
        CHECK (created_checkpoint BETWEEN 0 AND 18446744073709551615),
    inline_canonical_bytes BYTEA NULL CHECK (
        inline_canonical_bytes IS NULL
        OR octet_length(inline_canonical_bytes) BETWEEN 1 AND 33554432
    ),
    blob_digest_algorithm_id INTEGER NULL
        CHECK (blob_digest_algorithm_id BETWEEN 0 AND 65535),
    blob_digest_bytes BYTEA NULL CHECK (
        blob_digest_bytes IS NULL OR octet_length(blob_digest_bytes) = 32
    ),
    PRIMARY KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, object_id, object_version
    ),
    UNIQUE (
        chain_id_bytes, validator_id, atomicity_domain_id, object_id, object_version,
        digest_algorithm_id, digest_bytes
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (inline_canonical_bytes IS NOT NULL)::INTEGER
        + (blob_digest_bytes IS NOT NULL)::INTEGER = 1
    ),
    CHECK ((blob_digest_algorithm_id IS NULL) = (blob_digest_bytes IS NULL)),
    CONSTRAINT object_versions_created_chain_matches_chain
        CHECK (created_chain_id_bytes = chain_id_bytes)
);

CREATE TABLE sunrise_edge.object_heads (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id) = 32),
    current_version NUMERIC(20, 0) NULL
        CHECK (current_version BETWEEN 1 AND 18446744073709551615),
    digest_algorithm_id INTEGER NULL CHECK (digest_algorithm_id BETWEEN 0 AND 65535),
    digest_bytes BYTEA NULL CHECK (digest_bytes IS NULL OR octet_length(digest_bytes) = 32),
    owner_projection BYTEA NULL CHECK (
        owner_projection IS NULL OR octet_length(owner_projection) <= 4096
    ),
    routing_projection BYTEA NULL CHECK (
        routing_projection IS NULL OR octet_length(routing_projection) <= 4096
    ),
    revision NUMERIC(20, 0) NOT NULL
        CHECK (revision BETWEEN 1 AND 18446744073709551615),
    tombstone BOOLEAN NOT NULL,
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id, object_id),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, object_id, current_version,
        digest_algorithm_id, digest_bytes
    ) REFERENCES sunrise_edge.object_versions
        (chain_id_bytes, validator_id, atomicity_domain_id, object_id, object_version,
         digest_algorithm_id, digest_bytes)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((digest_algorithm_id IS NULL) = (digest_bytes IS NULL)),
    CHECK (tombstone = (current_version IS NULL)),
    CHECK (tombstone = (digest_bytes IS NULL))
);

CREATE TABLE sunrise_edge.request_receipts (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    request_id BYTEA NOT NULL CHECK (
        octet_length(request_id) = 32
        AND request_id <> decode(repeat('00', 32), 'hex')
    ),
    event_digest_algorithm_id INTEGER NOT NULL
        CHECK (event_digest_algorithm_id BETWEEN 0 AND 65535),
    event_digest_bytes BYTEA NOT NULL CHECK (octet_length(event_digest_bytes) = 32),
    terminal_result_id BIGINT NOT NULL CHECK (terminal_result_id BETWEEN 0 AND 4294967295),
    canonical_response_bytes BYTEA NOT NULL
        CHECK (octet_length(canonical_response_bytes) BETWEEN 1 AND 33554432),
    commit_sequence NUMERIC(20, 0) NOT NULL
        CHECK (commit_sequence BETWEEN 1 AND 18446744073709551615),
    retention_watermark NUMERIC(20, 0) NULL
        CHECK (retention_watermark BETWEEN 0 AND 18446744073709551615),
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id),
    UNIQUE (
        chain_id_bytes, validator_id, atomicity_domain_id, request_id,
        event_digest_algorithm_id, event_digest_bytes
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE sunrise_edge.outbox_batches (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    request_id BYTEA NOT NULL CHECK (octet_length(request_id) = 32),
    event_digest_algorithm_id INTEGER NOT NULL
        CHECK (event_digest_algorithm_id BETWEEN 0 AND 65535),
    event_digest_bytes BYTEA NOT NULL CHECK (octet_length(event_digest_bytes) = 32),
    message_count INTEGER NOT NULL CHECK (message_count BETWEEN 0 AND 1024),
    creation_commit_sequence NUMERIC(20, 0) NOT NULL
        CHECK (creation_commit_sequence BETWEEN 1 AND 18446744073709551615),
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id),
    FOREIGN KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, request_id,
        event_digest_algorithm_id, event_digest_bytes
    )
        REFERENCES sunrise_edge.request_receipts
        (chain_id_bytes, validator_id, atomicity_domain_id, request_id,
         event_digest_algorithm_id, event_digest_bytes)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE sunrise_edge.outbox_messages (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    message_index INTEGER NOT NULL CHECK (message_index BETWEEN 0 AND 1023),
    payload_digest_algorithm_id INTEGER NOT NULL
        CHECK (payload_digest_algorithm_id BETWEEN 0 AND 65535),
    payload_digest_bytes BYTEA NOT NULL CHECK (octet_length(payload_digest_bytes) = 32),
    canonical_payload BYTEA NOT NULL
        CHECK (octet_length(canonical_payload) BETWEEN 1 AND 33554432),
    PRIMARY KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, request_id, message_index
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        REFERENCES sunrise_edge.outbox_batches
        (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE sunrise_edge.outbox_delivery (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    next_message_index INTEGER NOT NULL CHECK (next_message_index BETWEEN 0 AND 1024),
    state_id SMALLINT NOT NULL CHECK (state_id IN (1, 2, 3)),
    available_at_ms NUMERIC(20, 0) NOT NULL
        CHECK (available_at_ms BETWEEN 0 AND 18446744073709551615),
    active_lease_id BYTEA NULL CHECK (
        active_lease_id IS NULL OR (
            octet_length(active_lease_id) = 32
            AND active_lease_id <> decode(repeat('00', 32), 'hex')
        )
    ),
    lease_expires_at_ms NUMERIC(20, 0) NULL
        CHECK (lease_expires_at_ms BETWEEN 1 AND 18446744073709551615),
    attempt_count NUMERIC(20, 0) NOT NULL
        CHECK (attempt_count BETWEEN 0 AND 18446744073709551615),
    last_error_class_id INTEGER NULL CHECK (last_error_class_id BETWEEN 0 AND 2147483647),
    revision NUMERIC(20, 0) NOT NULL
        CHECK (revision BETWEEN 1 AND 18446744073709551615),
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        REFERENCES sunrise_edge.outbox_batches
        (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK ((active_lease_id IS NULL) = (lease_expires_at_ms IS NULL)),
    CHECK (state_id = 1 OR active_lease_id IS NULL)
);

CREATE UNIQUE INDEX outbox_delivery_active_lease_unique
    ON sunrise_edge.outbox_delivery
    (chain_id_bytes, validator_id, atomicity_domain_id, active_lease_id)
    WHERE active_lease_id IS NOT NULL;

CREATE INDEX outbox_delivery_due
    ON sunrise_edge.outbox_delivery
    (chain_id_bytes, validator_id, atomicity_domain_id, available_at_ms, request_id)
    INCLUDE (next_message_index, active_lease_id, lease_expires_at_ms)
    WHERE state_id = 1;

CREATE TABLE sunrise_edge.outbox_delivery_attempts (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    lease_id BYTEA NOT NULL CHECK (
        octet_length(lease_id) = 32
        AND lease_id <> decode(repeat('00', 32), 'hex')
    ),
    request_id BYTEA NOT NULL,
    message_index INTEGER NOT NULL CHECK (message_index BETWEEN 0 AND 1023),
    lease_expires_at_ms NUMERIC(20, 0) NOT NULL
        CHECK (lease_expires_at_ms BETWEEN 1 AND 18446744073709551615),
    state_id SMALLINT NOT NULL CHECK (state_id IN (1, 2, 3)),
    PRIMARY KEY (chain_id_bytes, validator_id, atomicity_domain_id, lease_id),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        REFERENCES sunrise_edge.outbox_batches
        (chain_id_bytes, validator_id, atomicity_domain_id, request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, request_id, message_index
    ) REFERENCES sunrise_edge.outbox_messages
        (chain_id_bytes, validator_id, atomicity_domain_id, request_id, message_index)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX outbox_delivery_attempt_request
    ON sunrise_edge.outbox_delivery_attempts
    (chain_id_bytes, validator_id, atomicity_domain_id, request_id, message_index);

CREATE TABLE sunrise_edge.checkpoints (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    checkpoint_sequence NUMERIC(20, 0) NOT NULL
        CHECK (checkpoint_sequence BETWEEN 0 AND 18446744073709551615),
    state_root_algorithm_id INTEGER NOT NULL CHECK (state_root_algorithm_id BETWEEN 0 AND 65535),
    state_root_bytes BYTEA NOT NULL CHECK (octet_length(state_root_bytes) = 32),
    covered_commit_sequence NUMERIC(20, 0) NOT NULL
        CHECK (covered_commit_sequence BETWEEN 0 AND 18446744073709551615),
    blob_manifest_digest BYTEA NOT NULL CHECK (octet_length(blob_manifest_digest) = 32),
    schema_generation NUMERIC(20, 0) NOT NULL
        CHECK (schema_generation BETWEEN 1 AND 18446744073709551615),
    verification_state_id SMALLINT NOT NULL CHECK (verification_state_id IN (1, 2, 3)),
    PRIMARY KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, checkpoint_sequence
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE sunrise_edge.migration_jobs (
    chain_id_bytes BYTEA NOT NULL,
    validator_id BYTEA NOT NULL,
    atomicity_domain_id BYTEA NOT NULL,
    migration_job_id BYTEA NOT NULL CHECK (octet_length(migration_job_id) = 32),
    source_generation NUMERIC(20, 0) NOT NULL
        CHECK (source_generation BETWEEN 1 AND 18446744073709551615),
    target_generation NUMERIC(20, 0) NOT NULL
        CHECK (target_generation BETWEEN 1 AND 18446744073709551615),
    range_start BYTEA NOT NULL CHECK (octet_length(range_start) BETWEEN 1 AND 1048576),
    range_end BYTEA NOT NULL CHECK (octet_length(range_end) BETWEEN 1 AND 1048576),
    resume_cursor BYTEA NULL CHECK (
        resume_cursor IS NULL OR octet_length(resume_cursor) <= 1048576
    ),
    checksum_algorithm_id INTEGER NOT NULL CHECK (checksum_algorithm_id BETWEEN 0 AND 65535),
    checksum_bytes BYTEA NOT NULL CHECK (octet_length(checksum_bytes) = 32),
    state_id SMALLINT NOT NULL CHECK (state_id IN (1, 2, 3, 4)),
    PRIMARY KEY (
        chain_id_bytes, validator_id, atomicity_domain_id, migration_job_id
    ),
    FOREIGN KEY (chain_id_bytes, validator_id, atomicity_domain_id)
        REFERENCES sunrise_edge.storage_metadata
        (chain_id_bytes, validator_id, atomicity_domain_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (source_generation < target_generation),
    CHECK (range_start < range_end)
);
