# PostgreSQL Reference Design

Status: accepted implementation design. The runtime structured envelope exists
As-Is; node-core wiring, schema migration, Rust adapter, and production
certification are not implemented.

This document refines [`PERSISTENCE.md`](PERSISTENCE.md) for the first
production-oriented PostgreSQL backend. It deliberately does not map the
current opaque SQLite table or `PersistenceLayout` key prefixes into SQL.

## 1. Adapter boundary prerequisite

The existing `AtomicStateTransaction` is not sufficient input for a normalized
adapter. It carries only binary state keys and values. A PostgreSQL driver must
not inspect text-like key prefixes to guess that a value is a request receipt,
outbox batch, delivery cursor, object head, or consensus record.

Runtime now has a structured durable transaction envelope with explicit bounded
sections:

- exact state-record read assertions and mutations;
- object-version creation and object-head assertions/mutations;
- one typed request-receipt insertion;
- zero or one typed immutable outbox batch and its ordered messages;
- one initial outbox-delivery row when a batch is present;
- the logical domain plus `DurableOperationContext`.

The implemented runtime envelope rejects cross-domain and receipt/outbox
request/event-digest drift, permits read-only state assertions, and bounds
aggregate bytes. Node-core has not migrated to construct it, and the concrete
object section intentionally supports only explicit empty. Before the adapter,
the envelope must additionally reject duplicate logical identities across
future object sections, require
every mutable head/state record to have a read assertion, and account for all
represented bytes before storage I/O. Receipt and outbox identities must match
the invocation request and event digest. The PostgreSQL adapter consumes those
sections directly. It never parses a `PersistenceLayout` path as correctness
input.

The first implementation leaves object-specific sections explicitly empty while the
node event dispatcher is incomplete, but their absence must be explicit. It
must not encode objects into a generic state row and call the schema normalized.

## 2. Namespace and exact SQL representations

Every authoritative row is scoped by:

`(chain_id_bytes, validator_id, atomicity_domain_id)`.

- `chain_id_bytes`: `BYTEA`, 1 through 128 UTF-8 bytes, copied exactly from the
  validated node configuration. SQL collation never defines chain identity.
- `validator_id`: `BYTEA`, exactly 32 bytes.
- `atomicity_domain_id`: `BYTEA`, exactly 32 non-zero bytes.
- protocol and operational digests: algorithm ID plus exactly 32 digest bytes.
- protocol type IDs: integer columns with explicit non-negative bounds; no SQL
  enum whose ordering can drift from stable protocol IDs.
- canonical payloads and keys: `BYTEA`; no correctness query parses UTF-8 paths.

Rust uses unsigned 64-bit revisions, epochs, sequences, deadlines, and writer
generations. PostgreSQL `BIGINT` is signed and cannot represent the complete
range. These fields use `NUMERIC(20,0)` plus `0 <= value <=
18446744073709551615`. The adapter performs checked `u64` conversion on every
read. Narrowing to signed range or wrapping is forbidden. Smaller bounded IDs
use `INTEGER`/`SMALLINT` only where the Rust type and check constraint agree.

Operational wall-clock values are Unix milliseconds in `NUMERIC(20,0)`. A
human-readable `TIMESTAMPTZ` may be generated for observability, but it is not
the authoritative lease or ordering value.

## 3. Schema identity and writer fencing

`storage_metadata` has exactly one row per namespace:

- fixed 32-byte schema identity;
- non-zero schema generation;
- migration phase and supported compatibility window;
- non-zero monotonic writer-fence generation;
- monotonic commit sequence;
- last verified checkpoint and operator metadata.

Every write transaction first locks this exact row and compares schema identity,
generation, and writer fence with trusted composition. A missing, duplicate,
unsupported, or stale row is a definite pre-commit rejection. Reads validate
the same values before returning authoritative data. Failover advances the
generation at the replacement authority only after the old writer is fenced;
rollback never restores an earlier generation.

The request path never creates or migrates this row. Bootstrap and migration
are explicit operator commands.

## 4. Normalized relations

All primary and foreign keys begin with the three namespace columns.

### `state_records`

Identity: `(namespace, record_kind_id, state_key)`.

Stores small canonical protocol/configuration records with `type_id`,
`encoding_version`, ABA-safe `revision`, canonical bytes, and tombstone state.
Rows are point-read only during transitions. A tombstone retains its revision;
delete/recreate never resets to zero. Absent means no row and revision zero.

### `object_versions`

Identity: `(namespace, object_id, object_version)`.

Immutable object body or verified blob reference, digest algorithm/digest,
schema/type version, and creation checkpoint. Exactly one of inline canonical
bytes or content-addressed blob identity is present. A blob reference is
publishable only after durable upload and digest verification.

### `object_heads`

Identity: `(namespace, object_id)`.

Current object version/digest, ownership/routing projection, ABA-safe revision,
and tombstone state. Head mutation and new immutable version commit together.

### `request_receipts`

Identity: `(namespace, request_id)` where request ID is exactly 32 non-zero
bytes.

Stores input event digest, terminal result ID, canonical response bytes,
commit sequence, and retention watermark. Reusing a request ID with a different
event digest is a deterministic conflict; an identical retry reads this row and
does not rerun the transition.

### `outbox_batches` and `outbox_messages`

Batch identity: `(namespace, request_id)`. Message identity:
`(namespace, request_id, message_index)`.

The batch stores event digest, bounded message count, and creation commit
sequence. Each message stores the exact canonical outbound event plus its
self-describing digest. Message indexes are contiguous from zero. Batch,
messages, receipt, initial delivery row, state records, and object changes are
one database transaction.

### `outbox_delivery`

Identity: `(namespace, request_id)`.

Stores next message index, closed state ID (`pending`, `completed`, or
operator-quarantined`), authoritative `available_at_ms`, active lease ID and
deadline as an all-or-none pair, checked attempt count, last bounded error class,
and an operational revision. Completed/quarantined rows are excluded from due
work.

The production due index is partial and covering in this order:

`(namespace, available_at_ms, request_id)` for `state_id = pending`.

Claim uses `FOR UPDATE SKIP LOCKED` only on this queue relation. Protocol state,
object, receipt, and batch reads never use `SKIP LOCKED`.

### `outbox_delivery_attempts`

Identity: `(namespace, lease_id)` with lease ID exactly 32 non-zero bytes.

Stores the immutable request/message binding, lease deadline, and closed status
(`claimed`, `acknowledged`, or `expired`). Repeating a claim with the same lease
returns the same still-owned message. Binding the lease to different work fails
closed. Repeating acknowledgement for an acknowledged tuple succeeds even if
later messages have advanced. Keeping only `last_acknowledged_lease` is not
sufficient for a delayed retry.

Attempt rows remain until the owning outbox batch is eligible for verified
retention deletion. A partial unique constraint prevents one active lease from
appearing on multiple delivery rows.

### `checkpoints` and `migration_jobs`

Checkpoints bind state-root commitment, covered commit sequence, blob manifest,
schema generation, and verification status. Migration jobs store an explicit
source/target generation, bounded key range, resumable cursor, checksum, and
terminal status. Neither is advanced implicitly by request traffic.

## 5. State transaction algorithm

One serializable transaction performs these steps in order:

1. apply transaction-local lock/statement timeout from the remaining absolute
   storage deadline;
2. lock and validate the exact `storage_metadata` row and writer fence;
3. point-read every declared state/head assertion in canonical key order;
4. compare every observed revision, including absence and tombstones;
5. allocate checked next revisions and one checked commit sequence;
6. insert immutable versions/messages and mutate heads/state/receipt/delivery;
7. validate deferred foreign keys and exact message count;
8. commit and classify the result.

A proven revision mismatch is `Conflict`. PostgreSQL serialization/deadlock
abort is `SerializationFailure` after the adapter's bounded retry budget. A
schema/fence/deadline rejection before commit dispatch is definite. Connection
loss, cancellation, or deadline after commit dispatch is `Indeterminate`
unless PostgreSQL supplies authoritative abort evidence. The driver never maps
an unknown commit result to success or definite failure.

The pure node transition is not rerun inside the driver. Any serialization
retry reuses the same structured envelope and read assertions. Once its deadline
or retry budget ends, policy returns to composition.

## 6. Indexed claim and acknowledgement

Claim first checks the lease-attempt identity. A matching active attempt returns
the same work; an acknowledged/expired or differently bound lease is not reused.
Otherwise it selects one due delivery row by the covering index, locks it with
`SKIP LOCKED`, validates the immutable batch/message, inserts the attempt, and
updates active lease, deadline, availability, and attempt count atomically.

On lease replacement after expiry, the previous attempt becomes `expired` in
the same transaction. Send occurs only after a reconciled claim commit.

Acknowledgement locks the attempt and delivery rows, validates exact
request/index/lease binding, and atomically marks the attempt acknowledged,
advances one message, and clears the active lease. If another message remains,
`available_at_ms` becomes zero (immediately due); otherwise delivery becomes
completed and leaves the partial index. An already acknowledged matching
attempt returns success without changing the cursor.

Claim and acknowledgement use the same fence/deadline/indeterminate rules as
state commit. An indeterminate claim is retried only with the same lease ID and
is never transported unresolved.

## 7. Pool, sessions, and reads

- The pool has explicit maximum connections, acquisition deadline, idle/max
  lifetime, and per-domain admission budget derived from measured capacity.
- Each transaction sets local timeouts from remaining budget; no session-global
  mutable setting leaks through pooled connections.
- Authoritative transition reads use the writer transaction. Read replicas are
  not accepted for revision assertions, deduplication, claim, acknowledgement,
  fencing, or readiness.
- Prepared statement and type decoding failures fail closed as schema mismatch
  or invalid persisted state, not an empty/default value.
- SQLSTATE classification is closed and tested. Unknown database errors remain
  unavailable/indeterminate according to commit phase; they do not become
  conflicts.

## 8. Migration and rollback policy

Schema changes use explicit expand, bounded backfill, verify, activate, and
later contract phases. Binaries declare the exact schema identity/generation
window they support. Request traffic never runs DDL or silently copies SQLite
rows. Legacy SQLite data remains a separate compatibility source and requires
an explicit, checksummed import tool if migration is later approved.

Activation advances schema generation and writer fence after verification.
Rollback means forward repair or safe disable; it never decrements generation,
reuses a fence, drops newly authoritative data, or rewrites protocol bytes.

## 9. Evidence before certification

The adapter is not production-certified until automated evidence covers:

- complete-read write skew and absent/tombstone races;
- duplicate request races and conflicting request-ID reuse;
- serialization/deadlock retry exhaustion and unknown SQLSTATE handling;
- stale writer, failover, and schema-generation fencing;
- claim/ack connection loss at every commit boundary;
- delayed acknowledgement after later messages advance;
- pool exhaustion, statement timeout, disk full, abrupt process/power loss;
- checkpoint/backup/restore with blob-manifest verification;
- migration skew across old/new binaries;
- measured connection, transaction-size, contention, recovery, load, and soak
  budgets;
- TLS, credential rotation, telemetry redaction, SLOs, alerts, and runbooks.

Passing unit tests, applying the first migration, or implementing Rust traits is
As-Is progress only, not a production-readiness claim.
