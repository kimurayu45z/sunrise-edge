# PostgreSQL Reference Design

Status: accepted implementation design. The runtime structured envelope,
node-core/native wiring, and explicit generation-one schema migration/bootstrap
exist As-Is. A bounded synchronous pool now implements fenced state/object/
receipt reads and serializable structured state/object/receipt/outbox commit with transaction-
local deadlines, bounded unchanged-envelope serialization retry, and typed
outcomes. Indexed exact-request/due outbox claim and acknowledgement now use
the normalized delivery index and retained lease-attempt history As-Is. An
optional shared commit-loss capability now proves commit-boundary connection
loss immediately before `COMMIT` dispatch for one state commit and,
separately, immediately after backend acceptance for a structured invocation
commit, outbox claim, and acknowledgement, over a plain `NoTls` transport; see
section 5. Migration operations beyond initial bootstrap, cancellation,
TLS-path connection loss, other fault/capacity evidence, and production
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
- canonical, unique, sorted body-free object-head assertions and contained
  create/update/delete mutations, plus separate immutable-version reads;
- one typed request-receipt insertion;
- zero or one typed immutable outbox batch and its ordered messages;
- one initial outbox-delivery row when a batch is present;
- the logical domain plus `DurableOperationContext`.

The implemented runtime envelope rejects cross-domain and receipt/outbox
request/event-digest drift, permits read-only state assertions, requires every
state or object mutation to have a matching read assertion, rejects duplicate
object IDs, validates checked object-version/head-revision transitions, and
bounds every section before I/O. Current head assertions contain only revision,
current version/digest, and canonical owner plus bounded routing projections;
head reads join only strict immutable metadata and inline presence/length, not
the inline bytes. Immutable payloads are read separately. Head owner/routing
projections are atomically written routing data and must not authorize
execution by themselves. An execution caller must separately read the linked
version, verify exact head version/digest, decode an inline Object, and compare
its typed owner. Blob-backed execution fails closed until blob fetch and
content verification are implemented. An object version stores exactly one
existing canonical `objects::Object` encoding or one self-describing blob
digest. The SQL `type_id` is the stable canonical Object record identifier,
not `Object::type_hash`, which remains inside the canonical Object bytes.
Inline owner projections are derived with `objects::encode_owner` at write
construction; blob upload, fetch, and digest/content verification remain
upstream/deferred. Node-core does
not yet dispatch object mutations, but memory and PostgreSQL consume the typed
section directly and never hide object writes in generic state.

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
The current adapter uses one closed application-state record kind and closed
operational opaque-canonical type/version projections. It does not infer a
protocol payload type from arbitrary state bytes or key prefixes. A future
typed state section must expand these projections explicitly.

### `object_versions`

Identity: `(namespace, object_id, object_version)`.

Immutable object body or verified blob reference, digest algorithm/digest,
schema/type version, and creation checkpoint. Exactly one of inline canonical
bytes or content-addressed blob identity is present. A blob reference is
publishable only after durable upload and digest verification.

Head reconstruction selects only this row's bounded metadata, representation
presence/inline length, and blob digest. Full inline bytes are selected and
canonically decoded only by the separate immutable-version read.

### `object_heads`

Identity: `(namespace, object_id)`.

Current object version/digest, ownership/routing projection, ABA-safe revision,
and tombstone state. Head mutation and new immutable version commit together.
The projections support bounded routing but are not an authorization source.

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

Live PostgreSQL conformance holds the only pool connection past a short
operation deadline and separately holds the fenced metadata row past its local
lock timeout. Pool acquisition returns a definite read deadline; row-lock expiry
returns a definite pre-commit deadline and publishes no state. SQLSTATE `57014`
at the commit boundary remains indeterminate for structured commit, claim, and
acknowledgement because PostgreSQL does not prove whether dispatch completed.

An optional shared commit-loss capability (`runtime::conformance::
CommitLossFixture`) now exercises the driver's own commit-boundary connection
loss, not just deadline SQLSTATEs. Its only current implementation is a
bounded, test-only `NoTls` TCP proxy in the live test: it binds port 0, relays
the untyped startup message and every later `1-byte-type + 4-byte-length`
frame, and detects the exact simple-query `COMMIT` a durable commit, claim, or
acknowledgement dispatches last. Severing the connection immediately before
that message reaches the backend, or forwarding it and severing immediately
after the backend returns a successful `CommandComplete("COMMIT")`/
`ReadyForQuery`, both surface to the driver with no SQLSTATE at all, a plain
transport-level I/O error rather than a database error response, and both are
classified by the catch-all arm as `Indeterminate(ConnectionLost)`; the driver
cannot and does not distinguish them by outcome alone. The shared case injects
the pre-dispatch instant once, for one plain state commit, and proves no state
was published, confirmed by an unfaulted retry of the same read assertion
committing successfully. It injects the post-acceptance instant three times:
for one structured invocation commit, proving the exact committed state
revision/value and exact receipt content were published and that replaying
the same invocation observes `RequestAlreadyCommitted`; for an outbox claim on
that invocation's message, first proving with a different, never-used lease
that the original lease is still active (`NoDueWork`) and then that a
same-lease replay reconciles to the identical claimed message; and for the
corresponding acknowledgement, first proving that reclaiming with the
original lease is rejected as lease-ID reuse and then that a same-identity
replay reconciles to `Acknowledged` with the acknowledgement persisted and no
message left due for this one-message batch. The discriminating probes matter
because a same-lease claim replay or same-identity acknowledgement replay
alone would succeed identically whether or not the prior transaction actually
persisted. A final unfaulted commit proves the connection pool recovers a
healthy connection. This is evidence that the backend returned a successful
commit acknowledgement over the plain transport before the driver lost it,
not proof of crash durability under abrupt process/power loss, and it says
nothing about TLS-path connection loss.

## 6. Indexed claim and acknowledgement

Claim first checks the lease-attempt identity. A matching active attempt returns
the same work; an acknowledged/expired or differently bound lease is not reused.
Otherwise it selects one due delivery row by the covering index, locks it with
`SKIP LOCKED`, validates the immutable batch/message, inserts the attempt, and
updates active lease, deadline, availability, and attempt count atomically.

On lease replacement after expiry, the previous attempt becomes `expired` in
the same transaction. Send occurs only after a reconciled claim commit.
Writer-fence advance does not erase or revoke an already committed unexpired
lease. The replacement writer observes no due work until trusted lease expiry,
then atomically expires and replaces the old attempt. The runtime-wide
five-minute maximum lease bounds this failover delivery delay.

Acknowledgement locks the attempt and delivery rows, validates exact
request/index/lease binding, and atomically marks the attempt acknowledged,
advances one message, and clears the active lease. If another message remains,
`available_at_ms` becomes zero (immediately due); otherwise delivery becomes
completed and leaves the partial index. An already acknowledged matching
attempt returns success without changing the cursor.

Claim and acknowledgement use the same fence/deadline/indeterminate rules as
state commit. An indeterminate claim is retried only with the same lease ID and
is never transported unresolved.

The adapter is bound to one logical domain at construction. A claim naming a
different domain is rejected as lease-ID reuse and an acknowledgement naming a
different domain is a definite lease mismatch. These are fail-closed mutation
outcomes because the runtime outbox rejection types do not currently expose a
separate domain-mismatch variant.

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
Request operations, schema inspection, and writer-fence advance all fail closed
unless the namespace row is in the active migration phase.
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

The feature-gated shared runtime suite now covers complete-read write skew,
the exact expired-deadline boundary, absent/tombstone races, concurrent definite
outcome classification, retained lease replacement, and writer-fence handoff
against both memory and PostgreSQL.
Its object extension covers absent/create/update/delete/recreate ABA behavior,
object conflicts with full rollback, bound-domain/fence/deadline/replay
rejection, the object read-count bound, and blob-reference round-trip
against both memory and PostgreSQL. The live fixture additionally asserts
retained immutable history, body-free current and tombstoned heads, lossless
blob-row representation, fail-closed corrupt metadata handling on head reads,
and malformed inline-body handling on full immutable-version reads.
When `SUNRISE_EDGE_TEST_POSTGRES_URL` is configured (as it is in CI), the live
PostgreSQL fixture additionally covers pool/row-lock deadline exhaustion,
commit-boundary deadline ambiguity, bounded retry exhaustion, non-active
migration-phase rejection, and exact schema-generation/window mismatch across
read, commit, claim, and acknowledgement. The same fixture's optional
commit-loss capability covers commit-boundary connection loss immediately
before `COMMIT` dispatch for a plain state commit, and immediately after
backend acceptance for the structured invocation commit, indexed outbox
claim, and acknowledgement boundaries, over a plain `NoTls` transport only;
it says nothing about TLS-path connection loss. Duplicate request races,
abrupt/process faults, disk-full/WAL exhaustion, TLS-path connection loss,
backup/restore, migration compatibility across real old and new binaries,
capacity/load/soak, real writer failover, and operational certification
remain open.
