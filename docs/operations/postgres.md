# PostgreSQL Reference Design

Status: accepted implementation design. The runtime structured envelope,
node-core/native wiring, and explicit generation-one schema migration/bootstrap
exist As-Is. Generation-one schema identity was redefined in place to `v2`
([DR-0068](../architecture/decisions/0058-0075-postgres-conformance.md)) to add `object_versions` provenance columns (`created_chain_id_bytes`,
`created_protocol_version`); this was an authorized pre-production in-place
redefinition, applied by bootstrap only, not a migration precedent — no
migration/backfill/verify/activate operation was added, and an existing `v1`
database fails closed with `SchemaMismatch` rather than being silently
accepted. A bounded synchronous pool now implements fenced state/object/
receipt reads and serializable structured state/object/receipt/outbox commit with transaction-
local deadlines, bounded unchanged-envelope serialization retry, and typed
outcomes. Indexed exact-request/due outbox claim and acknowledgement now use
the normalized delivery index and retained lease-attempt history As-Is. An
optional shared commit-loss capability now proves commit-boundary connection
loss immediately before `COMMIT` dispatch for one state commit and,
separately, immediately after backend acceptance for a structured invocation
commit, outbox claim, and acknowledgement, over a plain `NoTls` transport and,
separately, a strictly authenticated client-to-test-terminator TLS leg
([DR-0074](../architecture/decisions/0058-0075-postgres-conformance.md)); see section 5. A separate live test now also SIGKILLs the
database-process container immediately after a committed structured
invocation and verifies recovery after restart
([DR-0069](../architecture/decisions/0058-0075-postgres-conformance.md));
see section 5.
Migration operations beyond initial
bootstrap, cancellation, PostgreSQL-server/provider TLS, mTLS, PKI lifecycle,
and production certification beyond the bounded [DR-0074](../architecture/decisions/0058-0075-postgres-conformance.md) client leg, abrupt
host/power loss, and other fault/capacity evidence are not implemented. A
separate disposable-container test now proves bounded pre-commit
data-tablespace ENOSPC and recovery after freeing
space ([DR-0070](../architecture/decisions/0058-0075-postgres-conformance.md)); it deliberately leaves WAL and commit-boundary exhaustion
open. A separate two-container test now rehearses a bounded `pg_dump`-based
database-snapshot restore, verifying schema identity and restored namespace
metadata/state/receipt before fence promotion, an operator-only writer-fence
advance on the restored namespace, stale pre-backup context fencing, and exact
reconciliation plus fresh commit under a new context, alongside an atomic
invalid-dump rollback and a valid missing-state gate rejection
([DR-0073](../architecture/decisions/0058-0075-postgres-conformance.md));
see section 5. This is rehearsal evidence for one `pg_dump`/SQL-execute
snapshot cycle only — it is not a production backup/restore capability and
does not close the accepted backup/restore evidence criterion in section 9.
A separate two-container test now rehearses a bounded local PgBouncer
1.25.2 transaction-pooling proxy on an isolated Docker network, proving
configured transaction mode and exact single-backend reuse across two
simultaneously open client connections through PgBouncer's own admin
console, the real adapter pool routed through the proxy getting a definite
pre-commit `Rejected(UnavailableBeforeCommit)` once PgBouncer's own
`query_wait_timeout` elapses while its one backend is held by a direct
proxied client, and exact recovery/replay/claim/ack after release
([DR-0075](../architecture/decisions/0058-0075-postgres-conformance.md));
see section 5.
This is a bounded local rehearsal
only — it is not provider-managed pooler service certification, load/soak
capacity, PgBouncer high availability, or TLS evidence.

This document refines [the production persistence requirements](persistence.md) for the first
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
its typed owner. Node-core now fetches a blob-backed body from an explicit
`BlobStore` component and independently verifies it before decode/
authorization
([DR-0094](../architecture/decisions/0094-0098-blobs-audit-and-documentation.md)),
and publishes a new version an
accepted authenticated Create/Update mutation commits to that same `BlobStore` and
references it rather than storing it inline only when its canonical bytes
exceed a fixed deterministic 64 KiB threshold
(`node_core::MAX_INLINE_OBJECT_BODY_BYTES`,
[DR-0096](../architecture/decisions/0094-0098-blobs-audit-and-documentation.md)); a body
at or under the threshold, including every ordinary small object body,
stays inline exactly as before. This `object_versions` write path (inline
bytes or a `blob_digest` column pair) already accepts either representation
unconditionally, unchanged by [DR-0096](../architecture/decisions/0094-0098-blobs-audit-and-documentation.md); PostgreSQL itself still has no durable
`BlobStore` implementation, so a PostgreSQL-composed node needs some other
`BlobStore` (currently `runtime::MemoryBlobStore` or the local
`runtime-sqlite::SqliteBlobStore`) to publish into. The former is process-local;
the latter persists in a separate local SQLite file, not atomically with this
adapter and not as a production PostgreSQL-integrated composition. An object version stores
exactly one existing canonical `objects::Object` encoding or one
self-describing blob digest. The SQL `type_id` is the stable canonical Object
record identifier, not `Object::type_hash`, which remains inside the
canonical Object bytes. Inline owner projections are derived with
`objects::encode_owner` at write construction; a durable PostgreSQL-backed
`BlobStore` remains upstream/deferred. Node-core now loads
authenticated read-only and owned mutating/consuming manifest entries from
exact heads and immutable inline (or fetched blob-backed) versions, authorizes
the typed owner, and commits their complete head assertions and object
mutations; memory and PostgreSQL consume the typed section directly and never
hide object writes in generic state.

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
schema/type version, creating chain/protocol-version provenance, and creation
checkpoint. Exactly one of inline canonical bytes or content-addressed blob
identity is present. A blob reference is publishable only after durable
upload and digest verification.

`created_chain_id_bytes` (`BYTEA`, 1-128 octets) and `created_protocol_version`
(`BIGINT`, `0..=4294967295`) are the object version's creating
`chain_id`/`protocol_version` (`DurableObjectProvenance`, [DR-0068](../architecture/decisions/0058-0075-postgres-conformance.md)), required
on every row since generation one was redefined in place rather than
migrated — there are no legacy rows without them. They are the exact frame
inputs `node-core` needs to independently recompute the object digest with
`hashing::verify_digest`, using the algorithm self-describingly recorded in
`digest_algorithm_id`/`digest_bytes`, without trusting this adapter's own
integrity or the reader's current epoch hash suite. A table-level
`CHECK (created_chain_id_bytes = chain_id_bytes)` enforces that objects never
migrate chains; `created_protocol_version` has no equivalent equality check,
since a version legitimately created under an older protocol version must
still verify. Neither column is a lookup key or index.

Head reconstruction selects only this row's bounded metadata, representation
presence/inline length, and blob digest — it does not select provenance.
Full inline bytes and provenance are selected and canonically decoded only by
the separate immutable-version read.

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
loss, not just deadline SQLSTATEs. Its two current implementations are both
in the live test: a bounded, test-only `NoTls` TCP proxy, and a separate
bounded, test-only proxy that terminates a strictly authenticated
client-to-test-terminator TLS leg ([DR-0074](../architecture/decisions/0058-0075-postgres-conformance.md)) and relays plaintext to the
dedicated test database. Both bind port 0, relay the untyped startup message
and every later `1-byte-type + 4-byte-length` frame, and detect the exact
simple-query `COMMIT` a durable commit, claim, or acknowledgement dispatches
last. Severing the connection immediately before
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
commit acknowledgement over the plain or bounded client/driver-to-terminator
TLS transport before the driver lost it, not proof of crash durability under
abrupt process/power loss. The TLS proxy terminates TLS and relays plaintext
to PostgreSQL, so it says nothing about PostgreSQL-server/provider TLS,
mTLS, PKI lifecycle, or production certification beyond that one client leg.

A separate live test, serialized against the other live tests because it
kills the whole database-service container, commits one structured invocation
containing state, an exact receipt, and one outbox message and observes
`Committed` with the committing pool still alive; with no intervening SQL, it
validates the exact configured container ID and then invokes
`docker kill --signal=KILL` on it as argv with no shell. Only after the kill
does it drop the old pool/clients. It then `docker start`s the same
container, boundedly waits for readiness, and reconnects with a fresh
pool/client to verify the exact committed state revision/value, the exact
receipt, an identical `RequestAlreadyCommitted` replay, one exact claim and
acknowledgement followed by `NoDueWork` for that request, and a final
unfaulted commit. It also captures `pg_postmaster_start_time()` as an exact
integer microsecond count (via `EXTRACT`'s `numeric` return type, never a
float) immediately before the commit and again after restart through the
fresh connection, and asserts it strictly advanced — this fails the test if
the configured container ID is a valid but unrelated container, since
killing and restarting the wrong container leaves the real database
process, and its postmaster start time, untouched. This proves PostgreSQL
database-process SIGKILL and WAL recovery on a live host with a live page
cache; it does not prove abrupt host/power loss,
storage write-cache flush/torn-write/media/filesystem faults, disk-full/WAL
exhaustion, TLS-path behavior, backup/restore, capacity/load/soak, writer
failover, provider certification, or production readiness. This test is
required in CI (`SUNRISE_EDGE_TEST_POSTGRES_CRASH_REQUIRED`) and locally skips
only when both the live URL and the CI-provided container ID
(`SUNRISE_EDGE_TEST_POSTGRES_CONTAINER_ID`) are absent; partial configuration
fails rather than skipping.

A second separate live test starts and owns a digest-pinned disposable
PostgreSQL 18 container. PGDATA/WAL use an unfilled 512 MiB tmpfs while the
database default tablespace uses a distinct 64 MiB tmpfs. Before injecting the
fault, the test correlates its SQL connection with the Docker target through an
identity marker, verifies the tablespace path and capacity, and verifies that
the tablespace and PGDATA/WAL have different device IDs. It fills only the
tablespace, requires a direct incompressible relation write to return SQLSTATE
`53100`, and requires the adapter's structured invocation to return the
definite pre-commit `Rejected(UnavailableBeforeCommit)`. After removing the
filler it uses the same pool/store to prove absent state/receipt and unchanged
commit sequence, then commits and replays the identical invocation and
completes its exact outbox claim/acknowledgement. The container lifecycle uses
direct argv, bounded child time/output, strict digest/configuration parsing,
and panic-safe exact-container removal. CI makes the scenario required with
`SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_REQUIRED=1`; leaving both that flag and
`SUNRISE_EDGE_TEST_POSTGRES_DISK_FULL_IMAGE` unset skips it locally. This is
RAM-backed VFS data-tablespace ENOSPC evidence before `COMMIT`, not WAL or
commit-boundary ENOSPC, a real storage-media/filesystem fault, or certification.

Another separate live test starts and owns two digest-pinned disposable
PostgreSQL 18 containers — a source and a fully isolated target, each its own
container process with its own generated password and published host port,
never two databases inside one server. It commits one structured invocation
(state, receipt, one pending outbox message) on the source, captures a
snapshot with `pg_dump -d <db> --no-owner --no-privileges --inserts` inside
the source container, strips PostgreSQL 18 `pg_dump`'s bracketing
`\restrict`/`\unrestrict` lines (a `psql`-only safety meta-command pair, not
SQL), and applies the resulting self-contained `INSERT`-only script directly
into a fresh, empty database on the target with the same PostgreSQL driver
library. Before advancing the copied namespace fence it verifies exact schema
identity and reads the exact restored namespace metadata, state, and receipt
back through the normal adapter read path. It then advances the restored
namespace's writer fence through the operator-only `advance_writer_fence`
seam, proves a stale context still carrying the pre-backup fence is rejected
as the definite `Rejected(WriterFenced { .. })` against the restored target
with no publication, and proves a fresh context carrying the new fence
reconciles the exact restored receipt/state, observes `RequestAlreadyCommitted`
for the identical invocation, claims and acknowledges the
exact restored pending outbox payload, and commits genuinely new work. A
deterministic negative pair uses two additional databases on the same target:
a dump cut inside the required `storage_metadata` table definition must fail
its one simple-query batch atomically and leave no schema marker, while a
syntactically valid dump with only the fixture's `state_records` insert removed
must restore schema, namespace metadata, and receipt but fail the deeper
rehearsal verification gate on missing state. CI makes the scenario required with
`SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_REQUIRED=1`; leaving both that
flag and `SUNRISE_EDGE_TEST_POSTGRES_BACKUP_RESTORE_IMAGE` unset skips it
locally. This is a bounded database-snapshot restore rehearsal for one
`pg_dump`/SQL-execute cycle only, explicitly not a production
backup/restore capability: it does not prove point-in-time recovery,
continuous WAL archiving/shipping, a hot/consistent backup taken under
concurrent write load, `pg_basebackup`/replication-based backup, backup
encryption or off-host storage, retention/rotation policy, restore
automation, checkpoint publication (the schema has no implemented
checkpoint-publication path; `sunrise_edge.checkpoints` is not written or
read by anything in this crate), blob-manifest verification, state-root
verification, encryption-key verification, or certification.

A further separate live test starts a digest-pinned disposable PostgreSQL
18.6 container and a digest-pinned `ghcr.io/icoretech/pgbouncer-docker`
1.25.2 proxy container on one isolated, freshly generated Docker bridge
network; PgBouncer resolves PostgreSQL only by its network alias, never a
host-published address. The proxy's `pgbouncer.ini`/`userlist.txt` are
written in over stdin via `docker exec ... dd of=<path> status=none` (direct
argv, no shell, no host bind mount, and no echo of the written
credential/config into captured output — unlike `tee`, BusyBox `dd` with
`status=none` writes only to the target file and produces no stdout at all),
configuring `pool_mode = transaction`, exactly one backend
connection (`pool_size`/`default_pool_size`/`max_db_connections`/
`max_user_connections = 1`) for the tested database/user pool, a nonzero
`max_prepared_statements`, and a bounded `query_wait_timeout`; every one of
these is asserted directly through PgBouncer's own admin console (`SHOW
CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/`SHOW CLIENTS`, queried
over the simple query protocol, the only protocol the admin console
answers), never inferred from client behavior. `SHOW CONFIG`'s
`default_pool_size`/`max_db_connections`/`max_user_connections` and the
tested database's own `SHOW DATABASES` `pool_size` are each independently
read back and asserted exactly one. The pool's credential is a freshly generated
password; with `password_encryption=md5` pinned on the container, its
`pg_authid.rolpassword` is read back and used directly as the userlist's MD5
credential hash. Two distinct client connections, open simultaneously, each
run one sequential transaction; `SHOW SERVERS`' `remote_pid` is identical
after both, proving transaction pooling reused one physical PostgreSQL
backend. The real adapter (a genuine `r2d2` pool plus `PostgresDurableStore`,
distinguished by its own `application_name`) is then pointed at the proxy,
not PostgreSQL directly. While a separate direct proxied client holds the
pool's only backend inside an open transaction (left open by withholding
`COMMIT`/`ROLLBACK`, never a timed sleep, and proven by the sole `SHOW
SERVERS` row for that database reporting PgBouncer's own `active` state, not
merely existing), one adapter structured invocation
is driven with a context deadline well longer than PgBouncer's own
`query_wait_timeout`. PgBouncer's queue timeout surfaces as PostgreSQL
protocol SQLSTATE `08P01` (`query_wait_timeout`) on the adapter's
transaction-opening `BEGIN`; this crate's `PreCommitFailure::from_sqlstate`
has no dedicated arm for class `08` and so falls through to its default
`Unavailable` bucket, producing the definite pre-commit
`Rejected(UnavailableBeforeCommit)`, never `Indeterminate`. The observed
elapsed time is bounded from both directions around PgBouncer's own
`query_wait_timeout` specifically, proving the rejection's timing tracks the
proxy's queue timeout rather than this probe's own much larger context
budget. No state/receipt/outbox row is published, checked through a direct,
proxy-bypassing verification connection unaffected by the proxy's
contention. After the blocking transaction is released, the identical
invocation is retried through the same adapter pool/store; a bounded,
explicitly documented retry tolerates one specific, live-verified transient
distinct from a genuine proxy rejection by its timing alone (`r2d2` can
occasionally recycle rather than evict the blocked probe's connection if its
local closed-state check has not yet caught up with PgBouncer's asynchronous
socket close, so the very next checkout can be handed that already-dead
connection and fail near-instantly with a local, unclassified I/O
error — also `Rejected(UnavailableBeforeCommit)` by the same default
classification, but resolved in sub-millisecond time rather than tracking
`query_wait_timeout`); the loop's final outcome must still be `Committed`,
and its accumulator is seeded with a rejection, never `Committed`, so a
future edit that shrank the retry bound to zero attempts fails loudly
instead of vacuously passing.
Recovery proves `Committed`; `SHOW SERVERS`' `remote_pid`, read again,
proves the recovered commit was served by the exact same sole backend the
two synthetic clients observed; `SHOW CLIENTS` filtered by the adapter pool's
`application_name` proves specifically that the adapter pool's own proxy
connection reclaimed the freed backend; a replay of the identical invocation
returns exact `RequestAlreadyCommitted`; the exact outbox message claims and
acknowledges through `NoDueWork`; and the pool remains usable for a further
read. CI makes the scenario required with
`SUNRISE_EDGE_TEST_POSTGRES_PGBOUNCER_REQUIRED=1`; leaving both that flag and
the two pinned-image variables unset skips it locally, and configuring only
one of the two pinned images always fails rather than skipping. This is a
bounded local PgBouncer transaction-pooling rehearsal only: it does not
prove provider-managed pooler service certification, load/soak capacity,
PgBouncer high availability or connection draining, TLS on either the
client or backend leg, real writer failover, or production readiness.

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
- pool exhaustion, statement timeout, WAL/commit-boundary or real-device disk
  full, abrupt process/power loss;
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
claim, and acknowledgement boundaries, over a plain `NoTls` transport and,
separately, over a strictly authenticated client-to-test-terminator TLS leg
([DR-0074](../architecture/decisions/0058-0075-postgres-conformance.md)); it says nothing about PostgreSQL-server/provider TLS, mTLS, PKI
lifecycle, or production certification beyond that one client leg. The
separate [DR-0070](../architecture/decisions/0058-0075-postgres-conformance.md) scenario
now covers bounded pre-commit data-tablespace ENOSPC with exact non-publication
and recovery evidence. A separate two-container [DR-0073](../architecture/decisions/0058-0075-postgres-conformance.md) scenario now covers a
bounded `pg_dump`-based database-snapshot restore rehearsal, with exact
schema-identity/namespace-metadata/state/receipt verification before fence
promotion, operator-only writer-fence advance, stale-context fencing, and post-restore reconciliation
evidence for one snapshot cycle; this does not close the checkpoint/backup/
restore-with-blob-manifest-verification criterion above, since point-in-time
recovery, continuous WAL archiving, hot/concurrent backup, checkpoint
publication, and blob-manifest/state-root/encryption-key verification remain
unimplemented. A further two-container [DR-0075](../architecture/decisions/0058-0075-postgres-conformance.md) scenario now covers a bounded
local PgBouncer 1.25.2 transaction-pooling rehearsal on an isolated Docker
network, with configured-transaction-mode and single-backend-reuse evidence
asserted directly through PgBouncer's own admin console, the real adapter
pool routed through the proxy getting the definite pre-commit
`Rejected(UnavailableBeforeCommit)` once PgBouncer's own `query_wait_timeout`
elapses while its one backend is held by a direct proxied client, and exact
recovery/replay/claim/ack evidence after release; this does not close a
provider-managed pooler production-certification criterion, since load/soak
capacity, PgBouncer high availability/connection draining, and TLS on either
leg remain unimplemented. Duplicate request races, abrupt/process faults, WAL or
commit-boundary/real-device exhaustion, PostgreSQL-server/provider TLS,
mTLS, PKI lifecycle, and production certification beyond the bounded
[DR-0074](../architecture/decisions/0058-0075-postgres-conformance.md) client leg, migration compatibility across real old and new binaries,
capacity/load/soak, real writer failover, provider-managed pooler
certification beyond the bounded [DR-0075](../architecture/decisions/0058-0075-postgres-conformance.md) rehearsal, and operational
certification remain open.
