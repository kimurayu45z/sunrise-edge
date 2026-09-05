# Persistence architecture

This document defines how the runtime-neutral state machine maps onto explicit
atomicity domains, transactional state, objects, receipts, and outbox delivery.

## 41. Production persistence architecture

The production persistence contract is validator-local and provider-neutral.
Each invocation targets one explicit atomicity domain, asserts revisions for
its complete exact read set (including read-only, absent, and tombstoned keys),
and atomically commits application mutations, the request receipt, and initial
outbox data. Cross-domain write plans fail closed until a separate certified
protocol supplies prepare/commit and visibility semantics.

The logical schema separates small protocol records, immutable object versions,
object heads, request receipts, immutable outbox messages, mutable indexed
delivery state, checkpoints, and migration jobs. Large immutable values use a
content-addressed blob store. A dedicated due-work query replaces full
key-prefix scans for production outbox scheduling; `StateKeyScanner` remains a
repair, migration, and compatibility seam.

PostgreSQL is the first production-oriented reference backend, not a protocol
dependency. Cloudflare maps one atomicity domain to one SQLite-backed Durable
Object and AWS initially uses one fenced writer region. D1 read replicas,
DynamoDB Global Tables, alarms, queues, schedulers, and relays are not assumed
to make authoritative state writes globally atomic. Detailed schema,
provider mappings, migration, retention, backup/restore, fencing, and
certification requirements live in [the production persistence requirements](../operations/persistence.md).

Atomicity-domain identity is logical protocol configuration rather than
physical placement. The initial `DomainPlacementManifest` has one non-zero,
chain-unique, never-reused domain and a closed `AllState` rule. Node-core must
resolve the complete bounded application access plan before reads; receipt and
outbox records inherit that invocation domain. The adapter validates the
resolved domain rather than accepting it from an untrusted request. Deployment
metadata separately binds `(chain, validator, logical domain)` to PostgreSQL,
one Durable Object, or one fenced regional authority, so provider migration
does not change protocol identity.

`AtomicityDomainId` now lives in dependency-light `protocol-types` and rejects
the all-zero value. `ProtocolConfig` optionally carries the manifest as field
14 under encoding version 2. The historical version-1 genesis bytes remain
unchanged. Protocol version 1 rejects a manifest, while protocol version 2 and
later reject its absence. The manifest canonically commits its non-zero rule
version, logical domain, closed rule tag, and activation epoch; resolution
rejects empty plans and pre-activation events. Additive node-core resolved
handlers now derive the access plan once, resolve before storage reads, and
return the committed domain beside output. `native-http` exposes an additive
resolved-domain router only when the runtime store implements
`DomainTransactionalStateStore`. It accepts no HTTP domain input and carries
the node-core result into request-scoped outbox claim/ack. The legacy SQLite
router and scan-based unattended recovery remain compatibility paths.

The runtime now models that boundary explicitly with a non-zero 32-byte
`AtomicityDomainId`, a separately validated `AtomicStateReadSet`, a put/delete
`AtomicStateMutationSet`, and `AtomicStateTransaction`. Read and mutation sets
are unique and canonically key-ordered; every mutation must have a matching
read assertion. The envelope caps each set at 4,096 keys and caps aggregate
domain, key, revision, tag, and value bytes at 64 MiB. These are shared safety
ceilings, not measured provider capacity; provider adapters may require lower
bounds.

`DomainTransactionalStateStore` reads through an explicit domain and commits
exactly one such envelope. `MemoryStateStore` keeps domain maps isolated and
validates every read before calculating or applying any mutation revision. Its
legacy `StateStore` and `TransactionalStateStore` implementations remain in a
private test-only legacy domain so existing node-core and SQLite conformance do
not silently change physical layout. Node-core exposes additive domain-aware
transactional and idempotent handlers: both read through one explicit domain,
bind every declared observation into the dedicated read set, and release output
only after `commit_transaction`. The idempotent handler includes application
mutations, request receipt, immutable outbox batch, and initial delivery cursor
in that same domain transaction. Domain-aware outbox claim/ack reuses one
storage-neutral validation and cursor-transition implementation: only point
reads and the final transaction commit differ between legacy and domain stores.
The immutable batch observation and delivery-cursor mutation remain one domain
transaction. An additive native request path now composes these operations.
Normalized PostgreSQL implements the structured store and indexed unattended
recovery As-Is; other durable providers remain pending.

The additive `DurableDomainStateStore` boundary makes production operation
authority and uncertainty explicit without changing the legacy or domain
transaction traits. One `DurableOperationContext` carries a non-zero monotonic
writer-fence generation, an absolute storage deadline, and a fixed-size
non-zero correlation ID across reads and commit. These are deployment and
observability inputs, never canonical protocol fields, deduplication identity,
or HTTP-selected authority. A durable commit has exactly three top-level
states: committed, definitely rejected, or indeterminate. Revision conflict,
stale writer fence, exhausted serialization retry, and failures proved to
precede commit dispatch are definite rejections. Deadline, cancellation, or
connection loss after dispatch is indeterminate unless the backend proves an
abort; reconciliation must read the persisted request receipt before effects
are retried. Node-core, native composition, SQLite, and provider adapters have
not migrated to this new production boundary yet.

The additive `IndexedOutboxRepository` is the production discovery and lease
boundary. A claim receives one deployment-bound logical domain, trusted runtime time,
and a bounded restart-safe lease identity, then selects at most one eligible
row through stable `(available_at, request_id)` index order and installs the
lease atomically. It accepts no key-scan cursor or scheduler-selected domain.
The claimed payload is the exact bounded canonical outbound event projection.
Repeating the same lease ID reconciles an indeterminate claim by returning the
identical work while owned; reuse for another message fails closed. A matching
acknowledgement advances one message, while replay of the same acknowledged
`(request, index, lease)` succeeds idempotently. The normalized delivery model
therefore retains a uniquely bound delivery-attempt record through the owning
batch's retention window rather than erasing evidence when it clears the active
lease. Keeping only the most recent acknowledgement would fail after a later
message advances. Both claim and acknowledgement distinguish
definite pre-commit rejection from indeterminate commit. Callers never send an
indeterminate claim before reconciliation. Defining this contract does not
itself provide a durable repository. PostgreSQL now implements the boundary;
`StateKeyScanner` remains a compatibility path for stores that have not
migrated.

Native now also exposes additive `recover_indexed_outbox_once`. Trusted
embedding composition fixes the logical domain and current physical writer
fence, a bounded storage timeout strictly shorter than the lease, and a
restart-safe identity source before an untrusted scheduler triggers the call.
This authority may include explicitly draining old logical domains during a
fenced migration; it is not re-derived from an arbitrary request or scheduler
input. The path claims at most one message, makes one same-identity
reconciliation attempt for an indeterminate claim, validates and sends only
reconciled canonical event bytes, then makes one same-identity acknowledgement
reconciliation attempt. It shares native blocking admission and returns no scan
cursor. Scripted conformance proves unresolved claims are not sent. PostgreSQL
now supplies the durable repository; real scheduler binding and transport-aware
cancellation/deadline do not yet exist, so the scan path remains
compatibility-only rather than deleted.

[the PostgreSQL reference](../operations/postgres.md) fixes the first relational implementation design:
exact binary namespace columns, full-range unsigned numeric representation,
writer/schema metadata, normalized state/object/receipt/outbox/checkpoint
relations, retained lease-attempt history, serializable transaction order,
indexed claim/ack behavior, and explicit migration/certification evidence. It
also closes an API-design trap before SQL implementation: the existing
`AtomicStateTransaction` exposes only opaque keys and values. A normalized
driver must not parse `PersistenceLayout` prefixes to infer receipt, outbox, or
object rows. Node-core must first build a structured durable envelope with
separately typed and bounded sections. SQLite remains unchanged compatibility
data and is never request-path migrated into that schema.

Runtime now implements that input boundary as `DurableInvocationTransaction`
and `StructuredDurableDomainStateStore`. An invocation names one logical
domain, an optional `DurableStateTransaction`, one canonical typed receipt, an
optional typed ordered outbox batch, and an explicit object section. The state
section keeps a complete read set but may have zero mutations, allowing a
read-only transition to bind its observations while the receipt is written.
Constructors reject cross-domain state and receipt/outbox request or event
digest drift and cap the aggregate represented bytes. The object section has
canonical unique/sorted body-free head assertions and contained
create/update/delete mutations. Immutable versions and ABA-safe head revisions
are distinct; versions contain exactly one existing canonical Object encoding
or self-describing blob reference, and a separate read API returns immutable
records without loading bodies into head assertions. Head reads validate only
bounded immutable-row metadata and inline presence/length, never fetch or
decode inline bytes. Inline owner projections are derived from typed `Owner`
when written, but a head projection is routing metadata, not authorization:
an execution caller must separately read the exact immutable version, match
its version/digest to the head, decode the inline Object, and compare its typed
owner. Node-core's authenticated durable entrypoints now fetch a blob-backed
version's body from an explicit, separately supplied `BlobStore` component and
independently verify it before authorization
([DR-0094](decisions/0094-0098-blobs-audit-and-documentation.md)).
[DR-0096](decisions/0094-0098-blobs-audit-and-documentation.md) additionally
publishes over-threshold new versions before their structured commit and adds
local file-backed SQLite blob storage; production/cloud provider blob storage
remains unimplemented.
The generation-one SQL `type_id` is the stable
canonical Object record ID rather than the logical `Object::type_hash` retained
inside canonical bytes. Memory and PostgreSQL apply object/state/receipt/outbox
sections atomically, preventing an adapter from hiding object writes in generic
state. Node-core now uses the object section for authenticated read-only
manifest authorization and exact head assertions, plus an additive
owned-effects path that commits validated signed Address-object Update/Delete
mutations, both now reading a blob-backed input through an explicit `BlobStore`
component ([DR-0094](decisions/0094-0098-blobs-audit-and-documentation.md));
over-threshold new-version publication is implemented by
[DR-0096](decisions/0094-0098-blobs-audit-and-documentation.md), while Create
and Shared/System ownership remain deferred. Indexed outbox
repositories now refine the structured store trait so one implementation owns
initial commit and later delivery state. An additive node-core handler now
resolves the manifest domain before I/O, checks the typed receipt before state
reads, and constructs this envelope from one pure transition. Exact replay does
not rerun the transition or republish the outbox; read-only transitions retain
their full assertion set; rejected and indeterminate commits release no output.
A dedicated in-memory conformance store holds state, typed receipt, and typed
outbox under one lock, validates injected trusted time and writer generation,
and exercises commit, conflict, read-only, replay, deadline, and fence behavior
with the real node-core handler. It is not restart-safe production storage.
An additive native router now owns explicit normalized store, transport, clock,
and restart-safe identity components without requiring the store to implement
the legacy opaque `StateStore`/`Runtime` surface. Trusted embedding authority
fixes writer fence and time budgets; node-core resolves the manifest domain and
commits the typed invocation before native claims at most one message for that
exact request. Commit, claim, and acknowledgement reuse one bounded operation
context. Claim and acknowledgement ambiguity receive one same-identity
reconciliation attempt, and an unresolved claim is never sent. The in-memory
tests prove an older due row in the same domain is not mistaken for the current
request. The normalized PostgreSQL adapter now uses this boundary, while
started transport/storage work is not cancellable.

The `runtime-postgres` crate now makes the accepted generation-one schema
executable through an operator-only migration and exact namespace bootstrap.
Its dedicated `sunrise_edge` schema separates metadata, state records, object
versions/heads, request receipts, outbox batches/messages, indexed delivery,
retained lease attempts, checkpoints, and migration jobs. Namespace rows bind
exact chain bytes, validator identity, logical domain, schema identity and
generation, and a non-zero physical writer fence. Full-range `u64` values use
checked `NUMERIC(20,0)` constraints. PostgreSQL 18 CI applies the migration in a
dedicated test database and verifies idempotent schema application, bootstrap
fence mismatch rejection, exact relations/indexes, unsigned overflow rejection,
and zero-domain rejection. Its bounded pool performs fenced state, body-free
object-head, immutable object-version, and receipt reads plus serializable
structured state/object/receipt/outbox commits. Object assertions lock in
canonical ID order; tombstones clear current/digest/projection columns and
reconstruct the last version from immutable history; inline/blob payloads map
losslessly to the unchanged generation-one schema. The live fixture runs the
same domain/fence/deadline/bounds, create/update/delete/recreate ABA, conflict
rollback, replay, and blob round-trip contract as memory. It additionally
asserts immutable history, current/tombstone rows, blob mapping, body-free
metadata corruption rejection, and strict malformed-body rejection through
the separate immutable-version read. The same store
implements exact-request and stable `(available_at_ms, request_id)` indexed
claims, checks retained lease attempts before selecting work, expires a
replaced attempt in the replacement transaction, and advances one message only
through an exactly bound acknowledgement. Claim and acknowledgement take a
shared namespace-metadata lock so a fence advance cannot race them without
serializing unrelated delivery rows; `SKIP LOCKED` is confined to due delivery
selection. Request traffic does not run DDL or bootstrap. An optional shared
commit-loss capability now covers commit-boundary connection loss over the
plain `NoTls` transport and a separately authenticated TLS client leg that
terminates at a bounded test proxy
([DR-0074](decisions/0058-0075-postgres-conformance.md); see below), and a
separate serialized live test now
covers database-process SIGKILL and WAL recovery on a live host with a live
page cache ([DR-0069](decisions/0058-0075-postgres-conformance.md)). Separate
bounded disposable-container tests cover pre-commit data-tablespace ENOSPC
([DR-0070](decisions/0058-0075-postgres-conformance.md)) and pre-commit
WAL-filesystem ENOSPC
([DR-0071](decisions/0058-0075-postgres-conformance.md)); the latter shows the
same SQLSTATE `53100` at `PANIC`
severity crashes the whole server, not just the connection. A further bounded
disposable-container test covers real server connection-slot exhaustion
([DR-0072](decisions/0058-0075-postgres-conformance.md)), showing this adapter classifies it as the definite pre-commit
`Rejected(DeadlineExceededBeforeCommit)`, not `UnavailableBeforeCommit`,
because its pool-acquisition wait and the caller's own operation deadline
are, by construction, exhausted together. A further bounded two-container
test ([DR-0073](decisions/0058-0075-postgres-conformance.md)) covers a
`pg_dump`-based database-snapshot restore rehearsal:
schema identity and restored namespace metadata/state/receipt verified
before fence promotion, operator-only writer-fence advance on the restored
namespace, stale pre-backup context fencing, and exact reconciliation plus
fresh commit under a new context, alongside an atomic invalid-dump rollback
and a valid missing-state gate rejection; this is rehearsal evidence for one
`pg_dump`/SQL-execute snapshot cycle only, not a production backup/restore capability, and it does
not close the backup/restore evidence criterion in
[../operations/persistence.md](../operations/persistence.md). A further bounded
rehearsal ([DR-0075](decisions/0058-0075-postgres-conformance.md)) runs the real adapter (a genuine `r2d2` pool plus
`PostgresDurableStore`) through a real, digest-pinned `pgbouncer` 1.25.2 proxy
in transaction-pooling mode with exactly one backend connection for the
tested database/user pool, on an isolated generated Docker network: PgBouncer
admin-console evidence (never inferred) confirms configured transaction mode
and proves two simultaneously open, distinct client connections reuse the
exact same PostgreSQL backend across sequential transactions; while a direct
proxied client holds that one backend in an open transaction, one adapter
invocation gets the definite pre-commit `Rejected(UnavailableBeforeCommit)`
once PgBouncer's own `query_wait_timeout` elapses, with no state/receipt/
outbox publication; after release, the identical invocation commits, replays
as `RequestAlreadyCommitted`, and its outbox message claims/acknowledges
through `NoDueWork`, with the pool remaining usable. This is a bounded local
transaction-pooling rehearsal only, not provider-managed pooler service
certification, load/soak, failover, or TLS evidence. In-flight
cancellation, abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or real-device
ENOSPC, PostgreSQL-server/provider TLS beyond the bounded
[DR-0074](decisions/0058-0075-postgres-conformance.md) client leg,
point-in-time recovery, continuous WAL
archiving, hot/concurrent backup, checkpoint publication, blob-manifest/
state-root/encryption-key verification, capacity/load/soak, provider-managed
pooler production certification/load/failover beyond the bounded
[DR-0075](decisions/0058-0075-postgres-conformance.md)
rehearsal, real writer failover, and
production certification evidence remain open, so this is still As-Is
adapter evidence rather than production readiness.

Runtime exposes the vendor-neutral durable-store conformance cases only to its
own tests or adapters that opt into the non-default `durable-conformance`
feature. One fixture supplies the backend's trusted deadline clock, exact
logical domain, and operator-only writer-fence advance while the suite drives
only `StructuredDurableDomainStateStore` and `IndexedOutboxRepository` methods.
Memory and PostgreSQL run the same complete-read write-skew, concurrent absent
and tombstone, definite contention-outcome, retained outbox-lease, and
writer-fence cases. PostgreSQL additionally injects unsupported schema metadata
and a real serialization abort at an exhausted retry ceiling when the live-test
URL is configured; CI supplies it. A separate optional `CommitLossFixture`
capability, implemented only by that same live PostgreSQL test through a
bounded `NoTls` TCP proxy and a separate required-TLS client-to-terminator
proxy, can sever the connection either immediately before
a dispatched `COMMIT` reaches the backend or immediately after the backend
returns a successful acknowledgement for it; both instants classify as
`Indeterminate(ConnectionLost)`. The shared case injects the pre-dispatch
instant once, for one plain state commit, proving no state ground truth was
published. It injects the post-acceptance instant three times: for one
structured invocation commit, proving exact committed state/receipt ground
truth and that a same-identity replay observes `RequestAlreadyCommitted`; for
an outbox claim on that invocation's message, first proving with a different,
never-used lease that the original lease is still active (`NoDueWork`) and
then that a same-lease replay reconciles to the identical claimed message;
and for the corresponding acknowledgement, first proving that reclaiming with
the original lease is rejected as lease-ID reuse and then that a
same-identity replay reconciles to acknowledged with the acknowledgement
persisted and no message left due. These discriminating probes matter because
a same-lease claim replay or same-identity acknowledgement replay alone would
succeed identically whether or not the prior transaction actually persisted.
A final unfaulted commit proves the connection pool recovers afterward. This
shows the backend returned a successful acknowledgement before the driver
lost it, not crash durability under abrupt process/power loss. The TLS proxy
requires ordinary PostgreSQL `SSLRequest`, uses an ephemeral private CA and a
`localhost`-only server certificate, rejects an IP-host negative connection,
and records completed authenticated handshakes before running the exact same
shared cases. It terminates TLS and relays plaintext to PostgreSQL, so it proves
only client/driver-to-test-terminator TLS loss behavior, not server-terminated
TLS, provider PKI/mTLS/rotation/revocation, or production readiness. A
separate serialized live test now
proves database-process SIGKILL and WAL recovery on a live host with a live
page cache ([DR-0069](decisions/0058-0075-postgres-conformance.md)). Separate disposable-container scenarios prove bounded
data-tablespace ENOSPC before `COMMIT` and exact recovery after space is
freed ([DR-0070](decisions/0058-0075-postgres-conformance.md)), bounded WAL-filesystem ENOSPC before `COMMIT`, which
crashes and in-place restarts the whole server rather than just the
connection, with exact recovery after space is freed ([DR-0071](decisions/0058-0075-postgres-conformance.md)), and bounded
real server connection-slot exhaustion, which this adapter classifies as the
definite pre-commit `Rejected(DeadlineExceededBeforeCommit)` rather than
`UnavailableBeforeCommit` because its own pool-acquisition wait cannot
outlast the caller's operation deadline, with exact recovery after one
blocking connection is released ([DR-0072](decisions/0058-0075-postgres-conformance.md)), and a bounded two-container
`pg_dump`-based database-snapshot restore rehearsal, proving schema identity
and restored namespace metadata/state/receipt before fence promotion, an
operator-only writer-fence advance on the restored namespace, stale
pre-backup context fencing, and exact reconciliation plus fresh commit under
a new context, alongside an atomic invalid-dump rollback and a valid
missing-state gate rejection
([DR-0073](decisions/0058-0075-postgres-conformance.md)), and a bounded PgBouncer transaction-pooling rehearsal: PgBouncer
admin-console evidence proving configured transaction mode and exactly one
PostgreSQL backend reused across two simultaneously open client connections'
sequential transactions, the real adapter (`r2d2` pool plus
`PostgresDurableStore`) pointed at the proxy, one adapter invocation
definitely rejected (`UnavailableBeforeCommit`) once PgBouncer's own
`query_wait_timeout` elapses while a direct proxied client holds the pool's
one backend, no publication, and exact recovery/replay/claim/ack after
release ([DR-0075](decisions/0058-0075-postgres-conformance.md)); none of these
tests prove abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or
real-device ENOSPC, PostgreSQL-server/provider TLS beyond
[DR-0074](decisions/0058-0075-postgres-conformance.md),
point-in-time recovery, continuous WAL
archiving, hot/concurrent backup, checkpoint publication, blob-manifest/
state-root/encryption-key verification, capacity/load/soak,
provider-managed pooler production certification/load/failover beyond the
bounded [DR-0075](decisions/0058-0075-postgres-conformance.md) rehearsal, real writer
failover, provider certification, or production readiness, all of which
remain backend-specific evidence. Passing this suite is As-Is contract
evidence, not production certification.

A cancellation-enabled normalized native composition accepts and owns an
explicit trusted `InvocationCancellation` signal. It checks that signal in the
async request handler, again when the bounded blocking job begins, and
immediately before the first structured storage call. Cancellation at any of
those checkpoints returns 503 without state, receipt, outbox, send, or
acknowledgement effects. Once the first storage call starts, the job never
consults the signal again and completes commit/delivery reconciliation normally.
This deliberately does not cancel started synchronous PostgreSQL work or
manufacture `IndeterminateCommitReason::CancellationRequested`;
client-disconnect wiring, shutdown budgets, and in-flight cancellation remain
separate work.
