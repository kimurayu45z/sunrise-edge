# Production Persistence Architecture

Status: accepted target architecture; implementation and production
certification remain incomplete.

This document defines the To-Be persistence architecture for Sunrise Edge. It
does not promote the current `runtime-sqlite` crate to a production database.
That crate remains a local durable reference and conformance fixture.

## 1. Boundary and trust model

Persistence belongs to one validator. Validators do not share a database, and
the database is not a consensus trust root. A corrupt, stale, or unavailable
store may stop or compromise its validator, but must not manufacture another
validator's signature, voting power, quorum certificate, or protocol state.

Multi-cloud means that independent validators and deployments can use
conformant provider implementations. It does not mean one validator may accept
concurrent authoritative writes in several eventually consistent regions.
The first production profile is single-writer per atomicity domain. Failover
must fence the previous writer before accepting writes at the replacement.

Protocol canonical bytes are the source of deterministic meaning. SQL columns,
indexes, timestamps, lease deadlines, retry counts, and provider metadata are
operational projections. They must be derived and updated in the same
transaction as their canonical record, and must never silently change protocol
semantics.

## 2. Required correctness contract

A production store must provide all of the following:

1. A stable namespace of `(chain_id, validator_id, atomicity_domain)`. Active
   `protocol_version` is stored in versioned records; it is not a top-level
   physical namespace that makes older state disappear after an upgrade.
2. Exact, bounded point reads. A protocol transition may not make a decision
   from an unbounded scan or an operational index query.
3. A revision assertion for every observed key, including read-only, absent,
   and tombstoned keys. Validating only mutated keys permits write skew.
4. One all-or-none commit containing every application mutation, request
   receipt, immutable outbox batch, outbox message, and initial delivery row
   produced by the invocation.
5. Monotonic revisions that never reset after delete/recreate. Revision
   exhaustion fails closed.
6. Deterministic conflict reporting. Storage serialization failures and
   deadline expiry remain distinct from a proven revision conflict.
7. Indexed, bounded claiming of due outbox work. Full key-prefix scans are not
   the production scheduling mechanism.
8. A deadline propagated into admission, transaction acquisition, statements,
   commit, and cancellation. No adapter may report a definite abort while a
   commit can still succeed invisibly.
9. Fail-closed schema identity, explicit expand/migrate/contract phases, and no
   request-path auto-migration.
10. Backup, restore, checkpoint, capacity, fault-injection, and observability
    evidence before a provider implementation is certified.

The legacy `TransactionalStateStore` satisfies only part of this contract.
`StateMutation::Assert` lets current node-core handlers include every declared
observation in their atomic write set. `protocol-types` now owns the logical
`AtomicityDomainId`, while runtime defines the transaction shape as
`AtomicStateReadSet`,
`AtomicStateMutationSet`, `AtomicStateTransaction`, and
`DomainTransactionalStateStore`. The memory implementation proves domain
isolation and complete-read conflict behavior. Node-core now has additive
domain-aware transactional and idempotent handlers that commit application
state, request receipt, outbox batch, and initial delivery cursor through that
contract. Domain-aware outbox claim/ack uses the same shared delivery logic and
keeps the immutable batch assertion plus cursor mutation in one domain. An
additive native route carries node-core's resolved domain through
request-scoped delivery. SQLite/default composition and durable providers still
use the legacy interface, and no indexed due-work claim exists yet, so this
remains an As-Is contract milestone rather than the completed production API.

## 3. Atomicity domains and scale

An atomicity domain is the smallest independently writable state authority. Its
identifier and placement rule must be deterministic, versioned, committed by
protocol configuration, and derivable from the declared access plan before
state reads.

`AtomicityDomainId` is a logical protocol identity, not a database address. A
domain ID is assigned by genesis or an activated governance configuration,
must be non-zero and unique for the chain, and is never reused. It is not
derived from a PostgreSQL hostname/schema, Durable Object name, AWS region,
validator ID, process, or deployment environment. The validator ID remains a
separate outer namespace because each validator owns its own replica of the
same logical domains.

The first production profile commits a `DomainPlacementManifest` in protocol
configuration with:

- a monotonically increasing placement-rule version;
- exactly one active logical domain ID;
- the closed routing rule `AllState`;
- an activation epoch and the protocol version that understands the rule.

This manifest is now implemented As-Is as canonical ProtocolConfig field 14.
Historical ProtocolConfig encoding version 1 remains byte-for-byte unchanged;
a configuration carrying the manifest uses encoding version 2 and requires
protocol version 2 or later. Version 2 without the manifest and version 1 with
it both fail closed. The manifest has stable canonical vectors and rejects a
zero rule version, zero domain ID, an empty access plan, and use before its
activation epoch. Node-core now has additive resolved transactional and
idempotent handlers that derive the bounded application access plan exactly
once, resolve the committed manifest before storage reads, and return the
resolved domain beside committed output. Native HTTP now has an additive router
restricted to `DomainTransactionalStateStore`: it invokes that resolved path
and carries the returned domain through request-scoped outbox claim/ack. The
legacy/SQLite router and scan-based unattended recovery remain unscoped; no
durable production domain store is implemented yet.

Node-core resolves this manifest after validating event context and after
constructing the bounded access plan, but before any state read. Every
application key in the plan must resolve to the same domain. Receipt, outbox,
and delivery records inherit that resolved invocation domain; their key prefix
is not independently routed. A caller-supplied domain ID is therefore an
internal adapter parameter to validate against the resolved manifest, not an
untrusted request choice. An unknown manifest version, inactive domain, empty
plan, or multi-domain result fails before storage I/O.

Future scale-out may add closed, canonical routing variants based on stable
object/key identity. Each variant requires its own canonical encoding, test
vectors, activation rules, and proof that all keys needed by one transition
resolve before reads. Provider-specific callbacks, mutable lookup services,
load-based routing, and database discovery are forbidden correctness inputs.

Physical placement is deployment metadata outside protocol configuration. It
maps `(chain_id, validator_id, logical_domain_id)` to a PostgreSQL partition or
cluster, one Durable Object, or a regional AWS authority plus its writer-fence
generation. Moving that binding must preserve the logical ID and use explicit
copy, commitment verification, old-writer fencing, activation, and rollback-
independent disable steps. It must never rewrite protocol objects merely to
change providers.

One invocation may commit only inside one domain in the first production
profile. A provider adapter must reject a write set spanning domains before it
performs a partial write. This maps directly to one PostgreSQL transaction, one
SQLite-backed Durable Object, or one bounded regional DynamoDB transaction.

This constraint does not reduce a domain to one key: it may contain many
objects, indexes, consensus records, receipts, and outbox rows. Domain sizing
and object placement must be derived from measured transaction access patterns,
storage limits, contention, recovery time, and checkpoint cost.

Cross-domain atomic effects require a separate protocol decision: a certified,
idempotent prepare/commit record and a visibility rule that readers can verify.
They must not be simulated with best-effort dual writes or a provider-specific
distributed transaction. Until that protocol exists, cross-domain write plans
fail closed.

## 4. Logical data model

The production relational model separates protocol data from delivery and
operations. Names below describe responsibilities, not yet-stable SQL names.

| Relation | Identity | Required role and indexes |
| --- | --- | --- |
| `storage_metadata` | validator and domain | Schema generation, writer fencing generation, migration state, and last verified checkpoint. |
| `state_records` | domain, record kind, binary key | Small versioned protocol/configuration records with canonical bytes, schema/type version, monotonic revision, and tombstone state. No text-path parsing for correctness. |
| `object_versions` | domain, object ID, object version | Immutable canonical object version or verified content-addressed blob reference, object digest, creating chain/protocol-version provenance (`DurableObjectProvenance`, DR-0068), and creation checkpoint. |
| `object_heads` | domain, object ID | Current version/digest pointer, ownership/routing projection, revision, and tombstone. Updated atomically with the new immutable version. |
| `request_receipts` | domain, request ID | Event digest, terminal outcome, canonical response, commit sequence, and retention watermark. Unique request identity rejects conflicting reuse. |
| `outbox_batches` | domain, request ID | Immutable batch identity and event digest committed with state and receipt. |
| `outbox_messages` | domain, request ID, message index | Immutable ordered canonical payload and payload digest. |
| `outbox_delivery` | domain, request ID | Next index, state, availability time, active lease ID/deadline, attempt count, and last error class. A bounded `(domain, availability, request)` pending/due index replaces prefix scans. |
| `outbox_delivery_attempts` | domain, lease ID | Immutable request/message binding plus lease deadline and claimed/acknowledged status. The unique lease identity and retained acknowledgement status make delayed retry after an indeterminate commit idempotent even after later messages advance. |
| `checkpoints` | domain, checkpoint sequence | State-root commitment, covered commit sequence, blob manifest commitment, schema generation, and verification status. |
| `migration_jobs` | domain, migration ID, range | Resumable bounded backfill cursor, source/target schema generation, checksum, and terminal status. |

Large immutable values, historical object bodies, module binaries, checkpoint
segments, and snapshots belong in a content-addressed `BlobStore`. A database
row may publish a blob reference only after verifying its digest and durable
availability. Garbage collection requires a checkpointed reachability proof;
age alone is insufficient.

The current opaque `sunrise_state(key, revision, value)` table and text-like
`PersistenceLayout` keys remain readable compatibility data. They are not the
target operational schema, and new production queries must not depend on
decoding path-shaped keys.

## 5. Transaction and outbox behavior

The target runtime operation accepts one bounded transaction envelope:

- the atomicity domain and writer fencing generation;
- an exact read set with observed revisions, including absence/tombstones;
- bounded canonical state/object mutations;
- one request receipt and zero or one immutable outbox batch;
- a storage deadline and correlation identity.

Runtime now defines this operational boundary additively as
`DurableDomainStateStore`. `DurableOperationContext` carries a non-zero
monotonic `WriterFenceGeneration`, absolute `StorageDeadline`, and fixed-size
non-zero `StorageCorrelationId`; none is canonical protocol input or accepted
from HTTP. A durable commit returns `Committed`, a definite `Rejected` reason,
or `Indeterminate`. Conflict, stale fencing, exhausted serialization retries,
and failures proved to occur before commit dispatch are definite rejections.
Deadline, connection loss, or cancellation after dispatch is indeterminate
unless the backend supplies authoritative abort evidence. Callers reconcile
that case through the persisted request receipt instead of rerunning effects
blindly. Node-core uses this boundary through an additive structured handler;
an additive native composition supplies the trusted context. Normalized
PostgreSQL is the first restart-safe As-Is adapter; other providers remain
pending.

Native structured composition now accepts an explicit cooperative cancellation
signal but consults it only while no storage call has begun. Cancellation before
dispatch returns without state, receipt, or outbox effects. Once the first store
read starts, later cancellation is ignored and the bounded synchronous job
finishes commit and outbox reconciliation; the signal is not passed into the
store and does not construct a cancellation-flavored commit result. Client
disconnect and in-flight database cancellation remain deferred.

Runtime also now defines `DurableInvocationTransaction` and
`StructuredDurableDomainStateStore`. The transaction carries one logical
domain, an optional complete state section that may be read-only, one typed
canonical completed-request receipt, an optional typed ordered outbox batch,
and an explicit object section. Aggregate bytes are bounded before I/O, and
state domain plus receipt/outbox request and event-digest identity must match.
The object section now carries canonical unique/sorted body-free head
assertions and contained create/update/delete mutations with distinct checked
immutable versions and ABA-safe head revisions. Immutable records contain
exactly one inline canonical `objects::Object` or one self-describing blob
reference; current heads contain no body and immutable versions are read
through a separate API. Head reconstruction validates bounded immutable
metadata and inline presence/length without selecting inline bytes. Inline
owner projections come from typed `Owner` encoding at write construction, but
owner/routing projections are routing metadata rather than authorization. An
execution caller must separately load the linked version, match its
version/digest to the head, decode an inline Object, and compare typed owner;
a blob-backed body is now fetched from an explicit `BlobStore` component and
independently verified before decode/authorization (ARCHITECTURE.md DR-0094).
The SQL
`type_id` is the canonical Object record identifier,
not the logical type hash retained in canonical Object bytes. Memory and
PostgreSQL implement this section atomically with state, receipt, and outbox.
Node-core now loads and authorizes authenticated read-only and owned
mutating/consuming manifest entries, including a blob-backed input, and
commits their complete head assertions through this section. A new version an
accepted authenticated Create/Update mutation commits is published to an explicit
`BlobStore` (content-addressed insert-if-absent, keyed under the same object
digest) and referenced rather than stored inline only when its canonical
bytes exceed a fixed deterministic 64 KiB threshold
(`node_core::MAX_INLINE_OBJECT_BODY_BYTES`, ARCHITECTURE.md DR-0096); a
version at or under the threshold stays inline exactly as before, which
every ordinary small object body (an asset-account update included) always
does. The staging decision that picks inline vs. blob is a pure function of
the canonical bytes with no I/O; the actual `put_blob` calls run only after
the complete structured envelope has been built and validated, strictly
before the structured commit, so a publish failure aborts with zero
state/receipt/nonce/outbox/object changes and a later structured commit
rejection can only leave an already-published blob as an unreachable
content-addressed orphan. Only Update is currently reachable; Create effects
remain fail-closed, though the persistence-layout staging covers both mutation
variants so future Create support cannot bypass it. A durable provider
`BlobStore` beyond the local file-backed SQLite implementation, and
GC/checkpoint manifest work, remain deferred.
Indexed repositories refine this structured store boundary. Node-core constructs the envelope after one
manifest resolution and one pure transition, checks typed receipts before
state reads, preserves read-only assertions, and withholds output for rejected
or indeterminate commits. A single-lock in-memory structured store now provides
atomic state/object/receipt/outbox, deadline, fence, conflict, read-only, and
node-core replay conformance. PostgreSQL is the first restart-safe As-Is
implementation; provider certification remains pending.

The store validates the complete read set and fencing generation, then commits
all rows or none. A pure transition is not re-run inside a storage driver. An
adapter may retry a serialization/transport failure only within a fixed budget
and only while the original read assertions remain valid; otherwise it returns
conflict, a definite serialization failure, or an indeterminate result according
to the evidence available at the commit boundary.

Outbox recovery uses a dedicated operation such as `claim_due_outbox(domain,
now, lease_id)`. The claim query returns at most one row ordered by availability
plus stable identity, and atomically installs a fencing lease. Transport occurs
after commit; only a matching lease and message index may acknowledge it.
Schedulers, alarms, queues, and retries are liveness hints and remain
untrusted. At-least-once delivery is explicit, so consumers must deduplicate by
the stable message identity.

Runtime now exposes this as the additive `IndexedOutboxRepository` contract.
One call claims at most one row in stable `(available_at, request_id)` order;
the caller supplies trusted runtime time and a bounded restart-safe lease, not a
scan cursor. Repeating a claim with the same lease ID reconciles an
indeterminate claim and returns the identical work while that lease owns it;
binding one lease ID to different work fails closed. Acknowledgement is
idempotent for the same `(request, message index, lease)` and therefore requires
the normalized store to retain one uniquely bound delivery-attempt record until
the owning batch is eligible for retention deletion. Keeping only the last
acknowledged lease is insufficient because a delayed retry may arrive after a
later message advances. Advancing the namespace writer fence rejects all later
operations from the old writer but does not revoke an already committed,
unexpired delivery lease. The replacement writer may reclaim that work only at
trusted lease expiry; the runtime-wide five-minute maximum therefore bounds this
failover delivery delay. Claim and
acknowledgement each distinguish definite pre-commit rejection from an
indeterminate commit. An indeterminate claim is never transported until it is
reconciled. Native now has an additive, one-shot indexed recovery path. Trusted
embedding composition supplies one logical domain, its writer fence, a bounded
storage-operation timeout shorter than the lease, and restart-safe lease and
correlation identities. The scheduler supplies none of those values. Claim and
acknowledgement each receive one same-identity reconciliation attempt; an
unresolved claim is never sent. The path shares native blocking admission and
returns no scan cursor. Memory and PostgreSQL run shared repository conformance;
transport-aware in-flight cancellation and provider certification remain
pending. The shared stores implement the actual indexed repository contract:
initial delivery rows,
stable due ordering, lease expiry/replacement, same-lease claim replay, retained
attempt history, and delayed acknowledgement after later progress are covered.

Request-path delivery uses a separate exact-request claim with trusted
`(domain, request_id, now, lease_id, lease_expiry)` input. It targets only that
request's delivery row and returns no work when the row is completed, not due,
or actively leased. It never falls through to an older due row in the same
domain. Lease reconciliation and acknowledgement share the retained attempt
history used by unattended claiming. The additive structured native router
derives no storage authority from HTTP: trusted composition supplies writer
fence, clock, deadline budget, restart-safe lease/correlation identity,
transport, and store. It resolves the manifest through node-core, commits the
typed invocation, then claims at most one message for that exact request using
the same operation context. One same-identity reconciliation is attempted for
an indeterminate claim or acknowledgement; unresolved claims are never sent.
PostgreSQL provides restart-safe As-Is evidence for this seam, not production
fault/capacity/provider certification.

`StateKeyScanner` remains useful for repair, audit, bounded migration, and
compatibility recovery. It is not a production work queue.

## 6. First reference backend: PostgreSQL

The first production-oriented backend will be PostgreSQL because it can express
the multi-relation atomic commit, exact constraints, bounded indexes, and queue
claiming required above while remaining available across native and managed
cloud deployments.

The adapter must use a bounded connection pool, bounded transaction/statement
timeouts, and serializable transactions or a proven equivalent combination of
row/predicate locking and revision checks. Serialization failures are expected
typed outcomes with bounded retry; they are not mapped to revision conflicts
without revalidation. Due outbox rows use a partial/covering index and may use
`FOR UPDATE SKIP LOCKED` only for queue claiming, never for protocol state
reads. Schema migrations run as an explicit operator action.

PostgreSQL is the first implementation target, not a protocol dependency and
not a claim that a single database can hold unbounded chain state. Capacity,
partition count, connection budget, failover fencing, replica freshness,
backup/restore, and load/soak results are certification inputs.

The exact first-backend namespace, unsigned SQL representation, normalized
relations, attempt-history semantics, transaction order, migration policy, and
required evidence are fixed in [`POSTGRES.md`](POSTGRES.md). That design also
records a prerequisite: node-core must pass receipt/outbox/object sections in a
structured durable transaction envelope. A PostgreSQL adapter must not decode
opaque `PersistenceLayout` key prefixes to choose relational tables.

## 7. Provider mappings

| Environment | Authoritative hot state | Immutable data | Initial production boundary |
| --- | --- | --- | --- |
| Native / portable | PostgreSQL | S3-compatible object storage | First production-oriented reference and conformance baseline. |
| Cloudflare | One SQLite-backed Durable Object per atomicity domain | R2 | DO-local transactions only. D1 may serve control/read models, not authoritative validator writes. Alarms/Queues only trigger bounded recovery. |
| AWS | Aurora PostgreSQL or regional DynamoDB transactions per domain | S3 | One fenced writer region. Global-table replication is not assumed to preserve a cross-item transaction for validator correctness. |
| Vercel / Deno / Supabase | Conformant PostgreSQL-backed node-core service, or ingress-only relay | Provider object store | Serverless ingress is not required to own validator state. A hosted database is certified separately from the ingress wrapper. |

Cloudflare documents SQLite-backed Durable Object storage as private to one
object and strongly consistent/transactional within that object. That is why a
DO is an atomicity domain rather than a globally transactional database:
<https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/>.
D1 read replicas are asynchronous and require Sessions bookmarks for sequential
consistency, so D1 is not the initial validator write authority:
<https://developers.cloudflare.com/d1/best-practices/read-replication/>.

AWS documents DynamoDB transactions as regional and warns that replicas may
observe a transaction partially while Global Tables replicate it. The first
AWS profile therefore uses a single fenced writer region:
<https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables_HowItWorks.html>.

PostgreSQL serializable transactions require applications to handle explicit
serialization failures, and `SKIP LOCKED` is suitable for queue-like access but
not general state reads:
<https://www.postgresql.org/docs/current/transaction-iso.html> and
<https://www.postgresql.org/docs/current/sql-select.html>.

## 8. Migration, retention, and disaster recovery

- Schema change uses expand, bounded backfill, verification, activation, and
  later contract. Mixed-version binaries fail closed outside an explicitly
  supported compatibility window.
- A backfill is resumable, range-bounded, checksummed, observable, and never
  required to re-encode all historical protocol state during activation.
- Deduplication records cannot be removed until the protocol rejects every
  event in their replay window and a verified checkpoint/backup covers them.
  Until that window is specified, they are retained.
- Outbox rows are retained after acknowledgement until an explicit finalized
  checkpoint and operational retention watermark cover them.
- Tombstones and revisions are compacted only through a versioned checkpoint
  rule that prevents revision reuse. Restore must never reset an ABA token.
- A backup is valid only with a matching database snapshot, blob manifest,
  state-root/checkpoint commitment, schema generation, and encryption/key
  metadata. Restore occurs in isolation, verifies all commitments, advances
  the writer fence, and only then becomes eligible for traffic.
- Replica lag, failover, disk-full, connection exhaustion, partial blob
  availability, kill/power loss, and restore corruption are mandatory fault
  cases. Orderly reopen is not sufficient evidence.

## 9. Implementation order and certification

1. Preserve the additive fenced/deadline-aware durable boundary and add the
   structured state/receipt/outbox/object transaction envelope required by
   normalized stores without silently migrating legacy data (runtime envelope
   and node-core plus memory conformance, native composition, and normalized
   PostgreSQL implemented; other provider wiring pending).
2. Add a dedicated indexed outbox repository/claim contract; retain key scans
   only for maintenance and compatibility.
3. Apply the accepted PostgreSQL schema design, explicit migrations, and
   adapter, then run the shared conformance suite. The generation-one schema,
   operator-only namespace bootstrap/fence advance, fenced structured commit,
   indexed claim/ack, and shared memory/PostgreSQL contract suite are implemented
   As-Is. An optional shared commit-loss capability, exercised only over a real,
   severable network transport, now proves that severing the connection
   immediately before one plain state commit dispatches `COMMIT` classifies
   `Indeterminate(ConnectionLost)` with no state ground truth published, and
   that severing it immediately after the backend returns a successful
   acknowledgement for one structured invocation commit, one outbox claim, and
   one acknowledgement also classifies `Indeterminate(ConnectionLost)` while
   publishing exact state/receipt ground truth and `RequestAlreadyCommitted`
   for the commit. Because a same-lease claim replay or same-identity
   acknowledgement replay alone cannot tell a persisted commit from an
   uncommitted one, the claim and acknowledgement cases each first probe the
   store independently (a different-lease claim while the original lease is
   still active, and a reclaim attempt with the original lease after
   acknowledgement) before checking same-identity reconciliation, with the
   connection pool proven to recover afterward. The only current
   implementations are a bounded `NoTls` TCP proxy and a second bounded
   TLS-terminating proxy in `runtime-postgres`'s live test. The latter requires
   PostgreSQL `SSLRequest`, trusts only an ephemeral private CA, validates a
   `localhost` SAN, rejects an IP-host negative connection, and records a
   completed authenticated handshake before running the exact same shared
   cases. It proves client/driver-to-test-terminator TLS connection-loss
   behavior only: the backend leg is plaintext, so PostgreSQL-server/provider
   TLS, mTLS, certificate rotation/revocation, and production PKI remain open.
   Both show the backend acknowledged commit before the driver lost it, not
   crash durability under abrupt process/power loss. A separate,
   serialized live test now `docker kill --signal=KILL`s the database-service
   container immediately after a committed structured invocation (state, an
   exact receipt, and one due outbox message), then restarts the same
   container, waits for readiness, and reconnects to verify the exact
   state/receipt, an identical `RequestAlreadyCommitted` replay, one exact
   claim and acknowledgement followed by `NoDueWork` for that request, and a
   final unfaulted commit
   (implemented As-Is; see `ARCHITECTURE.md` DR-0069). This proves PostgreSQL
   database-process SIGKILL and WAL recovery on a live host with a live page
   cache; it does not prove abrupt host/power loss, storage write-cache
   flush/torn-write/media/filesystem faults, disk-full/WAL exhaustion,
   TLS-path connection loss, backup/restore, capacity/load/soak, real writer
   failover, provider certification, or production readiness.
   A separate required disposable-container scenario puts PGDATA/WAL on an
   unfilled bounded tmpfs and the database default tablespace on a distinct
   64 MiB tmpfs, then fills only the latter. It proves direct SQLSTATE `53100`,
   definite `UnavailableBeforeCommit`, no state/receipt/commit-sequence
   publication, and recovery through the same pool/store after freeing space
   (implemented As-Is; see `ARCHITECTURE.md` DR-0070). This closes only bounded
   pre-commit data-tablespace ENOSPC evidence.
   A second required disposable-container scenario relocates `pg_wal` alone
   onto its own bounded 64 MiB tmpfs, distinct from and much smaller than the
   unfilled 512 MiB tmpfs holding PGDATA and the default tablespace, then
   fills only the WAL mount. A direct incompressible write that crosses a WAL
   segment boundary still returns SQLSTATE `53100`, but at `PANIC` severity,
   and the connection then closes as PostgreSQL terminates every backend and
   crash-restarts the whole postmaster (its own automatic recovery attempt
   fails the same way, taking the server down a second time). After an
   in-place recovery, a second independent fill drives a bounded
   incompressible state mutation through the adapter so its own structured
   invocation commit exhausts WAL and crashes the server; its observed public
   outcome is the definite pre-commit `Rejected(UnavailableBeforeCommit)`.
   The adapter does not expose the raw database error, so only the direct
   first cycle claims exact SQLSTATE and severity.
   Because this fault is fatal to the whole server rather than to one
   connection, the container's entrypoint is overridden with a small
   supervisor script that keeps the container itself alive across the crash,
   so recovery can free WAL space and restart postgres in place with
   `pg_ctl start` on the same, never-torn-down tmpfs mounts (never
   `docker start`/`docker kill`, which would recreate the mounts empty and
   destroy the evidence). A strictly-advanced `pg_postmaster_start_time()`
   after each restart proves two genuine crash/recovery cycles, and the same
   pool/store then prove no state/receipt/commit-sequence publication and
   recovery after freeing space (implemented As-Is; see `ARCHITECTURE.md`
   DR-0071). This closes bounded pre-commit WAL-filesystem ENOSPC evidence;
   literal-`COMMIT` WAL/data ENOSPC remains untested, and no
   ENOSPC-specific classification is claimed for that boundary.
   A third required disposable-container scenario configures a tiny exact
   `max_connections`, zero `superuser_reserved_connections`, and zero
   PostgreSQL 16+ `reserved_connections` (a second, independent reserved pool
   for the `pg_use_reserved_connections` role), so no role gets a capacity
   carve-out; autovacuum is disabled too, but only as optional quiescence,
   since autovacuum workers/launcher are accounted from their own separate
   budget and never carved out of `max_connections`. After the short-lived
   admin client that creates the disposable database is dropped, the
   operator connection boundedly polls until exactly one active client
   backend (its own) is visible, proving the admin client's asynchronous
   teardown was actually processed server-side before exact blocker counting
   begins; this poll is safe only because no `r2d2` pool exists yet and
   nothing else in the scenario can independently change the connection
   count at that point. This scenario then saturates every server connection
   slot with a small, exactly bounded number of direct blocker connections,
   proving genuine exhaustion via a direct probe's SQLSTATE `53300` at
   `FATAL` severity and the exact active client-backend count. With capacity
   still exhausted, a freshly built, max-size-one adapter pool proven to hold zero physical
   connections drives one bounded structured invocation commit; because
   `r2d2`'s connection-acquisition wait never returns early on a bare
   refusal, the caller's own operation deadline has, by construction, also
   just elapsed by the time this crate classifies the failure, so pool
   exhaustion and deadline exhaustion collapse into the same observable,
   definite pre-commit `Rejected(DeadlineExceededBeforeCommit)` here — not
   `UnavailableBeforeCommit`, which this adapter reserves for a fault
   surfacing after a connection and transaction are already open. Because the
   adapter pool cannot open a new connection while saturated,
   non-publication of state/receipt/outbox rows and the commit sequence is
   proven through the still-open operator connection instead of through the
   store. The rejected attempt's own background connection retry keeps
   running independently after that call returns, so it (not necessarily any
   call this test makes) can reclaim the slot freed by releasing exactly one
   blocker connection at any time; rather than racing that independent retry
   with a poll for a transient count, this scenario proves recovery
   deterministically by requiring the next `commit_invocation` call to
   succeed, then, through the same still-open operator connection, proving
   the post-recovery, steady-state client-backend count is exactly
   `max_connections` with precisely one backend carrying the adapter pool's
   own `application_name`, confirming the adapter pool specifically reclaimed
   it. The identical invocation, exact replay/claim/acknowledgement, and pool
   usability are then proven through the same pool/store (implemented As-Is;
   see `ARCHITECTURE.md` DR-0072). This closes
   bounded server connection-slot exhaustion evidence and this adapter's
   resulting deadline-based classification for it; real-device resource
   exhaustion and load/soak capacity remain open. A further required
   live scenario runs a digest-pinned PostgreSQL 18.6 and a digest-pinned
   `ghcr.io/icoretech/pgbouncer-docker` 1.25.2 on one isolated, generated
   Docker network, with PgBouncer configured (via a `docker exec`
   stdin-piped `dd of=<path> status=none`, no shell, no host bind mount, and
   no echo of the written credential/config into captured output) for
   transaction pooling, exactly one backend connection for the tested
   database/user pool (`default_pool_size`/`max_db_connections`/
   `max_user_connections`, and the tested database's own `SHOW DATABASES`
   `pool_size`, each independently read back and asserted exactly one), a
   nonzero `max_prepared_statements`, and a bounded `query_wait_timeout`;
   every one of these is asserted through PgBouncer's own admin console
   (`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/`SHOW SERVERS`/`SHOW
   CLIENTS`), never inferred. Two simultaneously open, distinct client
   connections each
   complete a sequential transaction, and `SHOW SERVERS`' `remote_pid`
   proves both reused the exact same PostgreSQL backend. The real adapter
   (a genuine `r2d2` pool plus `PostgresDurableStore`) is then pointed at
   the proxy; while a separate direct proxied client holds the pool's only
   backend in an open transaction (proven by the sole `SHOW SERVERS` row for
   that database reporting PgBouncer's own `active` state, not merely
   existing), one adapter structured invocation gets
   the definite pre-commit `Rejected(UnavailableBeforeCommit)` once
   PgBouncer's own `query_wait_timeout` elapses (PostgreSQL protocol
   SQLSTATE `08P01`, which this adapter's classifier has no dedicated arm
   for and so treats as `Unavailable`, never `Indeterminate`), with no
   state/receipt/outbox publication, proven through a direct,
   proxy-bypassing verification connection unaffected by the proxy's
   contention. After the blocking transaction is released, the identical
   invocation commits through the same pool/store, `SHOW SERVERS`'
   `remote_pid` (read again) proves the recovered commit was served by the
   exact same sole backend the two synthetic clients observed, `SHOW
   CLIENTS` filtered
   by the adapter pool's own `application_name` proves specifically that
   the adapter pool reclaimed the freed backend, and exact
   replay/claim/acknowledgement/pool-usability are proven as in the other
   scenarios (implemented As-Is; see `ARCHITECTURE.md` DR-0075). This
   closes bounded local PgBouncer transaction-pooling rehearsal evidence
   only; provider-managed pooler service certification, load/soak
   capacity, PgBouncer high availability, TLS on either leg, real writer
   failover, and production certification remain open.
4. Preserve the implemented exact-boundary/pool/lock deadline evidence,
   pre-storage native cancellation, and the database-process SIGKILL/WAL
   recovery evidence above, then extend it with client-disconnect and
   in-flight cancellation semantics, abrupt real host/power fault (storage
   write-cache flush, torn-write, media/filesystem faults included),
   commit-boundary and real storage-device ENOSPC, PostgreSQL-server/provider
   TLS beyond the bounded client-to-terminator evidence, capacity/load/soak
   tests, backup/restore rehearsal, and real writer-fencing failover tests.
   Every one of these remains open except the bounded client-to-terminator TLS
   loss slice and bounded local PgBouncer rehearsal; the database-process
   SIGKILL/WAL recovery,
   bounded pre-commit data-tablespace and WAL-filesystem ENOSPC, bounded
   connection-exhaustion, bounded client-to-terminator TLS loss, and the
   bounded local PgBouncer transaction-pooling rehearsal above are the only
   implemented fault slices. The bounded snapshot-restore rehearsal is
   operational evidence rather than a fault-injection slice.
5. Implement Cloudflare Durable Object and AWS mappings against the same
   contract and pass real-provider conformance before claiming support.

A backend is production-certified only when its schema, consistency mapping,
resource bounds, migration behavior, fault results, backup/restore procedure,
SLOs, alerts, and operator runbook are reviewed together. Passing unit tests or
implementing the trait is not certification.
