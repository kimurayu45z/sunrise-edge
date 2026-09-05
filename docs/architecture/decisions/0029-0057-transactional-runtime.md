# Architecture decisions DR-0029–DR-0057

Transactional runtime, idempotency, atomicity-domain, outbox, and normalized
store-boundary decisions.

- DR-0029: Use monotonic per-key storage revisions and one bounded,
  canonically ordered atomic write set as the provider-neutral persistence
  contract. Retain deletion tombstones to prevent ABA, reject the complete
  transaction on the first ordered conflict, and treat the in-memory
  implementation as conformance evidence rather than durable storage.
- DR-0030: Require transactional node state machines to declare a bounded
  event-specific access plan before reads. Supply a versioned immutable
  snapshot, derive commit revisions inside node-core, reject undeclared and
  read-only updates, and release no output until the whole write set commits.
- DR-0031: Bind idempotency to both request ID and the complete canonical event
  digest in dedicated domain `0x000D`. Commit replayable responses and one
  ordered at-least-once outbox batch with application state, reject request-ID
  reuse for different bytes, and do not equate persisted batches with a
  completed delivery/acknowledgement recovery protocol.
- DR-0032: Deliver a persisted outbox in order, one message per bounded lease.
  Assert the immutable batch revision when claiming or acknowledging, replace
  only expired leases, and redeliver send-without-ack after expiry. Preserve
  explicit at-least-once semantics rather than claiming transport-level
  exactly-once delivery.
- DR-0033: Make the recoverable transactional path the native HTTP default.
  Require an injected restart-safe lease-ID source, deliver only through the
  persisted outbox cursor, acknowledge only after transport success, and replay
  completed responses without rerunning or resending acknowledged work. Keep
  unattended scheduling and durable crash recovery as explicit later gates.
- DR-0034: Implement the first durable transactional store with exact-pinned
  bundled SQLite, WAL plus synchronous FULL, immediate write transactions,
  revision tombstones, and fail-closed application/schema identity. Keep its
  blocking local-disk boundary out of async request tasks until bounded
  isolation and fault conformance are implemented.
- DR-0035: Require native embeddings to supply a non-zero synchronous-work
  concurrency limit. Acquire capacity before submitting one complete canonical
  decode/invoke/deliver/encode job to Tokio's blocking pool, reject excess work
  with 429, and keep liveness independent. Do not emit an invented retry delay
  or claim cancellable deadlines by timing out a started `spawn_blocking` job;
  design deadlines with the storage operation and commit boundary instead.
- DR-0036: Add optional bounded state-key discovery outside the protocol
  transition store contract. Require binary-prefix, exclusive-cursor pagination
  with a fixed page ceiling, canonical ordering, validated provider pages, and
  tombstone visibility. Treat pages as non-snapshot observations and require
  periodic prefix restarts before using the seam for unattended recovery.
- DR-0037: Expose unattended native recovery as a scheduler-invoked, one-shot
  bounded operation rather than a resident loop. Share HTTP blocking admission,
  validate persisted batch/delivery identity, skip live leases and completed
  records, recover at most one outbox, and return an exclusive continuation.
  Keep the scheduler untrusted and preserve lease-expiry redelivery after
  send-without-ack failure.
- DR-0038: Compose native runtimes from explicit independently typed components
  rather than embedding storage or transport defaults. Verify SQLite outbox and
  lease continuity across orderly close/reopen into a new composition, while
  reserving abrupt process/power-fault, filesystem, and real-provider claims
  for separate conformance evidence.
- DR-0039: Treat SQLite as a local durable reference, not the production
  database. Define validator-local atomicity domains, assert the complete read
  set, separate normalized object/receipt/outbox/checkpoint data, and require an
  indexed due-outbox query. Use PostgreSQL as the first production-oriented
  reference, map one Cloudflare Durable Object to one domain, begin AWS with one
  fenced writer region, and prohibit cross-domain or multi-region authoritative
  writes until their protocol and conformance evidence exist.
- DR-0040: Bind every key in a transactional node-core access plan into the
  atomic commit. Encode untouched read-write, read-only, absent, and tombstoned
  observations as revision-only `Assert` entries so a dependency change
  rejects application state, receipt, and outbox publication together.
- DR-0041: Represent the production transaction boundary as one explicit
  non-zero atomicity domain, one complete canonical read-assertion set, and one
  canonical put/delete mutation set. Require every mutation to match a read,
  bound aggregate bytes as well as key counts, and keep the legacy unscoped
  store contract isolated until node-core and durable adapters migrate.
- DR-0042: Add domain-aware node-core handlers without silently redirecting the
  legacy store contract. Read application and reserved invocation records from
  one explicit domain, bind all observations to one transaction, and commit
  application mutations, receipt, outbox batch, and initial delivery cursor
  together. Keep native routing on the legacy path until its domain identity
  and durable migration are explicit.
- DR-0043: Carry the explicit atomicity domain through outbox lease and
  acknowledgement transactions. Share identity, lease-expiry, cursor, and
  acknowledgement validation across legacy and domain entrypoints; vary only
  point reads and atomic commit construction. Assert the immutable batch and
  mutate its delivery cursor in the same domain transaction.
- DR-0044: Make atomicity-domain identity logical, chain-configured, and
  independent of physical storage placement. Begin with one never-reused
  domain and a closed `AllState` manifest rule, resolve every application key
  before reads, and make receipt/outbox records inherit the invocation domain.
  Bind that logical domain to provider resources only in fenced deployment
  metadata so migration does not rewrite protocol identity.
- DR-0045: Commit the first `DomainPlacementManifest` only through an explicit
  ProtocolConfig encoding-version boundary. Preserve historical version-1
  bytes, require field 14 for protocol version 2 and later, reject the field on
version 1, and fail closed on zero identity/rule version, empty access, or
  pre-activation routing. Keep the logical ID in `protocol-types` and defer
  native trust until node-core resolves the committed manifest.
- DR-0046: Resolve the committed domain manifest inside node-core after event
  context validation and one bounded access-plan derivation, but before any
  storage read. Return the resolved logical domain beside committed output so
  outbox delivery carries the same authority instead of rerunning placement or
  accepting a request-selected domain. Keep native composition migration
  explicit and additive.
- DR-0047: Add a native HTTP composition restricted to explicit-domain stores.
  Resolve placement in node-core, carry that returned domain through the shared
  request-scoped delivery loop, and never accept a domain from HTTP. Preserve
  the legacy SQLite route and scan recovery until a durable domain store and
  indexed due-work contract exist; do not mislabel the memory-backed route as
  production persistence.
- DR-0048: Model production durable operations with one non-zero writer fence,
  absolute deadline, and bounded correlation identity shared across reads and
  commit. Keep those values out of canonical protocol and HTTP authority.
  Return proven abort reasons separately from an indeterminate commit, and
  require receipt reconciliation whenever commit may have succeeded invisibly.
  Introduce the boundary additively so legacy SQLite data is not migrated by
  implication.
- DR-0049: Replace production outbox scans with an indexed, one-row claim that
  orders by availability and request identity and atomically installs a bounded
  restart-safe lease. Make same-lease claim retry a reconciliation operation,
  retain uniquely bound lease-attempt history for idempotent acknowledgement retry,
  and separate indeterminate claim/ack commits from proven aborts. Keep
  scheduler cursors and caller-selected domains outside authority.
- DR-0050: Add one-shot native indexed recovery under immutable embedding
  authority for a logical domain, physical writer fence, storage timeout, and
  restart-safe identities. Reconcile an indeterminate claim once with the same
  lease and never send it unresolved; reconcile acknowledgement with the same
  request/index/lease. Share blocking admission, expose no scan cursor, and
  retain the legacy scan path until a durable repository passes conformance.
- DR-0051: Fix the first PostgreSQL schema and transaction design before adding
  a database driver. Represent full-range unsigned protocol counters without
  signed narrowing, retain per-lease attempt history, fence every transaction
  through exact namespace metadata, and require explicit migrations. Add a
  structured state/object/receipt/outbox envelope first; prohibit the adapter
  from classifying opaque key prefixes into normalized relations.
- DR-0052: Add a structured durable invocation input before implementing SQL.
  Separate complete state assertions/mutations, canonical request receipt,
  ordered outbox messages, and object changes; bind domain, request, and event
  digest across sections and bound aggregate bytes. Permit read-only state
  sections, keep unsupported object changes explicitly empty, and require
  indexed delivery repositories to share this structured store boundary.
- DR-0053: Route normalized node-core persistence only through the structured
  durable invocation boundary. Resolve placement before reads, query a typed
  receipt before application state, bind every outbound canonical event and
  digest into the ordered outbox, and release output only for a definite commit
  or an exact persisted replay. Treat indeterminate commit as reconciliation
  work, never as a safe transition retry.
- DR-0054: Establish shared structured-store semantics in memory before writing
  a database driver. Keep state, receipt, and outbox projections under one
  atomic lock; inject trusted time and active writer generation; prove that
  conflicts, stale fences, and pre-dispatch deadlines publish no partial rows;
  and use the real node-core handler for commit and replay conformance. Treat
  this fixture as ephemeral evidence, not production persistence.
- DR-0055: Make the ephemeral structured store implement the same indexed
  outbox contract required of durable drivers. Create delivery state with the
  invocation commit, claim in stable availability/request order, reconcile an
  active same-lease claim, expire replaced attempts, and retain every lease
  binding so a delayed acknowledgement remains idempotent after later messages
  advance. Reject cross-domain lease reuse and keep this evidence non-durable.
- DR-0056: Give request-path outbox delivery an exact-request claim operation
  instead of reusing domain-wide unattended claiming. Bind trusted domain and
  canonical request identity to the lease request, return no work rather than
  selecting another due row, and reject lease reuse across requests or domains.
  Share retained attempt history and acknowledgement semantics with indexed
  recovery so native composition has one delivery model.
- DR-0057: Compose normalized native requests from explicit structured store,
  transport, clock, and restart-safe identity components instead of forcing the
  store through the legacy `Runtime` boundary. Resolve the protocol manifest in
  node-core, reuse one trusted fenced/deadline context across commit and the
  exact-request claim/ack attempt, reconcile each ambiguous outbox operation
  once with the same identity, and never send an unresolved claim. Bound the
  synchronous path with existing native admission and keep durable adapters,
  cancellation, and production capacity evidence as separate exit work.
