# Sunrise Edge

Sunrise Edge is an experimental, serverless-native Layer 1 blockchain core
written in Rust.

Its central idea is simple:

> A blockchain node is a state machine, not a process.

The protocol is designed as deterministic state transitions over authenticated
events and explicit persistent state. Long-running daemons, permanent P2P
connections, background workers, and large mutable in-memory state are not
protocol requirements. The same core should eventually run behind native
servers, edge functions, and cloud functions without making any provider a
consensus trust root.

> [!WARNING]
> Sunrise Edge is under active development. It is not production-ready, has not
> been independently audited, and must not be used to custody real assets.

## Design goals

- Object-centric, versioned state instead of one global mutable key-value store.
- ABI-declared state access for deterministic conflict detection and parallelism.
- Deterministic WASM execution with a Rust-first contract SDK.
- Event-driven consensus that does not require persistent validator processes.
- Stablecoin-denominated fees and validator bonds, without requiring a native
  token for protocol security.
- Explicit separation of validator identity, membership, voting power, bond,
  and economics.
- Governance-installed system modules and first-class protocol upgrades.
- Cryptographic agility without per-transaction algorithm negotiation.
- Self-describing digests, strict domain separation, and lazy migrations.
- A path toward ZK-friendly execution and state commitments.

## How the core fits together

```text
untrusted request / relay / scheduler event
                    |
                    v
       load the required persistent state
                    |
                    v
       deterministic protocol transition
          | execution | consensus |
                    |
                    v
       atomic persistence / compare-and-swap
                    |
                    v
      signed response and outbound messages
                    |
                    v
             invocation may end
```

Safety comes from canonical encoding, cryptographic authentication, quorum
rules, and persisted protocol state—not from the transport, scheduler, process
lifetime, or cloud provider.

## Current status

The workspace currently contains the foundations and experimental
cross-provider ingress milestones implemented through Phase 17:

- Canonical framed encoding for protocol-critical values.
- Bounded, zero-copy canonical frame decoding with strict order and length
  validation for adapter ingress.
- SHA-256 and SHA3-256 support with epoch-selected hash suites.
- Self-describing digests and domain-separated hash/signature framing.
- A ZIP-215-compliant Ed25519 `SignatureVerifier` in `crypto`, built on the
  exact-pinned `ed25519-zebra` 4.2.0 crate (declared once in the workspace
  root; the committed `Cargo.lock` pins its `curve25519-dalek` dependency at
  4.1.3), and a committed `TransactionAuthProfile` in `protocol-config`
  (`ProtocolConfig` field 15, encoding v3, required from protocol version 3
  and absent for v1/v2) that selects the signature scheme and address
  binding by configuration rather than per transaction. Profile ids are
  committed protocol identifiers, not arbitrary non-zero `u16` labels:
  `TransactionAuthProfile::new` and `TransactionAuthProfile::validate`
  reject zero, any id other than the public
  `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID` (1), and any unsupported
  scheme/binding, using the same rules. `crypto::SignatureSigner::sign_canonical`
  and `SignatureVerifier::verify_canonical` reject a `SignatureDomain` whose
  declared scheme does not match the signer's/verifier's own scheme before
  any framing or cryptographic operation runs. Only Ed25519 with an
  `AddressIsPublicKey` address binding is implemented today; no production
  signer exists. `runtime::MemorySigner` is a public in-memory wiring
  fixture used to compose test/local runtimes; it is deliberately
  non-cryptographic and must never be used for protocol authentication.
  `protocol-config` only commits and resolves this profile
  (`resolve_transaction_auth_profile` validates the whole configuration
  before returning, so a malformed configuration fails closed); it has no
  dependency on `crypto` or `objects` and performs no signature
  verification. `execution::decode_transaction` is a strict, standalone
  canonical decoder for `execution::Transaction` v1 (type/version, exact
  field 1-10/12 plus optional field 11, unknown/missing/duplicate/
  out-of-order field rejection, transaction-specific resource bounds applied
  before copying attacker-controlled entrypoint/args/signature/manifest
  entries, matching new decoders for `AccessManifest`/`AccessEntry`,
  `ObjectRef`/`ObjectId`/`Address`/access mode, and `FeePayment`/`AssetId`,
  duplicate-`ObjectId` and non-canonical `AccessManifest` layout rejection,
  and a decode/re-encode byte-identity check). It performs no signature
  verification and builds no `SignatureDomain`. `node-core` now adds a
  standalone, fail-closed `transaction_auth` boundary (workspace
  dependencies on `execution` and `crypto`; `protocol-config` itself still
  depends on neither) that composes this decoder, the committed profile, and
  the concrete Ed25519 verifier. Its `authenticate_transaction_bytes` takes
  untrusted canonical bytes plus an explicit `TrustedTransactionContext`
  (caller-supplied `ChainId`/`Epoch`, with protocol-version authority taken
  only from the referenced `ProtocolConfig`, never a separate caller value),
  rejects a chain/protocol-version/epoch mismatch before any cryptographic
  work, builds `SignatureDomain` from the trusted context and profile using
  the exact stable message family `"transaction-v1"`, bounds the canonical
  signable payload before framing or verifying it, and returns the new
  `AuthenticatedTransaction` — a private-field wrapper with no public
  constructor other than a successful call — only once the committed
  Ed25519 verifier confirms the signature. It distinguishes a malformed
  key/signature `CryptoError` from a well-formed but invalid signature.
  Signature-algorithm agility remains committed configuration resolved at a
  protocol-version/profile boundary, not per-transaction negotiation; only
  Ed25519 profile 1 (`AddressIsPublicKey`) is implemented. The production-
  oriented structured durable native route now consumes a committed
  `ProtocolConfig`, authenticates every `SubmitTransaction` into an
  unforgeable `AuthenticatedSubmitTransaction`, and captures placement from
  that same configuration before identity allocation, clock/storage work,
  access-plan derivation, transition, outbox claim, or send. Generic
  node-core handlers and legacy native routes reject `SubmitTransaction`
  rather than processing it unauthenticated. Exact durable replays still
  authenticate before receipt reconciliation. A fresh request must now equal
  the persisted per-sender, per-epoch next nonce; its read assertion and
  checked increment commit atomically with application state, receipt, and
  outbox. Application plans cannot claim the reserved nonce prefix. The same
  authenticated durable path now loads every signed read-only manifest entry
  through its exact head and immutable inline version, authorizes the typed
  owner against the verified sender, and commits the complete head assertions
  atomically. Every immutable object version now carries its creating
  chain/protocol-version provenance, and node-core independently recomputes
  and verifies each authenticated object's digest from that provenance and
  the self-describing stored digest algorithm — never the reader's epoch hash
  suite — under bounded inline-body budgets, so it no longer trusts the
  storage adapter for object-body integrity (see `ARCHITECTURE.md` DR-0068).
  An additive node-core owned-effects entrypoint now strictly translates
  effects for already verified owned Address objects into bounded durable
  Update/Delete mutations. It rejects creation, undeclared or duplicate
  effects, version/identity/shape changes, overflow, unsupported owners, and
  missing trusted mutation context, then atomically commits valid effects with
  exact head assertions, sender nonce,
  application state, receipt, and outbox. Exact request replay returns the
  persisted result without re-running or reapplying execution. `structured_durable_router`
  still calls the read-only entrypoint and therefore rejects Write/Consume
  before storage I/O; a new additive `preinstalled_wasm_structured_durable_router`
  (`_with_executor`) composes trusted `Arc<PreinstalledModuleCatalog>`/
  `WasmExecutionEngine`/`created_checkpoint` and calls the preinstalled-WASM
  entrypoint instead, so a signed owned Write/Consume can execute a governed
  deterministic contract over HTTP; both routers share the same request-scoped
  outbox claim/send/ack path and admission/cancellation bounds. Shared/system
  ownership, blob bodies, arbitrary module upload, fee debit, FastVote/FastCertificate,
  and certificate publication also remain unimplemented, so the owned fast
  path is not yet safe to activate on a live chain. The other externally
  accepted node-event families, especially certificate, protocol-upgrade, and
  validator-set-change events, still need their own authenticated and
  authorized ingress boundaries before any live activation. The outer
  `NodeEvent.request_id` remains unsigned and is only an idempotency identity;
  replay protection for fresh request IDs now comes from the signed nonce.
  Clients must submit one exact next nonce at a time: pipelining or queued
  future nonces is not supported.
- Versioned objects, object references, access manifests, and lazy migration.
- Runtime traits and an in-memory runtime for deterministic tests.
- A local durable SQLite transactional store using WAL, synchronous FULL,
  immediate write transactions, revision tombstones, and fail-closed schema
  identity/version checks. It also implements bounded, cursor-paginated binary
  prefix key discovery for recovery adapters. It is a local reference and
  conformance fixture, not the selected production database.
- An additive, local-only, non-production `SqliteDurableStore` in the same
  crate that implements the normalized `StructuredDurableDomainStateStore`
  and `IndexedOutboxRepository` contracts on their own SQLite tables and its
  own `PRAGMA application_id`, separate from the opaque legacy store above; it
  never reinterprets opaque state-key prefixes. Because `application_id` is a
  whole-file SQLite property, this store and the opaque legacy store each need
  their own database file. It is bound at construction to one trusted `(chain,
  validator, atomicity domain)` namespace, persists a fenced writer generation
  and a documented schema identity, and serializes every operation behind one
  process-local mutex plus one SQLite transaction — `Deferred` for a
  multi-statement read's consistent snapshot, `Immediate` for a write's
  `BEGIN IMMEDIATE` write lock — with no connection pool and no live
  fault-injected evidence. The caller's remaining `DurableOperationContext`
  deadline is propagated into that connection's SQLite `busy_timeout` before
  each transaction starts, clamped to a five-second maximum, so a blocked
  write fails closed near the caller's own deadline rather than always
  waiting the fixed default. Every digest, canonical-record-type identity,
  outbox-attempt status, and boolean column is decoded strictly through a
  typed representation and fails closed on corruption rather than being
  coerced; an object version's persisted creating chain is checked against
  the store's bound chain on both commit and read; and a current object head
  is trusted only after cross-checking it against its exact validated
  immutable version row and confirming that version is the maximum retained
  one. The same feature-gated shared conformance suite used by PostgreSQL —
  complete-read write skew, object head/version lifecycle, lease/writer
  fencing, and schema skew — passes against it, plus a dedicated restart test
  that closes and reopens the file to prove durable state, immutable object
  versions, receipts, and an in-flight outbox lease all survive, that exact
  request replay after reopen returns `RequestAlreadyCommitted`, and that
  outbox acknowledgement stays idempotent after reopen, and a bounded
  contention test proving a short deadline does not wait the fixed default.
  It exists so the preinstalled-WASM native routers can use one local durable
  structured store; it is not provider-hardened, and native binary/devnet
  startup wiring around it remains unimplemented.
- An accepted [production persistence architecture](PERSISTENCE.md) that makes
  validator-local atomicity domains, complete read-set validation, normalized
  object/receipt/outbox data, indexed recovery, writer fencing, migration, and
  disaster recovery explicit. PostgreSQL is the first production-oriented
  reference target; provider implementations must pass the same contract.
- An explicit PostgreSQL generation-one migration with normalized namespace,
  state, object, receipt, outbox, delivery-attempt, checkpoint, and migration-job
  relations. Operator-only bootstrap binds exact schema identity/generation and
  writer fence metadata; PostgreSQL 18 CI verifies the migration and core SQL
  constraints. A bounded synchronous pool now implements fenced/deadline-aware
  state/object/receipt reads, separate immutable object-version reads, and
  serializable structured state/object/receipt/outbox commits with complete
  read assertions and conservative commit-result classification. Current
  object heads remain body-free; canonical inline objects and blob references
  map losslessly to the generation-one schema. Head reads validate strict
  immutable metadata and representation presence/length without selecting an
  inline body. Owner/routing head projections are routing data, not execution
  authorization; authorization must separately load the linked immutable
  version, match version/digest, decode an inline Object, and compare its typed
  owner. Blob-backed execution remains unavailable until fetch and content
  verification exist. Serialization/deadlock aborts
  retry the unchanged envelope only within an explicit attempt ceiling and
  remaining deadline. Indexed
  exact-request/due claim and acknowledgement now use retained attempt history.
  One feature-gated shared suite exercises complete-read write skew,
  absent/tombstone races, exact-boundary pre-dispatch deadlines, definite
  contention classification, and lease/writer fencing against memory and
  PostgreSQL; the live PostgreSQL fixture additionally injects pool/row-lock
  deadline exhaustion, retry exhaustion, and schema skew when its required test
  URL is set. An optional shared commit-loss capability, exercised only by that
  same live fixture first through a bounded `NoTls` TCP proxy, injects a connection
  loss immediately before one plain state commit dispatches `COMMIT`, proving
  no state ground truth was published, and separately injects a connection
  loss immediately after the backend returns a successful acknowledgement for
  one structured invocation commit, one outbox claim, and one acknowledgement,
  proving exact committed state/receipt ground truth and `RequestAlreadyCommitted`
  for the commit. Because a same-lease claim replay or same-identity
  acknowledgement replay alone cannot tell a persisted commit from an
  uncommitted one, the claim and acknowledgement cases each first probe the
  store independently (a different-lease claim while the original lease is
  still active, and a reclaim attempt with the original lease after
  acknowledgement) before checking same-identity reconciliation. Both instants
  classify `Indeterminate(ConnectionLost)`, and the connection pool is proven
  to recover afterward. This shows the backend returned a successful
  acknowledgement over the plain transport before the driver lost it. The same
  shared cases also run through a second bounded proxy whose client leg requires
  PostgreSQL `SSLRequest`, a private ephemeral CA, a `localhost`-only leaf, and
  rustls CA/hostname verification; an IP-host negative connection is rejected
  and at least one completed authenticated handshake is asserted. That proxy
  terminates TLS and speaks plaintext to the test database, so DR-0074 proves
  only client/driver-to-test-terminator TLS connection-loss behavior, not
  PostgreSQL-server TLS, provider PKI, mTLS, rotation/revocation, crash durability
  under abrupt process/power loss, or capacity. Broader fault, operations, and production
  certification remain pending, so this is still As-Is evidence.
- A separate, serialized live PostgreSQL crash-recovery test (see
  `ARCHITECTURE.md` DR-0069) commits one structured invocation containing
  state, an exact receipt, and one outbox message and observes `Committed`
  with the committing pool still alive; with no intervening SQL, it then
  `docker kill --signal=KILL`s the exact database-service container, restarts
  that same container, waits for readiness, and reconnects with a fresh
  pool/client to verify the exact state and receipt, an identical
  `RequestAlreadyCommitted` replay, one exact claim and acknowledgement
  followed by `NoDueWork` for that request, and a final unfaulted commit. This proves
  PostgreSQL database-process SIGKILL and WAL recovery on a live host with a
  live page cache; it does not prove abrupt host/power loss, storage
  write-cache flush/torn-write/media/filesystem faults, disk-full/WAL
  exhaustion, TLS-path behavior, backup/restore, capacity/load/soak, writer
  failover, provider certification, or production readiness, so this remains
  As-Is evidence alongside the commit-boundary connection-loss evidence
  above.
- A separate required CI scenario (see `ARCHITECTURE.md` DR-0070) starts an
  exact digest-pinned disposable PostgreSQL container with PGDATA/WAL on an
  unfilled 512 MiB tmpfs and all database relations on a separate 64 MiB
  tmpfs tablespace. It fills only that tablespace, proves a direct write
  returns SQLSTATE `53100`, proves the adapter rejects the pre-commit
  structured invocation as `UnavailableBeforeCommit`, then frees space and
  reconciles no state/receipt publication before the identical invocation,
  outbox claim, and acknowledgement succeed. This is bounded pre-commit
  data-tablespace ENOSPC evidence only.
- A separate required CI scenario (see `ARCHITECTURE.md` DR-0071) relocates
  `pg_wal` alone onto its own bounded 64 MiB tmpfs, distinct from and much
  smaller than the unfilled 512 MiB tmpfs holding PGDATA and the default
  tablespace, then fills only the WAL mount. A direct write crossing a WAL
  segment boundary still returns SQLSTATE `53100`, but at `PANIC` severity,
  and PostgreSQL crash-restarts the whole postmaster; after an in-place
  recovery, a second independent fill drives the adapter's own structured
  invocation commit to exhaust WAL and crash the server, observing the
  definite pre-commit `Rejected(UnavailableBeforeCommit)`, then reconciles no
  publication and exact recovery through the same pool/store. This is bounded
  pre-commit WAL-filesystem ENOSPC evidence only.
- A separate required CI scenario (see `ARCHITECTURE.md` DR-0072) starts an
  exact digest-pinned disposable PostgreSQL container with a tiny exact
  `max_connections`, zero `superuser_reserved_connections`, and zero
  PostgreSQL 16+ `reserved_connections` (a second, independent reserved
  pool), so no role gets a capacity carve-out; autovacuum is disabled too,
  but only as optional quiescence, since autovacuum workers are accounted
  separately and never draw from `max_connections`. After the admin client
  that creates the disposable database is dropped, the operator connection
  boundedly polls until only its own connection remains — safe here, unlike
  later in the same scenario, because no connection pool exists yet to race.
  The scenario then saturates every server connection slot with a small,
  exactly bounded number of direct blocker connections, proving genuine
  exhaustion via a direct probe's SQLSTATE `53300` at `FATAL` severity. With
  capacity still exhausted, a max-size-one adapter pool proven to hold zero
  physical connections drives one bounded structured invocation commit; its
  outcome is the definite pre-commit `Rejected(DeadlineExceededBeforeCommit)`,
  since this adapter's pool-acquisition wait and the caller's own operation
  deadline are, by construction, exhausted together, rather than
  `UnavailableBeforeCommit`, which this adapter reserves for a fault
  surfacing after a connection is already open. Non-publication is proven
  through a still-open operator connection. Because the rejected attempt's
  own internal connection retry keeps running in the background after that
  call returns, this test does not poll for a transient count after
  releasing exactly one blocker connection (which would race that
  independent retry); it instead proves recovery deterministically through
  the next successful commit plus post-recovery server-side connection
  counts, then proves exact replay/claim/acknowledgement and pool usability
  through the same pool/store. This is bounded server
  connection-slot exhaustion evidence only.
- A separate required CI scenario (see `ARCHITECTURE.md` DR-0073) starts two
  fully separate, isolated digest-pinned disposable PostgreSQL containers (a
  source and a target — different processes, passwords, and published
  ports), commits one structured invocation on the source, and captures a
  `pg_dump --inserts` snapshot, stripping PostgreSQL 18's `psql`-only
  `\restrict`/`\unrestrict` bracketing lines before applying the
  self-contained script directly into a fresh target database with the same
  PostgreSQL driver library. Before fence promotion it verifies exact schema
  identity and restored namespace metadata/state/receipt ground truth, then
  advances the restored namespace's writer fence through the operator-only
  seam, proves a
  stale pre-backup context is rejected as `WriterFenced` with no publication,
  and proves a fresh context reconciles the restored state/receipt, observes
  `RequestAlreadyCommitted` for the identical invocation, claims and
  acknowledges the exact pending outbox payload, and commits new work. A
  deterministic negative pair proves both an atomic rollback for a dump cut
  inside a required `CREATE TABLE` and a deeper gate rejection after a valid
  restore omits only the fixture state row while retaining schema, metadata,
  and receipt. This is a bounded
  database-snapshot restore rehearsal for one `pg_dump`/SQL-execute cycle
  only, not a production backup/restore capability: it does not close the
  backup/restore evidence criterion.
- A separate required CI scenario (see `ARCHITECTURE.md` DR-0075) starts a
  digest-pinned PostgreSQL 18.6 container and a digest-pinned
  `ghcr.io/icoretech/pgbouncer-docker` 1.25.2 proxy container on one
  isolated, freshly generated Docker network, with PgBouncer configured for
  transaction pooling, exactly one backend connection for the tested
  database/user pool, a nonzero `max_prepared_statements`, and a bounded
  `query_wait_timeout` — every setting asserted directly through PgBouncer's
  own admin console, never inferred (`default_pool_size`/
  `max_db_connections`/`max_user_connections` and the tested database's own
  `SHOW DATABASES` pool size are each independently read back and asserted
  exactly one). It proves two simultaneously open,
  distinct client connections reuse the exact same PostgreSQL backend across
  sequential transactions, then points the real adapter (a genuine `r2d2`
  pool plus `PostgresDurableStore`) at the proxy. While a direct proxied
  client holds the pool's only backend inside an open transaction (proven
  `active`, not merely present, via `SHOW SERVERS`), one
  adapter invocation gets the definite pre-commit
  `Rejected(UnavailableBeforeCommit)` once PgBouncer's own
  `query_wait_timeout` elapses (PostgreSQL SQLSTATE `08P01`, which this
  adapter's classifier treats as `Unavailable`, never `Indeterminate`), with
  no state/receipt/outbox publication. After release, the identical
  invocation commits through the same pool/store; the same backend-PID
  evidence proves the recovered commit reused the exact backend the two
  synthetic clients observed, `SHOW CLIENTS` proves the
  adapter pool's own connection reclaimed the freed backend, a replay
  returns exact `RequestAlreadyCommitted`, and the exact outbox message
  claims and acknowledges through `NoDueWork`. This is a bounded local
  PgBouncer transaction-pooling rehearsal only, not provider-managed pooler
  service certification, load/soak, failover, or TLS evidence. Together,
  DR-0070/DR-0071/DR-0072/DR-0073/DR-0075
  leave literal-`COMMIT` WAL/data ENOSPC, real storage-device ENOSPC and
  block-device faults, load/soak capacity, provider-managed pooler service
  certification beyond DR-0075's bounded rehearsal,
  PostgreSQL-server/provider TLS beyond DR-0074,
  point-in-time recovery,
  continuous WAL archiving, hot/concurrent backup, checkpoint publication,
  blob-manifest/state-root/encryption-key verification, real writer failover,
  and production certification open.
- An explicit `ComposedRuntime` for assembling independently selected state,
  blob, signer, transport, clock, and scheduler components without hidden
  defaults. Native conformance tests close/reopen SQLite into a new composition,
  recover committed outboxes without reapplying state, preserve failed-send
  leases, and redeliver only after expiry.
- A bounded, replay-context-aware node-core invocation boundary that persists
  one pure transition with compare-and-swap before releasing output.
- A bounded, versioned multi-key transaction contract with ABA-safe tombstone
  revisions and an atomic in-memory conformance implementation.
- A domain-aware transaction envelope that separates a complete bounded
  `AtomicStateReadSet` from put/delete mutations, requires every mutation to
  have a matching read assertion, caps aggregate represented bytes, and keeps
  identical keys isolated across atomicity domains in memory. Additive
  node-core and native paths use it; durable providers have not yet migrated.
- An additive production durable-store boundary with a non-zero monotonic
  writer fence, absolute storage deadline, bounded operational correlation ID,
  and typed commit outcomes. Proven conflicts, fencing, serialization aborts,
  and pre-commit deadline/unavailability remain distinct from an indeterminate
  commit that must be reconciled by persisted request identity.
- A structured durable invocation envelope with an optional read-only-capable
  application state section, a typed canonical request receipt, a typed ordered
  outbox batch, and typed body-free object-head assertions plus contained
  create/update/delete mutations. Immutable versions use exactly one inline
  canonical Object or self-describing blob reference and are read separately.
  Head projections alone never authorize execution: a caller must match the
  separately loaded inline version to the head and validate its typed owner;
  blob-backed execution fails closed while blob verification is deferred.
  It bounds total
  represented bytes and rejects domain/request/event-digest drift, so a
  normalized adapter never needs to classify opaque key prefixes. An additive
  node-core handler constructs this envelope, replays typed receipts before
  state reads, supports read-only state assertions, and withholds output for
  rejected or indeterminate commits. A single-lock in-memory conformance store
  validates atomic state/object/receipt/outbox publication, bound domains,
  trusted time, fencing, conflicts, lifecycle ABA safety, the object read-count
  bound, blob round-trip, and exact replay. PostgreSQL now
  implements the same object boundary As-Is. Node-core now consumes it for
  authenticated read-only manifest authorization plus an additive
  owned-effects path that validates signed Address-object Update/Delete
  effects and, through a separate additive preinstalled-WASM entrypoint,
  deterministic bounded WASM execution against an exact-committed module
  catalog; Create, Shared/System ownership, blob transfer verification,
  native binary/devnet startup composition, and fee/gas metering remain
  deferred.
- An additive indexed durable-outbox repository contract that claims at most
  one due message in stable availability/request order, installs a bounded
  restart-safe lease atomically, and makes same-lease claim and acknowledgement
  retries reconcilable after an indeterminate commit. An additive native
  one-shot recovery path consumes trusted deployment domain/fence authority,
  sends no unreconciled claim, and shares blocking admission. The in-memory
  conformance repository now validates stable due order, expiry replacement,
  same-lease reconciliation, and retained delayed acknowledgement. The
  normalized PostgreSQL adapter implements the same indexed claim and
  acknowledgement boundary with retained attempt history; prefix scanning
  remains compatibility-only recovery.
- An exact-request durable outbox claim beside the unattended due-work claim.
  The additive structured native request path targets only the request that
  just committed, even when older work is due in the same domain. Commit,
  claim, and acknowledgement share one bounded operational context; an
  indeterminate claim receives one same-identity reconciliation attempt and is
  never sent while unresolved.
- A transactional node-core path that declares bounded state access before
  reads, transitions over an immutable versioned snapshot, and rejects
  undeclared or read-only updates before atomic commit. Every declared
  observation, including read-only and absent state, is revision-asserted in
  that commit so concurrent dependency changes cannot produce write skew.
- Canonical request/event-digest deduplication and ordered request-scoped
  outbox records committed atomically with application state, including
  response replay and conflicting request-ID reuse rejection.
- Additive domain-aware node-core handlers that bind the complete read set and
  commit application state, the request receipt, outbox batch, and initial
  delivery cursor inside one explicit atomicity domain. Existing native and
  SQLite paths are not silently redirected or migrated.
- An accepted domain-placement design that keeps logical, chain-configured
  domain identity separate from PostgreSQL, Durable Object, AWS, validator, and
  deployment coordinates. The initial canonical manifest uses one closed
  `AllState` domain under an explicit ProtocolConfig v2 boundary while
  preserving historical v1 bytes. Node-core resolves it once before storage
  reads and returns the committed domain with output; an additive native route
  carries that domain through request-scoped delivery.
- A one-message bounded outbox lease/ack cursor with explicit at-least-once
  redelivery after lease expiry; it does not claim transport exactly-once.
- Domain-aware outbox lease/ack entrypoints that keep immutable-batch assertions
  and cursor updates in the selected atomicity domain while sharing the same
  delivery validation with the legacy compatibility path.
- A native Axum/Tokio HTTP adapter with strict canonical binary media types,
  bounded bodies, deterministic status mapping, graceful shutdown wiring, and
  recoverable transactional invocation as its default state path.
- Native request-scoped outbox delivery through persisted 30-second leases and
  atomic acknowledgements; lease identities come from an injected source whose
  uniqueness must survive process restart.
- An additive native router for explicit-domain stores. It resolves placement
  in node-core, accepts no HTTP domain selector, and carries the committed
  domain through request-scoped delivery. The SQLite/default router and scan
  recovery remain compatibility paths, not production persistence.
- Explicit native blocking admission control: canonical decode, synchronous
  state transition, durable store access, outbox send/ack, and result encoding
  run outside Tokio request tasks with a host-selected non-zero concurrency
  bound. Excess work is rejected with 429 instead of entering an unbounded
  adapter queue.
- A scheduler-callable, one-shot native outbox recovery API that scans bounded
  durable pages, skips completed and actively leased records, recovers at most
  one outbox, returns an explicit continuation cursor, and shares the HTTP
  blocking admission pool. It creates no resident loop or scheduler trust root.
- A bounded Cloudflare Workers ingress that uses a generated private Service
  Binding, strict TypeScript, and workerd integration tests.
- A provider-neutral Web Fetch API ingress core for keeping future edge
  wrappers conformant with the same bounds and error contract.
- Transactions, execution effects, deterministic `wasmi` execution, and a
  Rust contract SDK.
- Stablecoin fee assets, deterministic fee calculation, bond assets, validator
  admission, and governance primitives.
- Versioned Chain IR and governance-managed system-module registries.
- Feature flags, hash-suite schedules, protocol-upgrade schedules, and lazy
  migration descriptors.
- Epoch-scoped validator sets with explicit voting power.
- Event-driven chained-HotStuff ordering for shared/conflicting transactions,
  including signed proposals, votes, quorum certificates, locking, and
  three-certificate commit.
- Versioned sparse-Merkle leaf/node commitment framing with SHA-256 and an
  experimental, inactive Poseidon2/BN254 implementation.
- Canonical execution-proof statements and bounded, exact-ID verifier dispatch;
  concrete proof backends are not yet implemented.

Important remaining work includes the owned-object fast path, concrete
node-event dispatch and protocol handlers, in-flight durable-I/O cancellation,
real provider trigger wiring, abrupt host/power-fault recovery conformance
(database-process SIGKILL/WAL recovery, bounded pre-commit data-tablespace
and WAL-filesystem ENOSPC, bounded server connection-slot exhaustion, a
bounded `pg_dump`-based database-snapshot restore rehearsal, bounded
client/driver-to-test-terminator TLS commit-loss behavior, and a bounded
local PgBouncer transaction-pooling rehearsal are covered As-Is;
see DR-0069/DR-0070/DR-0071/DR-0072/DR-0073/DR-0074/DR-0075 — DR-0073 is a
rehearsal for one snapshot cycle, not a production backup/restore
capability, and DR-0075 is a bounded local rehearsal, not provider-managed
pooler service certification),
portable system-module execution, cryptographic slashing proof verification,
fee-object debiting,
provider persistence bindings, runtime adapters, networking/RPC surfaces, and
independent security review.

The next milestone is the explicit [Developer MVP Gate](TODO.md#developer-mvp-gate),
so client-library and front-end work can exercise a real end-to-end product
before further production hardening. The owned-object Write/Consume durable
composition and an additive trusted preinstalled-WASM node-core entrypoint are
now available. The latter resolves the exact active module record captured
from committed `ProtocolConfig`, checks the preinstalled
code/manifest/semantics commitments under dedicated hash domains, remains
compatible with epoch-only hash-suite rotation, enforces a conservative fuel
ceiling, executes bounded deterministic WASM, and atomically commits its
owned-object effects, nonce, receipt, and outbox. Traps are normalized before
their canonical effects enter a durable receipt. A new additive native-http
composition, `preinstalled_wasm_structured_durable_router`, now invokes this
path over HTTP; `structured_durable_router` remains on the read-only
entrypoint and is unaffected.

The planned Developer MVP product surface (see `ARCHITECTURE.md` DR-0081) will
be implemented in this order: `apps/devnet` (a local devnet binary/startup
composition around the existing preinstalled-WASM route); a separate bounded
query-API slice in the protocol/native HTTP surfaces for chain/context info,
objects, receipts, and nonces; `clients/rust`; `apps/cli` (a
Rust-only developer CLI depending only on `clients/rust`, never a Node/browser
runtime), `clients/typescript`, `apps/explorer`, and `apps/wallet`. The
explorer and wallet are separate static/CSR SvelteKit + shadcn-svelte apps —
no request-time server-side rendering, server adapter, or server-held
sessions/keys; build-time prerendering of a fixed static shell is allowed, and
wallet signing keys stay in the browser only. These surfaces occupy six
product paths under `apps/` and `clients/`. Restart/duplicate-request E2E
coverage and explicit documented development-only limitations complete the
gate. This sequence and layout supersede DR-0080's earlier `clients/typescript`/
`demo/counter` pairing; no `demo/counter` directory is created. Extraction of
any `clients/*` directory into its own repository remains deferred until the
canonical contracts/vectors are stable, a real independent consumer or release
cadence exists, and E2E can target a released devnet artifact.

The planned devnet demonstration contract will be a preinstalled
`sunrise.devnet.asset_account.v1` module with one `transfer` entrypoint
between two ordinary, same-sender-owned asset-account objects, using the same
single `AssetId`/account/transfer path as every other asset — there is no
privileged native coin or special-cased balance/transfer/fee path. It will
enforce conservation and fail closed on zero amount, underflow, overflow, and
asset-ID mismatch.
Because cross-owner destination authorization and object owner changes remain
fail-closed on the existing owned-effects path, this demonstrates only
same-sender asset movement, not user-to-user transfer; the devnet's fee
registry stays empty and every transaction commits with `fee_payment: None`.
The MVP remains single-validator, owned-object only, fee-free, local-SQLite,
and explicitly non-production.

The Phase 15-17 production exit criteria and accepted persistence designs are
preserved. Additional capacity/load/soak evidence, PITR, HA/failover,
provider-managed pooler certification, real-provider deployment, provider
trust, observability, and release rehearsal are frozen until the Developer MVP
Gate passes unless one is required to protect MVP correctness or fail-closed
behavior.

## Workspace map

| Area | Crates | Responsibility |
| --- | --- | --- |
| Protocol foundation | `protocol-types`, `canonical-encoding`, `hashing`, `crypto`, `commitments` | Stable identifiers, canonical bytes, domain separation, hash suites, signatures, and state commitment schemes |
| State and access | `objects`, `abi` | Versioned objects, ownership, object references, access modes, and transaction access manifests |
| Execution | `execution`, `contract-sdk`, `chain-ir`, `system-modules` | Transactions/effects, deterministic WASM, proof envelopes/verifier interfaces, contract host APIs, portable IR, and governed modules |
| Economics and governance | `fees`, `bonds`, `governance`, `protocol-upgrades`, `protocol-config` | Stablecoin fees/bonds, admission, governance actions, upgrades, migrations, and committed configuration |
| Runtime and consensus | `runtime`, `runtime-sqlite`, `runtime-postgres`, `validator-set`, `consensus`, `node-core` | Persistence/runtime interfaces, local durable SQLite state plus a local-only non-production structured SQLite adapter, normalized PostgreSQL structured commit and indexed outbox adapter, epoch validator snapshots, event-driven shared-object ordering, and one-event conditional transitions |
| Adapters | `native-http`, `adapters/shared`, `adapters/cloudflare-workers`, `adapters/deno`, `adapters/vercel`, `adapters/supabase-edge`, `adapters/aws-lambda` | Bounded native routing, shared Web ingress, Cloudflare Service-Binding ingress, authenticated Deno/Vercel/Supabase ingress, and AWS HTTP API v2 mapping around the canonical contract |

The repository intentionally keeps vendor-specific dependencies out of the
protocol core. Future Cloudflare, Vercel, Supabase, AWS, Deno, and native HTTP
support belongs in adapters around these crates.

## Getting started

### Prerequisites

- Rust 1.97.1 through rustup (the repository toolchain file selects it).
- Cargo, installed with Rust through [rustup](https://rustup.rs/).
- Node.js 22.20.0 and npm for the Cloudflare workerd suite.
- Deno 2.9.4 for portable adapter checks.

### Build and test

```bash
git clone https://github.com/kimurayu45z/sunrise-edge.git
cd sunrise-edge

cargo build --workspace
cargo test --workspace --all-targets
```

Install the Cloudflare test dependencies once, then run the complete repository
gate before submitting a change:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
```

To work on one crate while iterating:

```bash
cargo test -p consensus
cargo test -p execution
cargo test -p native-http

npm --prefix adapters/cloudflare-workers run check
cd adapters/deno && deno task check
```

## Protocol invariants

These rules are part of the architecture, not optional implementation details:

- Protocol-critical payloads use explicit, versioned canonical framing.
- Integers have explicit endianness; lists and byte strings are length-framed;
  floating point is not used in consensus-critical logic.
- Every protocol message binds `chain_id`, `protocol_version`, and `epoch` where
  applicable.
- Hashes and signatures use centralized domain separation.
- Hash algorithms are selected by protocol/epoch configuration, never by the
  transaction sender.
- Unknown algorithms, versions, schemes, and discriminants fail explicitly;
  there is no silent fallback.
- Historical digests remain readable across hash-suite upgrades, and upgrades
  do not require a global state scan or rehash.
- Relays and Tick senders may drop, duplicate, reorder, delay, replay, or mutate
  messages without becoming a safety trust root.
- Protocol core crates do not spawn background tasks, maintain global mutable
  state, or require persistent connections.

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) records the implemented architecture and
  decision records.
- [`TODO.md`](TODO.md) is the original design brief, detailed requirements, and
  phase roadmap.
- [`PERSISTENCE.md`](PERSISTENCE.md) defines provider-neutral production
  persistence requirements; [`POSTGRES.md`](POSTGRES.md) fixes the first
  normalized relational implementation design.
- [`AGENTS.md`](AGENTS.md) contains repository-wide instructions for AI coding
  agents and is also a useful contributor checklist for protocol-sensitive work.

When code and an aspirational roadmap differ, treat the implemented wire
format, tests, and accepted architecture decisions as compatibility constraints.
Document intentional architecture changes before implementing them.

## Security

This repository is research-stage software and does not yet provide a formal
security policy or vulnerability-reporting channel. Do not report exploitable
issues in a public issue if disclosure would put users or deployments at risk;
contact the repository owner privately instead.

Protocol code forbids Rust `unsafe` by default. The existing contract SDK is the
exception at its raw WASM host-ABI boundary; contract-facing APIs wrap that
boundary with checked safe functions.

## License

Sunrise Edge is licensed under the [Apache License 2.0](LICENSE).
