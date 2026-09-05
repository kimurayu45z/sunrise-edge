# Architecture decisions DR-0058–DR-0075

PostgreSQL implementation, authentication, object integrity, and production
fault-conformance decisions.

- DR-0058: Materialize the accepted normalized PostgreSQL generation-one schema
  before implementing transaction code. Keep migration and namespace bootstrap
  as explicit operator APIs, bind exact binary namespace and writer metadata,
  represent full-range unsigned values with checked decimal constraints, and
  verify the real schema and due index in PostgreSQL 18 CI. Do not expose DDL on
  request paths or claim schema application alone is a durable adapter.
- DR-0059: Implement normalized PostgreSQL structured commit through an explicit
  bounded synchronous pool. Derive acquisition and transaction-local lock/
  statement timeouts from the absolute durable-operation deadline, lock and
  revalidate exact schema/fence metadata, validate every canonical state read,
  and commit checked revisions, receipt, ordered outbox messages, and initial
  delivery state in one serializable transaction. Retry only proven
  serialization/deadlock aborts using the unchanged envelope, explicit attempt
  ceiling, and remaining deadline. Treat pre-dispatch failures
  as definite only with database evidence and classify unknown commit-boundary
  loss conservatively as indeterminate. Keep pool maintenance operational rather
  than a protocol liveness assumption, and do not claim production certification
  before indexed claim/ack and fault/capacity evidence exist.
- DR-0060: Implement normalized PostgreSQL indexed outbox recovery with retained
  lease-attempt history. Check the lease identity before selecting work, use
  exact-request locking for request-path delivery and stable
  `(available_at_ms, request_id)` ordering with `SKIP LOCKED` only for due queue
  selection, and expire a replaced attempt in the transaction that installs its
  successor. Reconcile an active lease to identical bytes, reject reuse after
  acknowledgement or expiry, and make acknowledgement idempotent from retained
  evidence after later messages advance. Hold a shared namespace-metadata lock
  against fence changes, use checked attempt/cursor/revision arithmetic, retry
  only proven unchanged-identity serialization aborts, and preserve unknown
  commit results as indeterminate. Treat PostgreSQL 18 tests as As-Is evidence;
  cancellation, abrupt faults, capacity, recovery, and provider certification
  remain separate exit work.
- DR-0061: Define durable-store behavioral conformance once in runtime behind a
  non-default test-support feature and run it against memory plus every durable
  adapter. Let each fixture supply trusted deadline and operator fence authority;
  do not weaken the production traits with test controls or manufacture schema
  evidence for stores without persisted schema identity. Require complete-read
  write-skew and absent/tombstone races, bounded concurrent outcome
  classification, retained lease fencing, and writer-fence handoff. A fence
  advance revokes the old writer but not an already committed unexpired delivery
  lease; the replacement writer waits for trusted lease expiry before reclaiming
  the work. Keep induced database aborts and schema skew as adapter capabilities,
  and keep commit-loss, abrupt-fault, backup/restore, capacity, and real failover
  outside this As-Is contract evidence.
- DR-0062: Add cooperative native cancellation only before a structured
  request's first durable storage dispatch. A cancellation-enabled composition
  supplies an explicit signal checked before blocking dispatch, at blocking-job
  entry, and immediately before the first storage call; after that call begins,
  ignore later cancellation and finish commit, claim, send, and acknowledgement
  reconciliation. Keep the signal out of `DurableOperationContext` and
  durable-store traits so adapters do not claim they can stop started synchronous
  work. Extend shared conformance
  with the exact expired-deadline boundary and PostgreSQL evidence with pool and
  row-lock deadline exhaustion plus conservative commit-boundary classification.
  Keep client disconnect, shutdown budgets, in-flight database cancellation,
  commit loss, and capacity/fault certification deferred.
- DR-0063: Add an optional shared commit-loss capability to durable-store
  conformance and exercise it only against a real, severable network
  transport. A fixture that implements it arms exactly one future `COMMIT`
  to be severed either immediately before it reaches the backend or
  immediately after the backend returns a successful acknowledgement for it,
  and reports whether its own fault fired and whether the backend actually
  returned that successful `CommandComplete`/`ReadyForQuery` before severing.
  Both instants must classify as `Indeterminate(ConnectionLost)`. The shared
  case injects the pre-dispatch instant once, for one plain state commit, and
  proves no state ground truth was published. It injects the post-acceptance
  instant three times: for one structured invocation commit, proving exact
  committed state and receipt ground truth and that a same-identity replay
  observes `RequestAlreadyCommitted`; for an outbox claim on that invocation's
  message, first proving with a different, never-used lease that the original
  lease is still active (`NoDueWork`) and then that a same-lease replay
  reconciles to the identical claimed message; and for the corresponding
  acknowledgement, first proving that reclaiming with the original lease is
  rejected as lease-ID reuse and then that a same-identity replay reconciles
  to acknowledged with the acknowledgement persisted and no message left due.
  These discriminating probes are required because a same-lease claim replay
  or same-identity acknowledgement replay alone would succeed identically
  whether or not the prior transaction actually persisted. A final unfaulted
  commit proves the connection pool recovers a healthy connection. This is
  evidence that the backend returned a successful acknowledgement before the
  driver lost it; it is not proof of crash durability under abrupt
  process/power loss. This evidence is additive to, not a replacement for,
  DR-0061's existing induced-abort/schema-skew coverage. The first
  implementation is a bounded, test-only `NoTls` TCP proxy in
  `runtime-postgres`'s live PostgreSQL test: it binds port 0,
  relays the untyped startup message and every later typed frame, detects
  the exact simple-query `COMMIT` a durable commit, claim, or acknowledgement
  dispatches last, and tracks the one active physical connection so `Drop`
  can sever it directly instead of waiting on the pool's own client teardown
  or the bounded per-socket I/O timeout. DR-0074 adds the same shared suite
  over a strictly authenticated client-to-test-terminator TLS leg. Keep abrupt
  process/power fault, disk-full/WAL exhaustion, PostgreSQL-server/provider TLS,
  backup/restore,
  capacity/load/soak, real writer failover, client disconnect, and in-flight
  cancellation deferred.
- DR-0064: Activate the already-normalized generation-one object tables through
  one typed runtime contract without changing canonical bytes or schema
  generation. Reuse `objects::Object`, its canonical encoder/decoder, and typed
  `Owner`; treat SQL `type_id` as the canonical Object record projection rather
  than its logical type hash. Keep current heads body-free, read immutable
  inline-or-blob versions separately, distinguish absence from retained
  tombstones, and advance an independent head revision on every lifecycle
  mutation so delete/recreate cannot produce ABA. A head read validates strict
  immutable-row metadata without selecting inline bytes. Its bounded owner and
  routing projections are atomically written routing hints, not authorization;
  execution must separately load the linked version, match head version/digest,
  decode an inline Object, and compare typed owner. Blob-backed execution stays
  fail-closed until fetch and content verification. PostgreSQL locks canonical
  object IDs, validates all head assertions and prospective immutable keys
  before applying any section, then publishes object/state/receipt/outbox rows
  in the same serializable transaction with immediate constraint validation.
  Shared memory/PostgreSQL conformance must prove bound-domain/fence/deadline
  rejection, the object read-count bound, lifecycle, replay, conflict
  rollback including outbox/version absence, and generation-one inline/blob
  mapping. Keep node-core object dispatch, fees, blob transfer verification,
  owned-object fast routing, schema migrations, and production fault/capacity/
  provider certification deferred.
- DR-0065: Implement a real, consensus-deterministic Ed25519 verifier in
  `crypto` using the exact-pinned `ed25519-zebra` 4.2.0 crate (declared once
  in `[workspace.dependencies]` with default features disabled; the
  committed `Cargo.lock` pins its `curve25519-dalek` dependency at 4.1.3, and
  no unused direct dependency on `curve25519-dalek` is added — every future
  Dependabot proposal for either pin stays review-gated per the existing
  policy, not auto-merged), accepting only exactly-32-byte verification keys
  and exactly-64-byte signatures and using ZIP-215 verification semantics
  (accept non-canonical point encodings and small-order points) as the
  consensus validation profile, so every validator reaches the same
  accept/reject decision. `verify_framed` copies a length-checked signature
  into an explicit `[u8; 64]` and builds `ed25519_zebra::Signature` through
  its infallible fixed-size `From` constructor, so there is no
  dead/mislabeled length-error mapping on an already-length-checked value.
  Add no production signer. `runtime::MemorySigner` is a public in-memory
  wiring fixture used to compose test/local runtimes; it is deliberately
  non-cryptographic and must never be used for protocol authentication — it
  is not gated behind a test-only compilation flag, so callers must not
  infer safety from where it is used. `SignatureSigner::sign_canonical` and
  `SignatureVerifier::verify_canonical` (the trait default methods) reject
  with a typed `CryptoError::SignatureSchemeMismatch { expected, actual }`
  before any framing or cryptographic operation if the caller-supplied
  `SignatureDomain::signature_scheme_id` does not equal the signer's or
  verifier's own `scheme_id()`; `frame_signature_message`'s byte format is
  unchanged; only the trait default methods gained this precondition, and
  tests prove a mismatched scheme is rejected without the underlying
  operation running. Commit a `protocol_config::TransactionAuthProfile` as
  `ProtocolConfig` field 15 at a new encoding version 3, required only from
  protocol version 3 and absent for versions 1-2, leaving historical v1/v2
  bytes unchanged; the profile carries an explicit non-zero `u16 profile_id`
  (matching other stable protocol identifiers) that is itself a committed
  protocol identifier, not an arbitrary non-zero label —
  `TransactionAuthProfile::new` and the new `TransactionAuthProfile::validate`
  (called by `new` and by `ProtocolConfig::validate` on any committed
  profile, not only re-checking a zero id) apply the same rules: reject a
  zero id, reject every id other than the public
  `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID` constant (value 1) with a typed
  `UnsupportedTransactionAuthProfileId`, and only then validate the
  scheme/binding combination — a `SignatureSchemeId` (Ed25519 only;
  Secp256k1 is reserved and fails closed), and a closed `AddressBinding`
  enum whose only implemented variant, `AddressIsPublicKey`, treats a
  transaction's address bytes directly as its Ed25519 public key.
  `ed25519_address_is_public_key()` takes no argument and always constructs
  that one profile. Any new profile id, and any later address binding,
  requires a new protocol/transaction version and an explicit accepted
  decision, not a silently added identifier or enum variant. Add
  `protocol_config::resolve_transaction_auth_profile` as the
  commitment/resolution entry point: it validates the whole configuration
  before returning, so a malformed configuration fails closed ahead of any
  activation check, and it fails closed for a premature profile, a missing
  required profile, or any other invalid configuration. `protocol-config`
  performs no signature verification and has no dependency on `crypto` or
  `objects`; it resolves committed configuration only. Actual transaction
  authentication — constructing the `SignatureDomain` from the resolved
  profile and the exact transaction-v1 message family, rejecting (not
  reconciling) any mismatched context, verifying the signature, and bounding
  the canonical signable byte length before hashing or verifying it — is a
  separate boundary deferred to the PR that adds strict
  `execution::Transaction` v1 decoding. The owned fast-path certificate flow
  is likewise deferred, and protocol version 3 MUST NOT activate on any live
  chain before that decoding/enforcement boundary lands (see the hard
  activation constraint in [core-protocol.md §8](../core-protocol.md#8-signature-domain-separation)). `Ed25519Verifier` test evidence includes a
  fixed-bytes negative case for a 64-byte signature whose `S` component is
  non-canonical (`S >= l`), rejected as `Ok(false)` per RFC 8032 §5.1.7's and
  ZIP-215's shared, explicit `S < l` rule, alongside the existing RFC 8032
  known-answer, ZIP-215 small-order/non-canonical-point acceptance, and
  signature-domain-mismatch evidence; all fixed vectors were re-confirmed
  against the `ed25519-zebra` 4.2.0 / `curve25519-dalek` 4.1.3 pins.
- DR-0066: Enforce strict persistent sender nonce equality only on the
  authenticated structured durable `SubmitTransaction` path. Derive a private
  reservation from the verified inner transaction's exact sender, epoch, and
  nonce; callers cannot construct or override it. Persist canonical next-nonce
  record `0xE006`, whose bytes redundantly bind sender and epoch for strict
  key/value cross-checking, under the deterministic `PersistenceLayout`
  namespace keyed by chain, protocol version, sender, and epoch. Missing means
  zero, equality is exact, and increment uses checked `u64` arithmetic. Reconcile
  a matching completed receipt before reading the nonce; otherwise read and
  validate the nonce before any application state or transition, then include
  its revision assertion and increment in the same normalized invocation as
  application state, receipt, and outbox. This makes absent-record and
  existing-record races conflict atomically. A committed `Accepted` or
  deterministic `Rejected` response consumes the nonce; authentication,
  transition, or pre-commit rejection does not. An indeterminate commit must be
  reconciled under the original request ID. Return typed mismatch and overflow
  errors, mapped by native HTTP to `409 sender-nonce-mismatch` and
  `422 sender-nonce-overflow`. Reserve one atomic state-write slot and reject
  every application plan key under the complete nonce prefix for every event
  family, with the same post-transition defense; do not branch this namespace
  protection on event kind. Placement continues to use the application plan
  length only. Clients must serialize exact next-nonce submissions; no future
  nonce queue or pipelining is introduced. Epoch and protocol-version rollover
  create a fresh namespace, with trusted monotonically advancing node epoch and
  signed epoch providing the replay boundary. A non-initial tombstone fails
  closed rather than resetting an accepted epoch to zero. Pruning after an
  epoch becomes permanently unacceptable is safe in principle but remains
  operationally deferred. Exhausting `u64::MAX` bricks that sender until epoch
  rollover. Until fee debit and a bounded retention policy are composed, valid
  new senders can grow nonce state without economic metering; this As-Is route
  must not be exposed as activated live transaction ingress.
  Reuse the generic normalized state schema, so no database schema generation
  or Transaction wire/schema version changes; historical Transaction bytes are
  unchanged. Live protocol-version-3 activation remains blocked on atomic fee,
  typed object/effect, certificate, and non-transaction ingress authorization
  work.
- DR-0067: Before fee debit or object effects, authorize the signed read-only
  `AccessManifest` on the authenticated structured durable path. Derive the
  sole authority from the verified inner transaction sender; never re-decode
  the outer event or authorize from a body-free head projection. Reconcile an
  exact receipt first, enforce and reserve the sender nonce second, then load
  each bounded manifest entry in canonical object-ID order through exact head,
  exact immutable version, inline canonical Object, and typed owner. Address
  ownership must match the authenticated sender even for reads; immutable
  reads are allowed. Write/consume modes, shared/system owners, blob-backed
  bodies, absent/tombstoned objects, and adapters without normalized object
  storage fail closed. Match the signed self-describing version/digest and
  cross-check record identity and schema version, and require the current
  inline head's owner projection to exist and exactly match the typed owner
  before authorization. Object digest recomputation is now performed in
  node-core using the object version's own stored provenance (DR-0068); it is
  no longer withheld pending that provenance's availability. Cap this
  pre-activation fan-out at 32 entries before object I/O without changing
  committed domain placement semantics. Append every exact observed head as a
  mutation-free `DurableObjectChanges` read assertion after the pure
  application transition, so the machine cannot influence it and any
  concurrent head change rejects the whole state/nonce/receipt/outbox commit.
  Preserve exact replay and stale nonce short-circuits before object reads.
  Map object-head conflicts as a retryable 409 without consuming the nonce.
  Add no canonical wire type, type ID, database schema, asset balance
  representation, or object mutation. Protocol version 3 remains inactive
  pending module loading, fee debit, mutating/consuming effects,
  shared-object consensus routing, blob fetch/content verification, fast
  certificates, and the other externally accepted event-family authorization
  boundaries.
- DR-0068: Persist the creating `chain_id`/`protocol_version` (as
  `DurableObjectProvenance`) on every immutable object-version record, as a
  required field — the schema is redefined in place so there are no legacy
  rows and absence is unrepresentable. `node-core` independently recomputes
  and verifies each authenticated object's digest in
  `load_and_authorize_objects`, after the inline payload and identity/schema
  cross-checks and before the owner-projection cross-check, using
  `hashing::verify_digest` with the algorithm self-describingly recorded in
  the stored `Digest32` and the record's own provenance — never
  `HashSuiteResolver::hash_for_purpose`, which would select the algorithm from
  the reader's epoch suite and misjudge a legitimate object created under a
  different suite or protocol version. The record's provenance `chain_id`
  must equal the trusted event chain (objects never migrate chains); no
  equivalent check applies to `protocol_version`, since an older object must
  still verify. Inline bodies are bounded before hashing:
  `MAX_AUTHENTICATED_OBJECT_BODY_BYTES` (1 MiB) per object and
  `MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES` (8 MiB) aggregate per
  invocation — pre-activation admission budgets, not measured capacity
  limits, stricter than the 32 MiB storage-side `MAX_DURABLE_INLINE_OBJECT_BYTES`.
  `runtime` stores provenance as inert data and does not verify it itself (it
  depends on `hashing` only as an optional/dev dependency). PostgreSQL
  generation one is redefined in place under schema identity
  `POSTGRES_SCHEMA_IDENTITY` v2 (bootstrap only, `POSTGRES_SCHEMA_GENERATION`
  stays `1`), adding `created_chain_id_bytes`/`created_protocol_version`
  columns to `object_versions` with a `CHECK (created_chain_id_bytes =
  chain_id_bytes)` invariant; an existing v1 database fails closed with
  `SchemaMismatch` on bootstrap, inspection, and every request-path metadata
  read, with no tolerance, alias, or fallback identity. This discharges the
  DR-0067 "digest provenance" pending item. Still deferred: module loading,
  fee debit, mutating/consuming effects, shared/system owners, blob-backed
  body verification, and a future `HASH_DOMAIN_VERSION` bump (which is itself
  protocol-critical and would need its own provenance).
- DR-0069: Add a live, serialized `runtime-postgres` integration test that
  `docker kill --signal=KILL`s the database-process container immediately
  after a committed structured invocation and verifies recovery through
  `docker start` plus a fresh connection. The test commits one structured
  invocation containing state, an exact receipt, and one due outbox message,
  observes `Committed` with the committing pool still alive, then — with no
  intervening SQL — sends the kill as direct argv (never a shell string)
  against a container ID validated as lowercase hex and supplied only
  through CI-controlled configuration, never derived at test time. It then
  restarts the same container, boundedly polls a fresh client/`SELECT 1` for
  readiness — the exact readiness criterion this test needs is a fresh
  external connection plus `SELECT 1`, not a container-local probe — and
  reconnects to verify the exact state revision/value, the exact receipt, an
  identical `RequestAlreadyCommitted` replay, one exact claim and
  acknowledgement followed by `NoDueWork` for that request, and a final
  unfaulted commit. Also capture `pg_postmaster_start_time()`, projected as
  an exact integer microsecond count (via `EXTRACT`'s `numeric` return type,
  never a float, so nothing float-typed crosses into the Rust decode), once
  immediately before the commit and again after restart through the fresh
  connection, and assert it strictly advanced — this catches a configured
  container ID that is valid but names an unrelated container, since killing
  and restarting the wrong container leaves the real database process's
  postmaster start time unchanged. Serialize this
  test against every other live-database test with a bounded, cross-process,
  atomically created (`create_new`/`O_EXCL`) lock file, since more than one
  `cargo test` binary may run destructive live tests concurrently and this
  one kills the shared database-service container out from under the rest.
  An abandoned lock (its owning process killed before it could run `Drop`)
  is never automatically reclaimed — a reclaiming waiter would need a
  read-check-remove sequence that is inherently TOCTOU, able to delete a
  replacement lock a new legitimate owner had just created — so it instead
  fails every future acquisition loudly once the bound elapses, pointing at
  the file for a human to remove. CI supplies the exact database-service
  container ID and marks the scenario required so a broken container-ID
  derivation fails the run instead of silently skipping; partial
  configuration (only one of the live URL or container ID set) always fails
  rather than skipping. This proves PostgreSQL database-process SIGKILL and
  WAL recovery on a live host with a live page cache; it does not prove
  abrupt host/power loss, storage write-cache flush/torn-write/media/
  filesystem faults, WAL exhaustion, commit-boundary or real-device ENOSPC,
  TLS-path behavior,
  backup/restore, capacity/load/soak, real writer failover, provider
  certification, or production readiness, all of which remain open. DR-0070
  below separately covers bounded pre-commit data-tablespace ENOSPC only.
- DR-0070: Add a required live `runtime-postgres` integration test for a real,
  bounded data-tablespace `ENOSPC` before `COMMIT`. Start an exact
  digest-pinned disposable PostgreSQL 18 container with PGDATA, WAL, and
  transaction status on an unfilled 512 MiB tmpfs and the database default
  tablespace on a distinct 64 MiB tmpfs. Verify the SQL connection and Docker
  exec target share an identity marker, verify the tablespace and PGDATA/WAL
  device IDs differ, and verify the bounded filesystem capacity before
  filling only the tablespace. A direct large incompressible relation write
  must return SQLSTATE `53100`; the same fault applied to a structured durable
  invocation must return the definite pre-commit
  `Rejected(UnavailableBeforeCommit)`. After removing the filler, use the same
  pool/store to prove no state or receipt was published and the commit sequence
  did not advance, then commit and replay the identical invocation and complete
  its exact outbox claim/acknowledgement. Docker commands use direct argv,
  bounded time/output, strict digest/env parsing, and panic-safe removal of the
  exact created container. This changes no schema, schema identity/generation,
  canonical bytes, or protocol behavior. It proves only RAM-backed
  data-tablespace VFS `ENOSPC` before commit; WAL exhaustion, commit-boundary
  ENOSPC, real storage cache/media/filesystem failure, host/power loss, and
  production certification remain open.
- DR-0071: Add a required live `runtime-postgres` integration test for a real,
  bounded WAL-filesystem `ENOSPC`. Start an exact digest-pinned disposable
  PostgreSQL 18 container that relocates `pg_wal` with `initdb --waldir` onto
  its own 64 MiB tmpfs, distinct from and much smaller than the unfilled
  512 MiB tmpfs holding PGDATA and the (unmodified) default tablespace.
  Verify the SQL connection and Docker exec target share an identity marker
  on the WAL mount, verify `pg_wal` resolves to the exact configured WAL
  directory, verify the PGDATA/WAL device IDs differ, and verify both
  filesystems' bounded capacity before filling only the WAL mount. Live
  evidence, not an assumption carried over from DR-0070: a direct
  incompressible write large enough to force a new configured 2 MiB WAL
  segment still
  returns SQLSTATE `53100` (`disk_full`), but at `PANIC` severity rather than
  DR-0070's plain `ERROR`, and the same connection then closes as PostgreSQL
  terminates every backend and crash-restarts the whole postmaster (whose own
  automatic recovery attempt fails the same way, since it also needs to
  write WAL, taking the server down a second time). After freeing WAL space
  and restarting in place, refill the same mount independently and use a
  bounded incompressible state mutation so the adapter's own structured
  invocation commit is the operation that exhausts WAL and crashes the
  server. Its public outcome must be the observed definite pre-commit
  `Rejected(UnavailableBeforeCommit)`; the adapter does not expose the raw
  database error, so only the direct first cycle claims exact SQLSTATE and
  severity. The definite rejection is justified because this failure occurs
  before the adapter dispatches its own `COMMIT`, so no partial effect of
  that invocation can have reached durable storage. Because the fault
  is fatal to the whole server rather than to one connection (the key
  difference from DR-0070's data-tablespace ENOSPC, which leaves the
  connection and server alive), the container overrides its entrypoint with
  a small supervisor script that keeps the *container* itself alive across
  the crash — confirmed by asserting the container stays "running" while
  `pg_ctl status` reports the server is not — so recovery can free WAL space
  and restart postgres **in place** with `pg_ctl start` on the same,
  never-torn-down tmpfs mounts; `docker start`/`docker kill` are never used
  here, since either would recreate every tmpfs mount empty and destroy the
  evidence. A strictly-advanced `pg_postmaster_start_time()` after each of
  the two restarts proves two genuine crash/recovery cycles (not lucky
  reconnects to a server that never actually went down), and the same
  pool/store prove no state or receipt was published and the commit sequence
  did not advance, then commit and replay the identical invocation and
  complete its exact outbox claim/acknowledgement. Docker commands use direct
  argv, bounded
  time/output, strict digest/env parsing, and panic-safe removal of the
  exact created container. This changes no schema, schema
  identity/generation, canonical bytes, or protocol behavior. It proves only
  RAM-backed WAL-filesystem `ENOSPC` outside the commit boundary. Neither this
  nor DR-0070 has live evidence for a WAL or data `ENOSPC` at the commit
  boundary itself (that is, a fault during the literal `COMMIT` statement
  rather than an earlier statement in the same transaction); commit-boundary
  `ENOSPC` therefore remains open, and this decision makes no
  ENOSPC-specific claim about its result classification.
  Real storage-device ENOSPC, block-device faults, host/power loss, and
  production certification also remain open.
- DR-0072: Add a required live `runtime-postgres` integration test for real
  server connection-slot exhaustion. Start an exact digest-pinned disposable
  PostgreSQL 18 container configured with a tiny exact `max_connections`
  (5), zero `superuser_reserved_connections`, and zero PostgreSQL 16+
  `reserved_connections` (a second, independent reserved pool for roles with
  the `pg_use_reserved_connections` predefined role) so no role gets a
  capacity carve-out this scenario's counting would need to special-case.
  `autovacuum` is also disabled, but only as optional quiescence against
  unrelated background activity: autovacuum workers and the autovacuum
  launcher are accounted from their own separate budget
  (`autovacuum_max_workers`, alongside `max_worker_processes` and
  `max_wal_senders`), never carved out of `max_connections`, so this
  scenario's `backend_type = 'client backend'`-filtered counts already
  exclude them regardless. An already-open operator connection
  bootstraps the disposable namespace and, immediately after the short-lived
  admin client that created the database is dropped, boundedly polls through
  that same connection until exactly one active client backend (its own) is
  visible — proof the admin client's asynchronous connection teardown has
  actually been processed server-side, since without it the admin backend
  could still transiently count against capacity right as the blocker loop
  starts. This poll is safe because no `r2d2` pool exists yet at this point
  and nothing else in the scenario can spontaneously open or close a
  connection, unlike a later point in this same scenario (see below), where
  polling for a transient count would not be safe. The operator connection
  then reads back the server's own `max_connections`,
  `superuser_reserved_connections`, and `reserved_connections` settings as
  configuration ground truth, and stays open for the whole scenario. A small,
  exactly bounded number of direct blocker connections then saturate every
  remaining slot; one further direct connection attempt is live evidence of
  genuine exhaustion: SQLSTATE `53300` (`too_many_connections`) at `FATAL`
  severity, with the exact active client-backend count independently
  confirming full capacity through `pg_stat_activity`. With capacity still
  fully exhausted, a freshly built, max-size-one adapter pool — proven to
  hold zero physical connections before its first checkout via the pool's own
  `state()` — drives one bounded structured invocation commit. Live evidence,
  not the naively assumed `Rejected(UnavailableBeforeCommit)`: `r2d2`'s
  `Pool::get_timeout` only ever returns once it either succeeds or its entire
  requested wait elapses — it never returns early on a bare connection
  refusal — so by the time this crate's connection-acquisition helper
  re-checks the caller's operation deadline to classify the failure, that
  deadline has, by construction, also just elapsed. Pool exhaustion and
  deadline exhaustion therefore collapse into the same observable outcome in
  this adapter: the definite pre-commit
  `Rejected(DeadlineExceededBeforeCommit)`, not `UnavailableBeforeCommit`
  (which this adapter reserves for a fault surfacing after a connection and
  transaction are already open, as in DR-0070/DR-0071's disk-full/WAL-full
  scenarios). This is proven bounded, not merely assumed, by asserting the
  call's observed wall-clock duration tracks its configured context deadline
  rather than running away past it, and that the pool records zero
  connections both before and after the attempt. Because the adapter pool
  itself cannot open any new connection while the server is saturated,
  non-publication of the state row, receipt row, outbox row, and commit
  sequence is proven directly through the still-open operator connection
  instead of through the store. The rejected attempt's own internal
  connection attempt does not stop once `commit_invocation` returns: `r2d2`
  keeps retrying it independently, on its own short backoff, until it
  succeeds or the pool is dropped, so the slot freed by releasing exactly one
  blocker connection can be reclaimed by that already-running background
  retry at any time, not necessarily by a call this test makes. Polling for
  an intermediate server-side count after releasing the blocker would
  therefore race that independent retry and be flaky by construction; this
  test instead proves recovery deterministically by requiring the next
  `commit_invocation` call to succeed once capacity is available however it
  became available, then, through the same still-open operator connection,
  proving the post-recovery, steady-state active client-backend count equals
  `max_connections` exactly and that precisely one of those backends carries
  the adapter pool's own distinct `application_name` — confirming specifically
  that the adapter pool, not some other connection, reclaimed the freed slot.
  The identical invocation then commits through the same pool and store; the
  test also proves the exact `RequestAlreadyCommitted` replay, one exact
  outbox claim/acknowledgement followed by `NoDueWork`, and pool usability
  afterward. This changes no schema, canonical bytes, or protocol behavior.
  It proves only real PostgreSQL server-side connection-slot exhaustion and
  this adapter's resulting deadline-based classification; it does not prove
  real-device resource exhaustion, load/soak capacity, connection-pool
  behavior under a provider-managed pooler (e.g. PgBouncer), TLS-path
  connection loss, real writer failover, or production certification.
- DR-0073: Add a required live `runtime-postgres` integration test for a
  bounded database-snapshot restore rehearsal. Start two separate
  digest-pinned disposable PostgreSQL 18 containers — a source and a fully
  isolated target, each its own container process with its own generated
  password and published host port, never merely two databases inside one
  server — and commit one structured invocation (state, receipt, one pending
  outbox message) on the source. Take a snapshot with `pg_dump -d <db>
  --no-owner --no-privileges --inserts` inside the source container through
  bounded `docker exec` output capture; `--inserts` avoids `COPY ... FROM
  stdin` embedded data blocks, whose "data follows in the same script"
  convention is implemented by `psql` itself, not the wire protocol, so the
  captured plain-`INSERT` snapshot is a fully self-contained SQL script this
  test applies directly through `postgres::Client::batch_execute` over its
  own bounded connection to the target, with no intermediate file, `docker
  cp`, or `psql` subprocess. PostgreSQL 18's `pg_dump` additionally brackets
  plain output in `\restrict`/`\unrestrict` lines, a `psql`-only safety
  meta-command pair emitted by the pinned PostgreSQL 18 tool, not SQL; the
  server rejects them as a syntax error over the wire, so the test strips
  those two fixed lines before executing the snapshot, a deterministic format
  transform of *how* the snapshot is applied, not a content corruption of the
  schema or data it represents. Before advancing the copied namespace fence, the
  test verifies exact schema identity (`verify_initial_schema`) and reads the
  exact restored namespace metadata, state, and receipt back through the
  normal adapter read path, never by inferring row contents from raw SQL. It
  then advances the restored namespace's writer fence through the
  operator-only `advance_writer_fence` seam, proves a stale context still
  carrying the pre-backup fence is rejected as `Rejected(WriterFenced {
  .. })` against the restored target with no publication, and proves a fresh
  context carrying the new fence reconciles the exact restored
  receipt/state, observes `RequestAlreadyCommitted` for the identical
  invocation, and claims and acknowledges the exact restored pending outbox
  payload through `NoDueWork`, and then commits genuinely new work. This
  target-only fence advance does not stop or fence the separately running
  source database, so it is not evidence of a single-writer failover. A
  deterministic negative pair uses two additional databases on that same
  target container. A dump cut immediately after the opening parenthesis of
  the required `storage_metadata` table definition must fail its one
  simple-query batch atomically and leave no schema marker. A syntactically
  valid dump with exactly the fixture's `state_records` insert removed must
  restore schema identity, namespace metadata, and receipt cleanly, yet fail
  the deeper rehearsal verification gate on missing state. This
  changes no schema, canonical bytes, or protocol behavior. It is a bounded
  database-snapshot restore rehearsal only, explicitly not a production
  backup/restore capability, and critically does not close the accepted
  backup/restore evidence criterion: it does not prove point-in-time
  recovery, continuous WAL archiving/shipping, a hot/consistent backup taken
  under concurrent write load, `pg_basebackup`/replication-based backup,
  backup encryption or off-host storage, retention/rotation policy, restore
  automation, checkpoint publication (the schema has no implemented
  checkpoint-publication path; `sunrise_edge.checkpoints` is not written or
  read by anything in this crate), blob-manifest verification, state-root
  verification, encryption-key verification, multi-database/whole-cluster
  backup, backup under concurrent adapter write traffic, real storage-device
  or off-host transfer faults, capacity/load/soak, PostgreSQL-server/provider TLS,
  real writer failover beyond the one bounded fence advance proven here, or
  production certification.
- DR-0074: Run the existing shared commit-loss conformance a second time
  through a bounded test-only TLS terminator. The client uses ordinary
  PostgreSQL `SSLRequest` with `SslMode::Require`; rustls trusts only an
  ephemeral private CA and validates a `localhost` SAN, while a live IP-host
  negative connection must fail. The proxy counts completed authenticated
  handshakes, then inspects the decrypted PostgreSQL frames and injects the
  same before-dispatch and after-backend-acceptance faults, preserving the
  independent state/receipt/claim/ack ground-truth probes and pool-recovery
  proof. The proxy's backend leg is plaintext to the dedicated test database.
  This changes no schema, canonical bytes, or protocol behavior and proves
  only client/driver-to-test-terminator TLS connection-loss classification;
  PostgreSQL-server TLS, provider trust stores, mTLS, certificate
  rotation/revocation, and production certification remain open.
- DR-0075: Add a required live `runtime-postgres` integration test for a
  bounded local PgBouncer transaction-pooling rehearsal. Start a
  digest-pinned PostgreSQL 18.6 container and a digest-pinned
  `ghcr.io/icoretech/pgbouncer-docker` 1.25.2 container on one isolated,
  freshly generated Docker bridge network; PgBouncer resolves PostgreSQL only
  by its network alias, never a host-published address, and this test's own
  direct verification connections bypass the proxy entirely against
  PostgreSQL's own separately published port, so they stay usable even while
  the proxy's single backend is deliberately held busy. The proxy's
  `pgbouncer.ini`/`userlist.txt` are written into the container over stdin
  via `docker exec ... dd of=<path> status=none`, one argv call per file with
  no shell, no host bind mount, and no echo of the written credential/config
  into captured output — unlike `tee`, BusyBox `dd` with `status=none`
  writes only to the target file and produces no stdout at all; credentials
  are a freshly generated password whose PostgreSQL
  `pg_authid.rolpassword` (with `password_encryption=md5` pinned on the
  container) is read back and used directly as the userlist's MD5 credential
  hash, never invented or hashed by the test itself. The rendered
  configuration sets `pool_mode = transaction`, `pool_size`/
  `default_pool_size`/`max_db_connections`/`max_user_connections = 1` for the
  one tested database/user pool, a nonzero `max_prepared_statements`, and a
  bounded `query_wait_timeout`; every one of these is asserted through
  PgBouncer's own admin console (`SHOW CONFIG`/`SHOW POOLS`/`SHOW DATABASES`/
  `SHOW SERVERS`/`SHOW CLIENTS`, queried over the simple query protocol, the
  only protocol the admin console answers), never inferred from client-side
  behavior — `SHOW CONFIG`'s `default_pool_size`/`max_db_connections`/
  `max_user_connections` and the tested database's own `SHOW DATABASES`
  `pool_size` are each independently read back and asserted exactly one, not
  merely inferred from the rendered `pool_size` alone. Two
  distinct client connections, open simultaneously, each run one sequential
  transaction; `SHOW SERVERS`' `remote_pid` is identical after both, proving
  transaction pooling actually reused one physical PostgreSQL backend rather
  than opening a second. The real adapter (a genuine `r2d2` pool plus
  `PostgresDurableStore`, distinguished by its own `application_name`) is
  then pointed at the proxy, not PostgreSQL directly. While a separate direct
  proxied client holds the pool's only backend inside an open transaction
  (left open by simply not sending `COMMIT`/`ROLLBACK`, not a timed sleep,
  and proven by the sole `SHOW SERVERS` row for that database reporting
  PgBouncer's own `active` state, not merely existing),
  one adapter structured invocation is driven with a context deadline well
  longer than PgBouncer's own `query_wait_timeout`; live evidence, not an
  assumed classification: PgBouncer's queue timeout surfaces as
  PostgreSQL-protocol SQLSTATE `08P01` (`query_wait_timeout`) on the
  adapter's first statement (its transaction-opening `BEGIN`), which this
  crate's `PreCommitFailure::from_sqlstate` has no dedicated arm for and so
  falls through to its default `Unavailable` bucket — the definite pre-commit
  `Rejected(UnavailableBeforeCommit)`, never `Indeterminate`. The observed
  elapsed time is bounded from both directions around PgBouncer's own
  `query_wait_timeout` specifically (not this probe's own much larger context
  budget), proving the rejection's timing tracks the proxy's queue timeout,
  not an unrelated deadline. No state/receipt/outbox row is published,
  checked through the direct, proxy-bypassing verification connection, which
  the proxy's contention cannot affect. After the blocking transaction is
  released, the identical invocation is retried through the same adapter
  pool/store; a bounded, explicitly documented retry tolerates one specific,
  live-verified transient distinct from a genuine proxy rejection by its
  timing alone (`r2d2` can occasionally recycle, rather than evict, the
  blocked probe's connection if its local `is_closed()` state has not yet
  caught up with PgBouncer's asynchronous socket close, so the very next
  checkout can be handed that already-dead connection and fail near-instantly
  with a local, unclassified I/O error — also `Rejected(UnavailableBeforeCommit)`
  by the same default classification, but resolved in sub-millisecond time
  rather than tracking `query_wait_timeout`); the retry only tolerates that
  exact narrow shape, and the loop's final outcome must still be `Committed`
  (its accumulator is seeded with a rejection, never `Committed`, so a future
  edit shrinking the retry bound to zero attempts fails loudly instead of
  vacuously passing).
  Recovery proves `Committed`; `SHOW SERVERS`' `remote_pid`, read again,
  proves the recovered commit was served by the exact same sole backend the
  two synthetic clients observed above, not a different backend process;
  `SHOW CLIENTS` filtered by the adapter pool's
  `application_name` proves specifically that the adapter pool's own proxy
  connection reclaimed the freed backend, a replay of the identical
  invocation returns exact `RequestAlreadyCommitted`, the exact outbox
  message claims and acknowledges through `NoDueWork`, and the pool remains
  usable for a further read. This changes no schema, canonical bytes, or
  protocol behavior. It is explicitly a bounded local PgBouncer
  transaction-pooling rehearsal only: it does not prove provider-managed
  pooler service certification, load/soak capacity, PgBouncer high
  availability or connection draining, TLS on either the client or backend
  leg, real writer failover, or production readiness.
