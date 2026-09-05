# Architecture decisions DR-0076–DR-0080

Developer-MVP sequencing, owned effects, preinstalled WASM, SQLite, and native
HTTP composition decisions.

- DR-0076: Prioritize an explicit Developer MVP Gate before further Phase
  15-17 production hardening. Preserve every production exit criterion, but
  freeze additional capacity/load/soak, PITR, HA/failover, managed-pooler,
  provider-certification, and deployment work unless it blocks MVP correctness
  or fail-closed behavior. Start with a private verified-object/effect
  translator: it can consume only node-core's already-authorized typed inputs,
  rejects any mismatch or unsupported scope, and emits bounded runtime
  Update/Delete mutations. Keep live Write/Consume rejected until a subsequent
  change atomically composes trusted deterministic execution effects with the
  existing nonce/state/object/receipt/outbox transaction. Complete the MVP with
  one preinstalled deterministic contract, local devnet/query APIs, a
  TypeScript client, a counter UI, and restart/duplicate E2E evidence; retain
  explicit single-validator, owned-only, fee-free, local-SQLite,
  non-production limitations.

  **Amendment: product-surface deliverables superseded by
  [DR-0081](0081-0087-cli-first-roadmap.md).** The
  Developer MVP priority and production-hardening freeze above remain in
  force. [DR-0081](0081-0087-cli-first-roadmap.md) replaces only this entry's earlier TypeScript-client/counter-
  UI completion shape with the ordered local-devnet/query/Rust-client/Rust-
  CLI/TypeScript-client/explorer/wallet surface and its uniform asset-account
  demonstration; the counter UI is cancelled, not merely deferred.
- DR-0077: Expose owned Address-object Write/Consume as a separate additive
  authenticated node-core entrypoint rather than weakening the existing
  read-only path. Supply verified objects to the pure transition in signed
  manifest declaration order and require exact signed-access/effect
  correspondence. Treat the creation checkpoint as trusted composition input,
  reject checkpoint regression, and commit object head/version changes with
  nonce, state, receipt, and outbox in one structured durable invocation. Reconcile exact
  request replay before object I/O or execution. Generic handlers receive no
  objects and reject effects. Keep native HTTP on the read-only entrypoint
  until the preinstalled module commitment and bounded deterministic WASM
  execution provide the trusted caller; this changes no canonical bytes or
  storage schema.
- DR-0078: Add a trusted, additive preinstalled-WASM composition without
  weakening the read-only/native path. Interpret `Transaction.module_ref` on
  this MVP path as exact `(ModuleId, version, canonical_code_hash)` fields,
  capture the matching `SystemModule` record or its absence from the same
  committed `ProtocolConfig` used for authentication, and resolve bytes only
  from a bounded immutable node-supplied catalog. Verify code under
  `ContractCode` and manifests under the existing stable `SystemModule` domain
  through the new `SystemModuleManifest` purpose, always using each committed
  `Digest32`'s own algorithm so epoch-only hash-suite rotation preserves old
  modules. Because the hash frame also binds `protocol_version` and registry
  entries do not yet retain commitment provenance, governance must re-commit
  code and manifest digests for a protocol-version upgrade in the new
  `ProtocolConfig`; versioned provenance remains post-MVP work. Require at
  least one authenticated object, retain the object-count placement projection
  only for the current single `AllState` rule, and enforce a conservative
  pre-activation fuel ceiling. Return canonical execution effects, but
  normalize every engine trap to one fixed reason, a deterministic full-gas
  charge, and empty effects/events before receipt persistence. Successful
  execution retains deterministic `gas_used`; `wasmi` is therefore exact-pinned,
  and any engine update requires explicit compatibility review and the full
  repository gate. A successful execution that omits a declared Write/Consume
  effect remains a fail-closed
  non-commit, while an actual trap commits a Rejected receipt and consumes the
  nonce with exact object-head assertions and no mutation. Keep exact receipt
  replay ahead of module resolution, object reads, and execution. Create,
  Shared/System ownership, blob bodies, native HTTP/devnet wiring, arbitrary
  uploads, JIT/AOT, production metering, and versioned module commitment
  provenance remain deferred.
- DR-0079: Add an additive, local-only, non-production `SqliteDurableStore` in
  `runtime-sqlite` implementing `StructuredDurableDomainStateStore` and
  `IndexedOutboxRepository` so the preinstalled-WASM native devnet has a
  structured durable backend to wire against in a following PR. It lives in a
  separate module (`structured.rs`) and its own SQLite tables and its own
  `PRAGMA application_id`, distinct from the existing opaque
  `SqliteStateStore`; it never reinterprets that store's opaque state-key
  prefixes as typed rows. Because `application_id`/`user_version` are
  whole-file SQLite properties, this store and the legacy opaque store cannot
  share one database file: each requires its own separate file. The store is
  bound at construction to one trusted `(chain, validator, atomicity domain)`
  namespace (`SqliteNamespace`), auto-bootstraps a `durable_metadata` row with
  a documented schema identity and the initial writer fence on first open, and
  fails closed on schema-identity, schema-version, application-ID, or
  namespace (chain, validator, or domain) mismatch on every later open and
  every request-path operation. `advance_writer_fence` is an explicit
  operator-only method, not reachable through any runtime trait; it revalidates
  that same exact schema identity and chain/validator/domain namespace inside
  its own `BEGIN IMMEDIATE`, before reading or updating the fence, and resets
  the connection's `busy_timeout` back to the fixed operator default first,
  since it carries no request deadline and the shared connection may still
  have a short request-path timeout installed. A later additive schema change
  bumps the schema identity and version together. Unlike `runtime-postgres`'s
  pooled, multi-attempt-serializable design, every operation is serialized
  behind one process-local `Mutex<Connection>` plus one SQLite transaction, so
  there are no concurrent writers to retry against within the process. Every
  write commits through `BEGIN IMMEDIATE`: the writer fence is validated once,
  immediately after that transaction acquires the write lock, and stays valid
  through `COMMIT` because the write lock excludes any other writer from
  advancing it in the meantime; the fence is not re-read a second time before
  `COMMIT`, only the deadline is rechecked immediately before dispatching it.
  Every multi-statement read (metadata/fence check plus the requested
  payload) runs inside one `Deferred` transaction instead of two independent
  autocommit statements, so both are observed from one consistent snapshot
  rather than risking a concurrent writer's commit landing between them; the
  read transaction is then explicitly rolled back and any rollback failure is
  propagated. Before every transaction acquisition (`Deferred` for reads,
  `Immediate` for writes), the caller's remaining `DurableOperationContext`
  deadline is propagated into that connection's SQLite `busy_timeout`,
  checked, clamped to `[1ms, 5000ms]`; an already-expired deadline is a
  definite pre-commit rejection rather than a zero-length busy wait, and a
  lock wait bounded by a short deadline fails closed well before the fixed
  five-second connection default would otherwise apply. A local `COMMIT`
  failure is conservatively classified `Indeterminate` because embedded
  storage I/O carries the same fsync ambiguity the shared contract documents
  for a severed remote connection. State, immutable object versions,
  receipts, and outbox messages/delivery/lease-attempt state each live in
  their own table; the due-outbox claim uses a partial index on
  `(available_at_unix_millis, request_id) WHERE completed = 0` so an
  unattended scheduler claim is a bounded indexed lookup, not a table scan.
  Every digest, canonical-record-type-ID, outbox-attempt status, and boolean
  column is decoded strictly through a typed internal representation (for
  example, `OutboxAttemptStatus`, not a raw persisted integer compared
  ad hoc): an unknown algorithm ID, a byte length other than 32, exactly one
  of an algorithm/bytes pair present without the other, a persisted
  canonical-record-type ID other than the binary's own constant, an outbox
  attempt status outside the three known values, a completed flag other than
  exactly 0 or 1, or a tombstoned head carrying any current-only column is
  always `InvalidPersistedState`, never silently coerced or treated as
  absent. An object version's own persisted creating chain is also compared
  against the store's bound chain, both when a new version is inserted at
  commit and when an existing version is read back, so a version created
  under a different chain is rejected rather than trusted. A `Current` object
  head is trusted only after the object version it names is loaded through
  that same fully validated version-row path and confirmed to be the maximum
  retained version, with its digest matching the head row's own digest
  columns; a `Tombstoned` head resolves its last version through that same
  path rather than trusting a raw `MAX(object_version)` value on its own.
  Loading a head never recurses into itself: it may call the version-row
  loader, which never calls back into the head loader. The full feature-gated
  shared conformance suite that PostgreSQL uses
  (`run_durable_store_conformance`, `run_durable_object_conformance`,
  `run_schema_skew_conformance`) passes against it unmodified, plus a
  dedicated restart test that closes and reopens the file to prove committed
  state (including a real durable state read/mutation), an object's current
  head/immutable version, and a receipt all survive; that exact request replay
  after reopen returns `RequestAlreadyCommitted` without reapplying any
  effect; that acknowledging the same outbox lease twice after reopen remains
  idempotent; and that the persisted writer fence — not anything held in
  process memory — is what fences a stale context after an operator advance.
  A bounded contention test proves a short deadline lets a blocked write fail
  closed in roughly that deadline (with an explicit lower bound as well as an
  upper one, so the wait is shown to actually approach the requested budget
  rather than returning near-instantly), not the fixed five-second default.
  Focused corruption tests directly tamper with persisted columns through a
  second raw connection to prove representative strict-decode and
  cross-check rules above fail closed, including a discriminating case that
  inserts a complete, well-formed second immutable version row while leaving
  the head at the first version, proving the head is rejected specifically
  because it no longer names the maximum retained version rather than
  because of any individually malformed column (not an exhaustive
  enumeration of every rule: for example, a non-32-byte digest length is not
  separately covered). This adapter has none of `runtime-postgres`'s
  connection pooling, disk/WAL/connection-exhaustion fault evidence,
  PgBouncer/backup-restore rehearsal, or TLS commit-loss evidence, and is not
  suitable for multi-writer or production deployments.
- DR-0080: Expose DR-0078's preinstalled-WASM entrypoint through a new
  additive `native-http` composition (`preinstalled_wasm_structured_durable_router`
  / `_with_executor`) rather than changing `structured_durable_router`, which
  stays on the read-only entrypoint and is behaviorally unchanged; both
  routers now share one private core (`invoke_structured_durable_event_with_execution`)
  parameterized by a small private `StructuredDurableAuthenticatedExecution`
  policy enum (`ReadOnly` vs `PreinstalledWasm`), so the authenticated
  preparation, storage context construction, and exact request-scoped outbox
  claim/send/ack path is implemented once, not duplicated per router. A new
  public `PreinstalledWasmComposition` holds only `Arc<PreinstalledModuleCatalog>`,
  the zero-sized `execution::WasmExecutionEngine`, and a `created_checkpoint: u64`
  fixed at router-composition time; none of the three is ever read from HTTP
  body bytes, and `created_checkpoint` is never derived from wall-clock time.
  `SubmitTransaction` on the new route calls
  `handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`;
  every other event kind still runs through the same generic
  `TransactionalNodeStateMachine` path as every other native route. Blocking
  admission and pre-storage-dispatch cancellation are unchanged, because both
  routers dispatch through the identical shared core. `native-http` gained a
  normal (not dev-only) dependency on `execution`, needed only to name
  `WasmExecutionEngine` in `PreinstalledWasmComposition`'s public signature.
  Coarse HTTP error classification (`node_error_response`) was extended:
  malformed/inactive/unknown module reference
  (`PreinstalledModuleUnknown`/`Inactive`/`NotYetActive`/`ReferenceDigestMismatch`)
  and args/gas/zero-object request faults
  (`PreinstalledModuleArgsTooLarge`/`GasLimitExceedsCeiling`/`ZeroObjectAccess`)
  remain deterministic, opaque-coded client errors (`422`/`400`); catalog/commitment
  mismatch (`PreinstalledModuleNotCataloged`/`CodeHashMismatch`/`ManifestHashMismatch`/
  `SemanticsHashMismatch`) and `ObjectCreatedCheckpointRegression` are now
  classified as host/operator failures (`500`, opaque codes), because they can
  only mean the trusted composition-time catalog disagrees with the
  governance-committed registry or the trusted `created_checkpoint` regressed,
  never something the caller controls; no variant's `Display` text or internal
  digest/hash values are ever put in the response body. A follow-up review
  pass extended this same classification to every other execution/effect
  family the preinstalled route newly makes HTTP-reachable, matching
  `execution::ExecutionError` explicitly (no wildcard) in a dedicated
  `execution_error_response` helper: `MissingEntrypoint` (a client-chosen
  entrypoint name absent from an otherwise trusted, catalog-verified module)
  and `ResourceLimitExceeded` (deterministic bounds that scale with the
  caller's own manifest/args) are opaque `422` client faults; `WasmEngine`
  (the trusted catalog module itself failing fuel setup, compilation,
  host-function linking, instantiation, or start — a
  malformed-trusted-catalog-WASM host failure, bounded only by this route's
  admission/pre-activation limits, not production fee accounting; a
  wrong-signature entrypoint instead normalizes as a deterministic execution
  failure/trap, never this variant) and every remaining internal
  encoding/hashing/context variant (unreachable in practice once
  authentication has already re-encoded/re-hashed the same transaction once)
  are opaque `500`s. `NodeCoreError::ObjectVersionOverflow` and
  `ExecutionError::ObjectVersionOverflow` both map to `409` (an object at its
  maximum version is a real conflict); `ObjectCreationUnsupported` maps to
  `501`, consistent with every other `*Unsupported` object variant;
  `ObjectEffectMismatch` is an opaque deterministic `422`; and
  `DuplicateObjectEffect`/`TooManyObjectEffects`/`UndeclaredObjectEffect`/
  `ObjectMutationContextMissing`/`SystemModules` join the existing
  impossible-in-practice `500` "invalid-node-output" bucket. Composition-time-only
  catalog-construction variants (`PreinstalledModuleWasmTooLarge`/
  `ManifestIdMismatch`/`CatalogTooLarge`/`DuplicatePreinstalledModule`) are not
  HTTP-reachable and remain unclassified. Full composition-time
  registry/catalog reconciliation (iterating and cross-checking every
  registered module against every catalog entry before serving traffic) is
  deferred to the devnet composition; a mismatch discovered only at request
  time remains this fail-closed opaque `500`. Tests build every
  fixture (module code/manifest/semantics digests, object digests) from
  `HashSuiteResolver`/canonical encoders rather than pasting digests, cover a
  signed owned `Write` committing `Accepted` and advancing object
  version/nonce/receipt, an exact duplicate not re-executing or reapplying, a
  close/reopen `SqliteDurableStore` replay returning the persisted result
  (using a real wall-clock `DurableOperationContext`/`SystemClock`, since
  DR-0079's `SqliteDurableStore` compares its deadline against actual
  `SystemTime::now()`, unlike `MemoryDurableStateStore`'s settable virtual
  clock), directly asserting the receipt survives reopen and, separately from
  exact-replay reconciliation, that a fresh request ID at the already-spent
  nonce still conflicts after reopen (proving the persisted sender-nonce
  record itself survived, not only the receipt exact-replay reconciles from
  first), a deterministic trap committing `Rejected` while consuming the
  nonce and leaving the object unchanged, a zero-object call rejecting before
  its first storage dispatch — proven directly by reusing the existing
  cancel-on-first-receipt-read store/signal wrapper and observing the signal
  never flips, rather than only by output-side effects — a discriminating
  `MissingEntrypoint` case proving `422` with no receipt/object mutation, a
  corrupted-catalog case (WASM bytes no longer rehashing to the registry's
  committed code hash) proving the opaque `500` catalog-mismatch code end to
  end, the existing read-only route still rejecting `Write`/`Consume`, both
  routes sharing identical content-type/content-encoding/body-limit rejection
  behavior, and cancellation/admission bounds holding on the new route,
  including a discriminating test that walks the new route's cancellation
  observation at each of its three pre-storage checkpoints (the axum wrapper's
  own initial check plus the two checks inside the shared core) exactly like
  the pre-existing `structured_durable_router` coverage; Shared/System
  ownership and blob-transfer coverage stays at node-core rather than being
  duplicated at the HTTP layer, since neither can succeed on this MVP
  object-access surface — their fail-closed rejections
  (`ObjectOwnerKindUnsupported`/the then-existing `ObjectBodyUnavailable`,
  later removed once blob fetch/verification made it unreachable — see
  [DR-0094](0094-0098-blobs-audit-and-documentation.md)) already originate in
  shared node-core code, and the native HTTP boundary mapped those errors to
  `501`, so duplicating the same
  node-core tests at HTTP would add no discrimination. The two axum handlers (`submit_structured_durable_event`
  and `submit_preinstalled_wasm_structured_durable_event`) no longer duplicate
  their content-type/body-extraction/admission/cancellation-observation/blocking-dispatch
  logic: both are now thin wrappers around one private
  `submit_structured_durable_event_common` async helper parameterized by the
  caller's own initial cancellation observation, its blocking executor, and a
  `Send + 'static` blocking-work closure, while the inner shared core
  (`invoke_structured_durable_event_with_execution`) keeps its own two
  cancellation re-checks unchanged. `PreinstalledWasmComposition::new` now
  documents that `created_checkpoint` must be non-decreasing across process
  restarts for every object the composition may mutate, since a regression
  fails closed as `NodeCoreError::ObjectCreatedCheckpointRegression`, not
  silently accepted. Native binary/devnet startup wiring, query
  APIs, the TypeScript
  client, the counter UI, arbitrary module upload, and fee/gas metering remain
  out of scope and deferred, as does provider-hardening work.

  **Repository-boundary decision.** The TypeScript client and the minimal
  counter demo (Developer MVP Gate steps 5-6) stay inside this monorepo
  through the Developer MVP Gate, as top-level `clients/typescript` and
  `demo/counter` directories once those steps are implemented, rather than
  starting as separate repositories. Extraction into their own repositories is
  deferred until all of: the canonical wire contracts and shared test vectors
  they depend on are stable, a real independent consumer or an independent
  release cadence for the client exists, and an E2E suite can target a
  released devnet artifact instead of an in-tree build. Until then, splitting
  them out would only add release/versioning coordination overhead without a
  concrete consumer to justify it.

  **Amendment: repository-boundary deliverable superseded by
  [DR-0081](0081-0087-cli-first-roadmap.md).** The
  rest of this entry (the additive `native-http` composition, shared private
  core, error classification, and test evidence) remains the accepted,
  implemented history of what DR-0080 shipped and is not rewritten. Only the
  repository-boundary decision immediately above is superseded:
  [DR-0081](0081-0087-cli-first-roadmap.md)
  replaces the planned `clients/typescript`/`demo/counter` pairing with a
  six-directory monorepo layout (`clients/rust`, `clients/typescript`,
  `apps/devnet`, `apps/cli`, `apps/explorer`, `apps/wallet`) and a longer
  ordered product-surface sequence; no `demo/counter` directory is created.
  Consequently, the historical deferred-scope reference to "the counter UI"
  above no longer names planned work; that deliverable is cancelled.
  The extraction-timing reasoning stated above — wait for stable wire
  contracts/vectors, a real independent consumer or release cadence, and a
  released devnet artifact for E2E — is unchanged and still applies to every
  `clients/*` directory under [DR-0081](0081-0087-cli-first-roadmap.md).
