# Architecture decisions DR-0094–DR-0098

Blob-backed object handling, parallel release gates, publication, and
audit-first sequencing and documentation-ownership decisions.

- DR-0094: Wire the existing `runtime::BlobStore` into authenticated
  structured durable object loading, including native-http composition, so a
  `DurableObjectPayload::BlobReference` is fetched and independently verified
  As-Is, while blob upload/publication, a durable provider `BlobStore`, and
  GC/checkpoint manifest work remain deferred. This is non-Ledger S5
  prerequisite work; per the user's explicit roadmap reorder (2026-09-04),
  all remaining Ledger S4c Phase 2b/S4d physical-hardware/HIL/release work
  (see [DR-0093](0088-0093-hardware-signing.md)) is deferred while this proceeds, and S4, S5, the
  `CLI-First Node Production Gate`, production, and mainnet readiness all
  remain incomplete.

  **Explicit separate component, not a hidden default.** `BlobStore` stays
  independent from `StateStore`: no adapter is required to implement both.
  `native-http`'s `StructuredDurableNativeComponents<S, B, T, C, I>` gains an
  explicit `B` type parameter and a `blob_store: Arc<B>` constructor argument
  (both `new` and `with_cancellation`), threaded through
  `structured_durable_router`/`_with_executor` and
  `preinstalled_wasm_structured_durable_router`/`_with_executor` and every
  handler generic over the composition. `node-core`'s
  `handle_authenticated_resolved_durable_submit_transaction` and its
  `_with_owned_object_effects` and `_with_preinstalled_wasm_execution`
  siblings — every entrypoint that always declares an authenticated object
  dispatch — take an explicit `blob_store: &B where B: BlobStore` parameter,
  a deliberate, exhaustively updated Rust API break across every call site
  and test, not an additive overload. The fully generic
  `handle_resolved_durable_idempotent_event` never declares a dispatch and
  never loads or fetches an object body, so its public signature is
  unchanged; internally it passes `blob_store: None` into the shared
  `handle_durable_idempotent_event_with_plan` helper, which takes
  `Option<&dyn BlobStore>` instead of a generic `B` (object-safe, since only
  the two simple `BlobStore` methods are ever called through it) and treats
  `None` alongside a `Some(dispatch)` as an internal composition-invariant
  failure, never reachable from external input, since every caller that
  passes `Some(dispatch)` also always passes `Some(blob_store)`. The
  crate-private `load_and_authorize_objects` takes `blob_store: &dyn
  BlobStore` for the same reason. `apps/devnet::compose_devnet_router` wires
  a process-local
  `runtime::MemoryBlobStore`, since `SqliteDurableStore` has no durable
  `BlobStore` implementation yet: a blob-backed reference does not survive a
  devnet restart, and nothing in the devnet composition writes one.

  **Fetch ordering and bounds.** Inside `load_and_authorize_objects`, the
  version record's stored chain provenance is still checked from the record
  header alone — before a `BlobReference` payload is ever fetched, so a
  cross-chain record rejects without any blob-store I/O (proven by an
  instrumented `BlobStore` that asserts zero `get_blob` calls). Exact request
  replay is unaffected: the persisted-receipt short-circuit in
  `handle_durable_idempotent_event_with_plan` already runs before any object
  I/O, so a replayed request naming a blob-backed object still returns before
  `BlobStore` is ever touched (also proven by an instrumented double). Only
  then is `blob_store.get_blob` called: `Ok(None)` is the new
  `NodeCoreError::ObjectBlobMissing { object_id, blob_digest }`; `Err(_)` is
  the existing `NodeCoreError::Runtime`, not a silently downgraded absence.
  Fetched bytes are bounded at the existing per-object
  `MAX_AUTHENTICATED_OBJECT_BODY_BYTES` (1 MiB) limit and folded into the same
  running `MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES` (8 MiB) aggregate an
  inline body shares, via one `accumulate_authenticated_body_bytes` helper —
  both bounds run immediately after the fetch, before either digest is
  verified or the body is decoded, so an oversized-and-also-malformed blob
  rejects as `ObjectBodyTooLarge` without ever hashing or decoding it, and a
  blob that would push the aggregate over budget rejects the same way even if
  its own bytes are individually well-formed. An inline body's bound/aggregate
  check keeps its original position (after the record's id/version/schema
  cross-check, immediately before the shared `record.digest`
  re-verification below), unaffected by the blob-only reordering, and neither
  path double-counts. The payload's own
  `blob_digest` is then independently verified against the exact fetched
  bytes with `hashing::verify_digest` (`HashPurpose::Object`, the record's own
  stored chain/protocol-version provenance, self-describing algorithm
  selection from the digest itself) — a mismatch is the new distinct
  `NodeCoreError::ObjectBlobDigestMismatch { object_id, blob_digest }`, and an
  unsupported algorithm still fails closed as the existing
  `ObjectDigestUnverifiable`. Only after that does `objects::decode_object`
  run (a decode failure is the existing `DurableInvocationError`/
  `NodeCoreError::DurableInvocation`, never a panic); the existing object
  id/version/schema and head-owner-projection cross-checks and the
  independent `record.digest` re-verification against the same canonical
  bytes (`ObjectBodyDigestMismatch`) then run exactly as they already did for
  an inline body. The
  now-unreachable `NodeCoreError::ObjectBodyUnavailable` variant (a blob
  payload this slice could not read) is removed rather than left dead.

  **Mutation surface unchanged, read surface widened.** A declared
  `Write`/`Consume` access on the owned-effects and preinstalled-WASM
  entrypoints may now read a blob-backed previous version through the
  identical loader and verification path as a read-only access. At the time
  of this decision, every new immutable version either entrypoint committed
  was still always inline
  (`authenticated_object_effects::translate_update` never constructs a
  `DurableObjectPayload::BlobReference`), so blob upload/publication of a new
  version was unimplemented by simple absence of a code path; DR-0096 later
  added thresholded publication without changing `translate_update`. The bounded
  query API (`node_core::query_object`,
  [product-surfaces.md §43](../product-surfaces.md#43-bounded-developer-mvp-query-api)) is unchanged: it still returns
  only a `CurrentBlobReference` result's explicit head/version metadata and
  digests, and still never fetches or verifies a blob body, preserving the
  documented query/write asymmetry.

  **HTTP mapping stays opaque.** `native-http` maps `ObjectBlobMissing` and
  the existing `NodeCoreError::Runtime` (a `BlobStore` `RuntimeError`) to an
  opaque `503`, matching every other transient storage-unavailability
  variant; `ObjectBlobDigestMismatch` joins the existing opaque `500`
  corruption group alongside `ObjectBodyDigestMismatch`. No route ever
  serializes blob bytes or storage details into a response.

  **Tests.** `node-core` adds an `InstrumentedBlobStore` test double (call
  counting, scriptable `RuntimeError` injection) and unit tests for the
  happy read-only path, an owned `Write` updating a blob-backed previous
  version to a new inline version, a `BlobStore` `RuntimeError`, a missing
  blob, an oversized-before-hashing-or-decode blob, a `blob_digest` mismatch,
  a malformed/non-canonical decode failure, decoded identity/version/schema
  mismatches, an independently invalid `record.digest` after a valid
  `blob_digest`, an unsupported blob-digest algorithm, the provenance-before-
  fetch and exact-replay-before-fetch orderings, and the shared inline/blob
  aggregate bound. `native-http` adds a `CountingBlobStore`
  double and a full HTTP `preinstalled_wasm_structured_durable_router`
  end-to-end composition test that commits a blob-backed object directly into
  storage, submits a real signed `Write` `SubmitTransaction` over HTTP, and
  asserts both the response and the committed inline v2 body, proving the
  request dispatched through the exact supplied `BlobStore` rather than a
  hidden default.

  **Completion boundary.** Only blob fetch and verification for an
  already-existing content-addressed reference are As-Is. Blob
  upload/publication of a new version, a durable provider `BlobStore`
  implementation (PostgreSQL/SQLite/Cloudflare/AWS or otherwise),
  GC/checkpoint manifest work, and Cloudflare/AWS persistence and
  provider-certification evidence all remain deferred and unimplemented. S4,
  S5, the `CLI-First Node Production Gate`, production, and mainnet readiness
  remain incomplete; this DR changes none of their exit criteria.

- DR-0095: Separate the software-production and hardware-signing release
  tracks inside the existing CLI-First Node Production Gate, and restore the
  README to a human-facing entry point.

  **Roadmap sequencing, not a weaker release gate.** S0-S3 remain the common
  implemented As-Is baseline. The `Software Production Gate` consists of that
  baseline plus every existing S5 criterion. The `Hardware Signing Release
  Gate` consists of every existing S4 criterion. S4 and S5 may proceed in
  parallel; the explicitly deferred S4c Phase 2b/S4d Ledger hardware work no
  longer blocks completing S5 or starting the TypeScript client, explorer,
  and wallet after the Software Production Gate passes. The complete
  `CLI-First Node Production Gate`, live protocol activation, and any
  production or mainnet-readiness claim still require both tracks plus the
  existing independent security/release criteria. No S4, S5, Phase 15-17, or
  cross-phase release criterion is deleted, completed, or weakened.

  **Documentation ownership.** `README.md` is a concise project entry point:
  orientation, honest current capabilities and limitations, build commands,
  workspace map, invariants, and links. The detailed local devnet transfer and
  orderly-restart walkthrough moves without changing its command contract to
  `docs/guides/devnet.md`. `TODO.md` remains the authoritative roadmap and completion
  checklist; this file remains the architecture and decision record. Detailed
  persistence, PostgreSQL, and hardware-signing contracts remain in
  `docs/operations/persistence.md`, `docs/operations/postgres.md`, and `docs/signing/hardware-signing.md` respectively. Historical
  decision text remains historical evidence rather than being duplicated into
  a continuously growing README status narrative.

  **Compatibility.** This decision changes documentation structure and future
  work ordering only. It changes no canonical bytes, identifiers, digests,
  signature payloads, execution effects, object layout, persistence schema,
  runtime API, CLI flag, module/WAT/WASM byte, or implemented capability.

- DR-0096: Publish a new immutable object version an accepted authenticated
  Create/Update mutation commits to the explicit `BlobStore` from DR-0094
  when — and only when — its canonical bytes exceed a fixed deterministic
  threshold, referencing it instead of storing it inline, and add a local
  file-backed `runtime-sqlite::SqliteBlobStore` so a devnet-composed
  blob-backed version survives a restart. This is further non-Ledger S5
  prerequisite work; it changes none of DR-0095's exit criteria, and S4, S5,
  the `CLI-First Node Production Gate`, production, and mainnet readiness
  all remain incomplete.

  Only authenticated `Update` is reachable in the current product path;
  authenticated Create-effect support remains fail-closed and deferred. The
  staging helper handles both mutation variants so a future accepted Create
  cannot silently bypass the same persistence policy, but this decision does
  not make Create reachable.

  **A fixed 64 KiB inline/blob threshold, not unconditional publication.**
  An initial draft of this DR published every new version unconditionally,
  which broke the CLI: `apps/cli`'s transfer command requires `CurrentInline`
  and cannot fetch a blob body, so a second transfer against an
  already-published account would have failed. `node-core::MAX_INLINE_OBJECT_BODY_BYTES`
  (64 KiB of exact canonical-encoded bytes) fixes this: a version at or under
  the threshold stays inline exactly as before this DR, and only a version
  whose canonical bytes exceed it is published and referenced. Every
  node applies the identical fixed threshold to the identical canonical bytes.
  This is a deterministic persistence-layout policy, not transaction input or
  a protocol-config knob, and it changes neither canonical object bytes nor the
  logical digest/head. It is set far above ordinary small object bodies — a devnet asset-account body
  is a few dozen bytes — specifically so small-object callers keep working
  unchanged; only a body actually large enough to justify separate
  content-addressed storage crosses it.

  **`BlobStore::put_blob` is atomic insert-if-absent, not a blind
  overwrite.** Content-addressing means a digest determines its content
  uniquely, so storing byte-identical bytes under an already-present digest
  is a defined idempotent no-op success (the ordinary case for a retried or
  duplicate publication of the same version), while storing different bytes
  under an already-present digest is a new fail-closed
  `RuntimeError::BlobDigestConflict`, never a silent overwrite. This defines
  no delete or garbage-collection operation, but that is not a claim that
  every publisher retains every blob forever — GC/checkpoint manifest work
  that would reclaim unreferenced blobs remains deferred, not ruled out.
  `MemoryBlobStore` implements this by comparing against the existing entry
  under its lock; a poisoned lock (another caller panicked mid-mutation, so
  the map's contents are no longer trustworthy) now fails closed with
  `RuntimeError::DurableStoreUnavailable` rather than recovering a guard
  over possibly-torn state.

  **Node-core stages the inline/blob decision as a pure, I/O-free pass,
  separate from where the actual `put_blob` calls run, and `translate_update`
  stays pure throughout.** `translate_authenticated_object_effects`/
  `translate_fee_only_object_effects` are unchanged: they still produce
  inline `DurableObjectMutation::Update` entries exactly as before, and
  `translate_update` itself performs no I/O and is unaware publication
  exists. A new pure function in `handle_durable_idempotent_event_with_plan`,
  `stage_object_mutations_for_blob_store`, runs immediately after those
  translations (every effect has already been validated, though the
  complete envelope has not yet — see below) and does no I/O itself: for
  each `Create`/`Update` mutation whose inline canonical bytes exceed the
  threshold, it replaces the payload with `DurableObjectPayload::BlobReference`
  reusing the version's already-computed object `digest` unchanged as the
  payload's own `blob_digest` — the same value a verified read later
  re-derives and compares against the identical fetched bytes
  (`load_and_authorize_objects`), so reusing it is exactly what a correct
  read already expects, not a shortcut — and collects the exact bytes to
  publish as a `PendingBlobPublication`, deferred rather than published
  immediately. A body at or under the threshold, or a mutation that is
  already blob-backed, is returned unstaged. Iteration order is the
  mutations' existing deterministic order (the verified manifest's
  declaration order), so every validator stages the same publications in
  the same order.

  **The actual `put_blob` calls run only after the complete structured
  envelope has been built and validated, strictly before `commit_invocation`.**
  The handler builds `DurableStateTransaction`, `DurableObjectChanges`, and
  `DurableInvocationTransaction` from the staged mutations exactly as it
  already did before this DR — that construction is where the complete
  envelope (state/receipt/outbox/object aggregate bounds, cross-section
  identity) is actually validated, and it still runs whether or not
  anything was staged. Only once that construction has succeeded does a new
  `publish_pending_blobs` step perform every staged `put_blob` call, in
  order; `commit_invocation` is called only after every one of them
  succeeds. Staging itself, by contrast, runs before that validation and
  proves nothing about it — an earlier design published as part of staging,
  before the envelope was known to be valid, which this ordering corrects.

  **Ordering invariants, each following from where staging and publishing
  sit in the existing control flow.** Exact request replay already returns
  from the persisted-receipt short-circuit before the transition, effect
  translation, staging, or publishing ever run, so replay stages and
  publishes nothing — proven by an instrumented `BlobStore` asserting zero
  `put_blob` calls on replay. A `put_blob` failure (a typed `RuntimeError`,
  including a digest/content collision) is surfaced as the new
  `NodeCoreError::ObjectBlobPublishFailed { object_id, blob_digest, source }`
  before `commit_invocation` is ever called, so a publish failure guarantees
  zero state/receipt/nonce/outbox/object changes for that request — proven
  by asserting the scripted store's `commit_invocation` was never invoked.
  If more than one publication was staged, an earlier one that already
  succeeded before a later one fails is already durably stored: an
  unreachable content-addressed orphan, not evidence of a partial commit. A
  later `commit_invocation` rejection (e.g. a concurrent object-head
  conflict) can likewise only ever leave every already-published blob as an
  unreachable orphan: harmless, since nothing ever references it, and a
  retried publish of the identical content is the idempotent-put case
  above, not a new conflict. `native-http` maps `ObjectBlobPublishFailed` to
  the existing opaque `503` storage-unavailability group, distinct from the
  read-side `ObjectBlobMissing`/`ObjectBlobDigestMismatch` groups; no route
  ever serializes blob bytes or storage details.

  **`runtime-sqlite::SqliteBlobStore` is a separate file, schema, and SQLite
  `application_id` from both the opaque legacy store and
  `SqliteDurableStore`.** `application_id`/`user_version` are whole-file
  SQLite properties, so this store cannot share a database file with either
  existing one and never creates, reads, or migrates their tables. It opens
  in WAL journal mode with `synchronous = FULL` (matching both existing
  local SQLite adapters), verifies a persisted schema-identity string
  (`SQLITE_BLOB_SCHEMA_IDENTITY`) the same way `SqliteDurableStore` verifies
  its own, and stores content keyed by `(digest_algorithm, digest_bytes)` in
  one `WITHOUT ROWID` table. `put_blob` runs inside its own `BEGIN IMMEDIATE`
  transaction and implements the same insert-if-absent/conflict contract as
  `MemoryBlobStore`; `get_blob` is a single bounded point query against the
  connection, not wrapped in a transaction. Unlike `SqliteDurableStore`, it
  binds no chain/validator/domain namespace at open time: a blob is
  identified only by its self-describing digest. There is still no delete
  or garbage-collection operation.

  **`apps/devnet` wires this explicitly, not by a hidden default, kept for
  future/large-object use even though ordinary devnet traffic never crosses
  the threshold today.** `boot_local_store` now also opens `blobs.sqlite3`
  (a sibling file to `structured.sqlite3` under the same `--data-dir`) as a
  `SqliteBlobStore` and returns it alongside the structured store;
  `DevnetBoot::into_store` is replaced by `DevnetBoot::into_parts` returning
  both. `compose_devnet_router` gains an explicit
  `blob_store: Arc<SqliteBlobStore>` parameter threaded into
  `StructuredDurableNativeComponents`, replacing the process-local
  `MemoryBlobStore` DR-0094 wired here. Every devnet asset-account body is a
  few dozen bytes, always at or under the threshold, so in practice this
  wiring is not yet exercised by real devnet traffic — it exists so a
  future large object type (not asset accounts) would already have a
  durable local `BlobStore` to publish into. Seeding's restart-time
  verification (`apps/devnet::seed::verify_current_account`) still fetches
  and independently re-verifies a blob-backed *current* version if one is
  ever encountered (defensive, matching the read path), while the
  fail-closed `DevnetSeedError::BlobBackedSeedObject` remains reserved for
  the *version-one* seed row specifically, which seeding always creates
  inline and nothing ever republishes under a different representation.
  Every caller of `seed_asset_accounts`/`compose_devnet_router` (the devnet
  binary, its own tests, and every CLI/client loopback-TCP E2E test) is
  updated for the added parameters.

  **Tests.** `runtime` adds `MemoryBlobStore` idempotent-put,
  conflicting-put, and poisoned-lock-fails-closed tests. `runtime-sqlite`
  adds a `SqliteBlobStore` suite: put/get, reopen persistence, idempotent
  put, conflicting put, distinct algorithms over identical bytes,
  WAL/synchronous pragma verification, application-id/schema-version/
  unclaimed-database fail-closed cases, and a cross-file-identity check
  against `SqliteDurableStore`. A paired file-backed integration test publishes
  a large canonical body, commits only its `BlobReference` to the separate
  structured database, closes and reopens both files, and verifies the exact
  reference and bytes survive without an inline fallback. `node-core` adds a test proving an ordinary
  small update to a blob-backed *previous* version stays inline with zero
  `put_blob` calls (reading a blob-backed previous version never by itself
  forces the next version to also be blob-backed), a separate test with a
  body over the threshold proving publication and reference, exact-
  replay-publishes-no-blob, publish-failure-aborts-before-commit, and
  commit-rejection-leaves-a-directly-readable-orphan-blob (the latter three
  using an over-threshold body so the publish path is actually exercised);
  the existing HTTP-mapping table test and native-http's real end-to-end
  preinstalled-WASM write test are updated to expect the small committed
  body to stay inline. The real file-backed CLI restart/duplicate E2E
  (`apps/cli/tests/devnet_restart_duplicate_e2e.rs`) — already the
  repository's evidence for orderly-restart state continuity and exact-replay
  non-reapplication — now asserts every post-transfer current version is
  still `CurrentInline` both before and after the real close/reopen of both
  SQLite files, since an asset-account body never crosses the threshold.

  **Completion boundary.** Only publication into an explicitly supplied
  `BlobStore` (in-memory or local file-backed SQLite), gated by the fixed
  64 KiB threshold, is As-Is. A durable production/cloud provider
  `BlobStore` — PostgreSQL, Cloudflare, AWS, or otherwise — remains
  unimplemented and unclaimed by this decision: PostgreSQL's
  `object_versions` write path already accepted a `blob_digest` column pair
  before this DR and is unchanged by it, but PostgreSQL itself still has no
  `BlobStore` implementation to publish into. GC/checkpoint manifest work,
  Create-effect (new-object, as opposed to new-version) support, and
  Cloudflare/AWS persistence and provider-certification evidence all remain
  deferred and unimplemented. S4, S5, the `CLI-First Node Production Gate`,
  production, and mainnet readiness remain incomplete; this DR changes none
  of their exit criteria.

  **Compatibility.** Canonical `Transaction`/`Object`/receipt/nonce/submit
  bytes and logical object digest/head semantics are unchanged: a version's
  `digest` field and a verified read's re-derivation of it are identical
  whether the payload is inline or blob-backed, exactly as DR-0094 already
  established for the read side, and the threshold changes only which
  representation a given version's bytes are stored under, never the
  bytes themselves. This is an API break in the same family as DR-0094's:
  `DevnetBoot::into_store` is removed in favor of `into_parts`, and
  `seed_asset_accounts`/`compose_devnet_router` gain a required parameter,
  with every call site in this repository updated, not left on a deprecated
  overload.

- DR-0097: Introduce an Initial Code Security Audit Entry Gate immediately after the
  completed CLI Developer MVP instead of making the first independent audit
  wait for the entire production operations and multi-validator roadmap.

  **Problem.** The previous roadmap placed independent audit inside or after
  S5 and the complete CLI-First Node Production Gate. That conflated an
  immutable code-audit scope with mainnet release certification: adding
  FastCertificate, every external event family, checkpoint publication,
  PITR/off-host restore, HA orchestration, PKI rotation, physical storage
  faults, and long-running capacity evidence before inviting external review
  would accumulate more unaudited surface and postpone feedback on the
  already implemented transaction path.

  **Decision.** Freeze and audit the current CLI-first security core first:
  canonical encoding/hashing/signatures, authenticated `SubmitTransaction`,
  nonce/replay/dedup, owned-object and preinstalled-WASM effects, fees,
  structured runtime atomicity, SQLite/PostgreSQL state/object/receipt/outbox
  and blob contracts, bounded native HTTP, and Rust client/CLI signing and TLS
  context boundaries. The only currently known code change required before that scope is
  frozen is to close the public event surface: until a non-`SubmitTransaction`
  family has its own authentication and authorization, external ingress must
  reject it before identity allocation, time, storage, or transition work.
  Implementing every such family is explicitly not an initial-audit
  prerequisite. A concise threat model/audit packet, a clean immutable commit,
  and the complete repository gate are the remaining documentation and
  evidence prerequisites.

  **Deferred does not mean deleted.** FastCertificate and atomic certificate
  publication remain mandatory before multi-validator protocol-v3 activation.
  Any non-`SubmitTransaction` family later exposed externally must gain its
  family-specific authentication/authorization and a focused delta audit.
  Checkpoint/state-root publication and verified restore remain production
  state-recovery work. PITR/off-host restore, HA/failover orchestration, TLS
  certificate lifecycle, and additional fault/load/soak/capacity certification
  follow a selected deployment topology and explicit RPO/RTO/SLO; they do not
  block the first code audit. The final production release gate still requires
  all relevant operational evidence and resolution of material findings from
  both the initial audit and later delta reviews.

  **Existing PostgreSQL evidence is not reopened as new implementation.** The
  atomic state/object/receipt/outbox commit, indexed due-work claim,
  same-identity reconciliation, retained attempt history, and idempotent
  acknowledgement already exist As-Is. Existing database-process SIGKILL,
  bounded data/WAL ENOSPC, connection exhaustion, snapshot restore, TLS
  commit-loss, and PgBouncer rehearsals enter the audit evidence packet as
  implemented bounds. They do not prove PITR, real HA, provider PKI, physical
  media faults, or production capacity, which remain honestly deferred.

  **Compatibility.** This decision only reorders gates and audit timing. It
  changes no canonical bytes, type IDs, hashes, signatures, execution effects,
  object or persistence layout, HTTP behavior, module bytes, CLI behavior, or
  production/mainnet completion criterion. Remaining Ledger work and the
  TypeScript client/explorer/wallet stay deferred exactly as before.

- DR-0098: Keep changing project status in `TODO.md` only and move specialist
  documentation out of the repository root.

  **Document ownership.** `README.md` is the stable human entrypoint: project
  purpose, design goals, setup, workspace orientation, invariants, safety
  warning, and links. It must not duplicate current milestones, completion
  percentages, next work, gate summaries, or deferred-work lists. `TODO.md`
  remains the single source of truth for those changing facts. `AGENTS.md`
  contains durable contributor rules and points to `TODO.md`; it does not carry
  a second roadmap snapshot.

  **Architecture layout.** Implemented architecture is grouped under
  `docs/architecture/` by subsystem. Accepted decisions are split into bounded
  numeric ranges under `docs/architecture/decisions/`. The devnet runbook,
  provider-neutral persistence requirements, PostgreSQL mapping, and hardware
  signing contract live under `docs/guides/`, `docs/operations/`, and
  `docs/signing/`. The repository root retains only the three Markdown
  entrypoints `README.md`, `TODO.md`, and `AGENTS.md`.

  **Compatibility.** This is a documentation-only relocation and ownership
  rule. It changes no canonical bytes, hashes, signatures, execution effects,
  persisted layouts, HTTP behavior, or release criterion. Repository-internal
  links and source-code documentation references move with the files; the
  historical decision text remains otherwise intact.
