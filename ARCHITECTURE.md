# Sunrise Edge Architecture

This document records the initial architecture for Sunrise Edge Phase 1. The implementation focus is the cryptographic and serialization foundation required for later consensus, object, execution, and runtime phases.

## 1. Overall architecture
Sunrise Edge is designed as a deterministic state-transition system over authenticated events and persistent state. The protocol core is split into small Rust crates so the same core logic can be reused in serverless and native runtimes without embedding vendor-specific dependencies.

## 2. Crate boundaries
- `protocol-types`: protocol identifiers, digest types, hash domains, and suite metadata.
- `canonical-encoding`: deterministic framed serialization for protocol-critical payloads.
- `hashing`: domain-separated hash framing, built-in hash implementations, and hash-suite resolution.
- `crypto`: signature-domain framing and signer/verifier traits.
- `chain-ir`: versioned deterministic instruction program format for execution back-end neutrality.
- `validator-set`: immutable epoch membership, public keys, explicit voting
  power, quorum calculation, and validator-set commitments.
- `consensus`: canonical proposal/vote/certificate types and the event-driven
  shared-object chained-HotStuff state machine.
- `node-core`: bounded node-event ingress, replay-context validation, pure
  application transition dispatch, and conditional state persistence.
- `protocol-upgrades`: canonical feature flags, hash-suite schedules, protocol-version transitions, and lazy-migration descriptors.

## 3. Canonical serialization rules
All protocol-critical payloads use a SCALE-based framed binary encoding with explicit protocol magic, type identifier, encoding version, field count, field identifiers, field lengths, and field bytes. Fields are emitted in sorted field-id order to avoid map and construction-order nondeterminism.

The Phase 15 adapter prerequisite adds the shared inverse operation:
`decode_canonical_frame` validates one complete frame with a 32 MiB bound,
borrows field payloads without copying, rejects wrong magic, truncation,
duplicate or out-of-order field IDs, length overruns, and trailing bytes, and
provides checked integer and UTF-8 accessors. Schema decoders must additionally
require the expected type/version and reject fields outside their explicit
allow-list; parsing a generic frame alone does not authorize an event.

## 4. Hash architecture
Hashing is centralized in the `hashing` crate. Callers provide a canonical payload, a hash domain, protocol version, and chain id; the crate is solely responsible for producing the canonical domain-separation frame before hashing.

## 5. HashSuite lifecycle
`HashSuite` is an immutable protocol configuration object. `HashSuiteResolver` selects the active suite from a monotonically increasing epoch schedule, requires a genesis entry at epoch 0, and never silently falls back to a different algorithm.

## 6. Hash domain separation
Every protocol hash includes the protocol magic, selected `HashAlgorithmId`, `HashDomain`, domain version, `ChainId`, `ProtocolVersion`, and canonical payload in a framed structure.

## 7. Commitment scheme architecture
Commitment schemes are separate from general-purpose hashes. Phase 14 adds a
`CommitmentScheme` boundary with versioned sparse-Merkle leaf and internal-node
framing. Leaves bind a 256-bit tree key to canonical value bytes; internal
nodes bind their level and ordered child commitments. Every output remains
self-describing through `CommitmentSchemeId`, and cross-scheme children are
rejected rather than converted or downgraded. Tree traversal reads key bits
most-significant-bit first; level zero is the root and level 255 is the parent
of a leaf.

The built-in genesis implementation is SHA-256. Phase 14 also provides an
experimental Poseidon2/BN254 scheme using width 3, rate 2, capacity 1, the
`x^5` S-box, 8 full rounds, and 56 partial rounds. Canonical bytes are injected
as little-endian chunks of at most 31 bytes, with byte length in the capacity
lane; one permutation runs per rate block. The permutation parameters and
known-answer vector are pinned to the
[Horizen Labs reference implementation](https://github.com/HorizenLabs/poseidon2/commit/055bde3f4782731ba5f5ce5888a440a94327eaf3),
corresponding to the [Poseidon2 paper](https://eprint.iacr.org/2023/323)
(IACR ePrint 2023/323). The experimental implementation uses safe Rust only,
keeps the field arithmetic and pinned constants inside the `commitments` crate,
and repeats the reference known-answer test. SHA-256 outputs retain conventional
digest-byte order; BN254 field elements use fixed 32-byte little-endian form.
Until a separately reviewed constant-time implementation is selected, the
experimental Poseidon2 path accepts at most 4 KiB per leaf; SHA-256 retains the
general 16 MiB leaf bound. This prevents the intentionally simple safe-Rust
field arithmetic from becoming an unbounded CPU surface.

`SparseMerklePoseidon2Bls12381V1` remains a reserved identifier. Resolving it
as a built-in implementation fails explicitly; adding an identifier does not
activate or implement a cryptographic primitive.

## 8. Signature domain separation
Signature framing is distinct from hash framing. Signed payloads include `ChainId`, `ProtocolVersion`, `Epoch`, `message_type`, `SignatureSchemeId`, and the canonical payload to prevent replay across chains, epochs, protocol versions, and message families.

## 9. Object lifecycle
Objects are not implemented in Phase 1. Future object versions will reference self-describing digests so historical versions remain readable after hash-suite migration.

## 10. Transaction lifecycle
Transactions are not implemented in Phase 1. They will be canonically serialized first, then hashed by the active suite selected from `(chain_id, protocol_version, epoch)`.

## 11. Fast Path lifecycle
Fast Path is deferred. Its certificates will rely on the Phase 1 digest, suite-resolution, and signature-domain primitives.

## 12. Certificate lifecycle
Phase 13 adds shared-consensus quorum certificates. Each certificate binds the
chain, protocol version, epoch, view, height, and proposal digest to a
canonically sorted set of domain-separated validator votes. A non-genesis
certificate must carry voting power strictly greater than two thirds; replaying
an already processed certificate is a no-op. Fast-path certificates remain a
separate follow-up.

## 13. Persistent state layout
Runtime persistence uses deterministic chain/version namespaces for protocol
configuration, objects, effects, modules, upgrades, migrations, and Phase 13
epoch-scoped consensus state. Stored references preserve algorithm identifiers
in digests and never require a global rehash.

## 14. Validator lifecycle
Phase 13 introduces immutable epoch-scoped `ValidatorSet` snapshots. Validator
identity, membership, governance-assigned voting power, and bond amount remain
separate concepts; a larger stablecoin bond does not implicitly grant more
votes. Validator records commit the signature scheme and public verification
key used for consensus messages. Sets are canonically sorted by validator ID,
reject duplicates and zero power, and compute quorum as strictly greater than
two thirds of total voting power.

## 15. Genesis bootstrap
Genesis starts with a permissioned validator set and a conservative default hash suite. Phase 1 encodes this by exposing a `HashSuite::genesis()` helper that selects SHA-256 for all required purposes.

## 16. Bond lifecycle
Bond assets and bond lifecycle are deferred.

## 17. Slashing lifecycle
Slashing is deferred, but the architecture already separates message families for future equivocation evidence signatures.

## 18. Stablecoin fee lifecycle
Stablecoin fee accounting is deferred.

## 19. Governance lifecycle
Governance is the mechanism by which the active validator set and protocol
parameters can be changed after genesis. Phase 8 introduces the first
governance primitives in the `governance` crate.

**Proposal lifecycle:**
1. A governance participant submits a `GovernanceProposal` carrying a
   `GovernanceAction` and a `ProposalId`.
2. The proposal stays open for at least `GovernanceConfig.voting_epochs` epochs.
3. At tally time the `ProposalOutcome` (Approved / Rejected) is determined by
   comparing the fraction of approving votes against the configured quorum
   (`quorum_numerator / quorum_denominator`).
4. If approved, the encoded action is applied atomically at the epoch boundary.

**First concrete actions (Phase 8):**
- `UpdateValidatorAdmissionPolicy(ValidatorAdmissionPolicy)` – changes the
  active admission policy in `ProtocolConfig`.  The canonical genesis
  transition path is `GenesisPermissioned → BondAndGovernance`.
- `ApproveValidatorAdmission(ValidatorId)` – produces a `GovernanceApproval`
  record that can be attached to a `ValidatorAdmission` to satisfy permissioned
  admission checks.

**`ProtocolConfig` integration:**
`ProtocolConfig` now carries a `GovernanceConfig` field (field 8 in the
canonical encoding).  `GovernanceConfig` encodes the active quorum fraction
and minimum voting duration, keeping governance parameters in the same
deterministic config commitment as fees, bonds, and hash-suite settings.

**DR-008: `GenesisPermissioned → BondAndGovernance` transition**
The only allowable governance-initiated transition away from
`GenesisPermissioned` is to `BondAndGovernance`.  Direct transitions to
`GovernancePermissioned` or `BondRequired` are also supported for future
flexibility, but transitions back to `GenesisPermissioned` are rejected at the
action-validation layer to prevent permanent lock-in of the genesis set.

## 20. Epoch transition
Epoch transition activates configuration schedules lazily. New writes after activation may use the new suite, while historical data remains valid under its original algorithm identifier.

## 21. Protocol upgrade lifecycle
Phase 12 makes protocol upgrades versioned, explicit, governance-scheduled, and
future-activated. A `ProtocolUpgrade` commits to the source and target versions,
activation epoch, complete target `ProtocolConfig` hash, optional deterministic
migration hash, and compatibility policy. The hash and signature framing always
includes `ProtocolVersion`, so upgrades naturally fork cryptographic domains.

Pending transitions are stored in strictly increasing activation order, must
start from the active protocol version, and must form a continuous version
chain. Future activation is checked against the enactment epoch, not only the
proposal-submission epoch. When constructing the target configuration, already
activated transitions are pruned before computing `new_config_hash`; later
pending transitions remain committed.

`FeatureFlags` is a closed, canonically ordered set in `ProtocolConfig`. Unknown
features cannot silently fall back to disabled behavior.

## 22. Hash algorithm migration lifecycle
Hash migration is schedule-based, forward-only, and lazy. `ProtocolConfig`
commits the full per-purpose `HashSuite` definitions and activation epochs, and
consensus hashing APIs resolve the algorithm from
`(chain_id, protocol_version, epoch)` rather than accepting a caller-selected
algorithm. There is no global state rehash; existing digests remain
self-describing and verifiable with their recorded algorithm ID.

Object migrations are also lazy. Configuration commits a `MigrationDescriptor`
and implementation digest. Runtime wiring selects an implementation by that
digest and migrates one matching object on access, preserving its identity,
owner, and type while incrementing object and schema versions. Migration
implementations are deliberately excluded from canonical configuration values.

Phase 12 also versions new-object identifier derivation as version 2. The frame
now includes the transaction digest algorithm identifier before digest bytes and
the creation counter. This prevents identical raw digest bytes from colliding
across hash-suite migrations; historical version-1 object identifiers remain
unchanged.

## 23. System Module lifecycle
Phase 11 introduces deterministic, governance-installed system modules.

**Registry lifecycle:**
1. Governance submits an `InstallSystemModule` action carrying a full
   versioned module record.
2. The action is canonically encoded and included in the proposal commitment.
3. On approval, the module record is inserted into `SystemModuleRegistry` in
   canonical `(module_id, version)` order.
4. Activation is controlled by `activation_epoch` and `status`
   (`Pending`/`Active`/`Disabled`).

**Manifest lifecycle:**
- `SystemModuleManifest` commits to input/output schemas, max input size, gas
  model, and optional `zk_hint`.
- The module record stores `manifest_hash`, `canonical_code_hash`, and
  `semantics_hash` as explicit commitments.
- Consensus-critical hashing/signing remains unchanged; system modules are an
  execution-layer extension and do not replace protocol-root hash primitives.

**Native acceleration model:**
- Native implementations are optional and must be semantics-equivalent to the
  canonical portable implementation for identical inputs.
- Validators without native acceleration continue participating by executing
  the canonical path.

## 24. WASM / Chain IR execution
Phase 9 introduces the first concrete execution back-end: `WasmExecutionEngine`
in the `execution` crate, backed by `wasmi` — a deterministic, pure-Rust WASM
interpreter.

**Execution lifecycle:**
1. The validator resolves the objects declared in the transaction's
   `AccessManifest` into a `&[ResolvedObject]` slice.
2. `WasmExecutionEngine::execute` is called with the WASM module bytes, the
   entry-point name, the resolved objects, and the transaction args and gas
   limit.
3. A fresh `wasmi::Engine` is created with `consume_fuel(true)` to enable
   deterministic fuel-based gas metering.
4. Host functions are registered via `wasmi::Linker` under the `"env"` import
   module. The full ABI surface is documented in `execution::wasm_engine`.
5. The module is compiled and instantiated fresh for every execution call so
   there is no mutable shared state between invocations.
6. `gas_limit` fuel units are loaded before calling the entry point.
   `gas_used = gas_limit − remaining_fuel` is recorded in `ExecutionEffects`.
7. On return the accumulated `ObjectEffect`s and `EventRecord`s are packaged
   into the `ExecutionEffects` result. If execution trapped or `abort` was
   called, the status is `Failure` and all effects / events are discarded.

**Determinism invariants:**
- `wasmi` interpreter semantics are fully deterministic; JIT / native
  compilation is not used.
- Protocol version 1 object IDs remain
  `SHA-256(tx_hash_bytes ‖ creation_index_le_u32)`. Protocol version 2 and later
  prepend the derivation version and transaction hash algorithm identifier so
  the same transaction context always produces the same IDs without changing
  historical IDs.
- Fuel consumption is instruction-accurate and machine-independent.

**Contract SDK (`contract-sdk` crate):**
The `contract-sdk` crate provides a `no_std`-compatible Rust SDK for writing
WASM contracts. It declares the host ABI in the `host` module (linking against
`"env"`) and exposes safe, ergonomic wrappers: `object_data`, `write_object`,
`consume_object`, `create_object`, `emit_event`, `args`, and the `abort!`
macro. Panicking stubs replace the extern imports on native (non-wasm32)
builds so the crate can be unit-tested without a WASM toolchain.

**DR-009: `NullExecutionEngine` and `WasmExecutionEngine` coexist**
The existing `NullExecutionEngine` remains the default for wiring tests that do
not need real WASM execution. `WasmExecutionEngine` is the canonical
deterministic back-end for production use. Future optional back-ends (native
JIT/AOT) must produce output equivalent to `WasmExecutionEngine` for every
input.

**DR-010: introduce versioned deterministic `chain-ir` program format**
Phase 10 introduces the `chain-ir` crate as a stable, bounded and statically
inspectable execution IR with explicit instruction opcodes and operand framing.
Current contracts still execute through canonical WASM interpretation, but this
IR becomes the protocol-level seam for future native/JIT and ZK proving
back-ends that must preserve identical execution effects.

## 25. ZK execution architecture
Phase 14 introduces proof envelopes and the verifier boundary, while concrete
provers and proof-system backends remain deferred. An `ExecutionProofStatement`
binds `chain_id`, `protocol_version`, `epoch`, transaction digest, and the input
and output state commitments. `ExecutionProof` adds a non-zero,
protocol-assigned `ProofSystemId` and bounded opaque proof bytes.

Verification requires an expected statement supplied by the caller and an
`ExecutionProofVerifier` implementing the exact proof-system ID. Statement or
ID mismatch fails before backend dispatch, and there is no default verifier or
algorithm fallback. A proof-system ID is not active merely because it can be
encoded; protocol selection and concrete verifier implementations are future
work.

## 26. Security invariants
- No protocol-critical naked byte digests.
- No per-transaction hash negotiation.
- No silent algorithm fallback.
- No ambiguous concatenation in hashing or signing.
- Chain and protocol-version replay boundaries are mandatory.
- Historical digests remain readable across suite upgrades.

## 27. Failure scenarios
- Unknown hash or signature scheme IDs are rejected.
- Unsupported algorithms fail explicitly instead of downgrading.
- Invalid hash-suite schedules fail construction.
- Empty chain or message identifiers fail validation before framing.
- Wrong-chain, wrong-version, old-epoch, non-member, invalid-leader, and
  under-quorum consensus messages are rejected before state transition.
- Duplicate consensus delivery is idempotent; conflicting signed votes produce
  explicit equivocation evidence instead of being silently overwritten.

## 28. Serverless runtime constraints
The cryptographic core is pure, synchronous, and free of background workers, daemons, mutable globals, and runtime-vendor dependencies. This keeps the implementation portable to edge and serverless adapters.

`runtime-sqlite` is the first durable implementation of the versioned state
contracts. It uses an exact-pinned bundled SQLite release, WAL journaling,
`synchronous=FULL`, a five-second busy timeout, and `BEGIN IMMEDIATE` for every
write transaction. Revisions are stored as exact eight-byte big-endian values;
deletes retain rows with null values, so reopening the database preserves ABA
protection. Atomic write sets validate every expected revision in canonical key
order before applying any mutation. Schema and application identifiers fail
closed instead of adopting an unrelated database.

The workspace crate itself keeps `#![forbid(unsafe_code)]` and uses rusqlite's
safe API. The exact-pinned bundled dependency encapsulates the SQLite C/FFI
boundary; no repository-owned unsafe block or raw SQLite handle is introduced.

This is a local-disk durability component, not an adapter deployment claim.
SQLite WAL needs local shared-memory filesystem semantics, the API is blocking,
and the current tests prove reopen persistence, ordered conflict rollback,
revision-overflow rollback, CAS behavior, and schema rejection—not kill/power
fault recovery. Native HTTP must place it behind bounded blocking isolation,
deadlines, admission control, and cancellation policy before integration.

## 29. Shared-object consensus

Phase 13 routes shared or conflicting-object transactions through an
event-driven chained-HotStuff state machine. A `ConsensusEngine::on_event`
invocation consumes exactly one proposal, vote, certificate, or external Tick
plus explicit persisted `ConsensusState`, and returns the next state, outbound
messages, and newly committed ordered blocks. The caller atomically persists
the returned state; transports may drop, duplicate, reorder, delay, or replay
messages without becoming a safety trust root.

Leaders rotate deterministically by view. Proposals carry a quorum-certified
parent, validators sign domain-separated proposal/vote frames, and certificates
require voting power strictly greater than two thirds. The HotStuff lock rule
prevents an honest validator from voting across unsafe forks, and the canonical
three-certificate chain commits the grandparent. Votes and certificates are
stored in canonical validator order so arrival order cannot change bytes or
the resulting commit.

Timeouts enter only as `Tick` events. A Tick cannot advance a view before the
persisted deadline and advances at most one view per event; false time input can
affect liveness but cannot create a certificate or commit state. Consensus
parameters (protocol ID, block transaction bound, and timeout) are committed in
`ProtocolConfig`, and consensus state uses an epoch-namespaced persistence key.

## 30. Node-core invocation boundary

Phase 15 prerequisites introduce the runtime-neutral `node-core` crate. One
invocation accepts exactly one `NodeEvent` with explicit chain ID, protocol
version, epoch, non-zero request ID, closed event-kind ID, and a bounded
canonical application payload. Generic frame validation is only an ingress
property: the selected application state machine must still decode the exact
payload type/version and perform authentication, authorization, membership,
signature, quorum, and transition checks appropriate to that event kind.

`handle_event` validates replay context before storage access, reads one
explicit canonical state value, invokes a synchronous `NodeStateMachine`, and
uses compare-and-swap to persist the candidate next state. Responses and
outbound events remain held until the conditional write succeeds. CAS conflicts
are returned to the adapter without an internal retry, signature, send,
scheduling action, or background task. Request IDs enable application-level
idempotency records; their presence alone does not make a state machine
idempotent.

This first boundary intentionally performs a single-key state replacement. It
is the As-Is integration seam for the native adapter, not the production
persistence endpoint. Production completion requires a versioned atomic
write-set/transaction contract, durable request deduplication, crash-safe
outbox publication, bounded retry policy, and conformance across every
supported persistence adapter as recorded in the Phase 15 To-Be criteria.

The runtime now also defines the next As-Is persistence seam: a bounded
`TransactionalStateStore` accepts a unique, canonically key-ordered write set,
checks every expected per-key revision while holding one transaction boundary,
and applies all mutations or none. Revisions are monotonic optimistic-
concurrency tokens rather than protocol object versions. A delete retains a
tombstone revision, so delete/recreate cannot produce an ABA match. The memory
implementation validates atomicity, deterministic conflict selection,
resource bounds, and revision-overflow behavior; it is test infrastructure,
not the required durable production store.

Node-core exposes this seam through `handle_transactional_event`. A state
machine derives a bounded, unique access plan from the already context-checked
event before any storage read. Node-core loads a revision-bearing snapshot,
passes it into one pure transition, rejects undeclared or read-only updates,
and binds each accepted update to the revision it observed. Responses and
outbound messages remain withheld until the complete write set commits. The
legacy single-key handler remains for the current adapters, so this is not yet
a migration or production durability claim. Canonical deduplication records,
persisted outbox entries, adapter migration, and crash recovery remain
subsequent Phase 15 work.

The recoverable transactional path additionally hashes the complete canonical
`NodeEvent` under dedicated hash domain `0x000D`, using the active epoch hash
suite's certificate-hash algorithm slot. It reserves deterministic per-request
deduplication and outbox-batch keys. Application updates, a canonical completed
request record (`0xE003`), and a canonical ordered outbox batch (`0xE004`) enter
the same atomic write set. A retry with the same request ID and event digest
replays persisted responses without re-running the transition or returning the
outbox again; the same request ID with different event bytes fails closed.
Outbox presence makes committed messages recoverable and at-least-once, but no
adapter uses this path yet.

The outbox delivery cursor (`0xE005`) advances one message at a time. A caller
supplies a non-zero lease ID, an observed time, and a duration bounded to five
minutes. Claim atomically asserts the immutable batch revision and records the
lease, deadline, and checked attempt count. A matching acknowledgement advances
the cursor and clears the lease. An expired lease may be replaced for the same
message index, so send-then-crash-before-ack intentionally redelivers rather
than loses data. This is at-least-once, not exactly-once; downstream delivery
must be idempotent. Provider scheduling, trusted time policy, transport send,
adapter integration, retention/compaction, poison-message policy, durable
storage, and crash/fault conformance remain production work.

## 31. Native HTTP adapter

Phase 15 adds the `native-http` crate around node-core using Axum and Tokio.
`POST /v1/events` accepts exactly one body with media type
`application/vnd.sunrise-edge.node-event`, no unrecognized media-type
parameters, and no content encoding other than absent or `identity`. The body
limit is 16 MiB plus a fixed 512-byte framing allowance; the inner node event
still enforces its independent canonical and payload bounds. Successful calls
return a versioned canonical `HttpNodeResult` as
`application/vnd.sunrise-edge.node-result`. Nested responses retain stable
request IDs and adapter-neutral canonical `NodeResponse` framing.

Malformed events return 400, oversized bodies return 413, unsupported media or
content encoding returns 415, context/CAS conflicts return 409, deterministic
application rejection returns 422, and runtime/outbound delivery failure
returns 503. Error bodies expose stable coarse codes rather than internal state
or storage details. `GET /health/live` returns 204 without reading protocol
state. The server entry point requires a shutdown future so the embedding
native process can stop accepting work cleanly.

The default native route now requires a `TransactionalNodeStateMachine`, a hash
suite resolver, a transactional store, and an injected outbox lease-ID source.
Application updates, replayable responses, request/event deduplication, the
ordered outbox batch, and its delivery cursor commit atomically. The request
then claims one message at a time with a 30-second persisted lease, sends it,
and atomically acknowledges the matching lease and index. A transport failure
returns 503 while retaining the lease; retry after expiry deliberately
redelivers the message, while a fully acknowledged duplicate request replays
only its response and does not rerun the transition or resend the outbox.

Lease-ID sources must prevent reuse for the same request across process
restarts, because a delayed acknowledgement from an expired attempt must not
match a newer lease. This closes the old native commit-before-enqueue loss
window for request-scoped retries, but it is not the complete production
delivery architecture. No durable store, provider scheduler that discovers
unattended committed outboxes, poison-message policy, retention/compaction,
trusted time policy, or crash/fault conformance exists yet. TLS,
authentication, rate limiting, audit telemetry, and proxy hardening also remain
deployment requirements.

## 32. Cloudflare Workers ingress adapter

Phase 16 adds an ES-module Worker in `adapters/cloudflare-workers`. It preserves
the Phase 15 HTTP path, exact media types, content-encoding rejection, body
limit, liveness behavior, and no-store responses. Incoming bodies are consumed
with a bounded `ReadableStream` reader rather than an unbounded
`arrayBuffer()`/`text()` call. The implementation has no mutable module-level
request state, awaits every service-binding operation, sanitizes downstream
headers, and converts an internal downstream 500 into a coarse 502 response.

The ingress invokes a separately deployed node-core service through the
generated `Env.NODE_CORE` Service Binding. It never calls a public Worker URL
or the Cloudflare REST API. The binding capability removes embedded API
credentials and public network routing, but it does not authenticate the
protocol event and does not propagate Cloudflare Access context to the bound
service. Protocol signatures and node-core authorization remain mandatory.

Wrangler configuration is the source of truth. It pins the latest compatibility
date supported by the tested workerd build, enables `nodejs_compat`, generates
the binding type instead of hand-writing `Env`, and enables Workers
observability. Integration tests execute inside workerd with a mock Service
Binding. This As-Is Worker is only a bounded ingress/relay: it does not yet
provide the production node-core service, durable state, deduplication,
transactional outbox, authentication policy, WAF/rate-limit policy, or rollout
runbook required by the Phase 16 To-Be criteria.

## 33. Portable Web ingress core

The first Phase 17 prerequisite extracts the Fetch API request contract into
`adapters/shared/web-ingress.ts`. Provider wrappers now supply only a
`NodeCoreFetcher` capability. Paths, media types, bounded stream consumption,
status mapping, downstream content-type validation, response-header
sanitization, and fail-closed errors remain one implementation rather than
being copied across Cloudflare, Deno, Vercel, and Supabase adapters.

The shared module contains no environment lookup, provider SDK, credential,
retry loop, mutable global state, or durable-state assumption. Provider wrappers
remain responsible for constructing an authenticated/private `NodeCoreFetcher`
without weakening the shared bounds. The Cloudflare wrapper is the first
conformance consumer and continues to pass its generated Service Binding;
workerd tests exercise the extracted implementation unchanged.

Providers may narrow the accepted request body when their documented platform
capacity is below the protocol transport limit. The shared implementation
validates this policy as a positive integer no greater than its default bound;
provider configuration can therefore fail earlier with 413 but cannot expand
the security envelope. A lower provider limit is an explicit compatibility gap
that remains visible in Phase 17 production criteria rather than being called
full protocol conformance.

## 34. Deno Web ingress adapter

The Deno Phase 17 adapter uses the current Deno 2 default `fetch` export and
passes every public request to the portable Web ingress core. Its only runtime
capability is an immutable node-core fetcher configured from named environment
variables. The wrapper does not decode canonical bytes or own protocol state.

The As-Is node-core transport requires an exact HTTPS `/v1/events` URL and a
bounded Bearer token stored as a Deno Deploy secret. It reconstructs an
allow-listed upstream request, forbids redirects to prevent cross-origin
credential forwarding, and applies a bounded deadline through the shared
`authenticated-node-core.ts` capability. Configuration errors fail at startup;
network and timeout failures become the shared sanitized 503.

This authenticated public relay is an incremental conformance adapter, not the
production trust boundary. Phase 17 still requires a fixed private transport,
mTLS or signed service capability, rotation and revocation, durable
deduplication and outbox delivery, provider policy and limits, real deployment
tests, observability, incident response, and rollback rehearsal.

## 35. Vercel Web ingress adapter

The Vercel Phase 17 adapter is a Node.js Function with the Web `fetch` export.
Two same-application rewrites expose the canonical event and liveness paths to
one handler, which delegates request semantics to the portable ingress core and
uses the shared authenticated node-core capability. The function has a
ten-second maximum duration and a bounded downstream deadline.

Vercel's documented 4.5 MB Function request/response payload ceiling is below
the shared protocol transport bound. The As-Is adapter therefore declares a
conservative 4 MiB request policy and fails earlier with 413 when the request is
visible to the handler. This is not full protocol conformance: platform-level
rejection can precede the function, and protocol-valid events above the
provider ceiling cannot use this route.

The adapter has local, permission-free conformance tests but no claimed Vercel
deployment validation. Preview/production rewrite behavior, platform error
mapping, response limits, lifecycle reuse, private transport, key lifecycle,
durable effects, abuse controls, telemetry, and release rehearsal remain Phase
17 production requirements.

## 36. Supabase Edge ingress adapter

The Supabase Phase 17 adapter is a Deno-compatible Edge Function named
`sunrise-edge`. Supabase routes function-internal paths with the function name
as a prefix, so the wrapper removes `/sunrise-edge` only when the remainder is
one of the two exact canonical paths. The normalized request then uses the
portable ingress handler and shared authenticated node-core capability.

Gateway JWT verification remains explicitly enabled. This protects event
submission but also means liveness is not anonymously reachable in the As-Is
shape. Production must decide whether to split health into a separately
controlled function or keep it authenticated; it must not disable verification
for the combined privileged ingress by accident.

The hosted limits currently document 256 MB memory, two seconds of CPU per
request, and 150 seconds of request idle time without documenting a payload
ceiling on that limits page. The adapter retains the shared request bound and
does not claim hosted capacity until real gateway and deployment tests establish
it. Authentication claims, platform error mapping, private transport, durable
effects, lifecycle behavior, observability, abuse policy, and release rehearsal
remain Phase 17 production gates.

## 37. AWS HTTP API v2 ingress adapter

The AWS Phase 17 adapter maps API Gateway HTTP API payload format `2.0` events
to the portable Web ingress contract without an AWS SDK dependency. It validates
the event shape and version, reconstructs only contract-relevant headers, and
requires canonical event POST bodies to use strict canonical base64. Encoded
length is checked before allocation and decoded bytes are checked again.

API Gateway allows 10 MB API payloads, but synchronous Lambda invocation
request and buffered response payloads are limited to 6 MB including their JSON
envelopes. The adapter uses 4 MiB for both decoded requests and raw responses,
then base64-encodes the explicit payload-v2 result. The response stream is read
with a bound and only cache-control, content-type, and allow can cross back to
the gateway. This smaller envelope is an explicit conformance gap.

The repository deliberately does not ship an unauthenticated deployable API.
Production IaC must select payload format 2.0 and configure scoped JWT, IAM, or
custom authorization plus throttling/WAF, secret lifecycle, private node-core
transport, reserved concurrency, observability, durable effects, and rollout
rehearsal. Local mapper tests are not evidence of API Gateway/Lambda conformance.

## 38. Cross-provider ingress fixtures

One provider-neutral fixture matrix defines liveness and pre-dispatch rejection
behavior for unknown paths, wrong methods, parameterized media types, content
encoding, and non-canonical content length. Cloudflare workerd, Deno, Vercel,
Supabase, and AWS HTTP API mapper tests consume those exact vectors and compare
status, body, cache policy, and `Allow` headers.

The fixture matrix prevents local wrapper drift but does not satisfy production
conformance by itself. Each provider must run equivalent vectors through its
real public gateway, authentication layer, runtime, private transport, and
node-core deployment, including platform-generated rejection and timeout paths.

## 39. Repository validation gate

The repository pins Rust 1.97.1, Node.js 22.20.0 in CI, and Deno 2.9.4. One
`scripts/check-all.sh` entrypoint runs Rust formatting, all-feature clippy and
tests, Cloudflare type/lint/workerd validation, all four portable provider
adapter suites, and whitespace checks. GitHub Actions installs the locked npm
dependencies and executes the same script on pull requests and main.

This is an As-Is regression gate, not release provenance. Production still
requires reviewed periodic updates to the pinned action revisions, dependency
and toolchain provenance, SBOMs, reproducible artifacts, protected required
checks, real-provider test credentials and isolation, security scanning, and
release-signing policy.

## 40. Reviewed dependency update proposals

Dependabot checks the Rust workspace, Cloudflare npm lockfile, and GitHub
Actions weekly on a staggered schedule. It opens a bounded number of PRs with
ecosystem-specific commit prefixes and never auto-merges them. Every update is
expected to retain immutable action revisions and pass the repository-wide
gate after a human reviews changelogs and compatibility impact.

This As-Is automation discovers routine updates; it does not prove artifact or
upstream integrity. Production still requires ownership and response SLAs,
provenance and signature verification, emergency security-update procedures,
license/SBOM policy, and protected review/merge controls.

## Decision record
- DR-0001: Use a single canonical framed binary format for hashes, signatures, and protocol-critical payloads.
- DR-0002: Keep `HashAlgorithmId` broader than the currently enabled built-ins so future support can be added without changing digest shape.
- DR-0003: Treat hash-suite scheduling as configuration resolution, not as a bulk migration job.
- DR-0011: Introduce a governance-managed `SystemModuleRegistry` with versioned
  module commitments (`code`, `semantics`, `manifest`) and optional native/ZK
  acceleration hints while preserving canonical execution equivalence.
- DR-0012: Store complete hash-suite and protocol-upgrade schedules in canonical
  configuration, enforce future activation at enactment, and use per-object
  hash-identified lazy migrations instead of global state rewrites.
- DR-0013: Use event-driven three-chain HotStuff for shared-object ordering.
  Keep the protocol state explicit and persistable, accept untrusted relay and
  Tick delivery, and require authenticated quorum certificates for safety.
- DR-0014: Keep state commitments and execution proofs independently agile.
  Use versioned leaf/node framing, ship Poseidon2/BN254 only as an experimental
  inactive alternative to genesis SHA-256, reserve unsupported schemes without
  fallback, and dispatch bounded proof envelopes only to an exact-ID verifier.
- DR-0015: Put one bounded canonical event and one explicit conditional state
  transition behind a runtime-neutral node-core boundary. Publish no output
  before persistence succeeds, keep retries and delivery in adapters, and treat
  single-key CAS as an interim seam that must evolve into a crash-safe atomic
  write-set and outbox contract for production.
- DR-0016: Use an exact, versioned canonical binary HTTP contract for the native
  adapter, enforce independent transport and protocol bounds, and keep HTTP
  status mapping outside node-core. Dispatch outbound events only after state
  commit while treating the remaining commit/send window as deferred production
  work requiring a transactional outbox.
- DR-0017: Implement Cloudflare public ingress as a bounded ES-module Worker and
  call the private node service through a generated, awaited Service Binding.
  Treat the binding as routing/capability isolation rather than event
  authentication, and keep the ingress independently testable in workerd.
- DR-0018: Share one Web Fetch API ingress implementation across edge providers
  and inject only a minimal node-core fetch capability. Provider wrappers may
  add authentication and deployment wiring but must not fork canonical paths,
  media types, bounds, status rules, or response sanitization.
- DR-0019: Implement Deno ingress as a thin default-fetch wrapper over the
  shared contract. Require an exact HTTPS node-core endpoint, inject only a
  secret Bearer capability, reject redirects, and treat stronger private or
  mutually authenticated transport as a production Phase 17 requirement.
- DR-0020: Allow provider adapters to narrow the shared request-body capacity
  when the hosting platform has a smaller hard limit, but reject zero,
  non-integer, or larger values and record the resulting conformance gap.
- DR-0021: Share the interim exact-HTTPS, Bearer-authenticated node-core fetch
  capability across Web providers without moving environment lookup or secret
  lifecycle into the shared layer. Keep private or mutually authenticated
  transport as a production exit requirement.
- DR-0022: Model Vercel's smaller payload ceiling as an explicit 4 MiB adapter
  request budget rather than pretending it accepts the full protocol envelope.
  Reuse shared Web semantics and authenticated transport, and keep real Vercel
  deployment behavior as an unfulfilled production gate.
- DR-0023: Normalize only the exact Supabase function-prefixed contract paths
  and keep gateway JWT verification enabled for the combined function. Do not
  invent an undocumented hosted payload limit or equate local wrapper tests with
  production gateway conformance.
- DR-0024: Map only API Gateway HTTP API payload version 2.0, require canonical
  base64 for binary events, and cap decoded request and raw buffered response at
  4 MiB to stay conservatively below Lambda's 6 MB JSON-envelope limits. Ship no
  unauthenticated production API configuration.
- DR-0025: Define provider-neutral pre-dispatch ingress fixtures once and run
  them through every local provider consumer. Treat this as drift detection,
  not a substitute for real gateway and runtime conformance testing.
- DR-0026: Use one pinned repository validation entrypoint locally and in CI so
  Rust and every adapter gate run together. Treat green CI as regression
  evidence only, not production provenance or real-provider certification.
- DR-0027: Resolve CI actions from verified upstream tags and commit their full
  immutable revisions. Keep the human-readable release tag as a comment and
  require reviewed updates rather than following a mutable major tag.
- DR-0028: Ask Dependabot for bounded weekly Cargo, npm, and GitHub Actions
  update PRs, but never auto-merge them. Require human compatibility review and
  the complete repository gate for every proposed supply-chain change.
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
