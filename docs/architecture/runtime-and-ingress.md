# Runtime and ingress architecture

This document defines the runtime-neutral invocation boundary and the native
and serverless HTTP adapters around it.

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
fault recovery. Native HTTP now places synchronous work behind bounded blocking
admission, but production runtime composition, storage-aware deadlines,
cancellation, and capacity evidence remain open.

SQLite is not the selected production database. Its single opaque
`sunrise_state` table intentionally proves the minimal versioned key-value
contract, but it does not provide the normalized object, receipt, outbox,
checkpoint, migration, retention, or operational indexes required by the
accepted production persistence architecture.

`runtime-sqlite` additionally exposes `SqliteDurableStore`
([DR-0079](decisions/0076-0080-developer-mvp-foundation.md)): an
additive, local-only, non-production implementation of
`StructuredDurableDomainStateStore`/`IndexedOutboxRepository` in a separate
module, its own `PRAGMA application_id`, and separate SQLite tables from the
opaque `SqliteStateStore` above; because `application_id` is a whole-file
SQLite property, the two stores require separate database files, not a shared
one. It normalizes state, immutable object versions, receipts, and outbox
delivery/lease-attempt state, matching the shared contract that
`runtime-postgres` implements for production, but with none of that crate's
connection pooling, multi-writer serialization retries, or live fault
evidence — every operation is serialized behind one process-local mutex and
one SQLite transaction (`Deferred` for a multi-statement read's consistent
snapshot, `Immediate` for a write's `BEGIN IMMEDIATE` write lock), with the
caller's remaining deadline propagated into that connection's `busy_timeout`
before each transaction starts. It is a Developer MVP prerequisite for the
preinstalled-WASM native devnet, not a production persistence candidate.

`ComposedRuntime` owns explicitly supplied state, blob, signer, transport,
clock, and scheduler components and implements the same runtime trait without
selecting defaults. It allows a native embedding to pair `SqliteStateStore`
with independently chosen operational adapters while keeping every trust and
durability decision visible. Composition is wiring, not certification: memory
transport, signer, clock, and scheduler components remain test adapters.

Recovery and maintenance adapters may additionally require bounded discovery
of persisted keys. `StateKeyScanner` is deliberately separate from the
point-read `StateStore` contract. A validated request fixes a non-empty binary
prefix, an optional exclusive cursor inside that prefix, and a non-zero page
limit capped at 1,024. Results are strictly byte-ordered, carry a continuation
cursor only when one lookahead row proves another page exists, and include
revision tombstones. SQLite performs the range query over its BLOB primary key;
the memory store is a conformance reference.

Pagination is not a cross-page snapshot. A concurrently inserted key before a
cursor can be absent from that sweep, so unattended recovery must periodically
restart at the prefix. The scanner exposes keys only; it neither decodes
protocol records nor sends messages, schedules itself, or makes process
lifetime a correctness assumption. Native request work now has bounded blocking
admission, but storage-aware cancellation and a validated host capacity budget
remain open.

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
passes it into one pure transition, and rejects undeclared or read-only
updates. Every declared observation enters the final atomic write set: an
updated read-write key carries its mutation, while untouched read-write,
read-only, absent, and tombstoned keys carry `StateMutation::Assert`. A
concurrent dependency revision therefore rejects the whole commit before any
candidate update or output is released. The API still lacks an explicit
atomicity domain and dedicated read-set type, so this is not yet the production
persistence contract.

The recoverable transactional path additionally hashes the complete canonical
`NodeEvent` under dedicated hash domain `0x000D`, using the active epoch hash
suite's certificate-hash algorithm slot. It reserves deterministic per-request
deduplication and outbox-batch keys. Application updates, a canonical completed
request record (`0xE003`), and a canonical ordered outbox batch (`0xE004`) enter
the same atomic write set. A retry with the same request ID and event digest
replays persisted responses without re-running the transition or returning the
outbox again; the same request ID with different event bytes fails closed.
Outbox presence makes committed messages recoverable and at-least-once, but no
production deployment composition relies on this legacy path. The native
adapter no longer exposes it to non-transaction events: DR-0099 closes every
native public `POST /v1/events` surface to authenticated `SubmitTransaction`
only. Node-core retains the generic machinery for internal or future trusted
composition, while the structured route uses the normalized durable equivalent
described in [persistence.md §41](persistence.md#41-production-persistence-architecture).

`node-core` carries the Transaction v1 authentication boundary described in
[core-protocol.md §8](core-protocol.md#8-signature-domain-separation) (`node_core::transaction_auth`). It composes the strict
`execution::decode_transaction` decoder, the committed
`protocol_config::TransactionAuthProfile`, and the concrete
`crypto::Ed25519Verifier`. `authenticate_submit_transaction_event` now wires it
to `NodeEvent`, and the structured durable native route requires the resulting
private-field `AuthenticatedSubmitTransaction` before deriving an access plan
or entering its persistence/dispatch path. Generic node-core handlers and the
legacy native routes reject `SubmitTransaction`. The authenticated wrapper also
derives the private sender-nonce reservation. Exact next-nonce equality and its
checked increment now commit atomically with the structured invocation. Signed
read-only object manifests are loaded from exact heads and immutable inline
versions, authorized against the verified sender, and asserted in that same
invocation. The bounded S3 uniform ordinary-asset fee composition
([DR-0087](decisions/0081-0087-cli-first-roadmap.md))
and additive owned-effects/preinstalled-WASM module-object effects
entrypoints are implemented As-Is; shared-object ordering, fast-path
certificates/publication, family-specific authentication and authorization
before any future external re-opening of another event family, S4/S5, and the
independent security/release gates remain mandatory before live activation.

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

External ingress is submit-only (DR-0099). Of the eight known `NodeEventKind`
values, native HTTP authenticates and authorizes exactly one, `SubmitTransaction`,
end to end. Once a body decodes into a canonical `NodeEvent`, every one of the
other seven kinds — `ReceiveVote`, `ReceiveCertificate`,
`ReceiveConsensusMessage`, `ApplyGovernanceCertificate`,
`ApplyProtocolUpgrade`, `ApplyValidatorSetChange`, and `Tick` — is rejected by
a typed private native-http error before identity allocation, any clock read,
storage I/O, machine `access_plan`/transition, outbox work, or transport send.
Every one of those seven kinds maps to the same fixed, opaque
`501 event-family-requires-authenticated-route` response on all four native
router families (`router`, `resolved_domain_router`, `structured_durable_router`,
and `preinstalled_wasm_structured_durable_router`, including each
`_with_executor` constructor), so the response never leaks which specific kind
was sent. The two legacy routes (`router`, `resolved_domain_router`) authenticate
no event at all, so they additionally keep rejecting `SubmitTransaction` itself
with the pre-existing, unchanged `501 submit-transaction-requires-authenticated-route`
response — both legacy routes are therefore closed for every known kind. The
structured and preinstalled-WASM routes still accept a validly authenticated
`SubmitTransaction`; their generic non-`SubmitTransaction` branch is now
unreachable from HTTP and has been removed from native-http, but node-core's
generic `TransactionalNodeStateMachine` machinery this branch used is untouched
and remains available to any future per-family authenticated route. This closes
the audit-scope criterion that the external surface be limited to the one event
kind native-http actually authenticates; implementing authenticated ingress for
the other seven kinds remains open future work, not something this change
claims.

Malformed events return 400, oversized bodies return 413, unsupported media or
content encoding returns 415, context/CAS conflicts return 409, deterministic
application rejection returns 422, and runtime/outbound delivery failure
returns 503. The embedding process must supply a non-zero maximum number of
concurrent synchronous invocations. Once those permits are occupied, another
event submission returns 429; it does not wait in an adapter-owned queue. Error
bodies expose stable coarse codes rather than internal state or storage details.
`GET /health/live` returns 204 without reading protocol state. The server entry
point requires a shutdown future so the embedding native process can stop
accepting work cleanly.

Canonical event decoding, node-core invocation, synchronous runtime/store
calls, request-scoped outbox delivery, and canonical result encoding run as one
`spawn_blocking` job while holding the admission permit. The permit is acquired
before submitting the job, bounding both executing and Tokio-queued adapter
jobs. Liveness remains on the async executor and is outside this admission
pool. The adapter deliberately does not impose an HTTP timeout on started
blocking jobs: Tokio cannot abort `spawn_blocking` work after it starts, so
returning a timeout while a database commit may continue would create ambiguous
client semantics. The structured durable route supplies a storage-aware deadline
and checks an explicit cooperative cancellation signal before blocking dispatch,
at blocking-job entry, and immediately before its first storage call. Legacy
routes, client-disconnect wiring, shutdown budgets, cancellation of started
transport/storage work, load capacity, and circuit breaking remain required.

An embedding scheduler may call `recover_outboxes_once` without an active HTTP
request. It scans one bounded outbox-key page, validates delivery/batch identity
and cursor bounds, skips tombstones, completed batches, and unexpired leases,
then drains at most one eligible request through the same lease/send/ack path.
The result carries an exclusive continuation cursor when more keys remain; a
later sweep must restart without a cursor. Recovery and HTTP share an explicit
`NativeBlockingExecutor`, so scheduler invocations cannot bypass host blocking
capacity. Capacity exhaustion is retryable scheduler failure, not queued work.

The API creates no timer, task, loop, or daemon. Duplicate and concurrent
scheduler calls are safe only through persisted lease/CAS contention and
at-least-once downstream semantics. Transport failure leaves the lease, and a
later sweep after expiry redelivers. The current implementation stops on a
malformed record or transport failure instead of inventing a poison-message
policy. Real provider triggers, authenticated control-plane input, durable
SQLite reopen/process/power fault conformance, retention, scheduling backoff,
and operational observability remain open.

Native conformance now commits application state, deduplication, and an outbox
to SQLite, drops that runtime composition, reopens the same database in a new
composition, and recovers the outbox without rerunning the transition. A second
case persists send-failure lease state, proves a reopened runtime skips it
before expiry, and redelivers at expiry with the attempt counter retained.
These are orderly connection close/reopen tests. They are evidence for durable
state continuity, not kill -9, torn-write, filesystem, or power-loss safety.

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
delivery architecture. A local durable SQLite store, bounded native blocking
seam, and scheduler-callable one-shot discovery/recovery operation exist, but
no production runtime composition, real provider trigger, poison-message
policy, retention/compaction, trusted time policy, or crash/fault conformance
exists yet. TLS,
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
