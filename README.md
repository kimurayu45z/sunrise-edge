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
  verification and builds no `SignatureDomain`. Dispatch that builds the
  signing context from the committed profile and rejects any mismatch, and
  the owned fast path itself, remain unimplemented.
- Versioned objects, object references, access manifests, and lazy migration.
- Runtime traits and an in-memory runtime for deterministic tests.
- A local durable SQLite transactional store using WAL, synchronous FULL,
  immediate write transactions, revision tombstones, and fail-closed schema
  identity/version checks. It also implements bounded, cursor-paginated binary
  prefix key discovery for recovery adapters. It is a local reference and
  conformance fixture, not the selected production database.
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
  same live fixture through a bounded `NoTls` TCP proxy, injects a connection
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
  acknowledgement over the plain transport before the driver lost it, not
  crash durability under abrupt process/power loss, and it says nothing about
  TLS-path loss or capacity. Broader fault, operations, and production
  certification remain pending, so this is still As-Is evidence.
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
  implements the same object boundary As-Is; node-core object dispatch and
  blob upload/fetch verification remain deferred.
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
real provider trigger wiring, abrupt process/power-fault recovery conformance,
portable system-module
execution, cryptographic slashing proof verification, fee-object debiting,
provider persistence bindings, runtime adapters, networking/RPC surfaces, and
independent security review.

The next planned technical milestones work backward through the Phase 15
production exit criteria in [`TODO.md`](TODO.md) and the accepted
[persistence design](PERSISTENCE.md): implement the accepted
[PostgreSQL reference design](POSTGRES.md): extend the now-implemented fenced
structured commit, indexed outbox adapter, and shared memory/PostgreSQL
conformance, now including commit-boundary connection-loss evidence, with
capacity evidence. Native structured requests now honor an explicit
cooperative cancellation signal only before first storage dispatch;
client-disconnect cancellation, abrupt process/power fault, disk-full/WAL
exhaustion, TLS-path connection loss, backup/restore, real writer failover,
and provider conformance follow on that foundation. Phase 16/17 provider
trust, deployment, observability, and release rehearsal remain required.

## Workspace map

| Area | Crates | Responsibility |
| --- | --- | --- |
| Protocol foundation | `protocol-types`, `canonical-encoding`, `hashing`, `crypto`, `commitments` | Stable identifiers, canonical bytes, domain separation, hash suites, signatures, and state commitment schemes |
| State and access | `objects`, `abi` | Versioned objects, ownership, object references, access modes, and transaction access manifests |
| Execution | `execution`, `contract-sdk`, `chain-ir`, `system-modules` | Transactions/effects, deterministic WASM, proof envelopes/verifier interfaces, contract host APIs, portable IR, and governed modules |
| Economics and governance | `fees`, `bonds`, `governance`, `protocol-upgrades`, `protocol-config` | Stablecoin fees/bonds, admission, governance actions, upgrades, migrations, and committed configuration |
| Runtime and consensus | `runtime`, `runtime-sqlite`, `runtime-postgres`, `validator-set`, `consensus`, `node-core` | Persistence/runtime interfaces, local durable SQLite state, normalized PostgreSQL structured commit and indexed outbox adapter, epoch validator snapshots, event-driven shared-object ordering, and one-event conditional transitions |
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
