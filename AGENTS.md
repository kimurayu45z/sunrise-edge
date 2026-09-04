# AGENTS.md

This file applies to the entire Sunrise Edge repository. A more deeply nested
`AGENTS.md`, if one is added later, may refine these instructions for its
subtree.

## Mission

Build Sunrise Edge as a production-oriented, serverless-native blockchain state
machine. Preserve deterministic protocol behavior, historical compatibility,
cryptographic domain separation, and portability across runtimes.

The core principle is:

> A blockchain node is a state machine, not a process.

Do not introduce a daemon, persistent connection, background loop, or cloud
provider as a protocol assumption.

## Read before changing code

1. Read [`README.md`](README.md) for the current human-facing project status.
2. Read the relevant sections of [`ARCHITECTURE.md`](ARCHITECTURE.md).
3. Read the relevant requirements and implementation phase in [`TODO.md`](TODO.md).
4. Inspect the affected crate APIs, tests, and dependency direction.
5. Search the workspace for existing type IDs, enum tags, hash domains, error
   patterns, and canonical encoders before defining new ones.

`TODO.md` contains both implemented and aspirational design. Existing canonical
bytes, stable test vectors, accepted decision records, and released protocol
behavior are compatibility constraints. Do not rewrite them merely to match an
aspirational example.

## Non-negotiable architecture rules

- Keep vendor-specific dependencies out of protocol crates.
- Pass all state explicitly or load it through runtime traits. Do not add global
  mutable protocol state.
- Do not use `spawn`, infinite loops, background workers, persistent sockets, or
  process lifetime as a correctness requirement.
- Treat clients, relays, transports, schedulers, Tick senders, and cloud
  providers as untrusted.
- Treat atomicity-domain IDs as logical protocol configuration. Never derive
  them from provider/database coordinates or accept an untrusted request's
  domain as authoritative; physical placement is separate fenced deployment
  metadata.
- Keep validator identity, membership, voting power, bond, and economics
  separate. Bond amount must not silently determine voting power.
- Route owned/non-conflicting transactions toward the fast path and shared or
  conflicting transactions toward consensus; do not impose global ordering on
  all state access.
- Preserve deterministic execution and effects across machines and runtimes.
- Avoid whole-state migrations. Use versioned data and deterministic lazy
  migration.

## Protocol-critical change checklist

Treat a change as protocol-critical if it can alter canonical bytes, a digest,
a signature payload, execution effects, object identity/versioning, quorum
behavior, fee/bond arithmetic, governance outcomes, or persisted state layout.

For every protocol-critical change:

- Include explicit `chain_id`, `protocol_version`, and `epoch` replay boundaries
  wherever the message lifecycle requires them.
- Use `CanonicalStruct`; do not hand-build ambiguous concatenations.
- Give structures, enum variants, fields, algorithms, schemes, and domains
  explicit stable identifiers.
- Search all `*_TYPE_ID`, discriminants, and encoding tests before allocating an
  identifier. Never reuse an identifier within a canonical namespace.
- Frame variable-length data and collections with explicit lengths/counts.
- Define byte order explicitly. Do not use floats.
- Canonically sort unordered inputs before encoding or aggregation.
- Use checked arithmetic for amounts, gas, power, counters, epochs, heights,
  views, lengths, and deadlines.
- Add deterministic resource bounds before accepting attacker-controlled lists,
  byte strings, modules, signatures, keys, or schedules.
- Reject unknown or unsupported values explicitly. Never downgrade or silently
  fall back.
- Preserve old digest verification and historical state readability across
  upgrades.
- Add a stable encoding vector when adding or changing a wire type.
- Add negative/adversarial tests, not only happy-path tests.

If a required change breaks a stable encoding or consensus result, introduce an
explicit protocol/encoding version and document the activation and compatibility
policy. Do not edit an old vector and call the change compatible.

## Cryptography

- Hash algorithms are agile but never negotiable per transaction.
- Resolve the active `HashSuite` from protocol configuration and epoch.
- Use self-describing `Digest32` values for protocol references; do not spread
  naked `[u8; 32]` hashes through protocol APIs.
- Use the centralized hashing and signature framing APIs. Callers must not
  invent ad hoc prefixes.
- Keep general-purpose hashes and ZK/state commitment schemes separate.
- Adding an identifier is not the same as implementing or activating an
  algorithm. Unknown/unimplemented algorithms must fail closed.
- Do not add new cryptographic primitives from memory alone. Verify parameters,
  standards, and test vectors against primary sources.

## Consensus and untrusted delivery

- Consensus transitions consume explicit persisted state and exactly one event.
- Validate message context, membership, leader selection, signature scheme,
  signature, quorum, view/height relationships, and lock safety before voting or
  committing.
- Delivery must remain safe under duplication, replay, reordering, delay, and
  stale messages.
- Quorum/certificate bytes must not depend on vote arrival order.
- A Tick may affect liveness only; it must not manufacture authorization,
  quorum, or a commit.
- Keep state retention bounded and preserve idempotency when pruning.

## Rust rules

- Add `#![forbid(unsafe_code)]` to protocol and runtime crates.
- Do not add new Rust `unsafe` without explicit user authorization and an
  architecture decision explaining why a safe design is impossible.
- The existing `contract-sdk` raw WASM host-ABI layer is the sole current
  exception. Keep unsafe operations confined there and expose checked safe
  wrappers to contracts.
- Use typed errors with actionable variants. Do not panic on malformed external
  input.
- Avoid `unwrap`, `expect`, `panic!`, `todo!`, and `unimplemented!` in library
  paths. They are acceptable in focused tests when failure is the assertion.
- Prefer immutable values and deterministic collections (`BTreeMap`/
  `BTreeSet`) where iteration can affect protocol output.
- Avoid unnecessary clones, but favor correctness and explicit ownership at
  state-transition boundaries.
- Document public APIs and security-sensitive invariants.
- Keep dependencies minimal and declare shared versions in the workspace root.

## Crate boundaries

- `protocol-types`: dependency-light stable identifiers and core protocol types.
- `canonical-encoding`: the only canonical framing implementation.
- `hashing`, `crypto`, `commitments`: cryptographic abstraction and framing.
- `objects`, `abi`: versioned state and declared access.
- `execution`, `contract-sdk`, `chain-ir`, `system-modules`: deterministic
  execution surfaces.
- `fees`, `bonds`, `governance`, `protocol-upgrades`: protocol economics and
  controlled evolution.
- `validator-set`, `consensus`: epoch membership and shared-object ordering.
- `runtime`: storage, signing, transport, clock, and scheduler abstractions plus
  test adapters.
- `protocol-config`: the canonical commitment point for active protocol
  parameters.
- `signing-view`: dependency-light hardware profile decoding and exact
  signed-byte clear-signing policy; it must not depend on `execution`, a
  runtime, or any Ledger/USB/HID vendor crate.

Keep foundational crates low in the dependency graph. Avoid cycles and avoid
making protocol primitives depend on execution engines, runtimes, or adapters.

## Workflow

1. Inspect `git status` and preserve unrelated user changes.
2. Identify whether the task changes protocol behavior or only implementation.
3. For a new phase or architecture change, update `ARCHITECTURE.md` and add a
   decision record before or alongside the implementation.
4. Implement the smallest coherent change without compatibility shortcuts.
5. Add unit, stable-vector, integration, and adversarial tests proportional to
   the risk.
6. Run targeted tests while iterating.
7. Run the full required validation before handoff:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
```

The repository check includes Rust formatting, all-feature clippy and tests,
Cloudflare type/lint/workerd tests, Deno/Vercel/Supabase/AWS adapter checks, and
`git diff --check`. Run the targeted command while iterating, then the complete
script before handoff. Do not omit provider checks because a change appears to
touch only the shared Web layer.

Dependabot proposes weekly Cargo, Cloudflare npm, and GitHub Actions updates.
Never auto-merge those PRs. Review changelogs and compatibility impact, retain
immutable workflow-action SHAs, and require the complete repository gate before
accepting an update.

Do not claim success if any required command was skipped or failed. Explain any
environmental limitation precisely.

## Documentation and pull requests

- Keep `README.md` focused on human orientation, current capabilities, setup,
  status, and risks.
- Keep `DEVNET.md` as the exact local devnet/CLI operator walkthrough and
  restart comparison; do not duplicate that runbook into the README.
- Keep this file focused on durable agent/contributor instructions.
- Keep `ARCHITECTURE.md` synchronized with implemented behavior and decision
  records.
- Keep `TODO.md` as the detailed design brief and roadmap; do not mark work
  complete unless the implementation and validation exist.
- In PR descriptions, separate implemented scope, compatibility impact,
  deferred work, and exact validation commands.
- Do not mix unrelated cleanup into a protocol change.

## Current roadmap context

The implementation covers the major foundations through Phase 14 and local
As-Is adapter milestones through Phase 17. Poseidon2/BN254 is experimental and
inactive; BLS12-381 and concrete proof backends remain unsupported and must
fail closed. Phase 15 node-core/native HTTP, Phase 16 Cloudflare, and Phase 17
Deno/Vercel/Supabase/AWS implementations are bounded local seams, not completed
production trust, persistence, deployment, or operations architectures.

In `TODO.md`, an implemented Phase is only an As-Is milestone, never a
production-readiness claim. Preserve and work backward from each To-Be exit
criterion after context compaction. Re-check `main`, the open stacked PR chain,
and `TODO.md` before starting because repository state may have advanced. The
explicit `CLI Developer MVP Gate` (`TODO.md`; renamed and narrowed from the
earlier `Developer MVP Gate` to node/client/CLI capability criteria 1-6/10/11)
and S0-S3 of the production sequence are satisfied As-Is. S4a's strict
hardware-signing profile, signed-byte-only clear-signing fixture, and host
external-signer preflight are implemented As-Is by DR-0088. S4b's separate
dedicated Ledger device application, five-target builds, and Nano S+ Speculos
evidence are implemented As-Is by DR-0091; S4 is not complete. DR-0092
implements S4c Phase 1's host APDU/USB/HID transport and explicit CLI Ledger
signer selection As-Is, including profile/address checks and strict
USB-descriptor-level device recognition, but not active-app/firmware identity
checks or physical-hardware evidence. DR-0093 implements S4c Phase 2a's strict
Ledger OS identity/dashboard parsing and staged dashboard/firmware/open-app/
reconnect/active-app identity sequence in software As-Is, still without
physical-hardware validation. As of 2026-09-04 the user has explicitly
reordered the roadmap: all remaining Ledger work — S4c Phase 2b's
physical-hardware validation, S4d's golden/pixel UI, HIL, and release
evidence, and any other Ledger device/host/HIL completion — is deferred, and
no Ledger code is touched by non-Ledger slices. Non-Ledger S5 prerequisite
work (see DR-0094 below) may proceed instead, but S4, S5, the
`CLI-First Node Production Gate`
(`TODO.md`), production, and mainnet readiness all remain incomplete; passing
that gate was never mainnet readiness on its own — it is a real
node/persistence/operations gate defined entirely by reference to existing,
unchanged Phase 15 To-Be exit criteria, the Post-MVP persistence
implementation order, and the cross-phase release gate. DR-0095 keeps S0-S3
as the common baseline and makes S4 Hardware Signing and S5 Software
Production parallel tracks without weakening either (see ARCHITECTURE.md
DR-0085/DR-0095). S2's exact
cross-owner destination
policy is implemented by DR-0086. S3's uniform ordinary-asset fee composition,
actual-gas settlement, trap fee-only charge, and restart/replay evidence are
implemented by DR-0087 without changing historical WAT/WASM or canonical wire
bytes. The preinstalled-WASM fee-aware path accepts only an all-zero or a
base/execution-only committed `GasSchedule` shape, rejecting any priced
S3-unmeasured category and a zero `base_fee` paired with a non-zero
`execution_price` before engine work with a typed, opaque HTTP 500 mapping,
and the real file-backed SQLite E2E proves both the successful and trapped
invocation replay exactly, in the same boot and after reopen, without
reapplication. S1 implements remote TLS transport
plus a separate locally configured expected protocol-context check before
signing; these are two independent slices, and as of 2026-09-01 both are
implemented and tested As-Is, so S1 as a whole is complete. The
protocol-context slice: `clients/rust` has a public
`context::ExpectedProtocolContext` and `Client::query_verified_context`
covering chain id, protocol version, an exact-epoch policy, hash-suite id,
transaction-auth profile id, signature-scheme id, address-binding id, and the
logical `AtomicityDomainId` (never `protocol_config_bytes`, and never folded
into `crypto::SignatureDomain`), and `apps/cli`'s `transfer` requires five
`--expected-*` flags, rejects a missing/zero/malformed value before any
network dispatch, calls `query_verified_context` as its first network
request, and uses only the verified context for every later nonce/object
query, transaction construction, signing, and submission step; adversarial
tests prove every one of the eight compared fields stops `transfer` after
exactly one context request, before any later dispatch. The remote-TLS
slice: `clients/rust` adds `transport::RemoteTlsHttpTransport`, sharing
`LoopbackHttpTransport`'s exact bounded HTTP/1.1 request/response framing
and per-stage monotonic deadlines but driving a real `rustls`
`ClientConnection` handshake, requiring one caller-resolved `SocketAddr` (no
DNS resolution of its own), one caller-supplied DNS server name (used for
both SNI and hostname validation, never IP-hostname fallback), and one
caller-supplied CA trust-anchor DER capped at the public
`transport::MAX_CA_CERTIFICATE_DER_BYTES` — never a system trust store,
PEM/bundle, or mTLS client certificate;
`clients/rust/tests/remote_tls_transport.rs` exercises it against a real `rcgen`/`rustls`
loopback TLS server (correct/wrong hostname, correct/wrong CA, stalled/
closed handshakes, caller-deadline tightening, malformed-constructor
rejection, and a `LoopbackHttpTransport` regression check). `apps/cli`'s
`context`, `object`, `receipt`, `next-nonce`, and `transfer` commands each
accept a paired, optional `--tls-server-name`/`--tls-ca-cert-der-file` flag
set, parsed centrally in `apps/cli/src/net.rs` into one `CliTransport` enum:
neither flag keeps the legacy loopback-only plaintext path (still rejecting
non-loopback endpoints), both flags dial `RemoteTlsHttpTransport` against the
supplied endpoint, and exactly one flag fails closed with a typed
`CliError::PartialTlsConfiguration` before any network dispatch; the CA file
is read with `std` only, bounded by the same public maximum before the read
completes, and empty/oversized/unreadable files each return their own typed
`CliError` naming the path but never the file's contents.
`apps/cli/tests/tls_cli_e2e.rs` adds two real local TLS integration tests
(again `rcgen`/`rustls`, no external network): one proves a `context` query
succeeds over TLS with the exact expected `Host` authority, and the other
proves that a `transfer` invocation which successfully authenticates TLS
against a server whose `/v1/context` disagrees with `--expected-chain-id`
still makes exactly one context request (confirmed via the test server's own
connection counter) and returns the typed `ProtocolContextMismatch` before
ever reaching nonce/object/sign/submit — demonstrating that TLS endpoint
authentication and the expected-protocol-context check are two independent
boundaries, neither substituting for the other. This slice ships no mTLS, no
certificate revocation/rotation/lifecycle handling, and no CA
deployment/operations evidence; those remain explicitly deferred to later
slices, not silently assumed. TypeScript-client/explorer/wallet criteria 7-9
are kept verbatim, not completed or deleted, and remain deferred until the
Software Production Gate (S0-S3 + S5) passes; they do not wait for deferred
S4 hardware work. Existing production exit criteria remain
mandatory; capacity/PITR/HA/provider-certification work remains frozen
until S5 or an explicit SLO triggers it. Node-core now asserts every
declared read revision in its atomic write set. Runtime has the explicit atomicity
domain and dedicated read/mutation envelope with memory conformance; additive
node-core transaction, outbox delivery, and native request entrypoints now use
it; normalized PostgreSQL implements it As-Is, while other durable providers
have not migrated. The logical-domain manifest
is committed as ProtocolConfig encoding v2 without changing historical v1
bytes. Additive node-core handlers resolve it from one access-plan derivation
before storage reads and return the domain beside output. An additive native
router uses that result for request-scoped delivery and accepts no HTTP domain,
but SQLite/default routing and scan recovery remain legacy. The current Phase
15 sequence is: preserve the additive fenced/deadline-aware structured
state/object/receipt/outbox boundary now wired through node-core, ephemeral
memory conformance, and an explicit native request composition. Native commits
the typed invocation and uses the same operation context to claim/ack at most
one message for that exact request; it never sends an unresolved claim.
`runtime-postgres` now applies the explicit generation-one normalized schema
and bootstraps exact namespace/schema/fence metadata through operator-only APIs,
with real PostgreSQL CI. Its bounded pool now implements fenced structured
state/body-free object-head/immutable object-version/receipt reads,
serializable state/object/receipt/outbox commit, and indexed
claim/ack with retained attempt history As-Is. Object-head reads validate
strict immutable metadata and inline presence/length without selecting inline
bodies. Head owner/routing projections are routing data, never authorization.
The authenticated structured durable path now loads every signed manifest entry
through its exact head and immutable inline version and matches the typed owner
to the verified sender. A separate additive owned-effects entrypoint supplies
those inputs to a pure transition in signed manifest declaration order and
atomically commits strict Write/Consume Update/Delete effects with exact head
assertions, sender nonce, state, receipt, and outbox. `structured_durable_router`
still rejects Write/Consume before storage I/O; a separate additive
`preinstalled_wasm_structured_durable_router` composes a trusted preinstalled
catalog/engine/checkpoint and now accepts signed owned Write/Consume through
the preinstalled-WASM entrypoint instead. Shared/System ownership and
arbitrary module upload remain fail-closed on every route. Every
immutable object version now
carries its creating chain/protocol-version provenance (`DurableObjectProvenance`,
DR-0068), and node-core independently recomputes and verifies each
authenticated object's digest from that provenance and the stored `Digest32`
algorithm before authorizing it, under bounded inline-body budgets — node-core
no longer trusts the storage adapter for object-body integrity. DR-0094 wires
`runtime::BlobStore` into authenticated durable object loading: a
`BlobReference` payload is now fetched from an explicit `BlobStore` component
(threaded through `StructuredDurableNativeComponents` and every authenticated
node-core entrypoint as `B`, never folded into the state store) after
provenance/receipt/nonce checks and before transition, bounded at the same
per-object 1 MiB limit and folded into the same pre-activation 8 MiB
aggregate inline/blob budget before hashing or decode, with its own
`blob_digest` independently verified against the fetched bytes before
`objects::decode_object` runs and the existing `record.digest` re-verified
against the same canonical bytes afterward; a missing blob or a `BlobStore`
`RuntimeError` are distinct typed errors mapped to an opaque HTTP 503, and a
digest/decode failure is an opaque 500. Exact replay is unaffected. The fully
generic, never-dispatching `handle_resolved_durable_idempotent_event` keeps
its original signature (no `BlobStore` parameter); only the three
authenticated entrypoints, which always declare a dispatch, require one.
Blob upload/publication of a new
version, a durable provider `BlobStore`, and GC/checkpoint manifest work
remain unimplemented; the bounded query API still returns only blob reference
metadata and never fetches a body. PostgreSQL
generation one was redefined in place under schema identity v2
(bootstrap-only; an old v1 database fails closed) to add the provenance
columns. A shared memory/PostgreSQL conformance suite now
covers bound-domain/fence/deadline rejection, the object read-count bound,
typed object create/update/delete/recreate ABA, conflict rollback, inline/blob
mapping and blob round-trip, exact-boundary deadlines, complete-read races,
definite contention classification, lease/writer fencing, and PostgreSQL-only
pool/row-lock deadline exhaustion, serialization exhaustion, and schema skew
As-Is. An optional shared commit-loss capability, exercised only by that live
PostgreSQL fixture through a bounded `NoTls` TCP proxy, injects a
connection loss immediately before one plain state commit dispatches `COMMIT`,
proving no state ground truth, and separately immediately after the backend
returns a successful acknowledgement for one structured invocation commit, one
outbox claim, and one acknowledgement, proving exact state/receipt ground
truth plus `RequestAlreadyCommitted` for the commit. The claim and
acknowledgement cases each first probe the store independently (a
different-lease claim while the original lease is still active, and a reclaim
attempt with the original lease after acknowledgement) since a same-lease or
same-identity replay alone cannot tell a persisted commit from an uncommitted
one, then check same-identity reconciliation, with pool recovery proven
afterward. This shows the backend acknowledged commit before the driver lost
it, not crash durability under abrupt process/power loss, and it says nothing
about TLS-path loss. Native structured requests now support explicit
cancellation only before first storage dispatch, and this holds identically
on the new preinstalled-WASM router. The additive node-core
owned-effects composition is implemented As-Is, including trusted checkpoint
regression rejection and exact-replay non-reapplication, and `native-http`
now exposes DR-0078's preinstalled-WASM entrypoint through an additive
`preinstalled_wasm_structured_durable_router` (DR-0080); `structured_durable_router`
is unaffected and still uses the read-only entrypoint. DR-0081 fixes the
Developer MVP product-surface plan ahead of implementation: wire the local
devnet binary/startup (`apps/devnet`) around the additive SQLite structured
store with strict loopback binding, a persisted fence/boot generation,
startup registry/catalog reconciliation, and seeded asset accounts (see
`ARCHITECTURE.md` "Local devnet architecture"); add a bounded query API; then
build, in order, a Rust client (`clients/rust`), a Rust-only CLI (`apps/cli`,
depending only on `clients/rust`), a TypeScript client (`clients/typescript`),
and separate static/CSR SvelteKit + shadcn-svelte apps (`apps/explorer`,
`apps/wallet` — no request-time server-side rendering, server adapter, or
server-held sessions/keys; fixed-shell build-time prerendering is allowed and
wallet signing stays browser-only) with restart/duplicate E2E
evidence. `apps/devnet`, the bounded query API, `clients/rust`, `apps/cli`,
and the restart/duplicate E2E
(`apps/cli/tests/devnet_restart_duplicate_e2e.rs`) are implemented As-Is.
Under DR-0085's CLI-first production-strategy pivot as amended by DR-0095,
`clients/typescript`, `apps/explorer`, and `apps/wallet` remain deferred
(kept verbatim, not completed or deleted) until the Software Production Gate
(S0-S3 + S5) passes. This replaces DR-0080's earlier `clients/typescript`/`demo/counter`
pairing; no `demo/counter` directory is created. The devnet's own
demonstration contract is `sunrise.devnet.asset_account.v1`
(`transfer`), moving balance between two ordinary asset accounts under the
uniform fungible asset model (one `AssetId`/account/transfer/fee path for every
asset, no privileged native coin or special balance path) ratified in DR-0081.
DR-0086 permits only its exact existing cross-owner destination policy while
preserving both owners. DR-0087 activates module/semantics v3 with unchanged
WAT/WASM and v1/v2 vectors, requires the sender source as fee object, and
settles actual gas into the distinct treasury owner's ordinary destination.
Create, Shared/System ownership, blob upload/publication of a new version, a
durable provider `BlobStore`, GC/checkpoint manifest work, arbitrary module
upload, fee distribution/FastCertificate settlement, production gas
calibration, S4c Phase 2b/S4d Ledger physical-hardware/HIL/release completion
(deferred by the user's explicit roadmap reorder, not by a technical gap),
and production object migrations remain deferred.
The opaque SQLite table and prefix scanner remain local
compatibility/reference paths, not production schema. Started blocking work
remains uncancellable and its configured admission limit is not
a validated capacity budget.
