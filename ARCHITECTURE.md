# Sunrise Edge Architecture

This document records the initial architecture for Sunrise Edge Phase 1. The implementation focus is the cryptographic and serialization foundation required for later consensus, object, execution, and runtime phases.

## 1. Overall architecture
Sunrise Edge is designed as a deterministic state-transition system over authenticated events and persistent state. The protocol core is split into small Rust crates so the same core logic can be reused in serverless and native runtimes without embedding vendor-specific dependencies.

## 2. Crate boundaries
- `protocol-types`: protocol identifiers, digest types, hash domains, and suite metadata.
- `canonical-encoding`: deterministic framed serialization for protocol-critical payloads.
- `hashing`: domain-separated hash framing, built-in hash implementations, and hash-suite resolution.
- `crypto`: signature-domain framing and signer/verifier traits, plus a
  ZIP-215-compliant Ed25519 `SignatureVerifier` implementation. No production
  signer is implemented; `runtime::MemorySigner` is a public in-memory
  wiring fixture, deliberately non-cryptographic, and must never be used for
  protocol authentication.
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

`crypto::Ed25519Verifier` implements `SignatureVerifier` against exactly
32-byte verification keys and exactly 64-byte signatures using the pinned
`ed25519-zebra` 4.2.0 crate; the committed `Cargo.lock` pins its
`curve25519-dalek` dependency at 4.1.3. Dependabot may propose updates to
either pin, but every such change stays review-gated per the repository's
dependency-update policy, not auto-merged. Verification uses ZIP-215
semantics as the consensus validation profile: the crate's cofactored
equation accepts non-canonical point encodings and small-order points,
giving an exact, specified accept/reject decision for edge cases
[RFC 8032][rfc8032] leaves ambiguous, so every honest validator reaches the
same result on the same bytes. The signature's `S` component is a separate,
unambiguous requirement, not one of those edge cases: [RFC 8032][rfc8032]
§5.1.7 itself already requires decoding `S` in the range `0 <= S < L` and
states that `S` out of range makes the signature invalid, and
[ZIP-215][zip215] likewise requires a canonically encoded `S` strictly less
than the group order `l`. A non-canonical/out-of-range `S` is rejected,
which this module's tests prove against the pinned implementation to guard
against modulo-`l` signature malleability. `SignatureSigner::sign_canonical`
and `SignatureVerifier::verify_canonical` (the trait default methods every
caller uses) reject with `CryptoError::SignatureSchemeMismatch` before any
framing or cryptographic operation if `domain.signature_scheme_id` does not
equal the signer's/verifier's own `scheme_id()`, so a caller can never
produce or accept a frame that claims a scheme it did not actually use.
Callers always go through `frame_signature_message`/`verify_canonical`; no
caller builds an ad hoc signed-byte layout. Only verification is
implemented; no production signer exists in this crate. `runtime::MemorySigner`
is a public in-memory wiring fixture used to compose test/local runtimes; it
is deliberately non-cryptographic and must never be used for protocol
authentication.

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
[zip215]: https://github.com/zcash/zips/blob/master/zip-0215.rst

A committed `protocol_config::TransactionAuthProfile` selects the active
signature scheme and address binding by configuration, not per transaction.
It is encoded as `ProtocolConfig` field 15 starting at encoding version 3,
required from protocol version 3 onward and absent for versions 1-2, so
historical v1/v2 bytes are unchanged. Profile ids are committed protocol
identifiers, not arbitrary non-zero labels: the profile carries an explicit
non-zero `u16 profile_id` that `TransactionAuthProfile::new` and
`TransactionAuthProfile::validate` (the same rules, so any profile obtained
from elsewhere in the crate can be re-checked, not merely trusted) check
against the public `protocol_config::ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`
constant (value 1) and reject every other id, a `SignatureSchemeId` (only
`Ed25519` is implemented; `Secp256k1` is a reserved identifier that fails
closed), and a closed `AddressBinding` enum whose only implemented variant,
`AddressIsPublicKey`, treats a transaction's 32-byte address as its Ed25519
verification key directly. `ProtocolConfig::validate` calls
`TransactionAuthProfile::validate` on any committed profile rather than only
rechecking a zero id, so a config carrying a structurally-invalid profile
fails closed the same way a freshly constructed one would.
`protocol_config::resolve_transaction_auth_profile` validates the whole
configuration and resolves this committed profile; it fails closed for a
premature profile, a missing required profile, or any other invalid
configuration. `protocol-config` has no dependency on `crypto` or `objects`
and performs no signature verification itself: it is the commitment and
resolution layer, not the transaction authentication/execution layer. A
later transaction-authentication boundary (targeting `execution::Transaction`
v1) must construct the `SignatureDomain` from the resolved profile's
committed scheme and the exact transaction-v1 message family, and must
reject — not silently reconcile — any context a transaction presents that
does not match that constructed domain. That boundary must also bound the
canonical signable byte length before hashing or verifying it: an unbounded
transaction body is an attacker-controlled input, and framing/verification
must reject an oversized payload rather than hash or verify it, per the
resource-bounding rule in `AGENTS.md`. A new profile id, and any
address-binding scheme beyond `AddressIsPublicKey`, requires a new
protocol/transaction version and an explicit accepted decision, not a
silently added identifier or enum variant. This closes the
signature-verification and committed-scheme-resolution primitives; strict
`execution::Transaction` dispatch against this profile and the owned
fast-path certificate flow remain separate follow-up work.

`execution::decode_transaction` now implements the strict, standalone
canonical decoder that boundary must eventually consume: it requires the
transaction type id and encoding version 1, requires exactly fields 1-10 and
12 with field 11 (`fee_payment`) optional, and rejects unknown/missing/
duplicate/out-of-order fields, trailing or truncated bytes, invalid UTF-8,
wrong numeric/address/digest lengths, and unknown tags/algorithms in any
nested frame (`AccessManifest`/`AccessEntry`, `ObjectRef`/`ObjectId`/
`Address`/`AccessMode`, `FeePayment`/`AssetId`, all newly given matching
decoders in `objects`, `abi`, and `fees`). It applies transaction-specific
resource bounds — tighter than the shared 32 MiB canonical frame bound —
to the chain id, entrypoint, args, signature, and `AccessManifest` entry
count before copying any of that attacker-controlled data, rejects a
non-canonical `AccessManifest` count/field layout and any duplicate
`ObjectId` entry within it, and finally re-encodes the decoded value and
requires it to reproduce the input bytes exactly, so no alternate
representation of the same transaction is accepted. It performs no
signature verification and constructs no `SignatureDomain`; it is a
canonical-structure boundary only.

`node_core::transaction_auth` now composes those primitives into one
standalone, fail-closed authentication boundary. Its
`authenticate_transaction_bytes(input, context)` entrypoint, given an
explicit `TrustedTransactionContext` (the expected `ChainId` and `Epoch`
supplied directly, plus a reference to the committed `ProtocolConfig`; there
is deliberately no separate caller-supplied protocol-version field, so
protocol-version authority comes solely from `ProtocolConfig` and cannot
drift from it):
1. resolves the committed `TransactionAuthProfile` via
   `resolve_transaction_auth_profile`, failing closed before decoding for a
   premature, missing, or otherwise invalid configuration;
2. strictly decodes `input` with `execution::decode_transaction`;
3. compares the decoded transaction's `chain_id`, `protocol_version`, and
   `epoch` against the trusted context/config, rejecting any mismatch with a
   typed error before any cryptographic work runs, even against a
   malformed key or signature;
4. builds `crypto::SignatureDomain` solely from the trusted context and the
   resolved profile, using the exact stable message family
   `"transaction-v1"`;
5. encodes the signable payload (`execution::encode_transaction_signable`,
   which already excludes the signature field) and rejects it with a typed
   error if it exceeds the explicit, deterministic
   `node_core::MAX_TRANSACTION_SIGNABLE_BYTES` bound, before
   `crypto::frame_signature_message` or the verifier can allocate or hash it;
6. dispatches on the resolved profile's closed `AddressBinding` — only
   `AddressIsPublicKey` is implemented, treating the transaction's exact
   32-byte `sender` as the Ed25519 verification key directly; an
   unimplemented binding fails to compile rather than silently falling back;
7. verifies with the committed `crypto::Ed25519Verifier`, distinguishing a
   malformed key or malformed signature length (`CryptoError`) from a
   well-formed but cryptographically invalid signature
   (`InvalidTransactionSignature`);
8. returns the new `AuthenticatedTransaction` only on a verified `Ok(true)`.

`AuthenticatedTransaction` has no public constructor: its inner
`execution::Transaction` field is private, reachable only through a
read-only accessor and a consuming accessor, so a caller cannot construct
one except through a successful `authenticate_transaction_bytes` call.
`node-core` adds workspace dependencies on `execution` and `crypto` for this
boundary alone; `protocol-config` itself continues to depend on neither and
performs no verification. Signature-algorithm agility remains committed
configuration resolved at a protocol-version/profile boundary, never a
per-transaction choice: the boundary always builds the verifier from the
resolved profile, and today that profile can only ever resolve to Ed25519
profile 1 (`AddressIsPublicKey`).

Two admissibility questions stay explicitly open for future work rather than
being decided by this PR. First, a future `TransactionAuthProfile` that keeps
`SignatureSchemeId::Ed25519` but changes any other signed input this boundary
treats as implicit and stable (the `"transaction-v1"` message family, the
canonical `encode_transaction_signable` layout, or how the address binds to
the key) must introduce an explicit transaction/signature-domain version
boundary rather than silently reinterpreting bytes an old profile already
committed to signing; profile identity alone is not that boundary. Second,
`crypto::Ed25519Verifier` uses ZIP-215 semantics (see Section 8's own
signature-domain discussion above), which by design also accepts small-order
and other non-canonical verification-key encodings; combined with
`AddressIsPublicKey` binding a transaction's address directly to its
verification key, this means some addresses accepted by this boundary as
*authenticable* are not necessarily *safe to hold value at*. This PR does not
change `Ed25519Verifier`'s verification semantics, and does not add a
key/address admissibility policy (for example rejecting small-order or
identity-point addresses at the object/asset layer); that decision belongs to
whichever object/asset layer first lets an address hold value, and must be
made explicitly before it does.

The production-oriented structured durable native route now supplies the
first authenticated `SubmitTransaction` processing seam. Router composition
accepts one committed `ProtocolConfig`, requires its protocol version to match
the trusted `NodeConfig`, and derives both transaction-auth authority and
logical placement from that configuration. Request handling strictly decodes
and context-validates the outer `NodeEvent`, then constructs an
`AuthenticatedSubmitTransaction` by authenticating the inner transaction
before access-plan derivation, operational identity allocation, clock or
storage work, transition, outbox claim, or send. The wrapper captures the
committed placement used by the later normalized durable handler, preventing
authentication under one configuration followed by routing under another.
Exact replays authenticate again before durable receipt reconciliation.
Generic node-core handlers and the legacy native routers fail closed on
`SubmitTransaction`; non-transaction event behavior is unchanged.

**Hard activation constraint:** this closes the strict authentication-to-
durable-routing gap and the persistent transaction-nonce replay gap, but it
does not complete the owned fast path. For every fresh request, the structured
durable handler derives a private reservation only from the authenticated
transaction, loads the canonical sender-and-epoch-bound next-nonce record
(`0xE006`) before application state, requires exact equality, and atomically
commits its checked increment with application state, receipt, and outbox. A
completed exact-request receipt is reconciled before reading the nonce, so a
retry returns its persisted response without consuming twice. Application
plans are always excluded from the versioned sender-nonce prefix, including
non-transaction event families and exact replays. Concurrent absent-record and
existing-record submissions are serialized by the same complete read assertion
and atomic write set. A committed deterministic `Rejected` response consumes
the nonce; authentication, pre-commit, or transition failure does not.

Nonce records are keyed by `(chain_id, protocol_version, sender, epoch)`.
Missing means expected nonce zero; epoch or protocol-version rollover therefore
starts a new sequence without rewriting historical state. The trusted,
monotonically advancing `NodeConfig.epoch` prevents old-epoch ingress, while
the signed epoch prevents cross-epoch replay. Clients must serialize
submissions: future-nonce pipelining and queueing are intentionally unsupported.
At `u64::MAX`, checked increment fails closed and the sender cannot submit again
until epoch rollover. Retention/pruning is safe in principle only after the
corresponding epoch can no longer be accepted; production pruning policy is
deferred. A retained tombstone for an epoch that may still be accepted fails as
a persistence invariant and never resets the expected nonce to zero. Physical
reclamation must preserve that rule until the epoch is permanently
unacceptable. An indeterminate commit must be reconciled with the original
request ID rather than retried under a fresh ID. This uses the existing generic
normalized state table and changes no database schema generation or
Transaction wire field/version, but it allocates persisted record type ID
`0xE006`.

Protocol version 3 MUST NOT be activated on any live chain until fee debit,
module access, mutating/consuming object effects, shared-object ordering,
FastVote/FastCertificate, and certificate publication are implemented and
atomically composed with the authenticated transaction. The structured durable
path now derives read-only object authority only from the authenticated inner
transaction, loads exact heads and immutable inline versions, authorizes typed
owners, and commits complete head assertions. The generic application machine
still consumes the outer event and cannot inspect or influence those object
reads; effects composition remains a separate boundary.
This constraint is not limited to `SubmitTransaction`: every externally
accepted non-`SubmitTransaction` node-event family — especially certificate,
protocol-upgrade, and validator-set-change events — needs an equivalent
authenticated/authorized ingress boundary before live activation. Generic
node-core handlers failing closed on `SubmitTransaction` says nothing about
those other families, which remain accepted from untrusted ingress today.
Separately, the outer `NodeEvent`'s `request_id` remains unsigned and serves
only as the receipt-reconciliation identity. A fresh identifier cannot bypass
the signed persistent nonce sequence.

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

That path-shaped key layout describes the current compatibility seam, not the
production physical schema. The accepted To-Be design is specified in
[`PERSISTENCE.md`](PERSISTENCE.md). Production records use a stable chain,
validator, and atomicity-domain namespace; carry their own protocol/type/schema
versions; separate immutable object versions from heads, receipts, outbox
messages, delivery state, checkpoints, and migrations; and use explicit
operational indexes rather than parsing text-like keys.

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
fault recovery. Native HTTP now places synchronous work behind bounded blocking
admission, but production runtime composition, storage-aware deadlines,
cancellation, and capacity evidence remain open.

SQLite is not the selected production database. Its single opaque
`sunrise_state` table intentionally proves the minimal versioned key-value
contract, but it does not provide the normalized object, receipt, outbox,
checkpoint, migration, retention, or operational indexes required by the
accepted production persistence architecture.

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
adapter retains it for non-transaction events, while its structured route uses
the normalized durable equivalent described below.

`node-core` carries the Transaction v1 authentication boundary described in
Section 8 (`node_core::transaction_auth`). It composes the strict
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
invocation. Fee debit, module loading, mutating/consuming object effects,
shared-object ordering, fast-path certificates, and authorization for every
other externally accepted event family remain mandatory before live activation.

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

## 41. Production persistence architecture

The production persistence contract is validator-local and provider-neutral.
Each invocation targets one explicit atomicity domain, asserts revisions for
its complete exact read set (including read-only, absent, and tombstoned keys),
and atomically commits application mutations, the request receipt, and initial
outbox data. Cross-domain write plans fail closed until a separate certified
protocol supplies prepare/commit and visibility semantics.

The logical schema separates small protocol records, immutable object versions,
object heads, request receipts, immutable outbox messages, mutable indexed
delivery state, checkpoints, and migration jobs. Large immutable values use a
content-addressed blob store. A dedicated due-work query replaces full
key-prefix scans for production outbox scheduling; `StateKeyScanner` remains a
repair, migration, and compatibility seam.

PostgreSQL is the first production-oriented reference backend, not a protocol
dependency. Cloudflare maps one atomicity domain to one SQLite-backed Durable
Object and AWS initially uses one fenced writer region. D1 read replicas,
DynamoDB Global Tables, alarms, queues, schedulers, and relays are not assumed
to make authoritative state writes globally atomic. Detailed schema,
provider mappings, migration, retention, backup/restore, fencing, and
certification requirements live in [`PERSISTENCE.md`](PERSISTENCE.md).

Atomicity-domain identity is logical protocol configuration rather than
physical placement. The initial `DomainPlacementManifest` has one non-zero,
chain-unique, never-reused domain and a closed `AllState` rule. Node-core must
resolve the complete bounded application access plan before reads; receipt and
outbox records inherit that invocation domain. The adapter validates the
resolved domain rather than accepting it from an untrusted request. Deployment
metadata separately binds `(chain, validator, logical domain)` to PostgreSQL,
one Durable Object, or one fenced regional authority, so provider migration
does not change protocol identity.

`AtomicityDomainId` now lives in dependency-light `protocol-types` and rejects
the all-zero value. `ProtocolConfig` optionally carries the manifest as field
14 under encoding version 2. The historical version-1 genesis bytes remain
unchanged. Protocol version 1 rejects a manifest, while protocol version 2 and
later reject its absence. The manifest canonically commits its non-zero rule
version, logical domain, closed rule tag, and activation epoch; resolution
rejects empty plans and pre-activation events. Additive node-core resolved
handlers now derive the access plan once, resolve before storage reads, and
return the committed domain beside output. `native-http` exposes an additive
resolved-domain router only when the runtime store implements
`DomainTransactionalStateStore`. It accepts no HTTP domain input and carries
the node-core result into request-scoped outbox claim/ack. The legacy SQLite
router and scan-based unattended recovery remain compatibility paths.

The runtime now models that boundary explicitly with a non-zero 32-byte
`AtomicityDomainId`, a separately validated `AtomicStateReadSet`, a put/delete
`AtomicStateMutationSet`, and `AtomicStateTransaction`. Read and mutation sets
are unique and canonically key-ordered; every mutation must have a matching
read assertion. The envelope caps each set at 4,096 keys and caps aggregate
domain, key, revision, tag, and value bytes at 64 MiB. These are shared safety
ceilings, not measured provider capacity; provider adapters may require lower
bounds.

`DomainTransactionalStateStore` reads through an explicit domain and commits
exactly one such envelope. `MemoryStateStore` keeps domain maps isolated and
validates every read before calculating or applying any mutation revision. Its
legacy `StateStore` and `TransactionalStateStore` implementations remain in a
private test-only legacy domain so existing node-core and SQLite conformance do
not silently change physical layout. Node-core exposes additive domain-aware
transactional and idempotent handlers: both read through one explicit domain,
bind every declared observation into the dedicated read set, and release output
only after `commit_transaction`. The idempotent handler includes application
mutations, request receipt, immutable outbox batch, and initial delivery cursor
in that same domain transaction. Domain-aware outbox claim/ack reuses one
storage-neutral validation and cursor-transition implementation: only point
reads and the final transaction commit differ between legacy and domain stores.
The immutable batch observation and delivery-cursor mutation remain one domain
transaction. An additive native request path now composes these operations.
Normalized PostgreSQL implements the structured store and indexed unattended
recovery As-Is; other durable providers remain pending.

The additive `DurableDomainStateStore` boundary makes production operation
authority and uncertainty explicit without changing the legacy or domain
transaction traits. One `DurableOperationContext` carries a non-zero monotonic
writer-fence generation, an absolute storage deadline, and a fixed-size
non-zero correlation ID across reads and commit. These are deployment and
observability inputs, never canonical protocol fields, deduplication identity,
or HTTP-selected authority. A durable commit has exactly three top-level
states: committed, definitely rejected, or indeterminate. Revision conflict,
stale writer fence, exhausted serialization retry, and failures proved to
precede commit dispatch are definite rejections. Deadline, cancellation, or
connection loss after dispatch is indeterminate unless the backend proves an
abort; reconciliation must read the persisted request receipt before effects
are retried. Node-core, native composition, SQLite, and provider adapters have
not migrated to this new production boundary yet.

The additive `IndexedOutboxRepository` is the production discovery and lease
boundary. A claim receives one deployment-bound logical domain, trusted runtime time,
and a bounded restart-safe lease identity, then selects at most one eligible
row through stable `(available_at, request_id)` index order and installs the
lease atomically. It accepts no key-scan cursor or scheduler-selected domain.
The claimed payload is the exact bounded canonical outbound event projection.
Repeating the same lease ID reconciles an indeterminate claim by returning the
identical work while owned; reuse for another message fails closed. A matching
acknowledgement advances one message, while replay of the same acknowledged
`(request, index, lease)` succeeds idempotently. The normalized delivery model
therefore retains a uniquely bound delivery-attempt record through the owning
batch's retention window rather than erasing evidence when it clears the active
lease. Keeping only the most recent acknowledgement would fail after a later
message advances. Both claim and acknowledgement distinguish
definite pre-commit rejection from indeterminate commit. Callers never send an
indeterminate claim before reconciliation. Defining this contract does not
itself provide a durable repository. PostgreSQL now implements the boundary;
`StateKeyScanner` remains a compatibility path for stores that have not
migrated.

Native now also exposes additive `recover_indexed_outbox_once`. Trusted
embedding composition fixes the logical domain and current physical writer
fence, a bounded storage timeout strictly shorter than the lease, and a
restart-safe identity source before an untrusted scheduler triggers the call.
This authority may include explicitly draining old logical domains during a
fenced migration; it is not re-derived from an arbitrary request or scheduler
input. The path claims at most one message, makes one same-identity
reconciliation attempt for an indeterminate claim, validates and sends only
reconciled canonical event bytes, then makes one same-identity acknowledgement
reconciliation attempt. It shares native blocking admission and returns no scan
cursor. Scripted conformance proves unresolved claims are not sent. PostgreSQL
now supplies the durable repository; real scheduler binding and transport-aware
cancellation/deadline do not yet exist, so the scan path remains
compatibility-only rather than deleted.

[`POSTGRES.md`](POSTGRES.md) fixes the first relational implementation design:
exact binary namespace columns, full-range unsigned numeric representation,
writer/schema metadata, normalized state/object/receipt/outbox/checkpoint
relations, retained lease-attempt history, serializable transaction order,
indexed claim/ack behavior, and explicit migration/certification evidence. It
also closes an API-design trap before SQL implementation: the existing
`AtomicStateTransaction` exposes only opaque keys and values. A normalized
driver must not parse `PersistenceLayout` prefixes to infer receipt, outbox, or
object rows. Node-core must first build a structured durable envelope with
separately typed and bounded sections. SQLite remains unchanged compatibility
data and is never request-path migrated into that schema.

Runtime now implements that input boundary as `DurableInvocationTransaction`
and `StructuredDurableDomainStateStore`. An invocation names one logical
domain, an optional `DurableStateTransaction`, one canonical typed receipt, an
optional typed ordered outbox batch, and an explicit object section. The state
section keeps a complete read set but may have zero mutations, allowing a
read-only transition to bind its observations while the receipt is written.
Constructors reject cross-domain state and receipt/outbox request or event
digest drift and cap the aggregate represented bytes. The object section has
canonical unique/sorted body-free head assertions and contained
create/update/delete mutations. Immutable versions and ABA-safe head revisions
are distinct; versions contain exactly one existing canonical Object encoding
or self-describing blob reference, and a separate read API returns immutable
records without loading bodies into head assertions. Head reads validate only
bounded immutable-row metadata and inline presence/length, never fetch or
decode inline bytes. Inline owner projections are derived from typed `Owner`
when written, but a head projection is routing metadata, not authorization:
an execution caller must separately read the exact immutable version, match
its version/digest to the head, decode the inline Object, and compare its typed
owner. Blob-backed execution fails closed until fetch and content verification.
The generation-one SQL `type_id` is the stable
canonical Object record ID rather than the logical `Object::type_hash` retained
inside canonical bytes. Memory and PostgreSQL apply object/state/receipt/outbox
sections atomically, preventing an adapter from hiding object writes in generic
state. Node-core now uses the object section for authenticated read-only
manifest authorization and exact head assertions; object mutations/effects
remain deferred. Indexed outbox
repositories now refine the structured store trait so one implementation owns
initial commit and later delivery state. An additive node-core handler now
resolves the manifest domain before I/O, checks the typed receipt before state
reads, and constructs this envelope from one pure transition. Exact replay does
not rerun the transition or republish the outbox; read-only transitions retain
their full assertion set; rejected and indeterminate commits release no output.
A dedicated in-memory conformance store holds state, typed receipt, and typed
outbox under one lock, validates injected trusted time and writer generation,
and exercises commit, conflict, read-only, replay, deadline, and fence behavior
with the real node-core handler. It is not restart-safe production storage.
An additive native router now owns explicit normalized store, transport, clock,
and restart-safe identity components without requiring the store to implement
the legacy opaque `StateStore`/`Runtime` surface. Trusted embedding authority
fixes writer fence and time budgets; node-core resolves the manifest domain and
commits the typed invocation before native claims at most one message for that
exact request. Commit, claim, and acknowledgement reuse one bounded operation
context. Claim and acknowledgement ambiguity receive one same-identity
reconciliation attempt, and an unresolved claim is never sent. The in-memory
tests prove an older due row in the same domain is not mistaken for the current
request. The normalized PostgreSQL adapter now uses this boundary, while
started transport/storage work is not cancellable.

The `runtime-postgres` crate now makes the accepted generation-one schema
executable through an operator-only migration and exact namespace bootstrap.
Its dedicated `sunrise_edge` schema separates metadata, state records, object
versions/heads, request receipts, outbox batches/messages, indexed delivery,
retained lease attempts, checkpoints, and migration jobs. Namespace rows bind
exact chain bytes, validator identity, logical domain, schema identity and
generation, and a non-zero physical writer fence. Full-range `u64` values use
checked `NUMERIC(20,0)` constraints. PostgreSQL 18 CI applies the migration in a
dedicated test database and verifies idempotent schema application, bootstrap
fence mismatch rejection, exact relations/indexes, unsigned overflow rejection,
and zero-domain rejection. Its bounded pool performs fenced state, body-free
object-head, immutable object-version, and receipt reads plus serializable
structured state/object/receipt/outbox commits. Object assertions lock in
canonical ID order; tombstones clear current/digest/projection columns and
reconstruct the last version from immutable history; inline/blob payloads map
losslessly to the unchanged generation-one schema. The live fixture runs the
same domain/fence/deadline/bounds, create/update/delete/recreate ABA, conflict
rollback, replay, and blob round-trip contract as memory. It additionally
asserts immutable history, current/tombstone rows, blob mapping, body-free
metadata corruption rejection, and strict malformed-body rejection through
the separate immutable-version read. The same store
implements exact-request and stable `(available_at_ms, request_id)` indexed
claims, checks retained lease attempts before selecting work, expires a
replaced attempt in the replacement transaction, and advances one message only
through an exactly bound acknowledgement. Claim and acknowledgement take a
shared namespace-metadata lock so a fence advance cannot race them without
serializing unrelated delivery rows; `SKIP LOCKED` is confined to due delivery
selection. Request traffic does not run DDL or bootstrap. An optional shared
commit-loss capability now covers commit-boundary connection loss over the
plain `NoTls` transport (see below), and a separate serialized live test now
covers database-process SIGKILL and WAL recovery on a live host with a live
page cache (DR-0069). Separate bounded disposable-container tests cover
pre-commit data-tablespace ENOSPC (DR-0070) and pre-commit WAL-filesystem
ENOSPC (DR-0071); the latter shows the same SQLSTATE `53100` at `PANIC`
severity crashes the whole server, not just the connection. In-flight
cancellation, abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or real-device
ENOSPC, TLS-path connection loss, backup/restore, capacity/load/soak, real
writer failover, and production certification evidence remain open, so this
is still As-Is adapter evidence rather than production readiness.

Runtime exposes the vendor-neutral durable-store conformance cases only to its
own tests or adapters that opt into the non-default `durable-conformance`
feature. One fixture supplies the backend's trusted deadline clock, exact
logical domain, and operator-only writer-fence advance while the suite drives
only `StructuredDurableDomainStateStore` and `IndexedOutboxRepository` methods.
Memory and PostgreSQL run the same complete-read write-skew, concurrent absent
and tombstone, definite contention-outcome, retained outbox-lease, and
writer-fence cases. PostgreSQL additionally injects unsupported schema metadata
and a real serialization abort at an exhausted retry ceiling when the live-test
URL is configured; CI supplies it. A separate optional `CommitLossFixture`
capability, implemented only by that same live PostgreSQL test through a
bounded `NoTls` TCP proxy, can sever the connection either immediately before
a dispatched `COMMIT` reaches the backend or immediately after the backend
returns a successful acknowledgement for it; both instants classify as
`Indeterminate(ConnectionLost)`. The shared case injects the pre-dispatch
instant once, for one plain state commit, proving no state ground truth was
published. It injects the post-acceptance instant three times: for one
structured invocation commit, proving exact committed state/receipt ground
truth and that a same-identity replay observes `RequestAlreadyCommitted`; for
an outbox claim on that invocation's message, first proving with a different,
never-used lease that the original lease is still active (`NoDueWork`) and
then that a same-lease replay reconciles to the identical claimed message;
and for the corresponding acknowledgement, first proving that reclaiming with
the original lease is rejected as lease-ID reuse and then that a
same-identity replay reconciles to acknowledged with the acknowledgement
persisted and no message left due. These discriminating probes matter because
a same-lease claim replay or same-identity acknowledgement replay alone would
succeed identically whether or not the prior transaction actually persisted.
A final unfaulted commit proves the connection pool recovers afterward. This
shows the backend returned a successful acknowledgement before the driver
lost it, not crash durability under abrupt process/power loss, and it says
nothing about TLS-path connection loss. A separate serialized live test now
proves database-process SIGKILL and WAL recovery on a live host with a live
page cache (DR-0069). Separate disposable-container scenarios prove bounded
data-tablespace ENOSPC before `COMMIT` and exact recovery after space is
freed (DR-0070), and bounded WAL-filesystem ENOSPC before `COMMIT`, which
crashes and in-place restarts the whole server rather than just the
connection, with exact recovery after space is freed (DR-0071); none of these
tests prove abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or
real-device ENOSPC, TLS-path behavior, backup/restore, capacity/load/soak,
real writer failover, provider certification, or production readiness, all of which
remain backend-specific evidence. Passing this suite is As-Is contract
evidence, not production certification.

A cancellation-enabled normalized native composition accepts and owns an
explicit trusted `InvocationCancellation` signal. It checks that signal in the
async request handler, again when the bounded blocking job begins, and
immediately before the first structured storage call. Cancellation at any of
those checkpoints returns 503 without state, receipt, outbox, send, or
acknowledgement effects. Once the first storage call starts, the job never
consults the signal again and completes commit/delivery reconciliation normally.
This deliberately does not cancel started synchronous PostgreSQL work or
manufacture `IndeterminateCommitReason::CancellationRequested`;
client-disconnect wiring, shutdown budgets, and in-flight cancellation remain
separate work.

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
  process/power loss, and it proves nothing about TLS-path connection loss.
  This evidence is additive to, not a replacement for, DR-0061's existing
  induced-abort/schema-skew coverage. The only current implementation is a
  bounded, test-only `NoTls`
  TCP proxy in `runtime-postgres`'s live PostgreSQL test: it binds port 0,
  relays the untyped startup message and every later typed frame, detects
  the exact simple-query `COMMIT` a durable commit, claim, or acknowledgement
  dispatches last, and tracks the one active physical connection so `Drop`
  can sever it directly instead of waiting on the pool's own client teardown
  or the bounded per-socket I/O timeout. Keep abrupt process/power fault,
  disk-full/WAL exhaustion, TLS-path connection loss, backup/restore,
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
  activation constraint in §8). `Ed25519Verifier` test evidence includes a
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
