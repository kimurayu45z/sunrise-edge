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

The Developer MVP owned-effects entrypoint keeps the verified storage result
private inside node-core. After the signed reference, exact current head,
immutable inline version, provenance-bound digest, typed owner, and body bounds
have all been checked, the loader retains the exact typed `Object` beside its
head read assertion. A private pure translator then requires a one-to-one
correspondence between declared access and deterministic `ObjectEffect`: Read
accepts no effect, Write accepts exactly one same-identity `Mutated` effect with
an exact previous version and checked `+1` version, and Consume accepts exactly
one exact-version `Deleted` effect. Creation, undeclared or duplicate effects,
owner/type/schema changes, unsupported owners, overflow, and missing trusted
creation context fail closed. A Write is encoded canonically, and its new body
shares the same 8 MiB invocation budget already charged by verified input
bodies rather than receiving a second independent allowance. It is then
hashed with the active Object suite from trusted chain/protocol/epoch context,
and translated into a new immutable version plus Update mutation while
preserving its routing projection; Consume translates to Delete. The additive
owned-effects handler supplies the verified objects to the pure transition in
signed manifest declaration order, accepts Write/Consume only on that explicit
policy, and supplies a composition-trusted checkpoint that cannot come from
request bytes. It atomically composes the returned Update/Delete mutations and
exact head assertions with sender nonce, application state, receipt, and outbox.
Checkpoint regression relative to the prior immutable version fails closed;
an exact request replay reconciles the receipt before object reads or execution
and therefore cannot reapply an effect. Generic handlers receive no resolved
objects and reject any returned object effect instead of silently discarding
it. The existing read-only entrypoint (and `native-http`'s
`structured_durable_router`, which still calls only that entrypoint) retain
the read-only policy and still reject Write/Consume before storage I/O; a
separate additive `native-http` composition,
`preinstalled_wasm_structured_durable_router`, now accepts signed owned
Write/Consume through the preinstalled-WASM entrypoint below instead (see
DR-0080).

An additive trusted preinstalled-WASM composition now captures the exact
matching `SystemModule` record (or its committed absence) from the same
`ProtocolConfig` used at authentication, so a later caller cannot substitute
another registry entry without cloning the full registry per request. For this
MVP path,
`Transaction.module_ref` maps `ObjectId` bytes to `ModuleId`, object version to
module version, and object digest to the exact canonical code commitment. The
selected entry must be active at the transaction epoch, must declare at least
one authenticated object access (a zero-object call is rejected before domain
resolution), and must match a bounded immutable node-supplied catalog.
Node-core independently reverifies its WASM bytes against the registry's
committed `canonical_code_hash` under `ContractCode`, and its canonically
re-encoded manifest against the committed `manifest_hash` under the dedicated
`HashPurpose::SystemModuleManifest` purpose (mapped to the already-stable
`HashDomain::SystemModule` domain and the suite's `config_hash` algorithm),
and matches the supplied semantics digest. Both commitment checks use
`hashing::verify_digest` — the algorithm recorded on the committed digest
itself, plus the resolver's trusted chain/protocol-version context — rather
than the hash suite active at the transaction's epoch, so an epoch-only
hash-suite rotation does not require governance to recommit already-installed
modules; a `protocol_version` bump does, since it changes the hash frame
itself (see DR-0078). The transaction's `gas_limit` is rejected before the
engine ever runs if it exceeds a conservative pre-activation ceiling. Only
then does the bounded deterministic WASM engine run over the already verified
objects. Canonical `ExecutionEffects` are returned in the response; successful
owned effects use the existing atomic translator, while a trapped execution is
first normalized to one fixed, engine-independent failure reason and a
deterministic full-`gas_limit` charge with empty effects/events (discarding
the WASM engine's own untrusted trap text and fuel accounting) before that
normalized value is encoded and committed as a deterministic rejected receipt
and nonce with exact object head assertions but no mutation. Exact receipt
replay returns before module resolution, object reads, or execution. The
composition is object-only and uses the signed object-access count for
logical-domain placement without a dummy application key. This entrypoint was
initially added to node-core only (DR-0078, historical: at that point native
HTTP activation was still deferred); a later additive `native-http` router
now wires it up (see DR-0080). Arbitrary uploads, JIT/AOT, and production
metering remain deferred.

Protocol version 3 MUST NOT be activated on any live chain until shared-object
ordering, FastVote/FastCertificate, certificate publication, and every
externally accepted event family's authenticated/authorized ingress are
implemented and atomically composed with the authenticated transaction where
protocol semantics require it; independently, the CLI-First Node Production
Gate's remaining S4/S5 and the independent security/release gates must also be
completed. The bounded S3 uniform ordinary-asset fee composition (DR-0087) and
the additive owned-effects/preinstalled-WASM module-object effects entrypoints
are implemented As-Is, but implementing them alone does not satisfy this
constraint. The structured durable
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
The S3 local-devnet fee slice is implemented As-Is by DR-0087; validator/
certificate distribution and production stablecoin economics remain deferred.
A fee asset is an ordinary
`fees::AssetId`-tagged asset account using the same single account/transfer
path as every other asset, never a privileged native coin or a second
balance/transfer implementation. Fee-asset selection (which `AssetId`(s) may
pay fees, at what rate) is protocol policy layered over ordinary asset
accounts. The implemented preinstalled-WASM path reuses the sender-owned
declared fee-object access, exact-head assertions, and atomic object-effect
commit as every other transfer, and appends one trusted ordinary treasury
access that the module cannot observe. Settlement uses the committed receipt's
actual `gas_used`; it never charges `gas_limit` after a successful execution.

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

`runtime-sqlite` additionally exposes `SqliteDurableStore` (DR-0079): an
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
invocation. The bounded S3 uniform ordinary-asset fee composition (DR-0087)
and additive owned-effects/preinstalled-WASM module-object effects
entrypoints are implemented As-Is; shared-object ordering, fast-path
certificates/publication, authorization for every other externally accepted
event family, S4/S5, and the independent security/release gates remain
mandatory before live activation.

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
manifest authorization and exact head assertions, plus an additive
owned-effects path that commits validated signed Address-object Update/Delete
mutations; Create, Shared/System ownership, and blob transfer verification
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
plain `NoTls` transport and a separately authenticated TLS client leg that
terminates at a bounded test proxy (DR-0074; see below), and a separate serialized live test now
covers database-process SIGKILL and WAL recovery on a live host with a live
page cache (DR-0069). Separate bounded disposable-container tests cover
pre-commit data-tablespace ENOSPC (DR-0070) and pre-commit WAL-filesystem
ENOSPC (DR-0071); the latter shows the same SQLSTATE `53100` at `PANIC`
severity crashes the whole server, not just the connection. A further bounded
disposable-container test covers real server connection-slot exhaustion
(DR-0072), showing this adapter classifies it as the definite pre-commit
`Rejected(DeadlineExceededBeforeCommit)`, not `UnavailableBeforeCommit`,
because its pool-acquisition wait and the caller's own operation deadline
are, by construction, exhausted together. A further bounded two-container
test (DR-0073) covers a `pg_dump`-based database-snapshot restore rehearsal:
schema identity and restored namespace metadata/state/receipt verified
before fence promotion, operator-only writer-fence advance on the restored
namespace, stale pre-backup context fencing, and exact reconciliation plus
fresh commit under a new context, alongside an atomic invalid-dump rollback
and a valid missing-state gate rejection; this is rehearsal evidence for one
`pg_dump`/SQL-execute snapshot cycle only, not a production backup/restore capability, and it does
not close the backup/restore evidence criterion below. A further bounded
rehearsal (DR-0075) runs the real adapter (a genuine `r2d2` pool plus
`PostgresDurableStore`) through a real, digest-pinned `pgbouncer` 1.25.2 proxy
in transaction-pooling mode with exactly one backend connection for the
tested database/user pool, on an isolated generated Docker network: PgBouncer
admin-console evidence (never inferred) confirms configured transaction mode
and proves two simultaneously open, distinct client connections reuse the
exact same PostgreSQL backend across sequential transactions; while a direct
proxied client holds that one backend in an open transaction, one adapter
invocation gets the definite pre-commit `Rejected(UnavailableBeforeCommit)`
once PgBouncer's own `query_wait_timeout` elapses, with no state/receipt/
outbox publication; after release, the identical invocation commits, replays
as `RequestAlreadyCommitted`, and its outbox message claims/acknowledges
through `NoDueWork`, with the pool remaining usable. This is a bounded local
transaction-pooling rehearsal only, not provider-managed pooler service
certification, load/soak, failover, or TLS evidence. In-flight
cancellation, abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or real-device
ENOSPC, PostgreSQL-server/provider TLS beyond the bounded DR-0074 client leg,
point-in-time recovery, continuous WAL
archiving, hot/concurrent backup, checkpoint publication, blob-manifest/
state-root/encryption-key verification, capacity/load/soak, provider-managed
pooler production certification/load/failover beyond the bounded DR-0075
rehearsal, real writer failover, and
production certification evidence remain open, so this is still As-Is
adapter evidence rather than production readiness.

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
bounded `NoTls` TCP proxy and a separate required-TLS client-to-terminator
proxy, can sever the connection either immediately before
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
lost it, not crash durability under abrupt process/power loss. The TLS proxy
requires ordinary PostgreSQL `SSLRequest`, uses an ephemeral private CA and a
`localhost`-only server certificate, rejects an IP-host negative connection,
and records completed authenticated handshakes before running the exact same
shared cases. It terminates TLS and relays plaintext to PostgreSQL, so it proves
only client/driver-to-test-terminator TLS loss behavior, not server-terminated
TLS, provider PKI/mTLS/rotation/revocation, or production readiness. A
separate serialized live test now
proves database-process SIGKILL and WAL recovery on a live host with a live
page cache (DR-0069). Separate disposable-container scenarios prove bounded
data-tablespace ENOSPC before `COMMIT` and exact recovery after space is
freed (DR-0070), bounded WAL-filesystem ENOSPC before `COMMIT`, which
crashes and in-place restarts the whole server rather than just the
connection, with exact recovery after space is freed (DR-0071), and bounded
real server connection-slot exhaustion, which this adapter classifies as the
definite pre-commit `Rejected(DeadlineExceededBeforeCommit)` rather than
`UnavailableBeforeCommit` because its own pool-acquisition wait cannot
outlast the caller's operation deadline, with exact recovery after one
blocking connection is released (DR-0072), and a bounded two-container
`pg_dump`-based database-snapshot restore rehearsal, proving schema identity
and restored namespace metadata/state/receipt before fence promotion, an
operator-only writer-fence advance on the restored namespace, stale
pre-backup context fencing, and exact reconciliation plus fresh commit under
a new context, alongside an atomic invalid-dump rollback and a valid
missing-state gate rejection
(DR-0073), and a bounded PgBouncer transaction-pooling rehearsal: PgBouncer
admin-console evidence proving configured transaction mode and exactly one
PostgreSQL backend reused across two simultaneously open client connections'
sequential transactions, the real adapter (`r2d2` pool plus
`PostgresDurableStore`) pointed at the proxy, one adapter invocation
definitely rejected (`UnavailableBeforeCommit`) once PgBouncer's own
`query_wait_timeout` elapses while a direct proxied client holds the pool's
one backend, no publication, and exact recovery/replay/claim/ack after
release (DR-0075); none of these
tests prove abrupt host/power loss, storage write-cache
flush/torn-write/media/filesystem faults, commit-boundary or
real-device ENOSPC, PostgreSQL-server/provider TLS beyond DR-0074,
point-in-time recovery, continuous WAL
archiving, hot/concurrent backup, checkpoint publication, blob-manifest/
state-root/encryption-key verification, capacity/load/soak,
provider-managed pooler production certification/load/failover beyond the
bounded DR-0075 rehearsal, real writer
failover, provider certification, or production readiness, all of which
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

## 42. Local devnet architecture

DR-0081 fixed the local devnet's architecture ahead of its implementation so
the client/app work that depends on it can target a stable contract. The
devnet composes the existing `preinstalled_wasm_structured_durable_router`
around a dedicated startup binary in `apps/devnet` rather than introducing new
protocol behavior:

- **Strict loopback startup.** The devnet binds only a loopback address
  (`127.0.0.1`/`::1`); it never binds a non-loopback interface, and
  bundles no TLS termination, authentication, or public-exposure hardening.
  This is a local developer fixture, not a hosted network.
- **Persisted fence/boot generation.** After `SqliteDurableStore::open`
  completes its existing schema/namespace bootstrap and verification, startup
  reads the persisted writer fence through a new additive operator-only
  accessor, advances that exact value with checked arithmetic, and uses the
  result as that process's boot generation and `created_checkpoint`. It never
  invents an in-memory substitute for missing or invalid durable metadata.
  The implemented accessor and startup flow make boot generations
  non-decreasing across restarts
  and fences stale request contexts from a prior process.
- **SQLite structured store.** State, object, receipt, and outbox data use the
  additive, local-only, non-production `SqliteDurableStore` (DR-0079), never
  the opaque legacy `SqliteStateStore`; the two require separate files because
  `PRAGMA application_id` is a whole-file SQLite property.
- **Registry/catalog reconciliation at startup.** Before serving any request,
  startup constructs its dev-profile `SystemModuleRegistry` and bounded
  immutable `PreinstalledModuleCatalog` from the same committed in-process
  artifact, then validates their code/manifest/semantics commitments before
  router construction. This proves internal composition consistency and fails
  boot with an operator-legible error if either representation is altered; it
  is not an independent comparison with persisted governance configuration.
  The general preinstalled-WASM route's request-time mismatch behavior remains
  unchanged.
- **Seeded asset accounts.** Startup seeds exactly two ordinary
  `sunrise.devnet.asset_account.v1` objects (`Owner::Address`) per configured
  development owner and per required distinct fee-treasury owner. At most 63
  transfer owners may be configured, reserving the 64th bounded seed slot for
  that treasury owner. All accounts carry the same fixed, non-placeholder
  `fees::AssetId`; one starts funded and the other starts empty. A transfer may
  pair one configured owner's source with another configured owner's existing
  destination under the exact committed S2 policy. Their object IDs remain
  distinct and deterministic for that owner and slot. Restart verifies every
  current object's exact identity/owner/type/schema/canonical body/digest/
  provenance, its immutable version-one seed history and receipt, then checks
  the fixed total seeded supply across the bounded configured-owner set;
  per-owner pair totals and sequences are intentionally not assumed equal
  after legitimate cross-owner movement.
- **Bounded asset-account transition.** The dev profile reserves the otherwise
  unused local type-ID block `0xF001`-`0xF003`, all at encoding version 1. An
  asset-account body is one 76-byte `CanonicalStruct` (`0xF001`) with fields
  `1: asset_id[32]`, `2: balance u64`, and `3: sequence u64`. `transfer`
  arguments are one 24-byte `CanonicalStruct` (`0xF002`) with field
  `1: non-zero amount u64`. Transfer event data is one 90-byte
  `CanonicalStruct` (`0xF003`) with fields `1: asset_id[32]`, `2: amount u64`,
  `3: resulting source balance u64`, and `4: resulting destination balance
  u64`. These exact frames, including magic, type/version, field count,
  ordered field IDs, lengths, and little-endian fixed-width values, are shared
  as stable vectors; the WAT verifies constant framing bytes and patches only
  the declared values. The signed manifest declares exactly two `Write`
  distinct objects in source/destination order; canonical transaction decode
  and node-core both reject duplicate object IDs before WASM execution.
  Execution rejects unknown framing,
  unequal asset IDs, zero amount, insufficient source balance, destination
  overflow, and sequence overflow; otherwise it writes both objects,
  increments both sequences, preserves the combined balance, and emits
  `sunrise.devnet.asset_account.transferred.v1`. The event and both effects
  enter the same durable receipt and an exact duplicate replays that receipt
  without applying either effect again.
- **Uniform post-execution fee composition.** Protocol version 3 commits a
  base fee of 1, an execution price of 1 per actual `gas_used`, zero prices for
  unmetered categories, and exactly one enabled `DEVNET_ASSET_ID` quoted 1:1.
  A fee-bearing transaction declares its sender-owned source as `fee_object`
  and appends the trusted treasury owner's ordinary destination account as the
  final `Write`. Node-core hides that final access from WASM, settles only
  after execution, and asks the pure devnet `AssetAccountFeeComposer` to debit
  payer and credit treasury using the same strict `0xF001` codec. A successful
  source update merges application and fee bodies into one durable object
  version advance (the asset-account body sequence advances once per logical
  application/fee mutation). A normalized trap discards application effects,
  consumes full declared gas, and commits only payer/treasury fee effects with
  a rejected receipt. Exact replay reconciles before object I/O or composition.
  The transfer event remains module output: its `source_balance` is post-
  transfer but pre-fee; clients obtain the post-fee balance from the committed
  object and compute the charge from receipt `gas_used` plus the committed
  schedule.
- **Canonical catalog declarations.** The dev profile also reserves local
  declaration type IDs `0xF010` for the asset-account schema declaration and
  `0xF011` for its execution-semantics declaration. The schema declaration
  remains encoding version 1. The historical same-sender semantics declaration
  remains pinned at encoding version 1, the S2 cross-owner declaration remains
  pinned at version 2, and the active S3 declaration uses version 3 while
  preserving the exact WAT/WASM and canonical code hash. These declarations are complete `CanonicalStruct`
  frames and are hashed
  under the existing `SystemModule` purpose when deriving the preinstalled
  catalog commitments. They describe the `0xF001` body, `0xF002` arguments,
  `0xF003` event, exact two-object write manifest, rejection conditions, and
  conservation/sequence invariants. They are dev-profile catalog metadata,
  not an alternate balance, transfer, or fee-asset protocol path.
- **Committed destination type/owner boundary.** The WASM host ABI still
  exposes object data but not `type_hash`, `schema_version`, or owner metadata.
  Before object I/O, node-core resolves the exact trusted preinstalled module
  once and later requires source access index 0 to be Address-owned by the
  authenticated sender. Its only owner exception is the catalog policy at
  destination index 1 for the exact module/version, `transfer` entrypoint,
  `Write` mode, `asset_account_type_hash()`, and schema version 1. The loaded
  current destination must be Address-owned and match that type/schema exactly;
  the module still verifies the complete self-describing `0xF001` body frame,
  and the effect translator freezes all metadata including both owners.
- **Dev-profile identities are not protocol claims.** The seeded `AssetId` and
  asset-account `type_hash` are fixed, non-zero dev-profile identifiers so
  clients can render and exercise the local fixture. No mint/metadata object
  or on-chain asset registry currently vouches for them, and no new
  `HashPurpose` is introduced by this local composition. Wallet and explorer
  must therefore render the ID as opaque bytes plus an explicitly local label,
  never as production asset metadata.
- **No background sweeper.** The devnet runs no resident outbox-recovery loop,
  timer, or scheduler; unattended recovery, when needed, is invoked the same
  way the native binary already exposes it (see "Serverless runtime
  constraints" and the scheduler-callable recovery API above), consistent with
  treating process lifetime as a non-requirement.
  The current generic machine and asset transition produce responses but no
  outbound messages, so the local transport queue does not grow on this route;
  its fixed capacity remains a fail-closed bound for a future message-producing
  transition.

Current vs. planned: `apps/devnet` now has strict loopback-only configuration,
persisted writer-fence advancement across SQLite reopen, a restart-safe
bounded identity source, exact canonical asset-account codecs/vectors, a
committed WAT/WASM module, reconciled registry/catalog composition, and atomic
restart-idempotent account seeding. Its binary composes those pieces into the
bounded preinstalled-WASM native router and serves HTTP on the configured
loopback address. Live smoke validation observed a `204` liveness response and
verified the same seeded object IDs after reopening under the next writer
generation. Direct WASM tests prove successful same-asset movement and
effect-free rejection of mixed asset IDs. The bounded query API (chain/context
info, object reads, receipts, and an authenticated sender's next nonce), the
Rust client (`clients/rust`), the Rust-only CLI (`apps/cli`), and a signed
cross-owner duplicate-transfer restart/duplicate HTTP E2E
(`apps/cli/tests/devnet_restart_duplicate_e2e.rs`) are implemented As-Is per
the designs defined below and in "Rust client library" / "Rust client
external-signer boundary and Developer MVP CLI". Under the CLI-first
production-strategy pivot (see "Local devnet architecture" above and
DR-0085), the TypeScript client, explorer, and wallet remain deferred until
the CLI-First Node Production Gate passes (`TODO.md#cli-first-node-production-gate`);
no other `clients/*`/`apps/*` path from DR-0081 exists yet. Known current
limitations that
must stay visible at devnet startup and in documentation once implemented:
single validator; owned-object only (Create, Shared/System ownership, and
blob bodies remain fail-closed); one fixed ordinary fee asset and one ordinary
treasury without validator/certificate distribution, gas categories other
than base/execution pricing, or production economics; only the exact policy-bounded existing Address-owned destination
may differ from the sender, while literal owner reassignment/gifting remains
fail-closed; local SQLite only; the four bounded query routes are an
unauthenticated public-read API (any caller can read any object/receipt/
next-nonce/context — the address in `/v1/senders/{sender}/next-nonce` is a
public lookup selector, not authorization); query and submission share one
admission budget (`compose_devnet_router`'s single `NativeBlockingExecutor`
sized from `--max-concurrent`), so a burst of query traffic can starve
submissions and vice versa; and an overall non-production security/
operations posture.

## 43. Bounded Developer MVP query API

The Developer MVP exposes four additive `GET` routes from both normalized
structured routers. They share the event route's blocking-admission limit and
trusted storage authority, but accept no request body, writer fence, deadline,
domain, chain context, or protocol selector from HTTP:

- `/v1/context` returns the trusted `chain_id`, current `epoch`, exact canonical
  `ProtocolConfig`, and the single committed logical atomicity domain.
- `/v1/objects/{object_id}` returns true absence, a retained tombstone, a
  verified current inline object, or an explicit current blob reference.
- `/v1/receipts/{request_id}` returns typed absence or the exact canonical
  `NodeDedupRecord` after checking it against the outer durable receipt.
- `/v1/senders/{sender}/next-nonce` returns the next nonce for the current
  trusted epoch. The address in this URL is only an untrusted public lookup
  selector. It grants no authority and cannot substitute for transaction
  authentication; the returned value is usable only by a transaction whose
  signature authenticates that same sender under the committed auth profile.

Every path identifier is exactly 64 lowercase ASCII hexadecimal characters.
Malformed identifiers fail before identity allocation, clock access, or
storage I/O. Successful results use
`application/vnd.sunrise-edge.query-result`, `Cache-Control: no-store`, and
four independent canonical version-1 frames: context `0xE102`, object
`0xE103`, receipt `0xE104`, and next-nonce `0xE105`. Object status identifiers
are `1 = absent`, `2 = tombstoned`, `3 = current inline`, and `4 = current blob
reference`; receipt status identifiers are `1 = absent` and `2 = present`.
These identifiers and exact frames are stable client contracts and require
literal test vectors.

Absence is a normal `200` typed result so receipt polling needs no
transport-specific interpretation. A current inline object includes its head
revision, immutable version, self-describing digest, and exact canonical
`objects::Object` bytes. Node-core, not the HTTP adapter or storage adapter,
cross-checks head/version/digest/schema/provenance/owner projection and
recomputes the inline body digest from the version's stored chain and protocol
provenance before returning it. A blob-backed version returns only explicit
metadata and its blob digest; this MVP does not fetch or claim to verify an
unavailable blob body. A tombstone retains the ABA-safe head revision and last
immutable version. Receipt presence includes the outer event digest and exact
canonical dedup bytes only after strict decode, identity/digest agreement, and
canonical re-encoding checks. A deleted nonce record for an epoch that may be
accepted remains corruption and fails closed; true absence at initial revision
returns zero.

Every query route, including `/v1/context`, resolves the domain from the
committed manifest through the same activation-epoch-checked
`DomainPlacementManifest::resolve_domain` path the authenticated write path
uses (at the trusted current epoch, with one bounded access rather than a real
application plan) — never `placement.domain()` read unconditionally — through
one shared helper both `/v1/context` and the three storage-backed routes
call. All storage-backed queries additionally allocate a restart-safe
correlation identity and a bounded deadline from the embedding host, and run
through the same bounded blocking executor as submission. An inactive
placement therefore rejects before identity allocation, clock access, or
storage I/O for the three storage-backed routes, and before any response is
constructed for `/v1/context`; it remains an opaque `503` for every route,
while a malformed selector is a `400` rejected at the HTTP boundary.
Capacity exhaustion is `429`; malformed paths are `400`; a transient host or
storage-availability condition (identity-source unavailability, clock/runtime
failure, a durable read that proves writer fencing/deadline exhaustion/
backend unavailability/unsupported schema generation
(`DurableReadError::SchemaMismatch`, treated as an operator/deployment
condition rather than proof of corrupted persisted bytes), or committed
`ProtocolConfig` inactivity/misconfiguration) is an opaque `503`; corrupt or
unverifiable persisted content, result-encoding failure, and identity-source
exhaustion are an opaque `500`. Query responses are bounded by the existing
maximum canonical
object/receipt sizes; there is no scan, list, prefix, pagination, proof,
historical-version selector, or arbitrary state-key endpoint in this MVP
slice.

Every one of the four result types except `/v1/context` (which has no request
selector) carries the exact selector it answers — `object_id`, `request_id`,
or `sender` — in every status, including absence and tombstone. Node-core's
`ObjectQueryResult` and `ReceiptQueryResult` bind this selector at the type
level so the HTTP layer cannot construct a canonical result for one selector
from a lookup keyed by another; `native-http`'s wire codecs re-assert the same
binding as an always-present field, and the adapter independently re-checks
the selector on the result node-core returns before encoding it, as defense
in depth against a future regression.

Current vs. planned: this slice is implemented As-Is. `node-core` adds public
`query_sender_next_nonce`, `query_object`, and `query_request_receipt`
functions — implemented in a private internal module but re-exported from the
crate root, so `node_core::query_object` etc. are the stable public paths, not
a public `query` module — as the only entrypoints that can observe a
next-nonce value, an object, or a receipt outside node-core; the private
`SenderNonceRecord` framing never crosses that boundary, and the object/receipt
checks reuse the same cross-check/re-encoding rules as the authenticated write
and replay paths. `query_object` checks the immutable version's creating-chain
provenance against the trusted chain before branching on inline versus blob
payload, so a cross-chain blob record fails closed exactly like a cross-chain
inline record; a `CurrentBlobReference` result's `digest` and `blob_digest`
are the values recorded on the immutable version and cross-checked against the
head, never verified against fetched body bytes, since this MVP never fetches
a blob body. `native-http` adds the four canonical
`application/vnd.sunrise-edge.query-result` codecs (`0xE102`-`0xE105`) —
including strict decode validation of the nested canonical `objects::Object`
(id/version match, `MAX_AUTHENTICATED_OBJECT_BODY_BYTES`) and nested
`NodeDedupRecord` (request-id/event-digest match, exact re-encoding) carried
inside a `CurrentInline`/`Present` result, and rejection of a zero protocol
version/hash-suite/profile/scheme/binding id, an over-length chain id, or
empty canonical `ProtocolConfig` bytes in the context result — and wires
`GET /v1/context`, `/v1/objects/{object_id}`, `/v1/receipts/{request_id}`,
and `/v1/senders/{sender}/next-nonce` into both `structured_durable_router` and
`preinstalled_wasm_structured_durable_router`, sharing their
`NativeBlockingExecutor`, admission, and pre-storage cancellation semantics.
Every path selector is validated as exactly 64 lowercase ASCII hex characters
(and, for receipts, non-zero) before any identity allocation, clock access, or
storage I/O. Stable vectors, round-trip/unknown-tag/mismatched-selector decode
tests, both-router parity across all four routes (including a populated
current-inline object and a present receipt, not only absence), malformed-
path-before-side-effects, object absent/tombstone/current-inline/current-blob/
tamper/wrong-chain, receipt absent/present/corrupt, nonce
zero/advanced/deleted-corrupt, inactive-placement-before-side-effects cases
for `/v1/context` and a representative storage-backed object route, and the
`503`/`500` operational classification — a direct case table plus the
`SchemaMismatch` decision above — are covered in both crates' test suites.

## 44. Rust client library

The Developer MVP Rust client is a runtime-neutral library at `clients/rust`.
It exposes seed-based Ed25519 key/address handling, canonical transaction
construction and signing, submission, bounded receipt waiting, and the four
query operations from section 43. It stays application-agnostic: asset-account
transfer arguments, native-coin conventions, fee selection, and other contract
semantics belong to later consumers such as `apps/cli`, never to the base
client.

Canonical HTTP result frames and route/media-type constants are shared through
a dependency-light `node-wire` crate. `native-http` re-exports that contract so
existing server callers retain the same public names, while `clients/rust`
depends on `node-core` and `node-wire`, not on Axum or `native-http`. The shared
crate owns encoding and strict decoding only; routing, admission, clocks,
storage authority, and HTTP status classification remain server concerns.
Execution-effect decoders enforce the same collection and byte-size bounds as
their encoders and reject unknown identifiers, malformed nesting, trailing
bytes, and non-canonical representations. The transaction signature message
type is exported from node-core rather than duplicated by a client.

The initial transport is synchronous and deliberately local-development-only.
A small transport trait permits deterministic tests; the provided HTTP/1.1
implementation (`LoopbackHttpTransport`) connects only to an explicit loopback
address, opens one bounded `TcpStream` per request, applies connect/read/write
timeouts and header/body limits, requires an exact `Content-Length`, and
rejects transfer encoding, ambiguous lengths, truncated or trailing bodies,
unexpected content types, and non-loopback targets. It provides no TLS,
authentication, proxy, redirect, persistent connection, async runtime, or
production remote-node claim. (A separate, later-added `RemoteTlsHttpTransport`
lifts the loopback-only and no-TLS restrictions within S1's documented
bounds — see DR-0085 below — without changing this transport's own scope.)

`/v1/context` remains authoritative for chain, epoch, protocol-version, hash-
suite, authentication-profile, signature-scheme, binding, and atomicity-domain
identifiers. The canonical `ProtocolConfig` bytes are preserved as opaque bytes
in this slice rather than partially decoded. A caller supplies the exact trusted
preinstalled module reference and object references used by its transaction;
the client does not invent module discovery or object scans. Submission uses an
explicit non-zero request ID supplied by the caller, checks that the response is
bound to it, and never derives a protocol identity with an ad hoc hash.
Receipt absence is normal while waiting; polling always has explicit attempt,
elapsed-time, and backoff bounds and creates no background worker. Capacity and
temporary unavailability may be retried only within those caller-visible
bounds.

Stable literal vectors cover the shared query/response frames and signed
transaction bytes accepted by node-core. The client does not claim to recompute
transaction/effect hashes from the context's hash-suite identifier, fetch blob
bodies, verify certificates, or decode the full protocol configuration. Those
capabilities, production transports, key generation/keystores, CLI policy, and
application-specific helpers remain deferred until the MVP consumers require
them.

Current vs. planned: this slice is implemented As-Is. `node-wire` owns the
previously server-local codecs without changing their stable vectors, and
`native-http` re-exports the same public names. `execution` now strictly
decodes event records, object effects, and complete execution effects;
`clients/rust` re-exports those decoders for response consumers. The client
checks every returned object/request/sender selector against the exact query,
and the loopback transport rejects request framing injection, over-bound
headers/bodies, transfer encoding, ambiguous lengths, malformed status/header
syntax, truncation, trailing bytes, and failure to close a `Connection: close`
response within its timeout. Per-stage socket timeouts are also capped by one
monotonic complete-request deadline, and receipt polling passes its overall
elapsed deadline into every transport call, so a slow-drip peer cannot reset
the bound byte by byte. Nested effect-list decoders compare the declared count
with the frame's exact field count before allocating or iterating. Tests pin
the existing signed transaction vector, authenticate freshly client-signed
bytes through node-core, exercise fake submission/receipt behavior, exercise
adversarial raw TCP responses (including slow-drip and close timeout), and
query all four routes through a real composed devnet router over TCP. A live
signed asset transfer, duplicate replay, and restart sequence remains Developer
MVP criterion 10 work; this client slice does not claim that later E2E.

## 45. Rust client external-signer boundary and Developer MVP CLI

`clients/rust` gains a safe, additive two-stage transaction-construction API
(`transaction::PreparedTransaction`) alongside the existing single-call
`build_signed_transaction`, which is now implemented through the same path so
its stable output bytes are unchanged. `PreparedTransaction::prepare` takes an
explicit sender `Address`, the active `SignatureSchemeId` from a trusted
`/v1/context` result, and a `TransactionRequest`, and returns an immutable
value with the canonical Transaction v1 fields already fixed; it rejects any
scheme other than `Ed25519` before any framing happens, returning a
dedicated `ClientError::UnsupportedSignatureScheme(SignatureSchemeId)`.
Before this two-stage API existed, `build_signed_transaction` rejected the
same unsupported-scheme case later and less specifically: it always called
`SignatureSigner::sign_canonical`, whose own scheme-match guard returned a
wrapped `ClientError::Crypto(CryptoError::SignatureSchemeMismatch)` instead.
`build_signed_transaction`'s caller-visible error type for this case is
therefore different from before — this is a strictly additive, easier-to-
match error-type change, not a protocol change: the exact same case is still
rejected before any framing or signing, and every stable output byte for
every case that still succeeds is unchanged. `signable_frame`
exposes the exact centralized-domain-framed bytes
([`crypto::frame_signature_message`]) an external signer must produce a raw
signature over — the same bytes any in-process `SignatureSigner` ultimately
signs. `finalize` accepts that raw signature and only produces output after
independently constructing an `Ed25519Verifier` from the sender's 32 bytes
(the only implemented `AddressIsPublicKey` binding), re-deriving the same
framed bytes, and confirming the signature both has the scheme's exact
supported length and cryptographically verifies; a well-formed but invalid,
wrong-signer, or tampered (signature or transaction field) signature is
rejected with a typed `ClientError` and produces no output.
`sign_and_finalize_with` is a convenience composition of `finalize` for any
in-process `SignatureSigner` (for example `LocalSigner`), reusing
`sign_canonical`'s own scheme-match guard. This boundary exists so a future
external signer — including but not limited to a dedicated hardware wallet —
can be integrated without changing `PreparedTransaction`'s public shape or
this crate's stable transaction bytes: only a new caller supplying bytes to
`finalize` would be added.

**Ledger boundary is not implemented in this slice.** No USB/HID/Ledger
dependency exists anywhere in this workspace, and none belongs in a protocol
or client crate. `PreparedTransaction` is Ledger-*ready* only in the narrow
sense that it already exposes the exact bytes an external signer would need
and already independently verifies whatever signature comes back; it is not
a Ledger integration. A real integration additionally requires, at minimum: a
dedicated Sunrise Edge Ledger device application (existing Solana or Ethereum
Ledger apps must not be reused for Sunrise transaction signing — they know
nothing about this protocol's canonical framing and would either reject the
payload or, worse, sign it under the wrong domain); an APDU protocol and host
transport to that device application; on-device parsing and clear signing of
the exact Sunrise signature frame (chain/protocol-version/epoch/message-type/
scheme plus the canonical transaction payload) so a user approves what they
are actually signing, not opaque bytes; public-key/address verification
against the device; an explicit derivation-path policy; device/application/
firmware-version checks; explicit on-device user confirmation before signing;
host-side signature verification (which `PreparedTransaction::finalize`
already provides); and hardware-in-the-loop tests. None of this is
implemented or claimed here.

`apps/cli` is a new, additive, Rust-only Developer MVP CLI with exactly one
non-development/runtime dependency: `sunrise-edge-client`. (`Cargo.toml` also
declares a handful of `[dev-dependencies]` — `execution`, `native-http`,
`objects`, `rcgen`, `runtime`, `rustls`, `sunrise-edge-devnet`, `tokio` —
used only to compose a real local devnet, build canonical test fixtures,
build a decoded execution-effects fixture directly in this crate's own test
suite, and (`rcgen`/`rustls`) construct real TLS end-to-end test fixtures;
none of them are reachable from `main`, `lib`, or any non-test build.) It has no
Node/browser runtime, no argument-parsing crate (flags are
parsed by a small hand-written, strict `--flag value` parser that rejects
duplicates, unknown flags, and any non-flag/extra positional token), no
`unsafe` (`#![forbid(unsafe_code)]`), and no independent canonical
encode/decode, signing, or RPC path — every protocol interaction goes
through `sunrise-edge-client`. It provides six
commands: `address` (derives and prints the `AddressIsPublicKey` address
bound to an explicitly named development seed file — never a keystore, never
a home-directory default, and the seed is never accepted on argv or printed);
`context`, `object`, `receipt`, and `next-nonce` (thin wrappers over the
matching `sunrise-edge-client` query methods); and `transfer`, the bounded
devnet asset transfer command. Every network subcommand targets an
explicit `--endpoint`; with neither TLS flag supplied, `--endpoint` must be
loopback and this binary talks the legacy plaintext `LoopbackHttpTransport`
(a non-loopback address is rejected before any connection is attempted). With
both paired `--tls-server-name`/`--tls-ca-cert-der-file` flags supplied,
`--endpoint` is instead treated as an already-resolved `SocketAddr` with no
loopback restriction, and this binary dials `RemoteTlsHttpTransport`; this binary
performs no DNS resolution of its own, so `--endpoint` remains a literal
address either way. Output is deterministic,
line-oriented `key=value` text; every error is a typed, actionable
`CliError`, and every error exits the process non-zero. A successful node
response payload is decoded through `sunrise-edge-client`'s already-generic
`execution::ExecutionEffects` decoder when possible; receipts, object bodies,
and any payload that does not decode as effects are printed as bounded
lowercase hex instead of inventing a claim about their meaning.

`transfer` is the only place in this repository outside `apps/devnet` that
knows the `sunrise.devnet.asset_account.v1` module's fixed `transfer`
entrypoint name and its exact `CanonicalStruct(0xF002, v1){1: u64 amount}`
argument frame — `clients/rust` stays application-agnostic. To build that
frame and the transaction's access manifest without a second direct
dependency, `clients/rust` additively re-exports a small, generic surface
that adds no devnet-specific semantics of its own: `abi::{AccessEntry,
AccessManifest}`, `objects::{AccessMode, Object, ObjectError, Owner,
decode_object}`, `execution::ObjectEffect`, `canonical_encoding::{
CanonicalStruct, CanonicalEncodingError}`, `protocol_types::{AtomicityDomainId,
ChainId, Digest32, Epoch, HashAlgorithmId, HashSuiteId, ProtocolVersion,
SignatureSchemeId, TypeError}`, `NODE_RESULT_MEDIA_TYPE`, and three small
helpers/constants: `current_inline_object_ref` (extracts the exact `ObjectRef`
from a `CurrentInline` object-query result, `None` for every other status —
generic over any object, not asset-specific), the
`ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID` constant (the `AddressBinding::
AddressIsPublicKey` wire value, duplicated as a plain `u16` so a caller can
compare it against `HttpContextQueryResult::address_binding_id()` without a
direct `protocol-config` dependency; `protocol-config` remains a `clients/rust`
dev-dependency only, and a dedicated test pins the two values together so
they cannot silently drift), and the `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`
constant (the committed `TransactionAuthProfile` id `transfer` checks
`HttpContextQueryResult::transaction_auth_profile_id()` against before
signing, duplicated the same way and for the same reason). `objects::{
ObjectError, Owner, decode_object}` and `execution::ObjectEffect` exist so
`transfer` can decode a queried object's canonical body, check its owner
client-side as defense in depth, and print each object effect from decoded
execution effects, without a direct dependency on either lower crate.

`transfer` queries `/v1/context`, the sender's `/v1/senders/{sender}/next-nonce`,
and both `/v1/objects/{object_id}` results for the caller's exact
`--source-object`/`--destination-object` identifiers; validates the
committed profile is `Ed25519` + `AddressIsPublicKey` and that the context
and next-nonce queries agree on epoch, all before signing; requires both
objects to be `CurrentInline` (any other status is a typed, actionable
rejection); requires the source owner to equal the signer and the destination
owner to equal the separately required `--destination-owner` Address before
signing; constructs the exact two-entry `AccessManifest` with `Write`
access to source then destination, in that order; builds and signs the
transaction through `PreparedTransaction`/`build_signed_transaction`; and
submits it with an explicit, caller-supplied non-zero request id. Every
asset, including this one, uses the same uniform `AssetId`/account/transfer
path — there is no native-coin or fee special case. Cross-owner destination
authorization is available only through DR-0086's exact trusted preinstalled-
module policy; the general owned-effects path remains sender-only.
`transfer` treats the submission itself as fail-closed, not merely the
queries that precede it: an empty submit-result `responses()` list, any
response declaring `NodeResponseStatus::Rejected`, and any response whose
payload decodes to `ExecutionStatus::Failure` (even one the node accepted at
the node-core level) are each a typed, non-zero-exit `CliError` — this
command never reports a rejected or failed transaction as success. Every
response's diagnostics are printed before the command exits — the failure
is detected while iterating, not by inspecting `responses()` up front — and
`--wait` is never entered once any response has failed this way, so a
rejected or failed submission can never be turned into an apparent success
by also requesting `--wait`.
Waiting for the resulting receipt is optional (`--wait`) and, when
requested, every one of `--wait-max-attempts`, `--wait-initial-backoff-ms`,
`--wait-max-backoff-ms`, and `--wait-max-elapsed-ms` must also be supplied —
there is no hidden default poll bound, and supplying a wait-bound flag
without `--wait` is itself rejected.

The development seed file loaded by `address` and `transfer` must be an
explicit path (there is no default or home-directory location), must not be
a symlink, must be a regular file, must on Unix grant no permission bit to
group or other, and must contain exactly 64 hexadecimal digits plus at most
one trailing `\n` — anything else is a typed, actionable rejection before any
key material is derived. This is a development convenience, explicitly not a
keystore.

Current vs. planned: this slice is implemented As-Is except where marked.
`clients/rust`'s two-stage signer API, its small generic re-export surface,
and `apps/cli`'s six commands are implemented and tested, including
adversarial coverage of a mismatched, malformed-length, wrong-signer, and
tampered signature; parser rejection of duplicate/unknown/malformed/
extra-positional arguments; development seed file symlink/permission/length
rejection (Unix); a fake-`Transport` unit test per query command plus
`transfer`'s full success and epoch-mismatch/unsupported-scheme/
non-current-inline-object adversarial paths; and two real loopback-TCP tests
against a composed local devnet router — one exercising `context`/
`next-nonce`/`object`, and one exercising a complete signed `transfer`
against freshly seeded accounts through to a waited, present receipt.
DR-0088 subsequently implements S4a's strict host-side profile, exact
signed-byte clear-signing fixture, and external-signer preflight. DR-0091
records the separate repository's S4b Ledger SDK application and Nano S+
Speculos evidence As-Is. DR-0092 subsequently implements S4c Phase 1's host
APDU/USB/HID transport and CLI signer selection in this repository's own
`clients/ledger` crate — the profile/address checks and USB-descriptor-level
device recognition only, not the active-app/firmware checks. S4c itself,
physical-device HIL, and release evidence remain unimplemented and are not
claimed by any of these three boundaries.

**Development-only residual: no memory zeroization.** `load_dev_seed`'s read
buffer and decoded `[u8; 32]` seed, and `LocalSigner`'s in-memory signing
key, are ordinary Rust values with no `zeroize`-on-drop behavior anywhere in
this slice; a process-memory disclosure (a core dump, swap, or a debugger
attached to the process) can recover them for as long as they, or a copy the
allocator has not yet overwritten, remain resident. This is consistent with
`load_dev_seed`'s and `LocalSigner`'s existing documented status as
explicit, non-keystore, development-only conveniences — not production key
handling — and is called out here rather than silently assumed.
The restart/duplicate E2E is implemented As-Is (see
`apps/cli/tests/devnet_restart_duplicate_e2e.rs` and "Local devnet
architecture" above). Under the CLI-first production-strategy pivot (DR-0085),
`clients/typescript`, `apps/explorer`, and `apps/wallet` remain deferred until
the CLI-First Node Production Gate passes (see
`TODO.md#cli-developer-mvp-gate` and `TODO.md#cli-first-node-production-gate`).

## 46. Hardware Signing Profile v1 and external-signer preflight

S4 is split into four ordered boundaries so a host library cannot become a
surrogate for device-side authorization. S4a is implemented As-Is in this
repository; S4b's separate dedicated Ledger application and Nano S+ Speculos
evidence are implemented As-Is in `sunriselayer/sunrise-edge-ledger-app` by
DR-0091. S4c Phase 1's host APDU/USB and CLI signer selection (profile/address checks
and USB-descriptor-level device recognition) are implemented As-Is in this
repository by DR-0092, but S4c itself is not complete: it still needs an
active-app/firmware identity check and real hardware validation. S4d
completes the remaining physical-device, reproducibility, and
release-evidence gate. S4 is not complete
until S4d passes and the CLI has an actual production signing path replacing
its development-only seed flow.

`crypto::decode_signature_frame` is the strict counterpart to the established
`frame_signature_message` encoder. It accepts only canonical type `0x2001`,
encoding version 1, and exact fields 1-6, and changes no existing bytes.
The new dependency-light `signing-view` crate independently decodes the
signable Transaction v1 shape without depending on `execution`/`wasmi`, applies
Hardware Signing Profile v1's fixed 4 KiB frame and tighter nested bounds, and
re-encodes every accepted value to require byte identity. A dev-only
differential test proves this independent encoder agrees with `execution`.

Clear signing is exact-policy-only. The first policy recognizes only the
reference `sunrise-local-devnet`, protocol 3, epoch 0 asset-account transfer's
exact module id/version/SHA-256 code digest, `transfer` entrypoint, non-zero
`0xF002` v1 amount, three distinct ordered `Write` references, and fee object
equal to source index 0. Unknown module, digest algorithm or bytes, version,
entrypoint, argument schema, access shape, or fee shape is a typed rejection.
There is no raw-argument, blind-signing, or expert-mode fallback. Every
rendered line comes only from the signed frame: `request_id`, destination
owner, transferred-asset symbol/id, module display name, and other queried
metadata are excluded because Transaction v1 does not bind them. Fee asset id
is signed and is displayed.

`PreparedTransaction::clear_signing_view` derives the view only from
`signable_frame`. The additive `ExternalSigner` boundary and
`sign_and_finalize_external` compare the signer's reported scheme and address
to the prepared transaction before invocation, validate the exact frame under
the fixed profile/policy, then pass that same frame to the signer. Existing
`finalize` still independently checks length and Ed25519 validity against the
sender. The host view is only preflight/conformance evidence: the eventual
device app must independently parse and display the received frame.

`SIGNING.md` is normative for the fixed profile bounds, stable display fixture,
provisional explicitly unregistered development derivation path, and bounded
APDU state machine/status words. The dedicated device app lives in the separate
`sunrise-edge-ledger-app` repository because its custom targets, Rust SDK/C
bindings, Speculos workflow, device matrix, and Ledger release lifecycle cannot
pass or be hidden from this workspace's host-target gate. DR-0091 records that
device-side S4b boundary. DR-0092 places every vendor host dependency in the
new `clients/ledger` crate, never a protocol crate or `clients/rust`, and
explicitly amends the CLI's original one-runtime-dependency invariant
(DR-0084) to two: `sunrise-edge-client` and `sunrise-edge-ledger`. No
physical-device evidence, registered SLIP-0044 allocation, or release
artifact exists yet; `clients/ledger`'s real USB/HID transport is itself
unvalidated against physical hardware (see DR-0092).

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

  **Amendment: product-surface deliverables superseded by DR-0081.** The
  Developer MVP priority and production-hardening freeze above remain in
  force. DR-0081 replaces only this entry's earlier TypeScript-client/counter-
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
  (`ObjectOwnerKindUnsupported`/`ObjectBodyUnavailable`) already originate in
  shared node-core code, and the native HTTP boundary maps those errors to
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

  **Amendment: repository-boundary deliverable superseded by DR-0081.** The
  rest of this entry (the additive `native-http` composition, shared private
  core, error classification, and test evidence) remains the accepted,
  implemented history of what DR-0080 shipped and is not rewritten. Only the
  repository-boundary decision immediately above is superseded: DR-0081
  replaces the planned `clients/typescript`/`demo/counter` pairing with a
  six-directory monorepo layout (`clients/rust`, `clients/typescript`,
  `apps/devnet`, `apps/cli`, `apps/explorer`, `apps/wallet`) and a longer
  ordered product-surface sequence; no `demo/counter` directory is created.
  Consequently, the historical deferred-scope reference to "the counter UI"
  above no longer names planned work; that deliverable is cancelled.
  The extraction-timing reasoning stated above — wait for stable wire
  contracts/vectors, a real independent consumer or release cadence, and a
  released devnet artifact for E2E — is unchanged and still applies to every
  `clients/*` directory under DR-0081.
- DR-0081: Define the Developer MVP product-surface monorepo layout and ratify
  a uniform fungible asset model ahead of implementation.

  **Monorepo layout.** The repository gains six product paths under `apps/`
  and `clients/` as each is implemented: `clients/rust` and `clients/typescript`
  (protocol client libraries with no UI of their own), `apps/devnet` (the
  local devnet binary/startup composition; see "Local devnet architecture"
  above), `apps/cli` (a Rust-only developer CLI), and `apps/explorer`/
  `apps/wallet` (browser applications). `apps/cli` depends only on
  `clients/rust`: it is never a Node/JS/browser runtime and never talks to the
  protocol through anything but `clients/rust`'s own encode/decode/signing/RPC
  surface. `apps/explorer` and `apps/wallet` are separate SvelteKit
  applications using shadcn-svelte (Luma) as their component layer, each built
  and deployed as a static/CSR app only: no request-time server-side
  rendering, no SvelteKit server adapter, no `+page.server`/`+layout.server`/
  `+server` route files, and no server actions, remote functions, or
  server-held sessions or keys in either app.
  Build-time prerendering is allowed only for a fixed static shell; no dynamic
  chain data may be embedded by that build.
  `apps/wallet` generates, holds,
  and uses signing keys only in the browser; no wallet key or signature is
  ever generated on, or transits through, a server this project controls.
  Both apps fetch dynamic chain data (objects, balances, receipts, chain/
  context info) directly in the browser runtime through
  `clients/typescript`, never through a bundler-time or server-side data
  load. No shared UI package is introduced across `apps/explorer` and
  `apps/wallet` until real duplication between the two actually exists.

  **Developer MVP order.** Developer MVP completion order (see
  `TODO.md#cli-developer-mvp-gate`) is: local devnet, bounded query API, Rust
  client, Rust CLI, TypeScript client, explorer, wallet, restart/duplicate
  E2E, and explicit documented development-only limitations. This replaces
  DR-0080's earlier "TypeScript client + counter demo UI" pairing; no
  `demo/counter` directory is created.

  **Amendment: gate renamed and resequenced by DR-0085.** The monorepo
  layout, uniform fungible asset model, local devnet module, and deferred
  scope stated in this entry are unchanged. Only the ordering statement
  immediately above is resequenced: DR-0085 renames the gate this order
  belongs to `CLI Developer MVP Gate`, keeps this entry's `clients/typescript`/
  `apps/explorer`/`apps/wallet` steps verbatim as still-required future work,
  and defers starting them until a new `CLI-First Node Production Gate`
  passes. The `local devnet, bounded query API, Rust client, Rust CLI,
  restart/duplicate E2E` prefix of this order is implemented As-Is.

  **Uniform fungible asset model.** Every asset, including any future fee
  asset, uses exactly one `AssetId`/account/transfer implementation path.
  There is no privileged native coin, no second balance representation, and
  no separate transfer or fee-debit code path for a "special" asset. Which
  asset(s) may pay fees, and at what rate, is protocol policy layered over
  ordinary asset accounts, not a second implementation of balances or
  transfer (see "Stablecoin fee lifecycle" above). A future fee-debit effect
  must reuse the same declared object access, the same exact-head assertions,
  and the same atomic object-effect commit as every other asset transfer; it
  may not bypass them with bespoke fee-only state.

  **Local devnet module.** The local devnet's stateful preinstalled module is
  `sunrise.devnet.asset_account.v1`, exposing one `transfer` entrypoint over
  two ordinary owned asset-account objects that both belong to the same
  sender. Both accounts carry the same configured 32-byte `fees::AssetId`
  (never a placeholder or all-zero value), while their object identities are
  distinct. The transition enforces
  balance conservation (the debited and credited amounts are identical and
  the combined balance across the two accounts is unchanged), and fails
  closed on zero amount, amount underflow, amount overflow, and any asset-ID
  mismatch between the two accounts. Because destination-owner
  authorization for a transfer into an account owned by someone else, and any
  change of an object's owner, remain fail-closed on the existing owned-
  effects path (see "Node-core invocation boundary" above and DR-0077), this
  module demonstrates only same-sender balance movement between two of the
  sender's own asset accounts. It does not implement, and must not be
  described as, user-to-user transfer. The devnet's fee registry stays empty
  and every devnet transaction commits with `fee_payment: None`; this module
  charges, computes, or debits no fee. Its body, arguments, and event use the
  devnet-local canonical type IDs `0xF001`, `0xF002`, and `0xF003`; no raw
  hand-framed event or object bytes are accepted. The current host ABI does
  not expose object metadata to WASM, so this MVP verifies the complete
  canonical body structure while node-core separately verifies sender
  ownership and frozen metadata. A metadata-readable ABI or trusted catalog
  type constraint remains deferred until cross-owner transfer or another
  devnet application object type makes structural checking insufficient.

  **Deferred beyond this MVP surface.** Cross-owner transfer authorization and
  any change of object ownership; `Create` and any notion of "associated" or
  auto-derived accounts; mint, burn, supply tracking, and asset metadata/
  registry management; fee charging, gas accounting, and any fee-debit
  effect; freeze, close, delegate, and allowance/approval semantics; Shared/
  System object ownership; blob-backed object bodies and arbitrary module
  upload; and all other production-hardening work already frozen by DR-0076.

  **DR-0086 amendment (current status).** The same-sender-only and deferred
  cross-owner statements immediately above record DR-0081's original MVP
  boundary; they are not the current implementation status. S2 now permits
  the exact policy-bounded existing Address-owned destination described by
  DR-0086 while preserving both source and destination owners. Literal owner
  reassignment/gifting remains deferred and fail-closed. S2 is complete As-Is,
  S3 fee accounting/gas metering is next, and this is not production or
  mainnet readiness. Compatibility is explicit: this dev profile installs
  preinstalled asset module version 2 with the `0xF011` semantics declaration
  version 2; historical module/semantics version 1 bytes remain pinned but are
  not installed by this profile. The `0xF001` body, `0xF002` arguments, and
  `0xF003` event stay at schema version 1 and the WASM bytes are unchanged.
  This profile selection is not a claim that general upgrade activation is
  implemented.

  **DR-0087 amendment (current status).** The empty-registry/fee-free and
  deferred-fee statements above likewise preserve DR-0081's historical MVP
  boundary, not current behavior. S3 now uses the same ordinary asset-account
  path for payer and distinct treasury, settles actual gas after execution,
  and commits trap fee-only effects as described by DR-0087. The active
  module/semantics declaration is version 3; historical v1/v2 declarations,
  the `0xF001`/`0xF002`/`0xF003` schemas, and WAT/WASM/code hash remain pinned.
  DR-0088 subsequently implements S4a's hardware-signing profile/host
  preflight, DR-0091 records S4b's separate device application and Nano S+
  Speculos evidence As-Is, and DR-0092 implements S4c Phase 1's host
  APDU/USB/HID and CLI signer selection As-Is (S4c itself remains incomplete,
  pending an active-app/firmware identity check and real hardware
  validation); this is still not production or mainnet readiness.
- DR-0082: Add the bounded canonical Developer MVP query surface described in
  "Bounded Developer MVP query API". Keep query selectors non-authoritative,
  resolve all chain/domain/epoch/storage authority from trusted composition,
  independently verify durable object and receipt content before returning it,
  encode absence and blob-unavailable state explicitly, and exclude scans and
  arbitrary state access. This is a stable client wire contract, not a public
  RPC security or production indexing architecture.
- DR-0083: Define the Developer MVP Rust client boundary described in "Rust
  client library". Share canonical result codecs through `node-wire`, keep the
  client independent of `native-http`/Axum and application semantics, provide
  only a bounded loopback HTTP transport initially, require caller-supplied
  request/module/object identities, and defer production networking and full
  protocol-config/hash verification rather than approximating them.
- DR-0084: Define the Rust-only `apps/cli` Developer MVP boundary and the
  Ledger-ready external signing boundary described in "Rust client
  external-signer boundary and Developer MVP CLI". `apps/cli` has exactly one
  non-development/runtime dependency, `sunrise-edge-client` (test-only
  `[dev-dependencies]` exist to compose a real devnet and build fixtures for
  this crate's own tests, and are unreachable from any non-test build),
  parses arguments with a strict hand-written parser
  (no clap, no other argument crate), never accepts a seed directly on argv,
  and treats every development seed file as explicitly named, non-default,
  non-keystore input with symlink/permission/length checks. `clients/rust`'s
  new two-stage `PreparedTransaction` external-signer API is additive and
  keeps `build_signed_transaction`'s stable output bytes unchanged; it fails
  closed on any signature scheme other than the one implemented `Ed25519`/
  `AddressIsPublicKey` binding and independently verifies a returned
  signature's exact length and cryptographic validity before producing
  output. Real Ledger (or other external/hardware) signing is explicitly not
  implemented by this decision: it requires a dedicated Sunrise Edge Ledger
  device application, an APDU/host transport, on-device parsing and clear
  signing of the exact canonical signature frame, public-key/address
  verification, an explicit derivation-path policy, device/application/
  version checks, explicit user confirmation, host-side signature
  verification, and hardware-in-the-loop tests — none of which exist yet, and
  existing Solana/Ethereum Ledger apps must never be reused for Sunrise
  transaction signing. No USB/HID/Ledger dependency exists in any protocol or
  client crate. Devnet asset-transfer semantics (the module's entrypoint name
  and argument frame) live only in `apps/cli`'s `transfer` command; the small
  generic re-exports `clients/rust` adds to support it add no application
  semantics of their own.
- DR-0085: Adopt a CLI-first production strategy and add the CLI-First Node
  Production Gate. This is a sequencing decision, not a scope change: it
  reorders when work starts, and it does not complete, delete, weaken, or
  reinterpret any existing production criterion anywhere in `TODO.md`,
  `PERSISTENCE.md`, or `POSTGRES.md`.

  **Rationale.** The Developer MVP Gate (DR-0076, resequenced by DR-0081) put
  a browser-facing product surface (TypeScript client, explorer, wallet) in
  the same near-term gate as the node's own core capabilities (local devnet,
  owned-object execution, bounded query API, Rust client, Rust CLI,
  restart/duplicate E2E). That framing under-weighted the fact that the node
  itself — persistence, operations, and release evidence — is far short of
  the production posture `TODO.md`'s Phase 15 To-Be exit criteria already
  require, while a browser UI cannot usefully exercise a node that is not
  itself production-oriented. This decision narrows the near-term gate to the
  node/client/CLI capabilities that are implementable and independently
  verifiable today, renames it to make that narrowing explicit, and inserts
  an explicit node-production gate between it and the deferred browser
  surface.

  **Gate rename and resequencing.** The gate defined in `TODO.md` is renamed
  `CLI Developer MVP Gate`. Its criteria 1-6, 10, and 11 (local devnet,
  authenticated owned-object Read/Write/Consume, preinstalled deterministic
  WASM execution, bounded query API, Rust client library, Rust-only CLI,
  restart/duplicate E2E, and explicit non-production limitations) remain the
  near-term gate. Its criteria 7-9 (TypeScript client, explorer, wallet) are
  kept verbatim — not completed, not deleted, not weakened — and are
  explicitly deferred/resequenced to start only after the new CLI-First Node
  Production Gate below passes (see the "Amendment: gate renamed and
  resequenced by DR-0085" note on DR-0081's "Developer MVP order" above).

  **Current implementation status (2026-09-04).** The CLI Developer MVP Gate's
  criteria 1-6, 10, and 11 are implemented and validated As-Is, so that gate
  has passed without making a production-readiness claim. S0 below is also
  implemented As-Is. S1 below is now also implemented and tested As-Is (see
  "S1 implementation status" immediately below), and S2 is implemented and
  validated As-Is by DR-0086. S3 is implemented and validated As-Is by
  DR-0087. S4a is implemented and validated As-Is by DR-0088, and DR-0089
  subsequently makes eight S4b device-contract clarifications in `SIGNING.md`
  and one correction to DR-0088's blanket 230-byte whole-APDU data cap (FIRST rises
  230→255 bytes, first chunk 205→230 bytes, CONTINUE/LAST unchanged at
  230). DR-0090 records the separate
  `sunriselayer/sunrise-edge-ledger-app` repository's earlier host-validated
  `no_std` core milestone. DR-0091 records its merged PR #2 device application,
  five-target builds, and fixed-seed Nano S+ Speculos evidence; S4b is complete
  As-Is. DR-0092 implements S4c Phase 1's host APDU/USB/HID crate and CLI
  signer selection As-Is (profile/address checks and USB-descriptor-level
  device recognition); S4c itself is not complete, since it still needs an
  active-app/firmware identity check and real hardware validation. S4
  remains incomplete, and both the rest of S4c and S4d's physical-device HIL
  and release evidence are next. S5 remains its
  ordered successor, and the TypeScript
  client/explorer/wallet surface remains deferred until the complete
  CLI-First Node Production Gate passes.

  **S1 implementation status (2026-09-01): both remote TLS transport and
  expected-protocol-context verification are implemented and tested As-Is;
  S1 as a whole is complete.** S1 below names two separate concerns, and both
  are now implemented by this update. `clients/rust` adds a public
  `context::ExpectedProtocolContext`: a caller supplies the exact locally
  trusted `chain_id`, `protocol_version`, an exact-epoch policy (this initial
  slice trusts one caller-supplied epoch exactly, not a floor or range —
  every subsequent epoch rollover requires the caller to update it
  deliberately, since this type never derives, advances, or widens it
  automatically), `hash_suite_id`, `transaction_auth_profile_id`,
  `signature_scheme_id`, `address_binding_id`, and logical
  `AtomicityDomainId`. `ExpectedProtocolContext::new` rejects a zero
  `protocol_version`, `hash_suite_id`, `transaction_auth_profile_id`,
  `signature_scheme_id`, or `address_binding_id` (an empty `chain_id` or an
  all-zero `domain` is already rejected by `ChainId`/`AtomicityDomainId`
  themselves before construction); zero `epoch` is deliberately accepted,
  since epoch zero is the legitimate genesis epoch. It deliberately never
  pins or decodes `protocol_config_bytes`: approximating full
  `ProtocolConfig` verification is out of scope for this slice, not silently
  weakened. `ExpectedProtocolContext::verify` compares every one of those
  eight fields against an untrusted `/v1/context`
  `node_wire::HttpContextQueryResult` and returns a typed, field-specific
  `ProtocolContextMismatch` on the first disagreement, in a fixed
  deterministic field order; `Client::query_verified_context` is the new
  client API that queries `/v1/context` and requires an exact match before
  returning the result at all, so an untrusted mismatched response is never
  handed to a caller under the pretense of being verified. The logical
  `AtomicityDomainId` comparison here is a routing/placement expectation —
  which logical atomicity domain the caller intends to reach — and is
  deliberately never folded into `crypto::SignatureDomain`; it adds no new
  signature-domain binding beyond the existing chain id/protocol
  version/epoch/message type/signature scheme already described in Section 8.
  No library path panics: every failure is a typed
  `ExpectedProtocolContextError` (construction) or `ProtocolContextMismatch`
  (comparison), wrapped by a new `ClientError::ProtocolContextMismatch`
  variant.

  `apps/cli`'s `transfer` command now requires five `--expected-*` flags —
  `--expected-chain-id`, `--expected-protocol-version`, `--expected-epoch`,
  `--expected-hash-suite-id`, `--expected-domain` — and builds an
  `ExpectedProtocolContext` from them before any network dispatch, rejecting
  a missing, zero, or malformed value at that point (`ArgsError::MissingFlag`
  for an absent flag; `ExpectedProtocolContextError`/`TypeError` for a zero or
  otherwise invalid value; `HexError` for a malformed `--expected-domain`).
  The transaction-authentication profile id, signature-scheme id, and
  address-binding id expectations are not separate flags — this workspace
  implements exactly one combination (the committed
  `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`, `Ed25519`, and
  `AddressIsPublicKey`) — but `transfer` still supplies them explicitly to
  `ExpectedProtocolContext::new` so the client verifier independently
  compares them against the remote result rather than trusting them
  implicitly. `transfer` then calls only
  `Client::query_verified_context` — never the unverified `query_context` —
  and uses only that verified `HttpContextQueryResult`, never any value
  independently derived from the raw remote response, for every subsequent
  step: the next-nonce query, both object queries, transaction construction
  (chain id/protocol version/epoch), signing, and submission. Adversarial
  tests cover every one of `ProtocolContextMismatch`'s eight variants
  (chain id, protocol version, epoch, hash-suite id, transaction-auth
  profile id, signature-scheme id, address-binding id, domain) and each
  proves `transfer` issues exactly one request — the context query — before
  returning the typed error, never reaching the nonce/object queries or
  signing/submission that would follow a verified context. Existing stable
  wire bytes, every previously implemented command, and this command's prior
  parser/seed-file/two-stage-signer/owner-check behavior are all preserved
  unchanged; only the pre-signing context check moved from three ad hoc
  per-field comparisons inside `transfer` into the new typed, reusable
  `clients/rust` verification boundary, and gained the five additional
  chain-id/protocol-version/epoch/hash-suite/domain comparisons S1a requires.

  **S1's remote TLS transport slice.** `clients/rust` adds
  `transport::RemoteTlsHttpTransport`, a second production `Transport`
  implementation alongside the unchanged, still loopback-only plaintext
  `LoopbackHttpTransport`. Both share one private bounded-stream abstraction
  (`BoundedTransportIo`), so the exact same HTTP/1.1 request/response byte
  framing, header/body bounds, and per-stage monotonic-deadline handling
  apply to plaintext and TLS traffic alike; `RemoteTlsHttpTransport` differs
  only in driving a real `rustls` `ClientConnection` — including its own
  deadline-checked `read_tls`/`write_tls`/`process_new_packets` handshake
  pump, never `rustls`'s unbounded `complete_io` — ahead of that shared
  framing. `RemoteTlsHttpTransport::new` requires one caller-supplied
  `SocketAddr` (this transport performs no DNS resolution of its own — the
  caller must already have resolved one), one caller-supplied DNS server
  name (used for both the TLS SNI extension and post-handshake hostname
  validation, and rejected if empty or an IP-address literal — this
  transport never falls back to validating the connection's IP as a
  hostname), and one caller-supplied CA trust-anchor DER, capped at the new
  public `transport::MAX_CA_CERTIFICATE_DER_BYTES` (16 KiB) and rejected if
  empty, oversized, or not a valid X.509 certificate; that DER is the
  transport's sole trust anchor; no system root store is ever consulted, no
  PEM/bundle format is accepted, and no client certificate (mTLS) is ever
  presented. Every timeout (connect, TLS-handshake read/write, and
  post-handshake read/write) must be nonzero and forms one hard total
  request budget by checked addition, exactly like
  `LoopbackHttpTransport`'s; a `WireRequest::deadline` may only tighten that
  budget, never extend it. Real loopback-TCP tests
  (`clients/rust/tests/remote_tls_transport.rs`) issue an ephemeral
  `rcgen`-issued CA/leaf pair and drive a real `rustls` `ServerConnection`
  server against the real client code (never a fake `Transport`), proving:
  a correct hostname/CA succeeds and sends the exact validated-DNS-name
  `Host` header (never the connected `SocketAddr`'s IP); a wrong hostname
  and a wrong CA each fail with a TLS protocol error during the handshake; a
  stalled handshake and a peer that closes before the handshake completes
  each fail promptly rather than busy-spinning or blocking past the
  deadline; a short caller deadline tightens a much larger configured
  budget; and every malformed-constructor input (bad DNS name, an IP
  literal, empty/oversized/invalid CA DER, a zero timeout) is rejected
  before any network I/O. A dedicated regression test in the same file also
  proves the shared bounded-stream refactor left `LoopbackHttpTransport`'s
  plaintext framing byte-for-byte unchanged.

  `apps/cli`'s `context`, `object`, `receipt`, `next-nonce`, and `transfer`
  commands each gain one paired, optional
  `--tls-server-name`/`--tls-ca-cert-der-file` flag set, parsed centrally in
  `apps/cli/src/net.rs` into exactly one new `CliTransport` enum
  (`Loopback`/`RemoteTls`) implementing `Transport`, so every command's
  generic `execute<T: Transport>` body is unchanged regardless of which mode
  a given invocation selected. With neither flag, a command behaves exactly
  as before (loopback-only plaintext, `CliError::NonLoopbackEndpoint` on a
  non-loopback `--endpoint`). With both flags, `--endpoint` is parsed as an
  already-resolved `SocketAddr` (no loopback restriction, and still no DNS
  resolution) and the command dials `RemoteTlsHttpTransport`. Supplying
  exactly one of the two flags returns a new typed
  `CliError::PartialTlsConfiguration` before any network dispatch. The CA
  file is read with `std` only, through a bounded `Read::take` adaptor
  capped at one byte more than the same public
  `MAX_CA_CERTIFICATE_DER_BYTES` the transport itself enforces, so a
  mistaken or hostile oversized file can never make this binary buffer an
  unbounded amount of data before rejecting it; an empty file, an oversized
  file, and any I/O failure each return their own typed, actionable
  `CliError` variant naming the file path but never its contents.
  `apps/cli/tests/tls_cli_e2e.rs` adds two deterministic local TLS
  integration tests (again a real `rcgen`/`rustls` loopback TLS server, no
  fake transport, no external network): one proves a real `context`
  invocation succeeds over TLS with the exact expected `Host` authority; the
  other proves that when a `transfer` invocation successfully authenticates
  TLS against a server whose `/v1/context` result disagrees with
  `--expected-chain-id`, it dispatches exactly one `/v1/context` request —
  confirmed by the test server's own connection counter, which would observe
  a second connection attempt if one occurred — and returns the typed
  `ProtocolContextMismatch` before ever reaching the nonce/object/sign/submit
  steps that a verified context would unlock. This is the same ordering and
  same typed-mismatch guarantee S1a's existing fake-`Transport` unit tests
  already proved, now demonstrated over a real authenticated TLS connection
  instead of a fake transport, which is exactly why TLS endpoint
  authentication and the expected-context check must remain two independent
  boundaries: successfully authenticating the TLS endpoint above proves only
  that the CLI reached a server holding a trusted key for
  `--tls-server-name`, never that the server speaks the caller's intended
  chain/protocol, so the pre-existing S1a check is what actually stops the
  transfer here.

  **Explicit limits (not silently assumed).** This slice performs no DNS
  resolution anywhere; the caller must always supply an already-resolved
  `SocketAddr`. It trusts exactly one caller-supplied CA DER file as the sole
  anchor — never a system/OS trust store, never a PEM/bundle format, never
  more than one combined anchor. It never performs mTLS (no client
  certificate is ever presented). It has no certificate revocation checking
  (no CRL/OCSP), no certificate rotation or lifecycle handling, and no
  deployment/operations evidence for how a CA certificate reaches an
  operator's filesystem or how it is rotated over a validator's lifetime —
  all of that remains explicitly deferred to later CLI-First Node Production
  Gate slices (S5) or the Post-MVP Production Hardening persistence/
  operations work, not silently approximated here. TLS endpoint
  authentication and the separate `ExpectedProtocolContext` check are
  intentionally never merged into one another: a successful TLS handshake
  never substitutes for the expected-context check, and a verified context
  never widens what the TLS layer itself trusts. This is real S1 evidence,
  not a mainnet-readiness or production-certification claim: Phase 16/17's
  production exit criteria and an independent security audit remain
    required afterward, unchanged, and S2 (cross-owner transfer) was the next
  ordered slice at that decision point.

  **DR-0086 amendment (current status).** The preceding "S2 is next" sentence
  records DR-0085's S1 completion point. S2 is now implemented and validated
  As-Is through the exact committed destination policy, with literal owner
  reassignment still deferred; S3 is now implemented by DR-0087. S4/S5, Phase
  16/17 exit criteria, and an independent security audit remain outstanding,
  so no production/mainnet readiness is claimed.

  **CLI-First Node Production Gate.** This new gate sits between the CLI
  Developer MVP Gate and the deferred browser surface. It is a real
  node/persistence/operations gate, not client-library work, and it is
  defined entirely by reference to existing, unchanged criteria:
  `TODO.md`'s Phase 15 To-Be production exit criteria (1-10); the Post-MVP
  Production Hardening Phase 15 persistence implementation order (steps
  1-6, covering the durable domain adapter boundary, the indexed due-outbox
  repository, the normalized PostgreSQL structured-durable schema and its
  shared conformance suite, real host/power-fault and capacity/backup
  rehearsal evidence, and real Cloudflare Durable Object/AWS provider
  certification); the cross-phase production release gate; the existing hard
  activation constraint that protocol version 3's live activation stays
  prohibited until shared-object ordering, FastVote/`FastCertificate`,
  certificate publication, and every externally accepted event family's
  authorization are implemented and atomically composed where protocol
  semantics require it, and, independently, until S4/S5 and the independent
  security/release gates are completed — the bounded S3 uniform ordinary-asset
  fee composition (DR-0087) and additive owned-effects/preinstalled-WASM
  module-object effects entrypoints are implemented As-Is, but on their own do
  not satisfy this constraint; and the existing hard activation constraint that
  every externally accepted node-event family other than `SubmitTransaction`
  (especially certificate, protocol-upgrade, and validator-set-change events)
  needs its own authenticated/authorized ingress boundary before live
  activation. Passing this gate is explicitly **not** mainnet readiness:
  Phase 16 (Cloudflare) and Phase 17 (Deno/Vercel/Supabase/AWS) To-Be
  production exit criteria and an independent security audit remain required
  afterward, unchanged.

  **Ordered slices.** The CLI-First Node Production Gate's work is sequenced
  as S0-S5 (see `TODO.md#cli-first-node-production-gate`):

  - S0: an automated restart/duplicate E2E, plus a separate documented
    command sequence that reproduces the local devnet/CLI experience (start,
    transfer, receipt, orderly restart, persisted state) by hand — not the
    raw byte-identical duplicate replay itself, which only the automated E2E
    proves (implemented As-Is by this decision; see criterion 10,
    `apps/cli/tests/devnet_restart_duplicate_e2e.rs`, and README "Run the
    local devnet and CLI").
  - S1 (implemented As-Is; see "S1 implementation status" above): remote TLS
    transport and mandatory trusted protocol-context validation before
    signing, as two separate concerns. The transport performs normal TLS
    server-identity and hostname validation under an explicit trust policy
    (this slice's `RemoteTlsHttpTransport` uses one explicitly configured
    CA/anchor and DNS name, never a system CA store); this does not require
    brittle leaf-certificate pinning as the only valid TLS trust design.
    Separately, because a successful TLS handshake authenticates the
    transport endpoint, not the protocol context, a valid TLS connection
    alone does not prove the remote server speaks the client's intended
    chain/protocol and does not by itself prevent cross-chain signing. The
    client/CLI therefore also requires a locally configured expected chain
    identity and protocol policy, and compares the remote `/v1/context`
    result's chain id, protocol version, epoch policy, signature scheme,
    address binding, and transaction auth profile against that expectation
    before any signing occurs.
  - S2 (implemented As-Is by DR-0086): cross-owner transfer through an exact
    committed destination-owner policy on the trusted preinstalled-module
    path. The roadmap phrase "object owner changes" means correct handling of
    differing source/destination owner projections; it does not authorize
    literal owner reassignment, which remains fail-closed.
  - S3 (implemented As-Is by DR-0087): uniform ordinary-asset fees and actual-
    gas metering on the local preinstalled-WASM devnet path, including
    deterministic trap fee-only settlement and restart/replay evidence.
  - S4: a secure signer replacing today's development-only `LocalSigner`, and
    a real dedicated Sunrise Edge Ledger integration (see "Rust client
    external-signer boundary and Developer MVP CLI" and DR-0084; existing
    Solana/Ethereum Ledger apps are never reused).
  - S5: production persistence, outbox operation, provider deployment
    (Cloudflare Durable Object/AWS), operations (observability, runbooks),
    security (independent audit), and release evidence (migration/backup/
    disaster-recovery rehearsal, reproducible build) — i.e., the Post-MVP
    Production Hardening persistence implementation order above.

  Capacity/load/soak, PITR, and HA/failover evidence stay frozen exactly as
  the existing freeze already states, until S5's own certification or an SLO
  actually requires one of them; this decision does not add or relax that
  freeze.

  **Production target.** The conservative production target this gate and
  the existing validator-set/consensus criteria are sequenced toward is a
  multi-validator L1, not a permanently single-operator service. Nothing in
  this decision narrows validator-set, bond, or consensus criteria to a
  single-validator design; the devnet's current single-validator posture
  remains an explicit MVP-only limitation (see "Local devnet architecture"
  above), not the production target.
- DR-0086: Implement S2 as a bounded committed cross-owner destination policy,
  without introducing literal object-owner reassignment.

  **Roadmap interpretation.** DR-0085's S2 phrase "destination-owner
  authorization and object owner changes" means correctly loading,
  authorizing, preserving, and committing different source/destination owner
  projections. It does not mean gifting or reassignment of an object's owner.
  Existing effect translation still requires an updated object's owner to
  equal its authenticated pre-state owner, so literal reassignment remains
  fail-closed and deferred.

  **Generic committed envelope.** A trusted `PreinstalledModuleCatalogEntry`
  now carries a bounded `PreinstalledModuleSemanticsEnvelope`: opaque
  application-semantics bytes (at most 64 KiB) plus at most 16 sorted,
  unique-index `PreinstalledObjectAccessPolicy` records. The policy and
  envelope use stable canonical type IDs `0xE007` and `0xE008`, encoding
  version 1, with stable encoding vectors. `SystemModule.semantics_hash`
  commits the exact full envelope bytes, not only the opaque application
  declaration. Both startup registry/catalog reconciliation and request-time
  module resolution independently encode and verify the actual trusted
  envelope bytes. No request field, storage projection, or caller-supplied
  digest can create or widen a policy.

  **Authorization and ordering.** The sender still owns signed access index 0,
  and the general owned-effects entrypoint remains sender-only. On the trusted
  preinstalled-WASM path only, a policy may authorize a non-sender existing
  `Owner::Address` object at one exact nonzero signed access index, exact
  entrypoint, `AccessMode::Write`, exact type hash, and exact schema version.
  Policy resolution occurs exactly once per non-replay execution, after receipt
  and nonce reconciliation but before object I/O; the resolved module is reused
  for authorization and execution. Therefore an exact replay still reconciles
  before policy/module/object work and never reapplies effects. Source-index
  policy, `Read`/`Consume`, wrong index/mode/type/schema/entrypoint/module,
  missing policy, and Shared/System/Immutable ownership all fail closed.

  **Devnet policy and startup.** The devnet catalog declares exactly one policy:
  signed destination index 1, `transfer`, `Write`, the exact asset-account type
  hash, and schema version 1. The opaque devnet semantics states that source
  index 0 is sender-owned, the existing destination may have another Address
  owner, and both owners remain unchanged. Startup seed reconciliation no
  longer assumes per-owner source/destination balance totals or paired
  sequences, because legitimate cross-owner movement invalidates both
  assumptions. It still verifies exact current owner/id/type/schema/canonical
  body/digest/provenance, immutable version-one history, and the seed receipt
  for every account, then performs one checked global fixed-supply invariant
  over the bounded configured-owner set before serving.

  **CLI and evidence.** `apps/cli transfer` requires an explicit
  `--destination-owner <32-byte-hex-address>`. Before signing it requires the
  queried source owner to equal the local signer and the queried destination
  owner to equal that explicit expected address. The real file-backed SQLite
  E2E seeds separate sender and recipient owners, transfers into the recipient
  destination, proves both balances change and the recipient owner remains
  unchanged, closes every store/router reference, reopens under writer
  generation N+1, and proves exact same-boot and post-restart request replay
  returns byte-identical submit/receipt results without reapplication. Reusing
  a committed request ID with different signed bytes returns HTTP 409 while
  both canonical object query results, both relevant receipts, and the sender
  nonce remain unchanged; the old writer generation remains fenced.

  This implementation preserves established canonical transaction,
  `ObjectEffect`, `Object`, receipt, nonce, and submit-result bytes. S2 is
  implemented and validated As-Is only. DR-0087 subsequently replaces the
  fee-free devnet posture while preserving S2's exact policy and historical
  vectors. The TypeScript client, explorer, wallet,
  S4 secure signer/Ledger work, and S5 persistence/provider/operations/release
  evidence remain deferred, and Phase 16/17 exit criteria plus an independent
  security audit remain mandatory.
- DR-0087: Implement S3 as uniform ordinary-asset fee composition on the
  trusted preinstalled-WASM devnet path, without changing historical wire,
  WAT/WASM, or storage bytes.

  **Admission and settlement.** The committed protocol configuration uses
  non-zero base/execution prices and enables exactly `DEVNET_ASSET_ID` at a
  1:1 quote. A due fee requires signed `FeePayment`; its `max_fee` must cover
  the worst case at `gas_limit` before engine work begins. The final charge is
  computed only after execution from canonical `ExecutionEffects.gas_used`.
  Successful application effects are merged with the fee debit/credit and
  committed atomically with state, nonce, receipt, and outbox. A deterministic
  trap is normalized first, discards every application effect/event, charges
  its normalized full gas through a restricted fee-only mutation, and commits
  a Rejected receipt. An insufficient payer balance after successful execution
  rejects the whole transaction, so execution work may be spent without a
  commit; this bounded devnet limitation is not production admission policy.

  **Schedule-shape invariant.** S3 only ever measures `execution_units`:
  every `fees::FeeUsage` the preinstalled-WASM machine builds leaves
  `state_read_units`, `state_write_units`, `storage_units`, and
  `system_module_units` at their default zero. Before fee admission or the
  engine ever runs, it independently validates the committed `GasSchedule`'s
  shape (`fee_effects::validate_gas_schedule_shape`): a non-zero
  `read_price`/`write_price`/`storage_price`/`system_module_price` is
  rejected as `NodeCoreError::UnsupportedGasScheduleShape` rather than
  silently multiplied by zero usage and dropped from the total by
  `fees::calculate_fee`, and a non-zero `execution_price` paired with a zero
  `base_fee` is rejected the same way, because a legitimate zero-`gas_used`
  success could otherwise settle a zero fee even though worst-case admission
  at `gas_limit` already required a treasury `Write`. The genesis all-zero
  schedule and the current devnet `base_fee`/`execution_price`-only schedule
  both pass unchanged. This is a trusted committed-configuration fault, never
  a caller-supplied one; native HTTP maps it to an opaque `500
  fee-schedule-unsupported`, distinct from every caller-facing 4xx fee code.

  **Ordinary accounts and trusted boundary.** The payer is one sender-owned
  declared `Write` object and the trusted fee sink is the distinct configured
  treasury owner's ordinary seeded destination account. The signed manifest
  names that treasury exactly once as its final `Write`, but node-core removes
  it before invoking WASM. The module therefore still observes exactly the two
  source/destination objects and cannot redirect, inspect, or authorize the
  fee sink. The pure `AssetAccountFeeComposer` receives only opaque effective
  payer/treasury bodies and a settled amount, uses the existing strict
  `0xF001` codec, checks matching asset IDs and checked balance/sequence
  arithmetic, and returns two bodies. Node-core independently freezes identity,
  owner, type/schema, provenance, and object version; a no-op or malformed
  trusted composition fails closed. One successful transaction advances each
  touched durable object version once, while the payer body sequence advances
  once for the application transfer and once for the fee mutation.

  **Catalog compatibility.** The active module and semantics declaration move
  to version 3 solely to commit the new host-side fee/treasury/event facts.
  Historical v1 same-sender and v2 cross-owner declarations remain exact
  pinned vectors and are not installed. The asset body/args/event encoding
  remains v1, the WAT/WASM bytes are unchanged, and a fixed-context canonical
  code-hash test pins the same artifact. The transfer event is deliberately
  pre-fee module output: `source_balance` is the balance after transfer but
  before settlement; the durable source object is lower by `base_fee +
  gas_used * execution_price` under this profile.

  **CLI, startup, and evidence.** Devnet configuration requires a treasury
  owner distinct from all transfer owners and reserves one of the 64 seed
  slots for it. Startup seeds/verifies all owners, selects the treasury
  destination, and wires it with the composer into the native router. CLI
  `transfer` accepts the all-or-none `--fee-asset-id`/`--max-fee`/
  `--fee-treasury-object` trio, fixes source as fee object, queries treasury
  last, and appends its final `Write`; partial input, zero max fee, or treasury
  collision fails locally. Native HTTP assigns explicit 4xx classifications
  to caller fee faults and 5xx classifications to trusted policy/composition
  invariant failures. The real file-backed SQLite E2E proves a successful
  actual-gas charge, event pre-fee semantics, and a trapped fee-only charge,
  then replays both the successful and the trapped request once in the same
  boot and once after an orderly close/reopen: every replay returns
  byte-identical canonical submit-result bytes and mutates neither the
  canonical source/destination/treasury query bytes, the second-transfer or
  trapped receipt, nor the sender's next nonce. It also proves
  writer-generation advancement/fencing and request-ID reuse conflict with
  the same canonical source/destination/treasury query bytes, all three
  receipts, and nonce unchanged.

  **Limits and next step.** This is single-validator, one fixed fee asset, one
  serializing treasury, and local SQLite only. It does not implement fee
  distribution through `FastCertificate`, multiple governed fee assets,
  production gas calibration, sufficient-balance preflight, treasury sharding,
  Shared/System/blob objects, or crash/power-loss durability. TypeScript,
  explorer, and wallet stay deferred. DR-0088 implements S4a's hardware
  profile/host preflight, DR-0091 records S4b's dedicated device application
  and Nano S+ Speculos evidence As-Is, and DR-0092 implements S4c Phase 1's
  host/CLI integration As-Is (S4c itself remains incomplete). The rest of
  S4c and S4d's physical-device evidence are next. S5,
  Phase 16/17 exit criteria, and independent audit remain mandatory.
- DR-0088: Implement only S4a's hardware-signing profile and host preflight in
  this repository, with the dedicated Ledger application isolated in a
  separate repository and S4 completion reserved for physical evidence.

  **Exact signed source.** Hardware Signing Profile v1 interprets only the
  established `0x2001` v1 signature frame and its `0x6001` v1 Transaction
  signable payload. `crypto` adds a strict decoder but changes no encoder,
  canonical identifier, signature domain, transaction byte, or stable
  historical vector. `signing-view` applies immutable device-sized bounds,
  independently decodes and byte-identically re-encodes the transaction shape
  without an `execution`/`wasmi` runtime dependency, and emits bounded ASCII
  lines only after the complete signed value matches one exact policy.

  **No blind signing.** The first policy is limited to the fixed README
  reference devnet module id/version/code digest, transfer argument schema,
  three ordered `Write` entries, and source-bound fee authorization. Any
  unknown module/digest/entrypoint/arguments/access/fee shape is a typed
  rejection. Unsigned `request_id`, destination owner, transferred asset
  metadata, module names, or host labels never enter the view. The stable
  fixture pins both the exact frame and display lines for the future device
  repository.

  **Host seam and repository boundary.** `clients/rust` adds no USB/HID or
  Ledger dependency. Its external-signer seam verifies reported scheme and
  address, performs exact-frame clear-signing preflight, invokes the signer on
  that same frame, and retains `PreparedTransaction::finalize` as independent
  signature verification. The dedicated Rust device application belongs in a
  separate `sunrise-edge-ledger-app` repository so custom Ledger targets,
  bindings, Speculos, device workflows, and release artifacts cannot be hidden
  from this workspace gate. Later S4c vendor transport code belongs in a
  separate `clients/ledger` crate and requires an explicit amendment to the
  CLI's one-runtime-dependency decision.

  **Completion boundary.** `SIGNING.md` fixes the future APDU state machine,
  status words, bounds, clear-signing fields, and a provisional explicitly
  unregistered devnet-only derivation path. S4a has no device app, APDU I/O,
  USB/HID, Speculos, physical-device, registered coin-type, or release evidence;
  `LocalSigner` remains development-only and unchanged. S4b implements and
  emulates the dedicated app, S4c integrates the host/CLI, and S4d requires
  Speculos CI, physical HIL for each claimed model, verified address and user
  confirmation, a pinned app/firmware matrix, reproducible build hash, and
  release/submission evidence. S4 remains incomplete until those criteria and
  the real CLI production signer replacement are satisfied.
- DR-0089: Make eight S4b Ledger device-contract clarifications for details
  `SIGNING.md` left implicit after DR-0088's freeze, and one correction to DR-0088's explicit
  blanket 230-byte whole-APDU data cap for `sign transaction`: FIRST's
  maximum command data rises from 230 to 255 bytes and its first chunk from
  205 to 230 bytes, while CONTINUE/LAST chunks remain capped at 230 bytes,
  unchanged. Neither the clarifications nor this correction change a
  Sunrise canonical transaction/signature byte, encoder, canonical
  identifier, or the `0x2001`/`0x6001` frame shapes DR-0088 already fixed,
  and no implementation code changes because S4b has no implementation in
  this or any other repository yet.

  **Scope.** This is a documentation-only clarification and correction of
  the future S4b APDU/derivation contract in `SIGNING.md`. It changes no
  code, canonical byte, encoder, or historical vector in this repository,
  and it is not itself S4b device-app or Speculos/physical-device evidence.

  **Clarifications and correction.** (1) Pins the provisional devnet derivation path to
  SLIP-0010 Ed25519 exactly, not only the five-component hardened path
  shape DR-0088 already froze. (2) Defines the returned public key as the
  standard RFC 8032 compressed Ed25519 encoding and distinguishes two Ledger
  SDK paths to it, not treating every Ledger SDK output as raw or manual
  conversion as universally required: starting from
  `ECPrivateKey::public_key`'s raw, uncompressed `04 || X || Y` point, app
  code must convert it (`Y` from the SDK's big-endian byte order to
  little-endian, sign bit from `X`'s parity); using the current Ledger SDK's
  `cx_edwards_compress_point_no_throw` helper, its `pubkey[1..33]` output is
  already the compressed RFC 8032 bytes and must be used as-is, with no
  second reversal or sign-bit transformation. It requires the separate S4b
  repository to add a deterministic test vector (fixed seed/path in, fixed
  32-byte compressed public key out) for whichever path it implements
  before S4b can be considered complete, and, if both paths are
  implemented, to show they agree; no such vector is fabricated in this
  repository, since one written here could not be verified against a real
  device or SDK. (3) Fixes `get configuration` success data at exactly six bytes
  (`profile` `u16`, pinned to `1` for Hardware Signing Profile v1; semver
  `major`/`minor`/`patch` `u8` each; `flags` `u8`), states every currently
  defined flags bit is `0`, defines an unknown flag as any set flag bit
  that either the host's own supported version or the responding device's
  version does not define, and requires a future host to reject a response
  with an unknown flag set rather than ignore it. (4) Separates the app's own `E0`-CLA status-word table
  from Ledger SDK/OS-level statuses it does not own or define — `6E03`
  (the SDK I/O layer's malformed-APDU-length rejection, distinct from the
  app's own `6A80`), `5515` (Ledger OS locked-device status), and `E000`
  (an unhandled panic/exception caught by Ledger's own fault handling) —
  and documents that Ledger's common CLA `B0` is intercepted by the
  platform before reaching this app's dispatcher, while `E0` remains this
  app's own CLA for every command in its table. (5) Requires the device to
  derive the public key from the path supplied on FIRST and compare it
  byte-for-byte against the parsed Transaction v1 `sender` before
  rendering any review screen, returning `6A80` and wiping the buffered
  frame/derivation state on mismatch, so a wrong-key session can never
  reach a display page. (6) Pins the device policy's chain id, protocol
  version, and epoch (`sunrise-local-devnet`, `3`, `0`, the same README
  reference context DR-0088 already used) together with the exact devnet
  fee `AssetId`
  (`ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8`, the
  normative value `crates/signing-view/src/policy.rs`'s
  `DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id` field fixes, which
  `crates/signing-view/tests/fixtures.rs` exercises only as fixture
  evidence) as one policy, rejecting any other combination rather than
  matching fields independently. (7) Requires a typed rejection when any two of the three
  `Write` access entries (source/destination/treasury) share an
  `ObjectId`, even when mode and position are otherwise well-formed;
  DR-0088's "three ordered `Write` entries" language did not previously
  state this explicitly. (8) **Correction, not clarification:** supersedes
  DR-0088's explicit blanket 230-byte whole-APDU data cap for
  `sign transaction`. The 230-byte figure now names the chunk-payload
  bound specifically (not the whole APDU), and CONTINUE/LAST chunks stay
  capped at 230 bytes, unchanged. FIRST's total command data rises from
  230 to 255 bytes: `total_length` (4 bytes) plus the fixed depth-five
  path (21 bytes) plus up to 230 bytes of first chunk — so FIRST's own
  chunk allowance rises from 205 to 230 bytes. This is a normative change
  to the future APDU wire contract, not a restatement of an existing
  implicit bound; it changes no canonical transaction/signature byte and
  no implementation code, since S4b has no implementation to change.
  (9) States FIRST/CONTINUE success responses carry empty data (only LAST
  carries the 64-byte signature), and that the returned public key equals
  the Sunrise address only because the chain's committed
  `protocol_config::TransactionAuthProfile` — which Hardware Signing
  Profile v1 relies on rather than itself commits — selects
  `AddressIsPublicKey`, not as a general equivalence.

  **Evidence boundary unchanged; byte bound corrected.** DR-0088's S4
  evidence/completion criteria are unchanged by this clarification and
  correction: S4a remains implemented and validated As-Is; S4b still has
  no device application, APDU transport, USB/HID dependency, or
  Speculos/physical-device evidence in this or any other repository,
  S4d's Speculos CI/physical-HIL/reproducible-build gate is untouched, and
  S4 remains incomplete. What DR-0089 does change, per (8) above, is
  DR-0088's explicit blanket 230-byte whole-APDU data cap for
  `sign transaction`: this document corrects — not merely clarifies — it
  to a 255-byte FIRST maximum and a 230-byte first-chunk maximum
  (CONTINUE/LAST unchanged at 230). That correction is confined to the
  future wire contract: no canonical transaction/signature byte, encoder,
  canonical identifier, or implementation code changes, since none exists
  yet for S4b. TypeScript client, explorer, wallet, and S5 remain
  deferred, unaffected by this clarification.
- DR-0090: Establish the first separate-repository S4b implementation milestone
  as a host-validated device core without treating it as a Ledger application or
  S4 completion.

  **Implemented boundary.** `sunriselayer/sunrise-edge-ledger-app` PR #1
  introduces an allocation-free `no_std` core with the application-owned E0
  APDU state machine, exact app status words and chunk bounds, an independent
  from-scratch canonical decoder, strict Transaction v1 and nested-object
  decoding, duplicate-`ObjectId` rejection, the exact devnet transfer policy,
  a signed-fields-only bounded review value, and a `PublicKeyDeriver` boundary.
  The core selects the validated path supplied to that boundary and compares
  the returned RFC 8032 public key byte-for-byte with the signed sender before
  emitting a transaction-review outcome. Its copied fixture is byte-identical
  to `signing-view`'s stable frame at source commit `1dd4d2d`, and all 32 pinned
  display facts are checked independently. Twenty-five host tests and pinned
  GitHub CI validate that slice.

  **No canonical or source-workspace change.** This milestone changes no
  Sunrise Edge canonical encoder, transaction/signature byte, identifier,
  policy activation, or code dependency in this repository. The device core is
  deliberately isolated in the separate repository and depends on none of this
  workspace's crates; copied stable data and differential conformance preserve
  the independence required by DR-0088.

  **Completion boundary.** The merged repository still has no Ledger SDK
  binary, device-target build, actual SLIP-0010 derivation, Ed25519 signing,
  on-device address or transaction UI, APDU/USB/HID transport, Speculos/Ragger
  evidence, reproducible device artifact, or physical-device result. It is a
  host-validated Phase-0 core only, not a dedicated device application and not
  S4b, S4, production, or mainnet readiness. The next S4b slice must integrate
  the core into current Ledger Rust tooling and establish deterministic
  derivation/signing and Speculos UX evidence without weakening these bounds.
  S4c/S4d, the TypeScript client/explorer/wallet, and S5 remain deferred in
  their existing order.
- DR-0091: Complete S4b As-Is in the separate Ledger repository without
  claiming S4, production, or mainnet readiness.

  **Implemented device boundary.** Merged
  `sunriselayer/sunrise-edge-ledger-app` PR #2 (merge commit `6f6f882`) pins
  `ledger_device_sdk` 1.37.0 and digest-pinned official builder/dev-tools
  images, then integrates DR-0090's independent allocation-free core into a
  `no_std`/`no_main` Ledger application. It builds cleanly for Nano S+, Nano X,
  Stax, Flex, and Apex P. The device adapter performs exact SLIP-0010 Ed25519
  derivation at the provisional hardened path, converts the SDK's raw
  `04 || X || Y` point once to RFC 8032 compressed bytes, compares that key
  with the signed Transaction sender before review, renders the bounded
  signed-fields-only policy through NBGL, and signs only the session-captured
  path and exact buffered signature frame after approval.

  **Deterministic evidence.** Host conformance pins every one of the 32 review
  facts and RFC 8032 conversion vectors. A fixed public development seed under
  Nano S+ Speculos/Ragger pins the exact six-byte configuration, exact derived
  public key, and exact 64-byte signature for a 1,221-byte canonical-shape
  fixture whose sender is replaced with that derived key. The byte-identical
  copied source fixture retains its original `01…01` sender and proves sender
  mismatch before review; the suite also proves explicit reset recovery in the
  same emulator backend and user rejection. Unknown INS retains `6D00` while
  wiping an active core session. Malformed APDU length, locked-device, SDK
  fault, in-review `6901`, and CLA `B0` behavior remain explicitly SDK/OS-owned
  rather than application status words. The full Python dependency closure is
  version/hash locked and installed with `--require-hashes`; CI runs host
  checks, every target build, and Nano S+ Speculos from clean checkouts.

  **Compatibility and completion boundary.** No file in this workspace and no
  Sunrise canonical transaction, signature, object, receipt, nonce, submit, or
  protocol-activation byte changed to implement the separate device app. S4b
  is implemented and validated As-Is, but S4 is incomplete. S4c is next: a
  separate `clients/ledger` host APDU/USB/HID crate plus explicit CLI signer
  selection and device/app/firmware/profile/address checks. S4d still requires
  golden/pixel UI evidence, broader adversarial device-session and disconnect/
  reset evidence, physical-device HIL for every claimed model, a pinned
  app/firmware compatibility matrix, two-clean-build reproducibility evidence,
  Ledger release/submission, a registered coin-type decision and migration
  policy, and actual replacement of the CLI's development-only `LocalSigner`.
  Nano X/Stax/Flex/Apex P are build-validated only, not emulated or physically
  validated. TypeScript client, explorer, wallet, and S5 remain deferred in the
  existing order.
- DR-0092: Implement S4c Phase 1 As-Is — a separate `clients/ledger` host
  crate for the frozen device APDU/USB/HID contract, plus explicit,
  all-or-none CLI Ledger signer selection — without claiming S4c itself,
  S4, production, mainnet readiness, or physical-hardware validation.
  **S4c is not complete.** The roadmap's device/app/firmware/profile/address
  check set is only partly satisfied: this phase implements the profile and
  address checks in full and adds USB-descriptor-level device-model
  recognition, but it does not verify the active on-device application's
  name/version or the device firmware version, and nothing in it has been
  validated against physical hardware. The next S4c slice must close that
  gap before S4c itself — not just S4 — can be called complete.

  **New `clients/ledger` crate.** `sunrise-edge-ledger` is the only crate in
  this workspace that may depend on Ledger/APDU/USB/HID vendor code
  (`hidapi`, confined to its `hid` module, using the `linux-native-basic-udev`
  feature so it builds without any system package). It implements the exact
  `SIGNING.md` "Device APDU contract" against an injectable `apdu::Transport`
  trait: `device::LedgerDevice` drives `get configuration`, `verify public
  key`, `sign transaction`, and `reset signing`; `configuration::Configuration`
  decodes the exact six-byte response and rejects any profile id other than
  `1` or any flag bit this host does not define (the **profile check**);
  `path::DerivationPath` encodes the frozen provisional
  `m/44'/21333'/account'/0'/0'` path (rejecting an `account` value that
  already carries the hardened bit); and `error::DeviceError` maps every
  documented status word (`9000`/`6985`/`6986`/`6A80`/`6A84`/`6A86`/`6D00`/
  `6E00`/`6F00`) to a typed variant, with an unrecognized status word a typed
  `UnknownStatus`, never success. `sign transaction`'s host-side chunking
  sends the frame's first ≤230-byte piece as FIRST, every full-size middle
  piece as CONTINUE, and the final piece as LAST; because `SIGNING.md` states
  LAST is "valid only while collecting" (never the first APDU) and only
  LAST's response carries the signature, a frame that would otherwise fit
  entirely inside FIRST instead reserves its final byte for a dedicated LAST
  call, so every signing session sends at least one FIRST and one separate
  LAST; a frame too short to reserve that byte (fewer than two bytes) is a
  typed `DeviceError::FrameTooSmall`, distinct from `FrameTooLarge` (the
  frame is too small, not too large) and unreachable for any real
  Transaction v1 frame. If FIRST was accepted (status `9000`) and any later step in that same
  call — a further chunk's status, its response length, or the transport
  itself — then fails, `sign_transaction` attempts a best-effort `reset
  signing` before returning that original error; the reset's own outcome is
  always discarded, so it can never mask the primary error or itself surface
  as the result, and no reset is attempted when FIRST itself is what failed
  (the device never entered a session to wipe). `signer::LedgerExternalSigner`
  implements `sunrise_edge_client::ExternalSigner`: `connect` checks `get
  configuration` and fetches (with mandatory on-device confirmation) the
  public key/address before returning it to a caller, and `sign_frame`
  independently repeats both checks immediately before every signature,
  rather than trusting the connect-time result — the **profile and address**
  halves of "device-reported configuration/public key/address checks before
  signing". Every module above `hid` is generic over `Transport`, so
  `fake::FakeTransport` (a deterministic, pre-scripted, request-recording
  fake, analogous to `runtime`'s `Memory*` test adapters) exercises the
  complete protocol — chunking at every documented boundary, exact response
  lengths, every status word, configuration/flag rejection, public
  key/address identity and mismatch, mid-sequence disconnect, and the
  best-effort reset attempt (including when the transport remains usable for
  the reset call and when it does not) — with no native dependency, in the
  crate's default-feature and `usb-hid` all-feature unit tests.

  **`hid::HidTransport`: real, device-checked, but not hardware-validated.**
  This module owns two independent layers. First, USB device identification
  (the **device** check): `HidTransport::open` resolves the caller's exact
  path through `HidApi::device_list`, checks every descriptor record sharing
  that path (one physical device may expose several HID top-level
  collections), and requires at least one record to satisfy all three
  identity fields — Ledger's USB vendor id `0x2c97`, a product-id family in
  the exact S4b five-target build list (Nano X, Nano S Plus, Stax, Flex,
  Apex P — see DR-0091; the plain Nano S is deliberately excluded, since no
  S4b build target covers it), and exactly the Ledger HID usage page
  `0xffa0`. Some host libraries, including the independently published
  Zondax `ledger-go`, also accept a device reporting interface number `0` as
  an alternative to the usage page (a workaround for platforms that report
  an empty/zero usage page); this phase does not implement that fallback —
  without current official primary-source evidence for it and a tested,
  platform-`cfg`-specific policy for when it is safe, a mismatched usage
  page is treated as unrecognized. An unrecognized vendor id, product
  family, or usage page is a typed rejection before `HidApi::open_path` is
  ever called; when every same-path record is invalid, the typed error is
  selected independently of enumeration order. This is USB-descriptor-level
  identity only: it is not, and cannot be over this transport, the active
  on-device application's name/version or the device firmware version.
  Those live on two different CLAs depending on device context, neither of
  which this module sends: the active application's name/version is CLA
  `B0` `INS 01`; the device firmware version is CLA `E0` `INS 01`, but only
  while the device is at the dashboard with no application open — a
  distinct, OS-owned use of the same CLA byte `E0` this workspace's own
  Sunrise application uses for its own signing commands once it is the
  active app (see `SIGNING.md`, "Device APDU contract"). Verifying both
  therefore requires a staged sequence this phase does not implement: probe
  at the dashboard first, then open (or have the operator open) the Sunrise
  application and reconnect, then send this crate's own `E0` commands.
  Verifying the **app** and **firmware** checks is the explicitly
  unimplemented next S4c slice.
  Second, the generic USB HID packet framing every Ledger device application
  uses (fixed 64-byte reports, a `0x0101` channel id, a `0x05` tag, and a
  big-endian sequence index — one layer below, and independent of, the
  APDU-level FIRST/CONTINUE/LAST chunking above): every `hid_write` call
  must report writing the complete packet or the write is a typed
  `ShortWrite`; reassembly distinguishes a genuinely incomplete response
  (needs more packets) from a malformed one (wrong channel/tag, an
  out-of-order sequence index, or a declared length over the bounded
  short-APDU maximum of 260 bytes — up to 258 response-data bytes plus the
  2-byte status word) and fails immediately on the latter
  rather than looping until a timeout; and each complete read is bounded by
  a command-class wall-clock deadline (30 seconds for programmatic commands,
  120 seconds for each `verify public key` or signing LAST command that waits
  for a human), never a per-packet timeout multiplied by a packet-count
  limit, plus a small secondary packet-count bound. Every arithmetic step in this framing (offsets, remaining lengths,
  sequence increments) uses checked arithmetic with a typed
  `FramingBoundsExceeded` fallback in place of a panic or a silent
  saturating/truncating substitute. Its pure encode/decode functions have
  self-consistent round-trip unit tests plus independently hand-built byte
  vectors (not generated by this module's own encoder) matching the
  documented framing; neither proves agreement with real Ledger firmware,
  since no physical device or Speculos bridge was available to validate
  against in this change — real hardware-in-the-loop evidence for
  `HidTransport`, including whether its USB HID framing and device
  identification actually match real hardware, remains explicitly deferred.
  `hidapi`'s `linux-native-basic-udev` feature needs no system package (unlike
  the `linux-static-hidraw`/`linux-static-libusb` features, which need
  `libudev`/`libusb-1.0` development headers this environment lacks), so
  `hid` and the `hidapi` dependency are behind an off-by-default `usb-hid`
  Cargo feature on both `sunrise-edge-ledger` and `sunrise-edge-cli` purely
  to keep the default (non-`--all-features`) build/test/clippy gate free of
  any native dependency; `cargo clippy --workspace --all-targets
  --all-features` and `cargo test --workspace --all-targets --all-features`
  both pass in this environment with no system package installed.

  **CLI signer selection amends the one-runtime-dependency invariant.**
  `apps/cli` now depends on `sunrise-edge-ledger` in addition to
  `sunrise-edge-client` — DR-0084's original "exactly one non-development/
  runtime dependency" is revised to exactly these two, both still owning no
  application-specific (devnet) semantics. A new `apps/cli::signer` module
  adds `--seed-file`, `--ledger-hid-path`, and `--ledger-account` flags to
  `address` and `transfer`; `parse_signer_selection` requires exactly
  `--seed-file` alone or both Ledger flags together, rejecting neither, both
  groups at once, or exactly one Ledger flag, before any network dispatch or
  device connection. A Ledger selection resolves and verifies the signer
  (`signer::connect_ledger_with`, generic over `Transport` and tested with
  `FakeTransport`) strictly before `transfer` ever constructs a network
  `Client`, so a Ledger connection failure or on-device rejection is reported
  before any request reaches the node. Without the `usb-hid` feature, a
  Ledger selection fails closed with a typed `CliError::LedgerTransportFeatureDisabled`
  rather than silently falling back to the local signer. `transfer`'s Ledger
  path builds a `PreparedTransaction` exactly as the local path does, then
  calls `sign_and_finalize_external` with `DeviceSigningProfile::V1` and
  `DEVNET_ASSET_TRANSFER_POLICY` — the same host preflight DR-0088 already
  implements — so canonical transaction/signature bytes and the local-signer
  path are both completely unchanged. A feature-independent `FakeTransport`
  test executes this exact CLI helper with a real policy-conforming
  `PreparedTransaction` and a valid Ed25519 response, compares its canonical
  output with the local signer, and proves a policy mismatch is rejected
  before device signing. The current operator interaction is also explicit:
  `address` requires one on-device address confirmation, while `transfer`
  requires three (connect-time address, repeated pre-sign address, then the
  transaction review). The repeated address prompt is deliberate fail-closed
  Phase 1 behavior, not a production-UX claim.

  **Completion boundary.** This is S4c Phase 1 host integration As-Is only,
  and S4c itself is not complete. It adds no device application, no
  active-app/firmware identity check, no physical-device evidence, no
  registered SLIP-0044 allocation, and no release artifact; `LocalSigner`
  remains the CLI's only actually-replaceable-in-production signing path,
  unchanged. The next S4c slice must add the active on-device application
  name/version check (CLA `B0` `INS 01`) and the device firmware version
  check (CLA `E0` `INS 01` in dashboard context, staged before the Sunrise
  application is opened — see the `hid::HidTransport` discussion above),
  neither of which this app sends today, and real
  hardware validation boundaries for `HidTransport` (confirming its USB HID
  framing, device identification, write/read behavior, and best-effort
  reset actually work against physical devices, not only against
  `FakeTransport`), before S4c can be considered complete. S4 remains
  incomplete until S4c finishes, S4d supplies golden/pixel UI evidence,
  physical-device HIL for every claimed model, broader adversarial
  session/disconnect evidence, a pinned app/firmware compatibility matrix,
  two-clean-build reproducibility evidence, Ledger release/submission
  evidence, and the CLI's default signing path actually replaces
  `LocalSigner`. TypeScript client, explorer, wallet, and S5 remain deferred
  in the existing order.
