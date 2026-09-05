# Core protocol architecture

This document defines the provider-neutral protocol foundation: canonical
encoding, cryptography, objects, transactions, consensus, execution, economics,
governance, and security invariants.

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
`SubmitTransaction`. DR-0099 additionally closes every native public
`POST /v1/events` route to all seven non-transaction families before identity,
clock, storage, machine, outbox, or transport work; the generic node-core
behavior remains available only as internal reusable machinery until a future
family-specific authenticated route is explicitly implemented.

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
Write/Consume through the preinstalled-WASM entrypoint described in
[runtime-and-ingress.md §30](runtime-and-ingress.md#30-node-core-invocation-boundary) instead (see
[DR-0080](decisions/0076-0080-developer-mvp-foundation.md)).

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
itself (see
[DR-0078](decisions/0076-0080-developer-mvp-foundation.md)). The transaction's
`gas_limit` is rejected before the engine ever runs if it exceeds a
conservative pre-activation ceiling. Only
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
initially added to node-core only
([DR-0078](decisions/0076-0080-developer-mvp-foundation.md), historical: at
that point native HTTP activation was still deferred); a later additive
`native-http` router
now wires it up (see [DR-0080](decisions/0076-0080-developer-mvp-foundation.md)). Arbitrary uploads, JIT/AOT, and production
metering remain deferred.

Protocol version 3 MUST NOT be activated on any live chain until shared-object
ordering, FastVote/FastCertificate, certificate publication, and every
externally accepted event family's authenticated/authorized ingress are
implemented and atomically composed with the authenticated transaction where
protocol semantics require it; independently, the CLI-First Node Production
Gate's remaining S4/S5 and the independent security/release gates must also be
completed. The bounded S3 uniform ordinary-asset fee composition
([DR-0087](decisions/0081-0087-cli-first-roadmap.md)) and
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
[the production persistence requirements](../operations/persistence.md). Production records use a stable chain,
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
The S3 local-devnet fee slice is implemented As-Is by
[DR-0087](decisions/0081-0087-cli-first-roadmap.md); validator/
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
