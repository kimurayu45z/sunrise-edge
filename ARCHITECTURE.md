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

## 3. Canonical serialization rules
All protocol-critical payloads use a SCALE-based framed binary encoding with explicit protocol magic, type identifier, encoding version, field count, field identifiers, field lengths, and field bytes. Fields are emitted in sorted field-id order to avoid map and construction-order nondeterminism.

## 4. Hash architecture
Hashing is centralized in the `hashing` crate. Callers provide a canonical payload, a hash domain, protocol version, and chain id; the crate is solely responsible for producing the canonical domain-separation frame before hashing.

## 5. HashSuite lifecycle
`HashSuite` is an immutable protocol configuration object. `HashSuiteResolver` selects the active suite from a monotonically increasing epoch schedule, requires a genesis entry at epoch 0, and never silently falls back to a different algorithm.

## 6. Hash domain separation
Every protocol hash includes the protocol magic, selected `HashAlgorithmId`, `HashDomain`, domain version, `ChainId`, `ProtocolVersion`, and canonical payload in a framed structure.

## 7. Commitment scheme architecture
Commitment schemes are separate from general-purpose hashes. This phase does not implement commitments, but later commitment crates must follow the same explicit algorithm-ID and framing discipline without reusing general hash identifiers.

## 8. Signature domain separation
Signature framing is distinct from hash framing. Signed payloads include `ChainId`, `ProtocolVersion`, `Epoch`, `message_type`, `SignatureSchemeId`, and the canonical payload to prevent replay across chains, epochs, protocol versions, and message families.

## 9. Object lifecycle
Objects are not implemented in Phase 1. Future object versions will reference self-describing digests so historical versions remain readable after hash-suite migration.

## 10. Transaction lifecycle
Transactions are not implemented in Phase 1. They will be canonically serialized first, then hashed by the active suite selected from `(chain_id, protocol_version, epoch)`.

## 11. Fast Path lifecycle
Fast Path is deferred. Its certificates will rely on the Phase 1 digest, suite-resolution, and signature-domain primitives.

## 12. Certificate lifecycle
Certificates are deferred. Their hashes and signatures will use explicit certificate domains and future message-type identifiers.

## 13. Persistent state layout
Persistent storage is deferred, but stored references must preserve algorithm identifiers in digests and avoid any requirement for global rehashing.

## 14. Validator lifecycle
Validator identity and lifecycle are deferred. Future validator records will bind to explicit chain, epoch, and protocol-version context.

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
Protocol upgrades are versioned and explicit. The hash and signature framing always includes `ProtocolVersion`, so upgrades naturally fork cryptographic domains.

## 22. Hash algorithm migration lifecycle
Hash migration is schedule-based, forward-only, and lazy. There is no global state rehash; existing digests remain self-describing and verifiable with their recorded algorithm ID.

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
- Object IDs for new objects are derived as
  `SHA-256(tx_hash_bytes ‖ creation_index_le_u32)` so the same transaction
  always produces the same IDs.
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
ZK execution is deferred. The architecture reserves separate commitment-scheme evolution so ZK-specific cryptography can change independently from consensus hashes.

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

## 28. Serverless runtime constraints
The cryptographic core is pure, synchronous, and free of background workers, daemons, mutable globals, and runtime-vendor dependencies. This keeps the implementation portable to edge and serverless adapters.

## Decision record
- DR-0001: Use a single canonical framed binary format for hashes, signatures, and protocol-critical payloads.
- DR-0002: Keep `HashAlgorithmId` broader than the currently enabled built-ins so future support can be added without changing digest shape.
- DR-0003: Treat hash-suite scheduling as configuration resolution, not as a bulk migration job.
- DR-0011: Introduce a governance-managed `SystemModuleRegistry` with versioned
  module commitments (`code`, `semantics`, `manifest`) and optional native/ZK
  acceleration hints while preserving canonical execution equivalence.
