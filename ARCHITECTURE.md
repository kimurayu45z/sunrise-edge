# Sunrise Edge Architecture

This document records the initial architecture for Sunrise Edge Phase 1. The implementation focus is the cryptographic and serialization foundation required for later consensus, object, execution, and runtime phases.

## 1. Overall architecture
Sunrise Edge is designed as a deterministic state-transition system over authenticated events and persistent state. The protocol core is split into small Rust crates so the same core logic can be reused in serverless and native runtimes without embedding vendor-specific dependencies.

## 2. Crate boundaries
- `protocol-types`: protocol identifiers, digest types, hash domains, and suite metadata.
- `canonical-encoding`: deterministic framed serialization for protocol-critical payloads.
- `hashing`: domain-separated hash framing, built-in hash implementations, and hash-suite resolution.
- `crypto`: signature-domain framing and signer/verifier traits.

## 3. Canonical serialization rules
All protocol-critical payloads use framed binary encoding with explicit protocol magic, type identifier, encoding version, field count, field identifiers, field lengths, and field bytes. Fields are emitted in sorted field-id order to avoid map and construction-order nondeterminism.

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
Governance is deferred except for the hash-suite scheduling concept. Future governance actions will schedule suite upgrades for activation in a future epoch only.

## 20. Epoch transition
Epoch transition activates configuration schedules lazily. New writes after activation may use the new suite, while historical data remains valid under its original algorithm identifier.

## 21. Protocol upgrade lifecycle
Protocol upgrades are versioned and explicit. The hash and signature framing always includes `ProtocolVersion`, so upgrades naturally fork cryptographic domains.

## 22. Hash algorithm migration lifecycle
Hash migration is schedule-based, forward-only, and lazy. There is no global state rehash; existing digests remain self-describing and verifiable with their recorded algorithm ID.

## 23. System Module lifecycle
System modules are deferred. Their code hashes and governance actions will consume the same framing infrastructure once introduced.

## 24. WASM / Chain IR execution
Execution is deferred. Deterministic execution outputs will eventually be fed into `ExecutionEffects` hashing using the same canonical framing guarantees.

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
