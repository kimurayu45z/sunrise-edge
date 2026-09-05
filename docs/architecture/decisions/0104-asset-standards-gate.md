# Architecture decision DR-0104

Establish the Asset Standards Gate and the activation/replacement boundary for the
first standard-asset foundation.

- **DR-0104: gate asset semantics before builder or public-testnet exposure.**
  The first fungible standard is named **Standard Asset v1**. The separately
  versioned NFT-like standard is named **Unique Asset v1**. These are protocol
  standard names, not ticker symbols, marketing labels, Rust type names, or
  aliases for the existing development fixture. Unique Asset v1 is named here
  only to reserve the architectural distinction; its representation and
  behavior remain future work.

  **Coin and authority model.** Standard Asset v1 uses Sui-like owned coin
  objects and Sui-style capability authorities. An asset definition,
  `StandardAssetCoinV1` values, and authority capabilities are separate objects
  with separate schemas and lifecycle rules. Each coin contains exactly one
  `AssetId` and one integer amount; its object owner supplies the owning
  `Address`. An address may own any bounded number of coins for the same asset.
  Object identity and object version are the anti-replay and anti-double-spend
  mechanism. The coin body has no separate account sequence or nonce unless a
  later decision demonstrates an invariant that object versioning cannot
  provide.

  Privileged actions are authorized by possession and ownership of explicit
  typed capability objects, not by overloading a coin, embedding an ambient
  administrator address in every coin, or treating object ownership as voting
  power. Capability objects remain distinct from the asset definition and from
  ordinary value-bearing coins.

  **Owned-coin transfer model.** A transfer declares only sender-owned coin
  inputs. The canonical signed transaction binds the recipient and the exact
  intended operation, so the recipient does not sign and no recipient balance
  object is read or written. A whole-coin transfer is a narrowly policy-
  authorized change of that coin's owner. A partial transfer mutates the
  sender-owned input to the checked remainder and creates a new recipient-owned
  coin for the checked transferred amount. A merge mutates one selected
  sender-owned destination coin to the checked sum and consumes the remaining
  sender-owned coins carrying the same `AssetId`; it does not create a new coin.
  Every operation preserves the `AssetId`, rejects zero or
  overflowing amounts, and conserves value except where a separately
  authorized mint or burn operation applies.

  Owned-only transfers are eligible for the object fast path because they do
  not read or write recipient state and do not require total-order consensus
  merely to serialize unrelated balances. Fast path does not mean unilateral
  sender-recipient acceptance: validators must still authenticate, execute,
  certify with the required quorum, and atomically publish the resulting object
  versions. Client and CLI surfaces must hide coin selection, split, merge, and
  dust consolidation while preserving the exact signed inputs, recipient, and
  outputs they present for user approval.

  **Identity derivation requirements.** `AssetId` uses its own canonical,
  versioned derivation frame and explicit domain separation. Asset identity
  binds the chain, Standard Asset v1, the authenticated creation authority, and
  a canonical uniqueness input. A newly created coin uses the protocol's
  generic versioned created-object `ObjectId` derivation from the exact signed
  transaction hash context and creation ordinal; the asset standard must reuse
  that implementation rather than introduce a second coin-specific formula.
  A coin ID is therefore independently reproducible and is not a deterministic
  per-owner balance address. Before activation, the generic helper and its
  historical version-one behavior must be exported or otherwise shared without
  changing the already pinned vectors. Derivation is deterministic across
  machines and runtimes, uses checked and length-framed inputs, and never uses a
  symbol, display metadata, map iteration order, wall clock, provider
  coordinate, or caller-selected hash algorithm as identity. The active
  protocol configuration selects any cryptographic algorithm required at
  creation, and the resulting derivation context must remain sufficient to
  reproduce historical identifiers after a hash-suite or protocol upgrade.

  The initial gate intentionally allocated no canonical type ID, enum tag, hash
  domain ID, feature flag, module ID, host-ABI number, or fixed vector. Before
  implementation activates any of these bytes, a follow-up additive decision
  must audit the complete existing identifier namespace, allocate every stable
  value once, specify the exact canonical fields and byte order, and pin both
  derivation and negative/adversarial vectors. No existing identifier may be
  reused or reinterpreted.

  **Implemented identity and value schemas (this slice).** A follow-up audit
  of the complete existing identifier namespace has allocated the stable
  values below for identity and value schemas only. Module activation,
  `Create`, owner change, transfer, CLI, fee integration, metadata, standalone
  minting, and supply accounting activate none of these bytes and remain
  future work. `HashDomain::AssetId = 0x000E` and the corresponding
  `HashPurpose::AssetId` bind Standard Asset v1 identity derivation into the
  existing domain-separated hashing framework; `HashSuite::algorithm_for`
  selects the active suite's protocol-configuration hash algorithm for this
  purpose, the same algorithm already used for
  `HashPurpose::SystemModuleManifest`, so no caller may select a derivation
  algorithm. `AssetId` moves from `fees` into the asset subsystem with its
  existing `0x7001` canonical type ID because its meaning has not changed.
  The audit reserves unused `0x7100` through `0x7103` for this implementation:
  `StandardAssetDefinitionV1` is `0x7101`, `StandardAssetCoinV1` is `0x7102`, and
  `StandardAssetMintCapabilityV1` is `0x7103` (the AssetId derivation input
  frame, `0x7100`, is a private encoding detail, not a public schema).
  `StandardAssetDefinitionV1` binds `asset_id`, `creation_authority: Address`,
  a non-zero 32-byte caller-supplied `creation_seed`, `creation_epoch`,
  `creation_protocol_version`, and `derivation_algorithm`, and can validate
  that the supplied resolver has the recorded protocol version before its
  stored `asset_id` and `derivation_algorithm` are recomputed.
  `StandardAssetCoinV1` binds exactly one `asset_id` and a non-zero
  `amount`. `StandardAssetMintCapabilityV1` binds exactly one `asset_id`.
  Strict decoders reject wrong type/version, missing/unknown fields,
  malformed lengths, unknown hash algorithms, a zero coin amount, and
  trailing bytes; derivation is pinned to change with creation authority,
  creation seed, chain, protocol version, and epoch/hash-suite schedule. The
  `AssetCreationSeed` type is deliberately distinct from node-core's
  request-idempotency `RequestId`; a caller may derive the former from the
  latter, but Rust code cannot accidentally interchange the two. No module
  activation, `Create`, owner change, CLI
  surface, minting, or fee integration exists yet, and duplicate-identity
  fail-closed enforcement remains future work because it requires the object
  store and `Create` path this slice does not implement.

  **Create and owner change remain narrow future capabilities.** Although the
  execution layer can represent `ObjectEffect::Created`, no existing generic or
  public path is authorized to commit it, and the current owned-effects path
  does not permit owner reassignment. The first reachable Create or owner change
  may be enabled only by a future additive protocol version and only for an
  exact governance-committed, trusted preinstalled module. Its committed policy
  must bind the module and version, entrypoint, signed recipient, maximum input
  and output counts and aggregate bytes, exact output set, type hashes and
  schema versions, permitted owner transition, identifier derivation, and
  atomic conservation rules. Node-core must independently validate every
  output and ID, require an exact absent-head assertion for each new identity,
  and commit all consumed, mutated, and created objects atomically with nonce,
  receipt, fees, and outbox. A current or tombstoned identity is a collision,
  not permission to recreate it. Exact replay must reconcile before execution
  or Create reads.

  The policy does not authorize arbitrary uploaded WASM, generic smart
  contracts, caller-selected object IDs, Shared/System ownership, owner changes
  outside the exact signed recipient transition, or unbounded output. Those
  paths continue to fail closed. The existing profile-versioned output-owner
  admissibility check is a prerequisite: every Address owner returned by
  authenticated execution must satisfy the owner policy that authenticated the
  transaction before any object mutation can commit. This check is necessary
  but is not itself Create or owner-change authorization.

  **Development fixtures and fees.** `AssetId` belongs to the new,
  dependency-light `standard-assets` crate; fee code imports that protocol
  type directly instead of exposing a transitional compatibility facade. No
  Sunrise Edge release exists. The
  existing devnet-local asset account and catalog bytes (`0xF001`, `0xF010`,
  and `0xF011`), their pinned WAT/WASM and hashes, seeded object identifiers,
  transfer behavior, and fee vectors are therefore development fixtures, not
  a public compatibility obligation: Standard Asset v1 activation is expected
  to replace them outright, not migrate or dual-support them. This decision
  does not relabel them as Standard Asset v1 and does not commit to
  preserving them historically. A Standard Asset v1 selected by fee
  policy pays fees from ordinary Standard Asset v1 coin objects under the same
  ownership, exact-version, checked-arithmetic, and atomic-effect rules as
  transfers; fee eligibility and rates remain protocol policy, never a native
  coin or privileged balance representation. Production fee handling must not
  introduce one globally hot treasury balance object into every otherwise
  independent fast-path transfer. The exact fee-output, aggregation, and
  certificate-signer distribution design remains open and requires its own
  bounded, deterministic decision before activation.

  **Deferred slices.** Authenticated issuance (`Create`); coin `ObjectId`
  derivation reuse from the generic created-object formula; owner change and
  transfer; metadata authenticity and update rules; mint, burn, fixed or
  capped supply, supply accounting and proofs; capability taxonomy,
  delegation, transfer, revocation, recovery, and destruction; freeze/close/
  allowance behavior; Standard Asset module code and activation; governed
  fee-asset admission; and the complete Unique Asset v1 design and
  implementation all remain future work. Until those slices and their
  focused delta security review are complete, the names, derivation
  requirements, and implemented schemas in this decision are a foundation,
  not a claim that a production asset standard is available.
