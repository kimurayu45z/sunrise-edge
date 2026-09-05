# Architecture decision DR-0104

Establish the Asset Standards Gate and the compatibility boundary for the
first standard-asset foundation.

- **DR-0104: gate asset semantics before builder or public-testnet exposure.**
  The first fungible standard is named **Standard Asset v1**. The separately
  versioned NFT-like standard is named **Unique Asset v1**. These are protocol
  standard names, not ticker symbols, marketing labels, Rust type names, or
  aliases for the existing development fixture. Unique Asset v1 is named here
  only to reserve the architectural distinction; its representation and
  behavior remain future work.

  **Account and authority model.** Standard Asset v1 combines a Solana-style
  per-owner balance account with Sui-style capability authorities. An asset
  definition, an owner's balance account, and authority capabilities are
  separate objects with separate schemas and lifecycle rules. A balance
  account holds ordinary fungible balance state for exactly one `AssetId` and
  exactly one `Address` owner. Privileged actions are authorized by possession
  and ownership of explicit typed capability objects, not by overloading the
  balance account, embedding an ambient administrator address in every
  account, or treating object ownership as voting power.

  Standard Asset v1 has exactly one default balance account for each
  `(AssetId, Address owner)` pair. Its object identity is derived
  deterministically from that pair and the committed derivation context. There
  are no optional numbered, named, or caller-selected subaccounts in v1. A
  later standard version may add another account model only through an
  additive version and an explicit coexistence/migration decision; it must not
  reinterpret a v1 default-account identifier.

  **Identity derivation requirements.** `AssetId` and the default-account
  `ObjectId` use distinct, canonical, versioned derivation frames and distinct
  domain separation. Asset identity binds the chain, the Standard Asset v1
  identity, the authenticated creation authority, and a canonical uniqueness
  input. Default-account identity binds the chain, Standard Asset v1, the exact
  `AssetId`, and the exact Address owner. Derivation is deterministic across
  machines and runtimes, uses checked and length-framed inputs, and never uses
  a symbol, display metadata, map iteration order, wall clock, provider
  coordinate, or caller-selected hash algorithm as identity. The active
  protocol configuration selects any cryptographic algorithm required at
  creation, and the resulting derivation context must remain sufficient to
  reproduce historical identifiers after a hash-suite or protocol upgrade.

  This decision intentionally allocates no canonical type ID, enum tag, hash
  domain ID, feature flag, module ID, host-ABI number, or fixed vector. Before
  implementation activates any of these bytes, a follow-up additive decision
  must audit the complete existing identifier namespace, allocate every stable
  value once, specify the exact canonical fields and byte order, and pin both
  derivation and negative/adversarial vectors. No existing identifier may be
  reused or reinterpreted.

  **Create remains a narrow future capability.** Although the execution layer
  can represent `ObjectEffect::Created`, no existing generic or public path is
  authorized to commit it. The first reachable Create may be enabled only by a
  future additive protocol version and only for an exact governance-committed,
  trusted preinstalled module. Its committed policy must bind the module and
  version, entrypoint, maximum created-object count and aggregate bytes, exact
  output type hashes and schema versions, permitted owner kinds, and identifier
  derivation. Node-core must independently validate every output, require an
  exact absent-head assertion for each new identity, and commit the resulting
  version-one objects atomically with nonce, receipt, fees, and outbox. A
  current or tombstoned identity is a collision, not permission to recreate it.
  Exact replay must reconcile before execution or Create reads.

  The Create policy does not authorize arbitrary uploaded WASM, generic smart
  contracts, caller-selected object IDs, Shared/System ownership, owner
  reassignment, or unbounded output. Those paths continue to fail closed. The
  existing profile-versioned output-owner admissibility check is a prerequisite:
  every Address owner returned by authenticated execution must satisfy the
  owner policy that authenticated the transaction before any object mutation
  can commit. This check is necessary but is not itself Create authorization.

  **Compatibility and fees.** `fees::AssetId` and its canonical encoding remain
  unchanged. The existing devnet-local asset account and catalog bytes
  (`0xF001`, `0xF010`, and `0xF011`), their pinned WAT/WASM and hashes, seeded
  object identifiers, transfer behavior, and fee vectors remain historical
  compatibility constraints. They are not relabeled as Standard Asset v1 and
  require no migration in this decision. A Standard Asset v1 selected by fee
  policy pays fees from the same ordinary per-owner balance account used for
  transfers; fee eligibility and rates remain protocol policy, never a native
  coin, privileged balance representation, or fee-only transfer path.

  **Deferred slices.** Canonical definition/account/capability schemas and
  stable identifiers; authenticated issuance; metadata authenticity and
  update rules; mint, burn, fixed or capped supply, supply accounting and
  proofs; capability taxonomy, delegation, transfer, revocation, recovery, and
  destruction; freeze/close/allowance behavior; Standard Asset module code and
  activation; governed fee-asset admission; and the complete Unique Asset v1
  design and implementation all remain future work. Until those slices and
  their focused delta security review are complete, the names and derivation
  requirements in this decision are a foundation, not a claim that a
  production asset standard is available.
