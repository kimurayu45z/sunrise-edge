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

The workspace currently contains the foundations implemented through the
experimental Cloudflare Workers ingress milestone:

- Canonical framed encoding for protocol-critical values.
- Bounded, zero-copy canonical frame decoding with strict order and length
  validation for adapter ingress.
- SHA-256 and SHA3-256 support with epoch-selected hash suites.
- Self-describing digests and domain-separated hash/signature framing.
- Versioned objects, object references, access manifests, and lazy migration.
- Runtime traits and an in-memory runtime for deterministic tests.
- A bounded, replay-context-aware node-core invocation boundary that persists
  one pure transition with compare-and-swap before releasing output.
- A native Axum/Tokio HTTP adapter with strict canonical binary media types,
  bounded bodies, deterministic status mapping, and graceful shutdown wiring.
- A bounded Cloudflare Workers ingress that uses a generated private Service
  Binding, strict TypeScript, and workerd integration tests.
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
node-event dispatch and protocol handlers, crash-safe transactional persistence
and outbox delivery, portable system-module execution, cryptographic slashing
proof verification, fee-object debiting, production persistence, runtime
adapters, networking/RPC surfaces, and independent security review.

The next planned technical milestone is the Phase 17 Vercel, Supabase, AWS, and
Deno adapter family described in [`TODO.md`](TODO.md), stacked on the portable
HTTP contract.

## Workspace map

| Area | Crates | Responsibility |
| --- | --- | --- |
| Protocol foundation | `protocol-types`, `canonical-encoding`, `hashing`, `crypto`, `commitments` | Stable identifiers, canonical bytes, domain separation, hash suites, signatures, and state commitment schemes |
| State and access | `objects`, `abi` | Versioned objects, ownership, object references, access modes, and transaction access manifests |
| Execution | `execution`, `contract-sdk`, `chain-ir`, `system-modules` | Transactions/effects, deterministic WASM, proof envelopes/verifier interfaces, contract host APIs, portable IR, and governed modules |
| Economics and governance | `fees`, `bonds`, `governance`, `protocol-upgrades`, `protocol-config` | Stablecoin fees/bonds, admission, governance actions, upgrades, migrations, and committed configuration |
| Runtime and consensus | `runtime`, `validator-set`, `consensus`, `node-core` | Persistence/runtime interfaces, epoch validator snapshots, event-driven shared-object ordering, and one-event conditional transitions |
| Adapters | `native-http`, `adapters/cloudflare-workers` | Bounded native routing plus Cloudflare Service-Binding ingress around the canonical HTTP contract |

The repository intentionally keeps vendor-specific dependencies out of the
protocol core. Future Cloudflare, Vercel, Supabase, AWS, Deno, and native HTTP
support belongs in adapters around these crates.

## Getting started

### Prerequisites

- A recent stable Rust toolchain with Rust 2024 edition support.
- Cargo, installed with Rust through [rustup](https://rustup.rs/).

### Build and test

```bash
git clone https://github.com/kimurayu45z/sunrise-edge.git
cd sunrise-edge

cargo build --workspace
cargo test --workspace --all-targets
```

Before submitting a change, run the full validation set:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

To work on one crate while iterating:

```bash
cargo test -p consensus
cargo test -p execution
cargo test -p native-http

cd adapters/cloudflare-workers
npm ci
npm run check
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
