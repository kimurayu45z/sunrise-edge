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
> Treat Sunrise Edge as experimental software. It is not production-ready and
> has not been independently audited. Do not use it to custody real assets.
> The authoritative readiness status, limitations, and remaining work are
> tracked in [`TODO.md`](TODO.md).

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

### Run the local devnet and CLI

[`docs/guides/devnet.md`](docs/guides/devnet.md) contains the complete
reproducible walkthrough for:

- creating development-only sender, recipient, and treasury keys;
- starting the loopback-only single-validator devnet;
- submitting an ordinary asset-account transfer with fees;
- querying the receipt, objects, and next nonce; and
- orderly restart and persisted-state comparison.

The guide also documents the optional remote TLS transport and its separate
locally configured expected-protocol-context check. The local devnet must never
be exposed beyond your machine or used to custody real assets.

## Workspace map

| Area | Crates | Responsibility |
| --- | --- | --- |
| Protocol foundation | `protocol-types`, `canonical-encoding`, `hashing`, `crypto`, `commitments` | Stable identifiers, canonical bytes, domain separation, hash suites, signatures, and state commitment schemes |
| State and access | `objects`, `abi` | Versioned objects, ownership, object references, access modes, and transaction access manifests |
| Execution | `execution`, `contract-sdk`, `chain-ir`, `system-modules` | Transactions/effects, deterministic WASM, proof envelopes/verifier interfaces, contract host APIs, portable IR, and governed modules |
| Economics and governance | `fees`, `bonds`, `governance`, `protocol-upgrades`, `protocol-config` | Fees/bonds, admission, governance actions, upgrades, migrations, and committed configuration |
| Runtime and consensus | `runtime`, `runtime-sqlite`, `runtime-postgres`, `validator-set`, `consensus`, `node-core` | Persistence/runtime interfaces, local SQLite, normalized PostgreSQL, validator snapshots, consensus, and one-event state transitions |
| Client wire and SDK | `node-wire`, `clients/rust` | Canonical HTTP/query frames, the Rust client, loopback plaintext, bounded remote TLS, and protocol-context verification |
| Hardware signing | `signing-view`, `clients/ledger` | Hardware signing policy, APDU/USB/HID host transport, and Ledger external-signer integration |
| Applications | `apps/devnet`, `apps/cli` | Local development network and Rust-only CLI |
| Adapters | `native-http`, `adapters/*` | Native and serverless HTTP ingress around the canonical node contract |

Vendor-specific dependencies stay outside the protocol core. Adapters may host
the same state-machine boundary without becoming protocol trust roots.

## Protocol invariants

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

- [`docs/README.md`](docs/README.md) is the documentation index.
- [`docs/architecture/`](docs/architecture/README.md) records the implemented
  architecture and decision records by subsystem.
- [`TODO.md`](TODO.md) is the detailed design brief, completion criteria, and
  roadmap.
- [`docs/operations/persistence.md`](docs/operations/persistence.md) defines
  provider-neutral production persistence requirements.
- [`docs/operations/postgres.md`](docs/operations/postgres.md) defines the
  normalized PostgreSQL design.
- [`docs/signing/hardware-signing.md`](docs/signing/hardware-signing.md) defines
  the hardware-signing profile and device contract.
- [`AGENTS.md`](AGENTS.md) contains repository-wide contributor instructions.

When code and an aspirational roadmap differ, treat implemented wire formats,
stable tests, and accepted architecture decisions as compatibility constraints.

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
