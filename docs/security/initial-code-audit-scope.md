# Initial Code-Security Audit Scope

This document fixes the intended source boundary for Sunrise Edge's first
independent code-security audit. It is an audit-entry artifact, not evidence
that the audit, production gate, or mainnet gate has completed. The reviewed
revision is fixed only by the final validation procedure below.

## Included source

The first engagement includes these path and component families:

| Paths | Included security behavior |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Workspace membership, locked direct/transitive versions, feature selection, and compiler provenance used by the included Rust paths. |
| `crates/protocol-types/**`, `crates/canonical-encoding/**`, `crates/hashing/**`, `crates/crypto/**`, `crates/commitments/**` | Stable identifiers and discriminants, canonical framing/decoding, self-describing digests, hash-suite resolution, signature-domain framing, Ed25519 verification, and commitment identifiers/primitives directly consumed by execution. Checkpoint/state-root publication remains excluded below. |
| `crates/objects/**`, `crates/abi/**`, `crates/protocol-config/**`, `crates/system-modules/**` | Object identity/version/owner rules, signed access manifests, committed transaction-authentication and domain-placement authority, and preinstalled module registry/semantics. |
| `crates/execution/**`, `crates/fees/**` | Canonical transaction/effects handling, deterministic preinstalled WASM execution and host calls, gas/fuel accounting, and ordinary-asset fee inputs/arithmetic. |
| `crates/runtime/**`, `crates/runtime-sqlite/**`, `crates/runtime-postgres/**` | Structured all-or-none state/object/receipt/outbox contract; writer fences, deadlines, namespaces, ambiguous-commit semantics, indexed claim/ack; SQLite/PostgreSQL mappings; and both adapters' inline/blob-reference projections. |
| `crates/node-wire/**`, `crates/node-core/**`, `crates/native-http/**` | Canonical HTTP/query frames, authenticated `SubmitTransaction`, nonce/replay/dedup, owned-object authorization/effect matching, blob publication/verification, preinstalled module/fee composition, native ingress bounds, submit-only event-family policy, error mapping, and outbox delivery. |
| `clients/rust/**`, `crates/signing-view/**` | Bounded loopback/TLS transports, expected-protocol-context verification, transaction construction/final signature verification, and the clear-signing policy reached by the Rust client. |
| `apps/devnet/**` | Concrete loopback composition, trusted protocol/module/treasury configuration, asset-account WASM and fees, local SQLite/blob resources, persisted writer generation, request authority, and bounded local transport. |
| `apps/cli/src/**`, `apps/cli/tests/{devnet_query_e2e.rs,devnet_restart_duplicate_e2e.rs,devnet_transfer_e2e.rs,tls_cli_e2e.rs}` | CLI parsing and network transaction path, local development signer selection/seed loading/address derivation, TLS/context pre-signing boundary, query/transfer behavior, final signature verification, and existing end-to-end evidence. Ledger-specific branches in the shared signer and command files are excluded below. |

Co-located `#[cfg(test)]` modules and test/fixture directories beneath an
included path are included. Generated build output and downloaded dependency
source are not audit inputs, but locked versions, enabled features, and the way
included code calls dependencies are in scope.

## Direct-dependency rationale

The scope follows the real authenticated mutation path rather than every
workspace crate. `node-core` directly depends on ABI, canonical encoding,
cryptography, execution, fees, hashing, objects, protocol configuration,
protocol types, runtime, and system modules
([`crates/node-core/Cargo.toml:7-18`](../../crates/node-core/Cargo.toml)).
`native-http` adds the canonical wire contract and Axum/Tokio ingress boundary
([`crates/native-http/Cargo.toml:7-19`](../../crates/native-http/Cargo.toml)).
The concrete devnet adds SQLite persistence and composition
([`apps/devnet/Cargo.toml:7-21`](../../apps/devnet/Cargo.toml)), while the Rust
client adds the TLS and signing-view boundary
([`clients/rust/Cargo.toml:7-19`](../../clients/rust/Cargo.toml)).

These dependencies are included because they can affect authentication,
authorization, canonical bytes, execution effects, fees, durable atomicity,
or what the client signs. A dependency is not included merely because it is a
workspace sibling. Where an in-scope `ProtocolConfig` constructor or encoder
uses a type defined by an otherwise excluded protocol crate, that directly
reached type, encoder, and validator remain in scope; the crate's unrelated
state machine and externally inactive event handling remain excluded.

## Explicit exclusions

The first engagement excludes:

- `crates/bonds/**`, `crates/governance/**`, `crates/protocol-upgrades/**`,
  `crates/validator-set/**`, and
  `crates/consensus/**`, including FastCertificate, certificate publication,
  multi-validator activation, governance, upgrades, and validator-set event
  families, except for directly reached configuration types, encoders, and
  validators described above;
- `crates/chain-ir/**` and `crates/contract-sdk/**`, including the existing raw
  WASM host-ABI unsafe boundary;
- `clients/ledger/**` and the Ledger-specific branches/functions co-located in
  `apps/cli/src/signer.rs`, `apps/cli/src/commands/address.rs`, and
  `apps/cli/src/commands/transfer.rs`, including USB, physical-device, HIL, UI,
  reproducible-build, and release evidence; the local-signer paths in those
  shared CLI files remain in scope;
- `adapters/**`, including provider-specific serverless ingress source,
  deployment configuration, authentication policy, networking, WAF/rate
  policy, secret lifecycle, and operational certification;
- externally accepted event families other than `SubmitTransaction`;
- checkpoint/state-root publication and verified restore; PITR, backup,
  off-host restore, HA/failover orchestration, PKI lifecycle, and provider
  deployment topology;
- browser TypeScript client, explorer, and wallet applications, which are not
  currently workspace members; and
- additional long-running load/soak/capacity and physical-fault campaigns.

The existing native fail-closed rejection of excluded event families remains
in scope because it defines the implemented external boundary
([`crates/native-http/src/lib.rs:2236-2263`](../../crates/native-http/src/lib.rs)).
An exclusion is not a statement that excluded code is secure, an accepted risk,
or exempt from private vulnerability reporting.

## Audit revision and evidence

The audit target is the final validated pull-request head, identified by one
complete 40-character Git commit SHA. A branch name, tag that can move, local
working tree, earlier review SHA, or merge-base is not the audit revision. Do
not record the SHA until the final documentation and code are committed and the
following commands succeed from that exact checkout:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
git diff --check
git status --short
git rev-parse HEAD
```

Required handoff evidence is:

1. complete, unedited command output associated with the exact SHA;
2. successful exit status for dependency installation, the repository gate,
   and `git diff --check`;
3. empty output from `git status --short`;
4. the 40-character output of `git rev-parse HEAD` matching the submitted audit
   revision; and
5. required GitHub checks passing for that same SHA.

A local pass does not establish production deployment behavior or complete the
independent audit. Until all evidence above exists, the audit revision remains
unfrozen and the audit-entry gate remains open.

## Delta-audit rule

Any later change that affects canonical bytes or identifiers, a hash/signature
domain, authentication, authorization, replay/nonce behavior, object effects,
WASM execution, fees, persistence atomicity, blob integrity, externally exposed
routes, or a previously excluded protocol/event/provider surface requires an
explicit focused delta audit before production activation. The delta review
must name its base audit SHA, exact changed SHA/range and paths, compatibility
impact, validation evidence, and disposition of findings. Documentation-only
changes may be classified separately only when review confirms they cannot
change executable behavior or the stated security boundary.
