# Security Review: sunrise-edge

## Scope

Fresh, independent Standard single-pass static source audit of immutable Sunrise Edge revision cdf438c51b1609eb4886d8edcddc22af183f48c0. SECURITY.md and docs/security/initial-code-audit-scope.md defined the binding security policy and included/excluded source boundary.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_5bd4c525ca61acfe28cfb4b8fe8b7d91bdbaa14d924d5750152c908955053558
- Revision: cdf438c51b1609eb4886d8edcddc22af183f48c0
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Runtime or test status: not executed by instruction
- Artifacts reviewed: SECURITY.md, docs/security/initial-code-audit-scope.md, Cargo.toml, Cargo.lock, rust-toolchain.toml, in-scope protocol, canonical encoding, hashing, crypto, commitment, object, ABI, protocol-config, system-module, execution, and fee crates, in-scope runtime, SQLite, PostgreSQL, node-wire, node-core, and native-http crates, in-scope Rust client, signing-view, devnet, CLI source, and named CLI end-to-end test source
- Scan context: The target remained at exact HEAD cdf438c51b1609eb4886d8edcddc22af183f48c0 with an empty working-tree status. No source files were changed.

Limitations and exclusions:
- No builds, tests, application execution, dependency installation, or network calls were performed by explicit instruction; checked-in regression tests were inspected only as source.
- No online dependency advisory database was queried. Locked versions, manifest features, source origins, and in-scope dependency use were inspected, but current advisory status is not dynamically verified.
- Production proxy, kernel, TLS termination, PostgreSQL deployment, credentials, backup, HA, PKI, load/soak, physical hardware, and mainnet behavior were outside this source-only conclusion.
- Capability preflight found three usable worker slots rather than the recommended six; work was completed in a smaller set of parallel waves with an independent baseline.
- Excluded crates/{bonds,governance,protocol-upgrades,validator-set,consensus}/\*\* except directly reached configuration types: Explicitly excluded by docs/security/initial-code-audit-scope.md; externally accepted non-Submit families remain rejected and that rejection boundary was reviewed.
- Excluded crates/{chain-ir,contract-sdk}/\*\* and clients/ledger/\*\* plus Ledger-only branches: Explicit first-audit exclusions, including raw WASM host ABI and hardware/HIL/release work.
- Excluded adapters/\*\*, provider deployments, checkpoint/restore, browser applications, backup/HA/PKI, and long-running or physical campaigns: Explicit scope exclusions and absent concrete source/deployment prerequisites; not treated as findings.
- Excluded runtime execution, builds, tests, dependency downloads, network calls, and external service validation: Explicit user instruction required an offline, source-read-only audit.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 0 |
| Severity mix | none |
| Confidence mix | none |
| Coverage | complete |
| Validation mode | independent architecture map, baseline review, six focused source receipts, and parent-led static validation |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

The concrete in-scope executable server is a loopback-only experimental devnet. A SubmitTransaction passes pre-parser connection/header/body limits, canonical NodeEvent decoding, submit-only family policy, committed profile-2 authentication, persisted request-receipt and event-digest reconciliation, nonce/object/module/fee authorization, a typed atomic state/object/receipt/outbox commit, and indexed delivery. Public queries are unauthenticated reads. The Rust client has separate loopback and explicit remote-TLS transports plus a locally expected protocol-context gate. PostgreSQL is an in-scope adapter library with no concrete in-scope deployment. This map does not establish production or mainnet readiness.

### Assets

- Canonical bytes, stable identifiers, hash and signature domains, and exact chain/protocol/epoch/request identity.
- Profile-2 sender and funded-owner authority while preserving explicitly weaker historical profile-1 bytes.
- Application state, sender nonce, immutable object versions/provenance, receipts, and outbox atomicity.
- Ordinary asset balances, committed destination policy, the composition-owned treasury, and fee conservation.
- Committed preinstalled module code, manifest, semantics, version, and execution checkpoint.
- Structured and blob persistence, namespaces, writer fences, deadlines, and indeterminate reconciliation.
- Development seed bytes, explicit TLS trust inputs, expected protocol context, and bounded ingress/transport capacity.

### Trust Boundaries

- Unauthenticated local caller to the loopback devnet listener; native_http::serve owns the pre-parser lifecycle bounds.
- Reusable Axum Router to embedding host; Router body/work bounds are distinct from serve/serve_with_policy connection/header/body-idle/response controls.
- HTTP bytes to authenticated mutation; non-SubmitTransaction families and invalid profile-2 signatures fail before identity, clock, module, or storage.
- Valid sender to signed transaction; profile 2 binds exact request_id and Transaction-v1 signable bytes under a distinct message family.
- Authenticated transaction to object state; signed references, provenance, body digests, every Address owner, destination policy, treasury identity, and effects are checked.
- Execution effects to atomic persistence; nonce, state, objects, receipt, and outbox share one typed invocation.
- Public query response to client use; v2 inline data carries recomputation context, while v1 inline data is explicitly unverified and rejected by the generic client.
- Trusted startup composition to request processing; protocol configuration, catalog, treasury, namespace, writer fence, clock, checkpoint, and identity source are not request inputs.
- CLI transport authentication to protocol intent; endpoint TLS and locally expected protocol-context verification are separate gates.

### Attacker Capabilities

- An unauthenticated caller can send malformed or canonical bounded requests, repeat, delay, reorder, or relabel them, select public lookup keys, and consume available admission capacity.
- A valid sender controls every signed transaction field, but not trusted protocol configuration, catalog semantics, treasury identity, namespace, writer fence, checkpoint, or clock.
- Relays, transports, and schedulers may drop, mutate, duplicate, delay, replay, or reorder delivery.
- No starting capability includes an operator account, sender private key, database administrator, trusted configuration, release infrastructure, or deployment credential.

### Security Objectives

- Authenticate exact trusted context and request-bound canonical transaction bytes before privileged or mutable work.
- Preserve profile-1 and Transaction-v1 history without a profile-2 downgrade.
- Reconcile request ID plus complete event digest before nonce, module, object, or application work and reject different-event reuse.
- Commit nonce, state, object, receipt, and outbox effects atomically or surface indeterminate state for exact reconciliation.
- Verify every object and owner and constrain destination, treasury, fees, and effects to signed and committed policy.
- Resolve executable code only from the trusted committed catalog.
- Reject externally inactive event families before side effects.
- Keep object-query v2 additive and historical inline data explicitly unverified/rejected by the generic client.
- Bound attacker-controlled connections, frames, bodies, modules, gas, outputs, deadlines, retries, leases, and concurrent work.
- Keep source conclusions separate from production and mainnet readiness.

### Assumptions

- Historical profile 1 intentionally retains ZIP-215 funded-owner semantics and does not bind the outer request ID; trusted committed configuration selects profiles, and the concrete devnet/CLI select profile 2.
- The concrete devnet uses native_http::serve. A different embedding host serving a raw Router must prove equivalent pre-parser lifecycle controls.
- Full canonical ProtocolConfig byte pinning is deferred; the client verifies eight selected signer-relevant context fields.
- Blob publication can precede a rejected structured commit and leave an unreachable content-addressed orphan; GC is absent. The sole active module emits fixed 76-byte bodies below the 64 KiB blob threshold.
- WasmExecutionEngine has fuel and byte/count bounds but no explicit Store memory limiter. The sole active trusted WAT declares one page and has no memory.grow; future catalog modules require focused review.
- Unix seed-file permission/inode controls do not establish non-Unix filesystem protection.
- Stale Rust comments do not override stricter executable behavior or SECURITY.md.

## Findings

### No findings

No reportable findings survived the canonical discovery, validation, and reportability gates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Architecture and effective-resource threat model | Concrete startup paths, trust boundaries, resource values, public queries, trusted composition, and absent deployment prerequisites. | No issue found | Mapped the loopback devnet, reusable Router/server boundary, authenticated submit path, CLI transports/context, local persistence, and conditional PostgreSQL seam without inferring production readiness. |
| Independent baseline security review | Canonical framing, authentication, replay, object effects, execution, fees, persistence, ingress, clients, and devnet composition. | No issue found | The independent baseline reported no candidate findings and independently agreed with all four remediation dispositions. |
| Object-query integrity and historical compatibility | Forged CurrentInline bodies, selector rebinding, v1/v2 compatibility, digest context, and transaction-reference consumption. | No issue found | csf_e77c8313ca0a303cedfa981b is fixed. Server state/provenance/body checks, additive v2 digest context, generic-client recomputation, and explicit HistoricalCurrentInline rejection close the reported redirect path. Unchanged non-inline statuses retain v1. |
| Profile-2 Ed25519 funded-owner admissibility | Noncanonical/identity/low-order senders, every loaded Address owner, destination, treasury, devnet configuration, and seed reconciliation. | No issue found | csf_f989f2782c1a74ecb3f1c63b is fixed for committed profile 2. Strict canonical non-identity prime-order validation precedes sender, destination, and treasury authorization. Profile 1 remains intentionally historical with no request-controlled profile-2 downgrade found. |
| Profile-2 request-ID and message-family binding | Unsigned request relabeling, canonical submission envelope, public authentication APIs, historical Transaction-v1, and pre-side-effect ordering. | No issue found | csf_0def7e2c09e504c51dc13d81 is fixed for committed profile 2. Envelope 0xE009 signs exact request ID plus Transaction-v1 bytes under submit-transaction-v1; native ingress authenticates before identity, clock, module, or storage. The no-ID public authenticator fails closed for profile 2. |
| Native HTTP pre-parser admission and deadlines | Connection permits, headers, body idle/total, response writes, keep-alive, all four Router families, and concrete startup consumers. | No issue found | csf_6b9af57d0e0e5c5425e690db is fixed for repository-owned native entrypoints. serve acquires a bounded permit immediately after accept and applies finite parsing/body/response limits; every in-scope concrete host uses it. Raw Router embeddings require equivalent controls, and no in-scope bypass was found. |
| Durable replay, atomicity, blobs, SQLite, and PostgreSQL | Receipt-first replay, nonce and state/object/receipt/outbox atomicity, namespaces, writer fences, deadlines, retries, leases, and indeterminate outcomes. | No issue found | No duplication, partial structured commit, cross-domain mapping, unsafe serialization retry, or blind indeterminate retry path was found. PostgreSQL deployment behavior remains unverified rather than inferred. |
| WASM, transports, expected context, seed handling, and fees | Execution fuel/byte/count bounds, trusted code selection, strict HTTP/TLS framing, context verification, local seed loading, and checked fee composition. | No issue found | No current reportable bypass was found. Current code is catalog-trusted and fixed-size; transports and polling are bounded; endpoint authentication and protocol context are separate; fee payer/treasury and arithmetic are checked and committed atomically. |
| Conditional unreachable-blob storage exhaustion | Pre-commit content-addressed publication without GC. | Rejected | Rejected as a current finding: the only concrete trusted module emits fixed 76-byte bodies below the 64 KiB threshold, so a request cannot reach blob publication. A future over-threshold attacker-varying module plus repeated post-publication rejection and absent capacity controls is a focused-review change condition. |
| Conditional WASM linear-memory exhaustion | Missing explicit wasmi Store memory limiter. | Rejected | Rejected as a current finding: transactions cannot upload code, and the sole active trusted WAT declares one memory page and no memory.grow. A future memory-growing catalog module is a focused-review change condition. |
| Rust security API and documentation drift | Stale authentication, fee, owner-binding, and production-transport prose. | Rejected | Several comments are inaccurate, but executable paths remain stricter and fail closed and SECURITY.md controls readiness. No attacker-controlled authorization, integrity, confidentiality, or availability consequence was established; documentation should still be corrected. |
