# Security Policy

Sunrise Edge is experimental, unaudited software. It is not production-ready
and must not be used to custody real assets.

## Reporting a Vulnerability

Report suspected vulnerabilities through
[GitHub Private Vulnerability Reporting](https://github.com/sunriselayer/sunrise-edge/security/advisories/new).
Do not disclose exploitable details in a public issue, discussion, pull
request, or social channel.

Include the affected commit, component, realistic attacker prerequisites,
impact, and a minimal reproduction when safe. Do not include private keys,
access tokens, production data, or unnecessary exploit payloads.

## System and Scope

Sunrise Edge is a serverless-native blockchain state-machine implementation.
The repository contains protocol crates, deterministic execution, runtime
contracts, SQLite and PostgreSQL persistence implementations, native and
serverless ingress adapters, a Rust client, and CLI/devnet applications.

The first independent code-security audit is intentionally narrower than the
whole repository. Its exact paths and exclusions are recorded in
`docs/security/initial-code-audit-scope.md`. Vulnerabilities in excluded or
deferred code may still be reported; an audit exclusion is not a suppression
or accepted-risk decision.

The implemented native external mutation surface accepts only authenticated
`SubmitTransaction` events. Other known event families must remain rejected
before identity allocation, clock access, storage I/O, state-machine
transition, outbox work, or transport delivery.

Devnet query routes are unauthenticated public reads. They expose context,
objects, receipts, and sender next-nonce values and must not be treated as an
authorization mechanism.

## Threat Model and Trust Boundaries

Assume an unauthenticated network caller can send malformed or canonical
bounded requests, repeat or reorder them, choose public lookup selectors, and
consume available admission capacity.

Assume a valid sender can choose every signed transaction field, including its
request ID, nonce, access manifest, module reference, entrypoint, arguments,
gas limit, and fee declaration. A valid signature authorizes only that exact
canonical transaction and must not grant authority over undeclared or
unauthorized state.

Relays, schedulers, transports, and cloud providers are untrusted for protocol
safety. They may drop, duplicate, delay, reorder, replay, or mutate messages.

Operator-supplied protocol configuration, active hash suite, atomicity-domain
placement, preinstalled module catalog, writer fence, persistence namespace,
fee treasury, trusted clock, checkpoint, and deployment credentials are
trusted composition inputs. Untrusted requests must not select or replace
them.

Do not assume that an attacker already controls an operator account, private
signing key, database administrator, trusted protocol configuration, or
release infrastructure. Findings requiring those privileges must state the
additional capability gained.

Local development seed files are not production keystores. Optional hardware
signing support has not completed physical-device validation or release
certification.

## Security Invariants

- Canonical bytes, type and field identifiers, enum tags, hash domains, and
  stable vectors must remain deterministic and versioned.
- A state-changing transaction must be authenticated against the trusted
  chain ID, protocol version, epoch, authentication profile, signature scheme,
  and sender binding before runtime identity or storage work.
- Request replay and request-ID reuse must reconcile against persisted receipt
  and event-digest state before nonce, object, module, or application work.
- Sender nonce, application state, object versions, receipt, and outbox effects
  must commit atomically or not at all.
- Object access and execution effects must remain within the signed manifest.
  Owner, type, and schema changes must fail closed unless an exact committed
  policy explicitly permits them.
- Preinstalled WASM code and semantics must be resolved from trusted committed
  configuration, not uploaded or substituted by a transaction.
- Fee debits and treasury credits must use ordinary asset-account state and
  remain atomic with the application result or the defined rejected-result
  fee path.
- Writer fencing, deadlines, namespaces, and logical atomicity domains must be
  enforced by persistence implementations and must not come from request
  authority.
- Blob content must match its self-describing digest. Conflicting content must
  never overwrite an existing digest.
- TLS endpoint authentication and locally configured expected-protocol-context
  verification are separate mandatory controls before remote signing.
- Attacker-controlled collections, frames, bodies, modules, gas, outputs,
  deadlines, retries, leases, and concurrent work must remain explicitly
  bounded.
- Unknown algorithms, versions, event kinds, modules, encodings, and policies
  must fail closed without downgrade or fallback.

## Reportable Findings and Severity Context

A finding is reportable when a realistic attacker can violate an invariant,
gain authority they did not already possess, disclose protected secrets, cause
unauthorized state or asset movement, bypass replay protection, corrupt durable
history, or create material unbounded resource consumption.

- **Critical:** practical private-key compromise, unauthenticated arbitrary
  asset/state mutation, or protocol-wide integrity loss.
- **High:** authentication or authorization bypass, replay causing a second
  mutation or fee, exploitable atomicity failure, arbitrary module execution,
  or cross-chain signing under realistic deployment assumptions.
- **Medium:** bounded but meaningful integrity, availability, or information
  exposure requiring additional prerequisites.
- **Low:** limited hardening issue with concrete impact and realistic
  reachability.

Severity must account for actual exposure, prerequisites, existing effective
controls, and the new capability gained. A hypothesis, missing production
deployment, or behavior already available to the attacker is not by itself a
confirmed vulnerability.

## Initial-Audit Exclusions

The following are deferred from the first audit engagement:

- FastCertificate and atomic certificate publication;
- externally accepted non-`SubmitTransaction` event families;
- production multi-validator consensus activation;
- checkpoint/state-root publication and verified restore;
- provider-specific production deployment and operations;
- PITR, backup, off-host restore, HA, failover orchestration, and PKI lifecycle;
- long-running load, soak, capacity, and additional physical-fault campaigns;
- TypeScript client, explorer, and wallet applications;
- remaining Ledger physical-device, HIL, reproducible-build, and release work.

New protocol-critical or externally exposed surfaces require a focused delta
audit before production activation.

## Known Limitations and Compensating Controls

- The concrete devnet is loopback-only, single-validator, and unsuitable for
  real assets.
- SQLite is a local developer persistence implementation, not a production
  backend.
- PostgreSQL implements the durable contract as a library, but this repository
  does not prove a deployed topology, credential lifecycle, backup, HA, or
  operator runbook.
- Blob publication occurs before the structured state commit. A later commit
  rejection may leave an unreachable content-addressed blob; this is not a
  partial state commit. Garbage collection remains deferred.
- Remote TLS authenticates the endpoint only. The client separately checks the
  locally expected protocol context; full canonical `ProtocolConfig` byte
  pinning remains deferred.
- Serverless adapters relay to a separately deployed trusted node capability.
  Deployment authorization, secret rotation, WAF/rate policy, and private
  connectivity are not established merely by adapter source code.
- Repository-owned Rust code forbids `unsafe` except for the existing raw WASM
  host-ABI boundary in `contract-sdk`, which must remain behind checked safe
  wrappers.

## Audit Revision and Verification

An audit target is identified by one complete 40-character Git commit SHA,
never by a mutable branch name. The initial engagement uses the final,
validated pull-request head commit; later changes require explicit delta
review.

Run the complete repository gate from that exact commit:

```bash
npm ci --prefix adapters/cloudflare-workers
./scripts/check-all.sh
git diff --check
git status --short
git rev-parse HEAD
```

`git status --short` must be empty. The recorded audit handoff must bind the
exact commit SHA to the successful local gate and required GitHub checks.
