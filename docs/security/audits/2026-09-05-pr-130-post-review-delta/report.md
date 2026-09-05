# Security Review: sunrise-edge

## Scope

Exact commit b74c1ae1d12a2ce7d5c691b613457933c998defe against 4db26d470901cb7895e7c32444be072029932013.

- Scan mode: branch_diff
- Target kind: git_diff
- Target ID: target_sha256_6908c4c9e567ddaca40a429ff38210147729e713dc6eb6509c2e6d821bdb49a4
- Revision range: 4db26d470901cb7895e7c32444be072029932013...b74c1ae1d12a2ce7d5c691b613457933c998defe
- Snapshot digest: codex-security-snapshot/v1:sha256:68b869b170554225e71a4cbea60ba420e80ac8f18ce71c69b3bf4878294f89bd
- Inventory strategy: diff
- Included paths: .
- Excluded paths: none
- Runtime or test status: not recorded

Limitations and exclusions:
- No OS-level injected TcpListener::accept failure integration test.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 0 |
| Severity mix | none |
| Confidence mix | none |
| Coverage | complete |
| Validation mode | static source review plus targeted unit tests and complete repository gate |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Exact-commit focused delta: native HTTP retries listener accept errors with bounded nonzero backoff while preserving shutdown selection, and node-wire rejects encoding v2 for object-query statuses whose canonical representation remains v1.

### Assets

- Native server availability, executor fairness, prompt shutdown, and canonical object-query representation.

### Trust Boundaries

- Unauthenticated peer to kernel listener and native-http accept loop (crates/native-http/src/lib.rs:1083-1198).
- Untrusted response producer or transport to node-wire and Rust client (crates/node-wire/src/lib.rs:985-1114; clients/rust/src/client.rs:104-144).

### Attacker Capabilities

- A reachable unauthenticated peer may connect, abort, stall within deadlines, and consume admission capacity.
- A malicious node or mutated transport response may supply noncanonical object-query frames.

### Security Objectives

- Accept retry must be nonzero, bounded, recovery-reset, and shutdown responsive.
- Encoding v2 must fail closed for unchanged object-query statuses while historical v1 remains distinct.

### Assumptions

- A permanent listener fault yields bounded polling and is not classified in this delta.
- No OS-level injected TcpListener::accept failure integration test exists; source and helper tests cover the change.

## Findings

### No findings

No reportable findings survived the canonical discovery, validation, and reportability gates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| native HTTP listener accept-error retry and shutdown | not recorded | No issue found | Nonzero capped saturating backoff prevents tight looping; success resets the streak; shutdown races backoff. |
| node-wire object-query status/version canonicality | not recorded | No issue found | Encoder emits v1 for unchanged statuses and decoder rejects v2 before variant interpretation. |
