# Architecture decisions DR-0101–DR-0103

Close the first code-security-audit integrity and authentication findings
without reinterpreting historical protocol bytes.

- **DR-0101: verifiable inline object query v2.** Object-query result type
  `0xE103` encoding v2 adds the immutable version's creating `chain_id` and
  `protocol_version` to `CurrentInline`. The Rust client recomputes the
  self-describing object digest over the returned canonical body before
  exposing the result. Historical encoding v1 remains decodable for archival
  compatibility, but the generic client rejects its inline form because it
  lacks the digest context. The original v1 vector remains pinned and a new v2
  vector is additive. Blob-reference results remain explicitly body-unverified.

- **DR-0102: value-owner admissibility is profile-versioned.** Historical
  transaction-authentication profile 1 retains ZIP-215 verification and its
  original `AddressIsPublicKey` semantics. Profile 2 commits binding tag 2 and
  additionally requires every sender and every loaded address owner that may
  receive or spend value—including a policy-authorized destination and the
  trusted fee treasury—to be a canonical, non-identity point in the prime-order
  Ed25519 subgroup. Devnet configuration and seeding apply the same predicate
  before funding. This restriction is separate from, and does not alter,
  historical consensus signature verification.

- **DR-0103: profile-2 signatures bind durable request identity.** Canonical
  submission-signature envelope type `0xE009`, encoding version 1, contains the
  exact non-zero `request_id` and the exact existing Transaction v1 signable
  bytes. Profile 2 authenticates this envelope under the distinct
  `submit-transaction-v1` signature message family. The outer event's request
  id is supplied to authentication before module resolution, identity, clock,
  or storage work, so relabeling invalidates the signature. Transaction type
  `0x6001`, its canonical encoding, profile 1, and the historical
  `transaction-v1` signature vector are unchanged; there is no downgrade.

  The Rust client exposes explicit profile-2 submission preparation requiring
  the request id, and the CLI uses it after verifying committed profile 2.
  Existing hardware clear-signing understands only the historical transaction
  frame and therefore fails closed for the new message family; Ledger support
  for profile 2 remains deferred rather than falling back to blind signing.

These decisions are source-level remediation and deterministic local evidence.
They do not by themselves complete the independent re-audit, deployment audit,
production-readiness, or mainnet-readiness gates.
