# Architecture decisions DR-0081–DR-0087

Local devnet, client/CLI, CLI-first sequencing, transfer policy, and uniform
fee decisions.

- DR-0081: Define the Developer MVP product-surface monorepo layout and ratify
  a uniform fungible asset model ahead of implementation.

  **Monorepo layout.** The repository gains six product paths under `apps/`
  and `clients/` as each is implemented: `clients/rust` and `clients/typescript`
  (protocol client libraries with no UI of their own), `apps/devnet` (the
  local devnet binary/startup composition; see "Local devnet architecture"
  above), `apps/cli` (a Rust-only developer CLI), and `apps/explorer`/
  `apps/wallet` (browser applications). `apps/cli` depends only on
  `clients/rust`: it is never a Node/JS/browser runtime and never talks to the
  protocol through anything but `clients/rust`'s own encode/decode/signing/RPC
  surface. `apps/explorer` and `apps/wallet` are separate SvelteKit
  applications using shadcn-svelte (Luma) as their component layer, each built
  and deployed as a static/CSR app only: no request-time server-side
  rendering, no SvelteKit server adapter, no `+page.server`/`+layout.server`/
  `+server` route files, and no server actions, remote functions, or
  server-held sessions or keys in either app.
  Build-time prerendering is allowed only for a fixed static shell; no dynamic
  chain data may be embedded by that build.
  `apps/wallet` generates, holds,
  and uses signing keys only in the browser; no wallet key or signature is
  ever generated on, or transits through, a server this project controls.
  Both apps fetch dynamic chain data (objects, balances, receipts, chain/
  context info) directly in the browser runtime through
  `clients/typescript`, never through a bundler-time or server-side data
  load. No shared UI package is introduced across `apps/explorer` and
  `apps/wallet` until real duplication between the two actually exists.

  **Developer MVP order.** Developer MVP completion order (see
  `TODO.md#cli-developer-mvp-gate`) is: local devnet, bounded query API, Rust
  client, Rust CLI, TypeScript client, explorer, wallet, restart/duplicate
  E2E, and explicit documented development-only limitations. This replaces
  DR-0080's earlier "TypeScript client + counter demo UI" pairing; no
  `demo/counter` directory is created.

  **Amendment: gate renamed and resequenced by DR-0085.** The monorepo
  layout, uniform fungible asset model, local devnet module, and deferred
  scope stated in this entry are unchanged. Only the ordering statement
  immediately above is resequenced: DR-0085 renames the gate this order
  belongs to `CLI Developer MVP Gate`, keeps this entry's `clients/typescript`/
  `apps/explorer`/`apps/wallet` steps verbatim as still-required future work,
  and defers starting them until a new `CLI-First Node Production Gate`
  passes. The `local devnet, bounded query API, Rust client, Rust CLI,
  restart/duplicate E2E` prefix of this order is implemented As-Is.

  **Uniform fungible asset model.** Every asset, including any future fee
  asset, uses exactly one `AssetId`/account/transfer implementation path.
  There is no privileged native coin, no second balance representation, and
  no separate transfer or fee-debit code path for a "special" asset. Which
  asset(s) may pay fees, and at what rate, is protocol policy layered over
  ordinary asset accounts, not a second implementation of balances or
  transfer (see "Stablecoin fee lifecycle" above). A future fee-debit effect
  must reuse the same declared object access, the same exact-head assertions,
  and the same atomic object-effect commit as every other asset transfer; it
  may not bypass them with bespoke fee-only state.

  **Local devnet module.** The local devnet's stateful preinstalled module is
  `sunrise.devnet.asset_account.v1`, exposing one `transfer` entrypoint over
  two ordinary owned asset-account objects that both belong to the same
  sender. Both accounts carry the same configured 32-byte `fees::AssetId`
  (never a placeholder or all-zero value), while their object identities are
  distinct. The transition enforces
  balance conservation (the debited and credited amounts are identical and
  the combined balance across the two accounts is unchanged), and fails
  closed on zero amount, amount underflow, amount overflow, and any asset-ID
  mismatch between the two accounts. Because destination-owner
  authorization for a transfer into an account owned by someone else, and any
  change of an object's owner, remain fail-closed on the existing owned-
  effects path (see "Node-core invocation boundary" above and DR-0077), this
  module demonstrates only same-sender balance movement between two of the
  sender's own asset accounts. It does not implement, and must not be
  described as, user-to-user transfer. The devnet's fee registry stays empty
  and every devnet transaction commits with `fee_payment: None`; this module
  charges, computes, or debits no fee. Its body, arguments, and event use the
  devnet-local canonical type IDs `0xF001`, `0xF002`, and `0xF003`; no raw
  hand-framed event or object bytes are accepted. The current host ABI does
  not expose object metadata to WASM, so this MVP verifies the complete
  canonical body structure while node-core separately verifies sender
  ownership and frozen metadata. A metadata-readable ABI or trusted catalog
  type constraint remains deferred until cross-owner transfer or another
  devnet application object type makes structural checking insufficient.

  **Deferred beyond this MVP surface.** Cross-owner transfer authorization and
  any change of object ownership; `Create` and any notion of "associated" or
  auto-derived accounts; mint, burn, supply tracking, and asset metadata/
  registry management; fee charging, gas accounting, and any fee-debit
  effect; freeze, close, delegate, and allowance/approval semantics; Shared/
  System object ownership; blob-backed object bodies and arbitrary module
  upload; and all other production-hardening work already frozen by DR-0076.

  **DR-0086 amendment (current status).** The same-sender-only and deferred
  cross-owner statements immediately above record DR-0081's original MVP
  boundary; they are not the current implementation status. S2 now permits
  the exact policy-bounded existing Address-owned destination described by
  DR-0086 while preserving both source and destination owners. Literal owner
  reassignment/gifting remains deferred and fail-closed. S2 is complete As-Is,
  S3 fee accounting/gas metering is next, and this is not production or
  mainnet readiness. Compatibility is explicit: this dev profile installs
  preinstalled asset module version 2 with the `0xF011` semantics declaration
  version 2; historical module/semantics version 1 bytes remain pinned but are
  not installed by this profile. The `0xF001` body, `0xF002` arguments, and
  `0xF003` event stay at schema version 1 and the WASM bytes are unchanged.
  This profile selection is not a claim that general upgrade activation is
  implemented.

  **DR-0087 amendment (current status).** The empty-registry/fee-free and
  deferred-fee statements above likewise preserve DR-0081's historical MVP
  boundary, not current behavior. S3 now uses the same ordinary asset-account
  path for payer and distinct treasury, settles actual gas after execution,
  and commits trap fee-only effects as described by DR-0087. The active
  module/semantics declaration is version 3; historical v1/v2 declarations,
  the `0xF001`/`0xF002`/`0xF003` schemas, and WAT/WASM/code hash remain pinned.
  DR-0088 subsequently implements S4a's hardware-signing profile/host
  preflight, DR-0091 records S4b's separate device application and Nano S+
  Speculos evidence As-Is, DR-0092 implements S4c Phase 1's host
  APDU/USB/HID and CLI signer selection As-Is, and DR-0093 implements S4c
  Phase 2a's active-app/firmware identity check As-Is, strictly in software
  (S4c itself remains incomplete, pending Phase 2b's real hardware
  validation); this is still not production or mainnet readiness.
- DR-0082: Add the bounded canonical Developer MVP query surface described in
  "Bounded Developer MVP query API". Keep query selectors non-authoritative,
  resolve all chain/domain/epoch/storage authority from trusted composition,
  independently verify durable object and receipt content before returning it,
  encode absence and blob-unavailable state explicitly, and exclude scans and
  arbitrary state access. This is a stable client wire contract, not a public
  RPC security or production indexing architecture.
- DR-0083: Define the Developer MVP Rust client boundary described in "Rust
  client library". Share canonical result codecs through `node-wire`, keep the
  client independent of `native-http`/Axum and application semantics, provide
  only a bounded loopback HTTP transport initially, require caller-supplied
  request/module/object identities, and defer production networking and full
  protocol-config/hash verification rather than approximating them.
- DR-0084: Define the Rust-only `apps/cli` Developer MVP boundary and the
  Ledger-ready external signing boundary described in "Rust client
  external-signer boundary and Developer MVP CLI". `apps/cli` has exactly one
  non-development/runtime dependency, `sunrise-edge-client` (test-only
  `[dev-dependencies]` exist to compose a real devnet and build fixtures for
  this crate's own tests, and are unreachable from any non-test build),
  parses arguments with a strict hand-written parser
  (no clap, no other argument crate), never accepts a seed directly on argv,
  and treats every development seed file as explicitly named, non-default,
  non-keystore input with symlink/permission/length checks. `clients/rust`'s
  new two-stage `PreparedTransaction` external-signer API is additive and
  keeps `build_signed_transaction`'s stable output bytes unchanged; it fails
  closed on any signature scheme other than the one implemented `Ed25519`/
  `AddressIsPublicKey` binding and independently verifies a returned
  signature's exact length and cryptographic validity before producing
  output. Real Ledger (or other external/hardware) signing is explicitly not
  implemented by this decision: it requires a dedicated Sunrise Edge Ledger
  device application, an APDU/host transport, on-device parsing and clear
  signing of the exact canonical signature frame, public-key/address
  verification, an explicit derivation-path policy, device/application/
  version checks, explicit user confirmation, host-side signature
  verification, and hardware-in-the-loop tests — none of which exist yet, and
  existing Solana/Ethereum Ledger apps must never be reused for Sunrise
  transaction signing. No USB/HID/Ledger dependency exists in any protocol or
  client crate. Devnet asset-transfer semantics (the module's entrypoint name
  and argument frame) live only in `apps/cli`'s `transfer` command; the small
  generic re-exports `clients/rust` adds to support it add no application
  semantics of their own.
- DR-0085: Adopt a CLI-first production strategy and add the CLI-First Node
  Production Gate. This is a sequencing decision, not a scope change: it
  reorders when work starts, and it does not complete, delete, weaken, or
  reinterpret any existing production criterion anywhere in `TODO.md`,
  `docs/operations/persistence.md`, or `docs/operations/postgres.md`.

  **Rationale.** The Developer MVP Gate (DR-0076, resequenced by DR-0081) put
  a browser-facing product surface (TypeScript client, explorer, wallet) in
  the same near-term gate as the node's own core capabilities (local devnet,
  owned-object execution, bounded query API, Rust client, Rust CLI,
  restart/duplicate E2E). That framing under-weighted the fact that the node
  itself — persistence, operations, and release evidence — is far short of
  the production posture `TODO.md`'s Phase 15 To-Be exit criteria already
  require, while a browser UI cannot usefully exercise a node that is not
  itself production-oriented. This decision narrows the near-term gate to the
  node/client/CLI capabilities that are implementable and independently
  verifiable today, renames it to make that narrowing explicit, and inserts
  an explicit node-production gate between it and the deferred browser
  surface.

  **Gate rename and resequencing.** The gate defined in `TODO.md` is renamed
  `CLI Developer MVP Gate`. Its criteria 1-6, 10, and 11 (local devnet,
  authenticated owned-object Read/Write/Consume, preinstalled deterministic
  WASM execution, bounded query API, Rust client library, Rust-only CLI,
  restart/duplicate E2E, and explicit non-production limitations) remain the
  near-term gate. Its criteria 7-9 (TypeScript client, explorer, wallet) are
  kept verbatim — not completed, not deleted, not weakened — and are
  explicitly deferred/resequenced to start only after the new CLI-First Node
  Production Gate below passes (see the "Amendment: gate renamed and
  resequenced by DR-0085" note on DR-0081's "Developer MVP order" above).

  **Current implementation status (2026-09-04).** The CLI Developer MVP Gate's
  criteria 1-6, 10, and 11 are implemented and validated As-Is, so that gate
  has passed without making a production-readiness claim. S0 below is also
  implemented As-Is. S1 below is now also implemented and tested As-Is (see
  "S1 implementation status" immediately below), and S2 is implemented and
  validated As-Is by DR-0086. S3 is implemented and validated As-Is by
  DR-0087. S4a is implemented and validated As-Is by DR-0088, and DR-0089
  subsequently makes eight S4b device-contract clarifications in `docs/signing/hardware-signing.md`
  and one correction to DR-0088's blanket 230-byte whole-APDU data cap (FIRST rises
  230→255 bytes, first chunk 205→230 bytes, CONTINUE/LAST unchanged at
  230). DR-0090 records the separate
  `sunriselayer/sunrise-edge-ledger-app` repository's earlier host-validated
  `no_std` core milestone. DR-0091 records its merged PR #2 device application,
  five-target builds, and fixed-seed Nano S+ Speculos evidence; S4b is complete
  As-Is. DR-0092 implements S4c Phase 1's host APDU/USB/HID crate and CLI
  signer selection As-Is (profile/address checks and USB-descriptor-level
  device recognition), and DR-0093 subsequently implements S4c Phase 2a's
  active-app/firmware identity check As-Is (strict Ledger OS identity/
  dashboard response parsing and bounds, a staged dashboard/firmware/
  open-app/reconnect/active-app sequence, and a required
  `--ledger-expected-firmware-version` CLI flag) — strictly in software,
  against `FakeTransport` only; S4c itself is still not complete, since it
  still needs Phase 2b's real hardware validation. S4
  remains incomplete. DR-0095 supersedes the old strict ordering: S4c Phase
  2b and S4d's physical-device HIL/release evidence are deferred, while S5 is
  an independent parallel software-production track. The TypeScript client,
  explorer, and wallet remain deferred until the Software Production Gate
  (S0-S3 + S5) passes; they do not wait for deferred S4 hardware work.

  **S1 implementation status (2026-09-01): both remote TLS transport and
  expected-protocol-context verification are implemented and tested As-Is;
  S1 as a whole is complete.** S1 below names two separate concerns, and both
  are now implemented by this update. `clients/rust` adds a public
  `context::ExpectedProtocolContext`: a caller supplies the exact locally
  trusted `chain_id`, `protocol_version`, an exact-epoch policy (this initial
  slice trusts one caller-supplied epoch exactly, not a floor or range —
  every subsequent epoch rollover requires the caller to update it
  deliberately, since this type never derives, advances, or widens it
  automatically), `hash_suite_id`, `transaction_auth_profile_id`,
  `signature_scheme_id`, `address_binding_id`, and logical
  `AtomicityDomainId`. `ExpectedProtocolContext::new` rejects a zero
  `protocol_version`, `hash_suite_id`, `transaction_auth_profile_id`,
  `signature_scheme_id`, or `address_binding_id` (an empty `chain_id` or an
  all-zero `domain` is already rejected by `ChainId`/`AtomicityDomainId`
  themselves before construction); zero `epoch` is deliberately accepted,
  since epoch zero is the legitimate genesis epoch. It deliberately never
  pins or decodes `protocol_config_bytes`: approximating full
  `ProtocolConfig` verification is out of scope for this slice, not silently
  weakened. `ExpectedProtocolContext::verify` compares every one of those
  eight fields against an untrusted `/v1/context`
  `node_wire::HttpContextQueryResult` and returns a typed, field-specific
  `ProtocolContextMismatch` on the first disagreement, in a fixed
  deterministic field order; `Client::query_verified_context` is the new
  client API that queries `/v1/context` and requires an exact match before
  returning the result at all, so an untrusted mismatched response is never
  handed to a caller under the pretense of being verified. The logical
  `AtomicityDomainId` comparison here is a routing/placement expectation —
  which logical atomicity domain the caller intends to reach — and is
  deliberately never folded into `crypto::SignatureDomain`; it adds no new
  signature-domain binding beyond the existing chain id/protocol
  version/epoch/message type/signature scheme already described in Section 8.
  No library path panics: every failure is a typed
  `ExpectedProtocolContextError` (construction) or `ProtocolContextMismatch`
  (comparison), wrapped by a new `ClientError::ProtocolContextMismatch`
  variant.

  `apps/cli`'s `transfer` command now requires five `--expected-*` flags —
  `--expected-chain-id`, `--expected-protocol-version`, `--expected-epoch`,
  `--expected-hash-suite-id`, `--expected-domain` — and builds an
  `ExpectedProtocolContext` from them before any network dispatch, rejecting
  a missing, zero, or malformed value at that point (`ArgsError::MissingFlag`
  for an absent flag; `ExpectedProtocolContextError`/`TypeError` for a zero or
  otherwise invalid value; `HexError` for a malformed `--expected-domain`).
  The transaction-authentication profile id, signature-scheme id, and
  address-binding id expectations are not separate flags — this workspace
  implements exactly one combination (the committed
  `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`, `Ed25519`, and
  `AddressIsPublicKey`) — but `transfer` still supplies them explicitly to
  `ExpectedProtocolContext::new` so the client verifier independently
  compares them against the remote result rather than trusting them
  implicitly. `transfer` then calls only
  `Client::query_verified_context` — never the unverified `query_context` —
  and uses only that verified `HttpContextQueryResult`, never any value
  independently derived from the raw remote response, for every subsequent
  step: the next-nonce query, both object queries, transaction construction
  (chain id/protocol version/epoch), signing, and submission. Adversarial
  tests cover every one of `ProtocolContextMismatch`'s eight variants
  (chain id, protocol version, epoch, hash-suite id, transaction-auth
  profile id, signature-scheme id, address-binding id, domain) and each
  proves `transfer` issues exactly one request — the context query — before
  returning the typed error, never reaching the nonce/object queries or
  signing/submission that would follow a verified context. Existing stable
  wire bytes, every previously implemented command, and this command's prior
  parser/seed-file/two-stage-signer/owner-check behavior are all preserved
  unchanged; only the pre-signing context check moved from three ad hoc
  per-field comparisons inside `transfer` into the new typed, reusable
  `clients/rust` verification boundary, and gained the five additional
  chain-id/protocol-version/epoch/hash-suite/domain comparisons S1a requires.

  **S1's remote TLS transport slice.** `clients/rust` adds
  `transport::RemoteTlsHttpTransport`, a second production `Transport`
  implementation alongside the unchanged, still loopback-only plaintext
  `LoopbackHttpTransport`. Both share one private bounded-stream abstraction
  (`BoundedTransportIo`), so the exact same HTTP/1.1 request/response byte
  framing, header/body bounds, and per-stage monotonic-deadline handling
  apply to plaintext and TLS traffic alike; `RemoteTlsHttpTransport` differs
  only in driving a real `rustls` `ClientConnection` — including its own
  deadline-checked `read_tls`/`write_tls`/`process_new_packets` handshake
  pump, never `rustls`'s unbounded `complete_io` — ahead of that shared
  framing. `RemoteTlsHttpTransport::new` requires one caller-supplied
  `SocketAddr` (this transport performs no DNS resolution of its own — the
  caller must already have resolved one), one caller-supplied DNS server
  name (used for both the TLS SNI extension and post-handshake hostname
  validation, and rejected if empty or an IP-address literal — this
  transport never falls back to validating the connection's IP as a
  hostname), and one caller-supplied CA trust-anchor DER, capped at the new
  public `transport::MAX_CA_CERTIFICATE_DER_BYTES` (16 KiB) and rejected if
  empty, oversized, or not a valid X.509 certificate; that DER is the
  transport's sole trust anchor; no system root store is ever consulted, no
  PEM/bundle format is accepted, and no client certificate (mTLS) is ever
  presented. Every timeout (connect, TLS-handshake read/write, and
  post-handshake read/write) must be nonzero and forms one hard total
  request budget by checked addition, exactly like
  `LoopbackHttpTransport`'s; a `WireRequest::deadline` may only tighten that
  budget, never extend it. Real loopback-TCP tests
  (`clients/rust/tests/remote_tls_transport.rs`) issue an ephemeral
  `rcgen`-issued CA/leaf pair and drive a real `rustls` `ServerConnection`
  server against the real client code (never a fake `Transport`), proving:
  a correct hostname/CA succeeds and sends the exact validated-DNS-name
  `Host` header (never the connected `SocketAddr`'s IP); a wrong hostname
  and a wrong CA each fail with a TLS protocol error during the handshake; a
  stalled handshake and a peer that closes before the handshake completes
  each fail promptly rather than busy-spinning or blocking past the
  deadline; a short caller deadline tightens a much larger configured
  budget; and every malformed-constructor input (bad DNS name, an IP
  literal, empty/oversized/invalid CA DER, a zero timeout) is rejected
  before any network I/O. A dedicated regression test in the same file also
  proves the shared bounded-stream refactor left `LoopbackHttpTransport`'s
  plaintext framing byte-for-byte unchanged.

  `apps/cli`'s `context`, `object`, `receipt`, `next-nonce`, and `transfer`
  commands each gain one paired, optional
  `--tls-server-name`/`--tls-ca-cert-der-file` flag set, parsed centrally in
  `apps/cli/src/net.rs` into exactly one new `CliTransport` enum
  (`Loopback`/`RemoteTls`) implementing `Transport`, so every command's
  generic `execute<T: Transport>` body is unchanged regardless of which mode
  a given invocation selected. With neither flag, a command behaves exactly
  as before (loopback-only plaintext, `CliError::NonLoopbackEndpoint` on a
  non-loopback `--endpoint`). With both flags, `--endpoint` is parsed as an
  already-resolved `SocketAddr` (no loopback restriction, and still no DNS
  resolution) and the command dials `RemoteTlsHttpTransport`. Supplying
  exactly one of the two flags returns a new typed
  `CliError::PartialTlsConfiguration` before any network dispatch. The CA
  file is read with `std` only, through a bounded `Read::take` adaptor
  capped at one byte more than the same public
  `MAX_CA_CERTIFICATE_DER_BYTES` the transport itself enforces, so a
  mistaken or hostile oversized file can never make this binary buffer an
  unbounded amount of data before rejecting it; an empty file, an oversized
  file, and any I/O failure each return their own typed, actionable
  `CliError` variant naming the file path but never its contents.
  `apps/cli/tests/tls_cli_e2e.rs` adds two deterministic local TLS
  integration tests (again a real `rcgen`/`rustls` loopback TLS server, no
  fake transport, no external network): one proves a real `context`
  invocation succeeds over TLS with the exact expected `Host` authority; the
  other proves that when a `transfer` invocation successfully authenticates
  TLS against a server whose `/v1/context` result disagrees with
  `--expected-chain-id`, it dispatches exactly one `/v1/context` request —
  confirmed by the test server's own connection counter, which would observe
  a second connection attempt if one occurred — and returns the typed
  `ProtocolContextMismatch` before ever reaching the nonce/object/sign/submit
  steps that a verified context would unlock. This is the same ordering and
  same typed-mismatch guarantee S1a's existing fake-`Transport` unit tests
  already proved, now demonstrated over a real authenticated TLS connection
  instead of a fake transport, which is exactly why TLS endpoint
  authentication and the expected-context check must remain two independent
  boundaries: successfully authenticating the TLS endpoint above proves only
  that the CLI reached a server holding a trusted key for
  `--tls-server-name`, never that the server speaks the caller's intended
  chain/protocol, so the pre-existing S1a check is what actually stops the
  transfer here.

  **Explicit limits (not silently assumed).** This slice performs no DNS
  resolution anywhere; the caller must always supply an already-resolved
  `SocketAddr`. It trusts exactly one caller-supplied CA DER file as the sole
  anchor — never a system/OS trust store, never a PEM/bundle format, never
  more than one combined anchor. It never performs mTLS (no client
  certificate is ever presented). It has no certificate revocation checking
  (no CRL/OCSP), no certificate rotation or lifecycle handling, and no
  deployment/operations evidence for how a CA certificate reaches an
  operator's filesystem or how it is rotated over a validator's lifetime —
  all of that remains explicitly deferred to later CLI-First Node Production
  Gate slices (S5) or the Post-MVP Production Hardening persistence/
  operations work, not silently approximated here. TLS endpoint
  authentication and the separate `ExpectedProtocolContext` check are
  intentionally never merged into one another: a successful TLS handshake
  never substitutes for the expected-context check, and a verified context
  never widens what the TLS layer itself trusts. This is real S1 evidence,
  not a mainnet-readiness or production-certification claim: Phase 16/17's
  production exit criteria and an independent security audit remain
    required afterward, unchanged, and S2 (cross-owner transfer) was the next
  ordered slice at that decision point.

  **DR-0086 amendment (current status).** The preceding "S2 is next" sentence
  records DR-0085's S1 completion point. S2 is now implemented and validated
  As-Is through the exact committed destination policy, with literal owner
  reassignment still deferred; S3 is now implemented by DR-0087. S4/S5, Phase
  16/17 exit criteria, and an independent security audit remain outstanding,
  so no production/mainnet readiness is claimed.

  **CLI-First Node Production Gate.** This new gate sits between the CLI
  Developer MVP Gate and the deferred browser surface. It is a real
  node/persistence/operations gate, not client-library work, and it is
  defined entirely by reference to existing, unchanged criteria:
  `TODO.md`'s Phase 15 To-Be production exit criteria (1-10); the Post-MVP
  Production Hardening Phase 15 persistence implementation order (steps
  1-6, covering the durable domain adapter boundary, the indexed due-outbox
  repository, the normalized PostgreSQL structured-durable schema and its
  shared conformance suite, real host/power-fault and capacity/backup
  rehearsal evidence, and real Cloudflare Durable Object/AWS provider
  certification); the cross-phase production release gate; the existing hard
  activation constraint that protocol version 3's live activation stays
  prohibited until shared-object ordering, FastVote/`FastCertificate`,
  certificate publication, and every externally accepted event family's
  authorization are implemented and atomically composed where protocol
  semantics require it, and, independently, until S4/S5 and the independent
  security/release gates are completed — the bounded S3 uniform ordinary-asset
  fee composition (DR-0087) and additive owned-effects/preinstalled-WASM
  module-object effects entrypoints are implemented As-Is, but on their own do
  not satisfy this constraint; and the existing hard activation constraint that
  every externally accepted node-event family other than `SubmitTransaction`
  (especially certificate, protocol-upgrade, and validator-set-change events)
  needs its own authenticated/authorized ingress boundary before live
  activation. Passing this gate is explicitly **not** mainnet readiness:
  Phase 16 (Cloudflare) and Phase 17 (Deno/Vercel/Supabase/AWS) To-Be
  production exit criteria and an independent security audit remain required
  afterward, unchanged.

  **Ordered slices, amended by DR-0095.** This decision originally sequenced
  the CLI-First Node Production Gate as S0-S5 (see
  `TODO.md#cli-first-node-production-gate`). DR-0095 preserves S0-S3 as the
  common baseline but supersedes the strict S4-before-S5 ordering: S4 and S5
  are independent parallel tracks.

  - S0: an automated restart/duplicate E2E, plus a separate documented
    command sequence that reproduces the local devnet/CLI experience (start,
    transfer, receipt, orderly restart, persisted state) by hand — not the
    raw byte-identical duplicate replay itself, which only the automated E2E
    proves (implemented As-Is by this decision; see criterion 10,
    `apps/cli/tests/devnet_restart_duplicate_e2e.rs`, and `docs/guides/devnet.md`).
  - S1 (implemented As-Is; see "S1 implementation status" above): remote TLS
    transport and mandatory trusted protocol-context validation before
    signing, as two separate concerns. The transport performs normal TLS
    server-identity and hostname validation under an explicit trust policy
    (this slice's `RemoteTlsHttpTransport` uses one explicitly configured
    CA/anchor and DNS name, never a system CA store); this does not require
    brittle leaf-certificate pinning as the only valid TLS trust design.
    Separately, because a successful TLS handshake authenticates the
    transport endpoint, not the protocol context, a valid TLS connection
    alone does not prove the remote server speaks the client's intended
    chain/protocol and does not by itself prevent cross-chain signing. The
    client/CLI therefore also requires a locally configured expected chain
    identity and protocol policy, and compares the remote `/v1/context`
    result's chain id, protocol version, epoch policy, signature scheme,
    address binding, and transaction auth profile against that expectation
    before any signing occurs.
  - S2 (implemented As-Is by DR-0086): cross-owner transfer through an exact
    committed destination-owner policy on the trusted preinstalled-module
    path. The roadmap phrase "object owner changes" means correct handling of
    differing source/destination owner projections; it does not authorize
    literal owner reassignment, which remains fail-closed.
  - S3 (implemented As-Is by DR-0087): uniform ordinary-asset fees and actual-
    gas metering on the local preinstalled-WASM devnet path, including
    deterministic trap fee-only settlement and restart/replay evidence.
  - S4: a secure signer replacing today's development-only `LocalSigner`, and
    a real dedicated Sunrise Edge Ledger integration (see "Rust client
    external-signer boundary and Developer MVP CLI" and DR-0084; existing
    Solana/Ethereum Ledger apps are never reused).
  - S5: production persistence, outbox operation, provider deployment
    (Cloudflare Durable Object/AWS), operations (observability, runbooks),
    security (independent audit), and release evidence (migration/backup/
    disaster-recovery rehearsal, reproducible build) — i.e., the Post-MVP
    Production Hardening persistence implementation order above.

  Capacity/load/soak, PITR, and HA/failover evidence stay frozen exactly as
  the existing freeze already states, until S5's own certification or an SLO
  actually requires one of them; this decision does not add or relax that
  freeze.

  **Production target.** The conservative production target this gate and
  the existing validator-set/consensus criteria are sequenced toward is a
  multi-validator L1, not a permanently single-operator service. Nothing in
  this decision narrows validator-set, bond, or consensus criteria to a
  single-validator design; the devnet's current single-validator posture
  remains an explicit MVP-only limitation (see "Local devnet architecture"
  above), not the production target.
- DR-0086: Implement S2 as a bounded committed cross-owner destination policy,
  without introducing literal object-owner reassignment.

  **Roadmap interpretation.** DR-0085's S2 phrase "destination-owner
  authorization and object owner changes" means correctly loading,
  authorizing, preserving, and committing different source/destination owner
  projections. It does not mean gifting or reassignment of an object's owner.
  Existing effect translation still requires an updated object's owner to
  equal its authenticated pre-state owner, so literal reassignment remains
  fail-closed and deferred.

  **Generic committed envelope.** A trusted `PreinstalledModuleCatalogEntry`
  now carries a bounded `PreinstalledModuleSemanticsEnvelope`: opaque
  application-semantics bytes (at most 64 KiB) plus at most 16 sorted,
  unique-index `PreinstalledObjectAccessPolicy` records. The policy and
  envelope use stable canonical type IDs `0xE007` and `0xE008`, encoding
  version 1, with stable encoding vectors. `SystemModule.semantics_hash`
  commits the exact full envelope bytes, not only the opaque application
  declaration. Both startup registry/catalog reconciliation and request-time
  module resolution independently encode and verify the actual trusted
  envelope bytes. No request field, storage projection, or caller-supplied
  digest can create or widen a policy.

  **Authorization and ordering.** The sender still owns signed access index 0,
  and the general owned-effects entrypoint remains sender-only. On the trusted
  preinstalled-WASM path only, a policy may authorize a non-sender existing
  `Owner::Address` object at one exact nonzero signed access index, exact
  entrypoint, `AccessMode::Write`, exact type hash, and exact schema version.
  Policy resolution occurs exactly once per non-replay execution, after receipt
  and nonce reconciliation but before object I/O; the resolved module is reused
  for authorization and execution. Therefore an exact replay still reconciles
  before policy/module/object work and never reapplies effects. Source-index
  policy, `Read`/`Consume`, wrong index/mode/type/schema/entrypoint/module,
  missing policy, and Shared/System/Immutable ownership all fail closed.

  **Devnet policy and startup.** The devnet catalog declares exactly one policy:
  signed destination index 1, `transfer`, `Write`, the exact asset-account type
  hash, and schema version 1. The opaque devnet semantics states that source
  index 0 is sender-owned, the existing destination may have another Address
  owner, and both owners remain unchanged. Startup seed reconciliation no
  longer assumes per-owner source/destination balance totals or paired
  sequences, because legitimate cross-owner movement invalidates both
  assumptions. It still verifies exact current owner/id/type/schema/canonical
  body/digest/provenance, immutable version-one history, and the seed receipt
  for every account, then performs one checked global fixed-supply invariant
  over the bounded configured-owner set before serving.

  **CLI and evidence.** `apps/cli transfer` requires an explicit
  `--destination-owner <32-byte-hex-address>`. Before signing it requires the
  queried source owner to equal the local signer and the queried destination
  owner to equal that explicit expected address. The real file-backed SQLite
  E2E seeds separate sender and recipient owners, transfers into the recipient
  destination, proves both balances change and the recipient owner remains
  unchanged, closes every store/router reference, reopens under writer
  generation N+1, and proves exact same-boot and post-restart request replay
  returns byte-identical submit/receipt results without reapplication. Reusing
  a committed request ID with different signed bytes returns HTTP 409 while
  both canonical object query results, both relevant receipts, and the sender
  nonce remain unchanged; the old writer generation remains fenced.

  This implementation preserves established canonical transaction,
  `ObjectEffect`, `Object`, receipt, nonce, and submit-result bytes. S2 is
  implemented and validated As-Is only. DR-0087 subsequently replaces the
  fee-free devnet posture while preserving S2's exact policy and historical
  vectors. The TypeScript client, explorer, wallet,
  S4 secure signer/Ledger work, and S5 persistence/provider/operations/release
  evidence remain deferred, and Phase 16/17 exit criteria plus an independent
  security audit remain mandatory.
- DR-0087: Implement S3 as uniform ordinary-asset fee composition on the
  trusted preinstalled-WASM devnet path, without changing historical wire,
  WAT/WASM, or storage bytes.

  **Admission and settlement.** The committed protocol configuration uses
  non-zero base/execution prices and enables exactly `DEVNET_ASSET_ID` at a
  1:1 quote. A due fee requires signed `FeePayment`; its `max_fee` must cover
  the worst case at `gas_limit` before engine work begins. The final charge is
  computed only after execution from canonical `ExecutionEffects.gas_used`.
  Successful application effects are merged with the fee debit/credit and
  committed atomically with state, nonce, receipt, and outbox. A deterministic
  trap is normalized first, discards every application effect/event, charges
  its normalized full gas through a restricted fee-only mutation, and commits
  a Rejected receipt. An insufficient payer balance after successful execution
  rejects the whole transaction, so execution work may be spent without a
  commit; this bounded devnet limitation is not production admission policy.

  **Schedule-shape invariant.** S3 only ever measures `execution_units`:
  every `fees::FeeUsage` the preinstalled-WASM machine builds leaves
  `state_read_units`, `state_write_units`, `storage_units`, and
  `system_module_units` at their default zero. Before fee admission or the
  engine ever runs, it independently validates the committed `GasSchedule`'s
  shape (`fee_effects::validate_gas_schedule_shape`): a non-zero
  `read_price`/`write_price`/`storage_price`/`system_module_price` is
  rejected as `NodeCoreError::UnsupportedGasScheduleShape` rather than
  silently multiplied by zero usage and dropped from the total by
  `fees::calculate_fee`, and a non-zero `execution_price` paired with a zero
  `base_fee` is rejected the same way, because a legitimate zero-`gas_used`
  success could otherwise settle a zero fee even though worst-case admission
  at `gas_limit` already required a treasury `Write`. The genesis all-zero
  schedule and the current devnet `base_fee`/`execution_price`-only schedule
  both pass unchanged. This is a trusted committed-configuration fault, never
  a caller-supplied one; native HTTP maps it to an opaque `500
  fee-schedule-unsupported`, distinct from every caller-facing 4xx fee code.

  **Ordinary accounts and trusted boundary.** The payer is one sender-owned
  declared `Write` object and the trusted fee sink is the distinct configured
  treasury owner's ordinary seeded destination account. The signed manifest
  names that treasury exactly once as its final `Write`, but node-core removes
  it before invoking WASM. The module therefore still observes exactly the two
  source/destination objects and cannot redirect, inspect, or authorize the
  fee sink. The pure `AssetAccountFeeComposer` receives only opaque effective
  payer/treasury bodies and a settled amount, uses the existing strict
  `0xF001` codec, checks matching asset IDs and checked balance/sequence
  arithmetic, and returns two bodies. Node-core independently freezes identity,
  owner, type/schema, provenance, and object version; a no-op or malformed
  trusted composition fails closed. One successful transaction advances each
  touched durable object version once, while the payer body sequence advances
  once for the application transfer and once for the fee mutation.

  **Catalog compatibility.** The active module and semantics declaration move
  to version 3 solely to commit the new host-side fee/treasury/event facts.
  Historical v1 same-sender and v2 cross-owner declarations remain exact
  pinned vectors and are not installed. The asset body/args/event encoding
  remains v1, the WAT/WASM bytes are unchanged, and a fixed-context canonical
  code-hash test pins the same artifact. The transfer event is deliberately
  pre-fee module output: `source_balance` is the balance after transfer but
  before settlement; the durable source object is lower by `base_fee +
  gas_used * execution_price` under this profile.

  **CLI, startup, and evidence.** Devnet configuration requires a treasury
  owner distinct from all transfer owners and reserves one of the 64 seed
  slots for it. Startup seeds/verifies all owners, selects the treasury
  destination, and wires it with the composer into the native router. CLI
  `transfer` accepts the all-or-none `--fee-asset-id`/`--max-fee`/
  `--fee-treasury-object` trio, fixes source as fee object, queries treasury
  last, and appends its final `Write`; partial input, zero max fee, or treasury
  collision fails locally. Native HTTP assigns explicit 4xx classifications
  to caller fee faults and 5xx classifications to trusted policy/composition
  invariant failures. The real file-backed SQLite E2E proves a successful
  actual-gas charge, event pre-fee semantics, and a trapped fee-only charge,
  then replays both the successful and the trapped request once in the same
  boot and once after an orderly close/reopen: every replay returns
  byte-identical canonical submit-result bytes and mutates neither the
  canonical source/destination/treasury query bytes, the second-transfer or
  trapped receipt, nor the sender's next nonce. It also proves
  writer-generation advancement/fencing and request-ID reuse conflict with
  the same canonical source/destination/treasury query bytes, all three
  receipts, and nonce unchanged.

  **Limits and next step.** This is single-validator, one fixed fee asset, one
  serializing treasury, and local SQLite only. It does not implement fee
  distribution through `FastCertificate`, multiple governed fee assets,
  production gas calibration, sufficient-balance preflight, treasury sharding,
  Shared/System/blob objects, or crash/power-loss durability. TypeScript,
  explorer, and wallet stay deferred. DR-0088 implements S4a's hardware
  profile/host preflight, DR-0091 records S4b's dedicated device application
  and Nano S+ Speculos evidence As-Is, DR-0092 implements S4c Phase 1's
  host/CLI integration As-Is, and DR-0093 implements S4c Phase 2a's
  active-app/firmware identity check As-Is, strictly in software (S4c itself
  remains incomplete). S4c Phase 2b's physical-device evidence and S4d are
  next. S5, Phase 16/17 exit criteria, and independent audit remain
  mandatory.
