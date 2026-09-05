# Developer product surfaces

This document defines the local devnet, query API, Rust client, CLI, and
hardware-signing host boundaries.

## 42. Local devnet architecture

DR-0081 fixed the local devnet's architecture ahead of its implementation so
the client/app work that depends on it can target a stable contract. The
devnet composes the existing `preinstalled_wasm_structured_durable_router`
around a dedicated startup binary in `apps/devnet` rather than introducing new
protocol behavior:

- **Strict loopback startup.** The devnet binds only a loopback address
  (`127.0.0.1`/`::1`); it never binds a non-loopback interface, and
  bundles no TLS termination, authentication, or public-exposure hardening.
  This is a local developer fixture, not a hosted network.
- **Persisted fence/boot generation.** After `SqliteDurableStore::open`
  completes its existing schema/namespace bootstrap and verification, startup
  reads the persisted writer fence through a new additive operator-only
  accessor, advances that exact value with checked arithmetic, and uses the
  result as that process's boot generation and `created_checkpoint`. It never
  invents an in-memory substitute for missing or invalid durable metadata.
  The implemented accessor and startup flow make boot generations
  non-decreasing across restarts
  and fences stale request contexts from a prior process.
- **SQLite structured store.** State, object, receipt, and outbox data use the
  additive, local-only, non-production `SqliteDurableStore` (DR-0079), never
  the opaque legacy `SqliteStateStore`; the two require separate files because
  `PRAGMA application_id` is a whole-file SQLite property.
- **Registry/catalog reconciliation at startup.** Before serving any request,
  startup constructs its dev-profile `SystemModuleRegistry` and bounded
  immutable `PreinstalledModuleCatalog` from the same committed in-process
  artifact, then validates their code/manifest/semantics commitments before
  router construction. This proves internal composition consistency and fails
  boot with an operator-legible error if either representation is altered; it
  is not an independent comparison with persisted governance configuration.
  The general preinstalled-WASM route's request-time mismatch behavior remains
  unchanged.
- **Seeded asset accounts.** Startup seeds exactly two ordinary
  `sunrise.devnet.asset_account.v1` objects (`Owner::Address`) per configured
  development owner and per required distinct fee-treasury owner. At most 63
  transfer owners may be configured, reserving the 64th bounded seed slot for
  that treasury owner. All accounts carry the same fixed, non-placeholder
  `fees::AssetId`; one starts funded and the other starts empty. A transfer may
  pair one configured owner's source with another configured owner's existing
  destination under the exact committed S2 policy. Their object IDs remain
  distinct and deterministic for that owner and slot. Restart verifies every
  current object's exact identity/owner/type/schema/canonical body/digest/
  provenance, its immutable version-one seed history and receipt, then checks
  the fixed total seeded supply across the bounded configured-owner set;
  per-owner pair totals and sequences are intentionally not assumed equal
  after legitimate cross-owner movement.
- **Bounded asset-account transition.** The dev profile reserves the otherwise
  unused local type-ID block `0xF001`-`0xF003`, all at encoding version 1. An
  asset-account body is one 76-byte `CanonicalStruct` (`0xF001`) with fields
  `1: asset_id[32]`, `2: balance u64`, and `3: sequence u64`. `transfer`
  arguments are one 24-byte `CanonicalStruct` (`0xF002`) with field
  `1: non-zero amount u64`. Transfer event data is one 90-byte
  `CanonicalStruct` (`0xF003`) with fields `1: asset_id[32]`, `2: amount u64`,
  `3: resulting source balance u64`, and `4: resulting destination balance
  u64`. These exact frames, including magic, type/version, field count,
  ordered field IDs, lengths, and little-endian fixed-width values, are shared
  as stable vectors; the WAT verifies constant framing bytes and patches only
  the declared values. The signed manifest declares exactly two `Write`
  distinct objects in source/destination order; canonical transaction decode
  and node-core both reject duplicate object IDs before WASM execution.
  Execution rejects unknown framing,
  unequal asset IDs, zero amount, insufficient source balance, destination
  overflow, and sequence overflow; otherwise it writes both objects,
  increments both sequences, preserves the combined balance, and emits
  `sunrise.devnet.asset_account.transferred.v1`. The event and both effects
  enter the same durable receipt and an exact duplicate replays that receipt
  without applying either effect again.
- **Uniform post-execution fee composition.** Protocol version 3 commits a
  base fee of 1, an execution price of 1 per actual `gas_used`, zero prices for
  unmetered categories, and exactly one enabled `DEVNET_ASSET_ID` quoted 1:1.
  A fee-bearing transaction declares its sender-owned source as `fee_object`
  and appends the trusted treasury owner's ordinary destination account as the
  final `Write`. Node-core hides that final access from WASM, settles only
  after execution, and asks the pure devnet `AssetAccountFeeComposer` to debit
  payer and credit treasury using the same strict `0xF001` codec. A successful
  source update merges application and fee bodies into one durable object
  version advance (the asset-account body sequence advances once per logical
  application/fee mutation). A normalized trap discards application effects,
  consumes full declared gas, and commits only payer/treasury fee effects with
  a rejected receipt. Exact replay reconciles before object I/O or composition.
  The transfer event remains module output: its `source_balance` is post-
  transfer but pre-fee; clients obtain the post-fee balance from the committed
  object and compute the charge from receipt `gas_used` plus the committed
  schedule.
- **Canonical catalog declarations.** The dev profile also reserves local
  declaration type IDs `0xF010` for the asset-account schema declaration and
  `0xF011` for its execution-semantics declaration. The schema declaration
  remains encoding version 1. The historical same-sender semantics declaration
  remains pinned at encoding version 1, the S2 cross-owner declaration remains
  pinned at version 2, and the active S3 declaration uses version 3 while
  preserving the exact WAT/WASM and canonical code hash. These declarations are complete `CanonicalStruct`
  frames and are hashed
  under the existing `SystemModule` purpose when deriving the preinstalled
  catalog commitments. They describe the `0xF001` body, `0xF002` arguments,
  `0xF003` event, exact two-object write manifest, rejection conditions, and
  conservation/sequence invariants. They are dev-profile catalog metadata,
  not an alternate balance, transfer, or fee-asset protocol path.
- **Committed destination type/owner boundary.** The WASM host ABI still
  exposes object data but not `type_hash`, `schema_version`, or owner metadata.
  Before object I/O, node-core resolves the exact trusted preinstalled module
  once and later requires source access index 0 to be Address-owned by the
  authenticated sender. Its only owner exception is the catalog policy at
  destination index 1 for the exact module/version, `transfer` entrypoint,
  `Write` mode, `asset_account_type_hash()`, and schema version 1. The loaded
  current destination must be Address-owned and match that type/schema exactly;
  the module still verifies the complete self-describing `0xF001` body frame,
  and the effect translator freezes all metadata including both owners.
- **Dev-profile identities are not protocol claims.** The seeded `AssetId` and
  asset-account `type_hash` are fixed, non-zero dev-profile identifiers so
  clients can render and exercise the local fixture. No mint/metadata object
  or on-chain asset registry currently vouches for them, and no new
  `HashPurpose` is introduced by this local composition. Wallet and explorer
  must therefore render the ID as opaque bytes plus an explicitly local label,
  never as production asset metadata.
- **No background sweeper.** The devnet runs no resident outbox-recovery loop,
  timer, or scheduler; unattended recovery, when needed, is invoked the same
  way the native binary already exposes it (see "Serverless runtime
  constraints" and the scheduler-callable recovery API above), consistent with
  treating process lifetime as a non-requirement.
  The current generic machine and asset transition produce responses but no
  outbound messages, so the local transport queue does not grow on this route;
  its fixed capacity remains a fail-closed bound for a future message-producing
  transition.

Current vs. planned: `apps/devnet` now has strict loopback-only configuration,
persisted writer-fence advancement across SQLite reopen, a restart-safe
bounded identity source, exact canonical asset-account codecs/vectors, a
committed WAT/WASM module, reconciled registry/catalog composition, and atomic
restart-idempotent account seeding. Its binary composes those pieces into the
bounded preinstalled-WASM native router and serves HTTP on the configured
loopback address. Live smoke validation observed a `204` liveness response and
verified the same seeded object IDs after reopening under the next writer
generation. Direct WASM tests prove successful same-asset movement and
effect-free rejection of mixed asset IDs. The bounded query API (chain/context
info, object reads, receipts, and an authenticated sender's next nonce), the
Rust client (`clients/rust`), the Rust-only CLI (`apps/cli`), and a signed
cross-owner duplicate-transfer restart/duplicate HTTP E2E
(`apps/cli/tests/devnet_restart_duplicate_e2e.rs`) are implemented As-Is per
the designs defined below and in "Rust client library" / "Rust client
external-signer boundary and Developer MVP CLI". Under the CLI-first
production-strategy pivot (see "Local devnet architecture" above and
DR-0085, amended by DR-0095), the TypeScript client, explorer, and wallet
remain deferred until the Software Production Gate (S0-S3 + S5) passes
(`TODO.md#software-and-hardware-release-gates`);
no other `clients/*`/`apps/*` path from DR-0081 exists yet. Known current
limitations that
must stay visible at devnet startup and in documentation once implemented:
single validator; owned-object only (Create and Shared/System ownership remain
fail-closed; a blob-backed input is fetched and independently verified through
an explicit `BlobStore` component (DR-0094), and DR-0096 publishes only a new
version larger than the fixed inline threshold); one fixed ordinary fee asset and one ordinary
treasury without validator/certificate distribution, gas categories other
than base/execution pricing, or production economics; only the exact policy-bounded existing Address-owned destination
may differ from the sender, while literal owner reassignment/gifting remains
fail-closed; local SQLite only; the four bounded query routes are an
unauthenticated public-read API (any caller can read any object/receipt/
next-nonce/context — the address in `/v1/senders/{sender}/next-nonce` is a
public lookup selector, not authorization); query and submission share one
admission budget (`compose_devnet_router`'s single `NativeBlockingExecutor`
sized from `--max-concurrent`), so a burst of query traffic can starve
submissions and vice versa; and an overall non-production security/
operations posture.

## 43. Bounded Developer MVP query API

The Developer MVP exposes four additive `GET` routes from both normalized
structured routers. They share the event route's blocking-admission limit and
trusted storage authority, but accept no request body, writer fence, deadline,
domain, chain context, or protocol selector from HTTP:

- `/v1/context` returns the trusted `chain_id`, current `epoch`, exact canonical
  `ProtocolConfig`, and the single committed logical atomicity domain.
- `/v1/objects/{object_id}` returns true absence, a retained tombstone, a
  verified current inline object, or an explicit current blob reference.
- `/v1/receipts/{request_id}` returns typed absence or the exact canonical
  `NodeDedupRecord` after checking it against the outer durable receipt.
- `/v1/senders/{sender}/next-nonce` returns the next nonce for the current
  trusted epoch. The address in this URL is only an untrusted public lookup
  selector. It grants no authority and cannot substitute for transaction
  authentication; the returned value is usable only by a transaction whose
  signature authenticates that same sender under the committed auth profile.

Every path identifier is exactly 64 lowercase ASCII hexadecimal characters.
Malformed identifiers fail before identity allocation, clock access, or
storage I/O. Successful results use
`application/vnd.sunrise-edge.query-result`, `Cache-Control: no-store`, and
four independent canonical version-1 frames: context `0xE102`, object
`0xE103`, receipt `0xE104`, and next-nonce `0xE105`. Object status identifiers
are `1 = absent`, `2 = tombstoned`, `3 = current inline`, and `4 = current blob
reference`; receipt status identifiers are `1 = absent` and `2 = present`.
These identifiers and exact frames are stable client contracts and require
literal test vectors.

Absence is a normal `200` typed result so receipt polling needs no
transport-specific interpretation. A current inline object includes its head
revision, immutable version, self-describing digest, and exact canonical
`objects::Object` bytes. Node-core, not the HTTP adapter or storage adapter,
cross-checks head/version/digest/schema/provenance/owner projection and
recomputes the inline body digest from the version's stored chain and protocol
provenance before returning it. A blob-backed version returns only explicit
metadata and its blob digest; this MVP does not fetch or claim to verify an
unavailable blob body. A tombstone retains the ABA-safe head revision and last
immutable version. Receipt presence includes the outer event digest and exact
canonical dedup bytes only after strict decode, identity/digest agreement, and
canonical re-encoding checks. A deleted nonce record for an epoch that may be
accepted remains corruption and fails closed; true absence at initial revision
returns zero.

Every query route, including `/v1/context`, resolves the domain from the
committed manifest through the same activation-epoch-checked
`DomainPlacementManifest::resolve_domain` path the authenticated write path
uses (at the trusted current epoch, with one bounded access rather than a real
application plan) — never `placement.domain()` read unconditionally — through
one shared helper both `/v1/context` and the three storage-backed routes
call. All storage-backed queries additionally allocate a restart-safe
correlation identity and a bounded deadline from the embedding host, and run
through the same bounded blocking executor as submission. An inactive
placement therefore rejects before identity allocation, clock access, or
storage I/O for the three storage-backed routes, and before any response is
constructed for `/v1/context`; it remains an opaque `503` for every route,
while a malformed selector is a `400` rejected at the HTTP boundary.
Capacity exhaustion is `429`; malformed paths are `400`; a transient host or
storage-availability condition (identity-source unavailability, clock/runtime
failure, a durable read that proves writer fencing/deadline exhaustion/
backend unavailability/unsupported schema generation
(`DurableReadError::SchemaMismatch`, treated as an operator/deployment
condition rather than proof of corrupted persisted bytes), or committed
`ProtocolConfig` inactivity/misconfiguration) is an opaque `503`; corrupt or
unverifiable persisted content, result-encoding failure, and identity-source
exhaustion are an opaque `500`. Query responses are bounded by the existing
maximum canonical
object/receipt sizes; there is no scan, list, prefix, pagination, proof,
historical-version selector, or arbitrary state-key endpoint in this MVP
slice.

Every one of the four result types except `/v1/context` (which has no request
selector) carries the exact selector it answers — `object_id`, `request_id`,
or `sender` — in every status, including absence and tombstone. Node-core's
`ObjectQueryResult` and `ReceiptQueryResult` bind this selector at the type
level so the HTTP layer cannot construct a canonical result for one selector
from a lookup keyed by another; `native-http`'s wire codecs re-assert the same
binding as an always-present field, and the adapter independently re-checks
the selector on the result node-core returns before encoding it, as defense
in depth against a future regression.

Current vs. planned: this slice is implemented As-Is. `node-core` adds public
`query_sender_next_nonce`, `query_object`, and `query_request_receipt`
functions — implemented in a private internal module but re-exported from the
crate root, so `node_core::query_object` etc. are the stable public paths, not
a public `query` module — as the only entrypoints that can observe a
next-nonce value, an object, or a receipt outside node-core; the private
`SenderNonceRecord` framing never crosses that boundary, and the object/receipt
checks reuse the same cross-check/re-encoding rules as the authenticated write
and replay paths. `query_object` checks the immutable version's creating-chain
provenance against the trusted chain before branching on inline versus blob
payload, so a cross-chain blob record fails closed exactly like a cross-chain
inline record; a `CurrentBlobReference` result's `digest` and `blob_digest`
are the values recorded on the immutable version and cross-checked against the
head, never verified against fetched body bytes, since this MVP never fetches
a blob body. `native-http` adds the four canonical
`application/vnd.sunrise-edge.query-result` codecs (`0xE102`-`0xE105`) —
including strict decode validation of the nested canonical `objects::Object`
(id/version match, `MAX_AUTHENTICATED_OBJECT_BODY_BYTES`) and nested
`NodeDedupRecord` (request-id/event-digest match, exact re-encoding) carried
inside a `CurrentInline`/`Present` result, and rejection of a zero protocol
version/hash-suite/profile/scheme/binding id, an over-length chain id, or
empty canonical `ProtocolConfig` bytes in the context result — and wires
`GET /v1/context`, `/v1/objects/{object_id}`, `/v1/receipts/{request_id}`,
and `/v1/senders/{sender}/next-nonce` into both `structured_durable_router` and
`preinstalled_wasm_structured_durable_router`, sharing their
`NativeBlockingExecutor`, admission, and pre-storage cancellation semantics.
Every path selector is validated as exactly 64 lowercase ASCII hex characters
(and, for receipts, non-zero) before any identity allocation, clock access, or
storage I/O. Stable vectors, round-trip/unknown-tag/mismatched-selector decode
tests, both-router parity across all four routes (including a populated
current-inline object and a present receipt, not only absence), malformed-
path-before-side-effects, object absent/tombstone/current-inline/current-blob/
tamper/wrong-chain, receipt absent/present/corrupt, nonce
zero/advanced/deleted-corrupt, inactive-placement-before-side-effects cases
for `/v1/context` and a representative storage-backed object route, and the
`503`/`500` operational classification — a direct case table plus the
`SchemaMismatch` decision above — are covered in both crates' test suites.

## 44. Rust client library

The Developer MVP Rust client is a runtime-neutral library at `clients/rust`.
It exposes seed-based Ed25519 key/address handling, canonical transaction
construction and signing, submission, bounded receipt waiting, and the four
query operations from section 43. It stays application-agnostic: asset-account
transfer arguments, native-coin conventions, fee selection, and other contract
semantics belong to later consumers such as `apps/cli`, never to the base
client.

Canonical HTTP result frames and route/media-type constants are shared through
a dependency-light `node-wire` crate. `native-http` re-exports that contract so
existing server callers retain the same public names, while `clients/rust`
depends on `node-core` and `node-wire`, not on Axum or `native-http`. The shared
crate owns encoding and strict decoding only; routing, admission, clocks,
storage authority, and HTTP status classification remain server concerns.
Execution-effect decoders enforce the same collection and byte-size bounds as
their encoders and reject unknown identifiers, malformed nesting, trailing
bytes, and non-canonical representations. The transaction signature message
type is exported from node-core rather than duplicated by a client.

The initial transport is synchronous and deliberately local-development-only.
A small transport trait permits deterministic tests; the provided HTTP/1.1
implementation (`LoopbackHttpTransport`) connects only to an explicit loopback
address, opens one bounded `TcpStream` per request, applies connect/read/write
timeouts and header/body limits, requires an exact `Content-Length`, and
rejects transfer encoding, ambiguous lengths, truncated or trailing bodies,
unexpected content types, and non-loopback targets. It provides no TLS,
authentication, proxy, redirect, persistent connection, async runtime, or
production remote-node claim. (A separate, later-added `RemoteTlsHttpTransport`
lifts the loopback-only and no-TLS restrictions within S1's documented
bounds — see DR-0085 below — without changing this transport's own scope.)

`/v1/context` remains authoritative for chain, epoch, protocol-version, hash-
suite, authentication-profile, signature-scheme, binding, and atomicity-domain
identifiers. The canonical `ProtocolConfig` bytes are preserved as opaque bytes
in this slice rather than partially decoded. A caller supplies the exact trusted
preinstalled module reference and object references used by its transaction;
the client does not invent module discovery or object scans. Submission uses an
explicit non-zero request ID supplied by the caller, checks that the response is
bound to it, and never derives a protocol identity with an ad hoc hash.
Receipt absence is normal while waiting; polling always has explicit attempt,
elapsed-time, and backoff bounds and creates no background worker. Capacity and
temporary unavailability may be retried only within those caller-visible
bounds.

Stable literal vectors cover the shared query/response frames and signed
transaction bytes accepted by node-core. The client does not claim to recompute
transaction/effect hashes from the context's hash-suite identifier, fetch blob
bodies, verify certificates, or decode the full protocol configuration. Those
capabilities, production transports, key generation/keystores, CLI policy, and
application-specific helpers remain deferred until the MVP consumers require
them.

Current vs. planned: this slice is implemented As-Is. `node-wire` owns the
previously server-local codecs without changing their stable vectors, and
`native-http` re-exports the same public names. `execution` now strictly
decodes event records, object effects, and complete execution effects;
`clients/rust` re-exports those decoders for response consumers. The client
checks every returned object/request/sender selector against the exact query,
and the loopback transport rejects request framing injection, over-bound
headers/bodies, transfer encoding, ambiguous lengths, malformed status/header
syntax, truncation, trailing bytes, and failure to close a `Connection: close`
response within its timeout. Per-stage socket timeouts are also capped by one
monotonic complete-request deadline, and receipt polling passes its overall
elapsed deadline into every transport call, so a slow-drip peer cannot reset
the bound byte by byte. Nested effect-list decoders compare the declared count
with the frame's exact field count before allocating or iterating. Tests pin
the existing signed transaction vector, authenticate freshly client-signed
bytes through node-core, exercise fake submission/receipt behavior, exercise
adversarial raw TCP responses (including slow-drip and close timeout), and
query all four routes through a real composed devnet router over TCP. A live
signed asset transfer, duplicate replay, and restart sequence remains Developer
MVP criterion 10 work; this client slice does not claim that later E2E.

## 45. Rust client external-signer boundary and Developer MVP CLI

`clients/rust` gains a safe, additive two-stage transaction-construction API
(`transaction::PreparedTransaction`) alongside the existing single-call
`build_signed_transaction`, which is now implemented through the same path so
its stable output bytes are unchanged. `PreparedTransaction::prepare` takes an
explicit sender `Address`, the active `SignatureSchemeId` from a trusted
`/v1/context` result, and a `TransactionRequest`, and returns an immutable
value with the canonical Transaction v1 fields already fixed; it rejects any
scheme other than `Ed25519` before any framing happens, returning a
dedicated `ClientError::UnsupportedSignatureScheme(SignatureSchemeId)`.
Before this two-stage API existed, `build_signed_transaction` rejected the
same unsupported-scheme case later and less specifically: it always called
`SignatureSigner::sign_canonical`, whose own scheme-match guard returned a
wrapped `ClientError::Crypto(CryptoError::SignatureSchemeMismatch)` instead.
`build_signed_transaction`'s caller-visible error type for this case is
therefore different from before — this is a strictly additive, easier-to-
match error-type change, not a protocol change: the exact same case is still
rejected before any framing or signing, and every stable output byte for
every case that still succeeds is unchanged. `signable_frame`
exposes the exact centralized-domain-framed bytes
([`crypto::frame_signature_message`]) an external signer must produce a raw
signature over — the same bytes any in-process `SignatureSigner` ultimately
signs. `finalize` accepts that raw signature and only produces output after
independently constructing an `Ed25519Verifier` from the sender's 32 bytes
(the only implemented `AddressIsPublicKey` binding), re-deriving the same
framed bytes, and confirming the signature both has the scheme's exact
supported length and cryptographically verifies; a well-formed but invalid,
wrong-signer, or tampered (signature or transaction field) signature is
rejected with a typed `ClientError` and produces no output.
`sign_and_finalize_with` is a convenience composition of `finalize` for any
in-process `SignatureSigner` (for example `LocalSigner`), reusing
`sign_canonical`'s own scheme-match guard. This boundary exists so a future
external signer — including but not limited to a dedicated hardware wallet —
can be integrated without changing `PreparedTransaction`'s public shape or
this crate's stable transaction bytes: only a new caller supplying bytes to
`finalize` would be added.

**Ledger boundary is not implemented in this slice.** No USB/HID/Ledger
dependency exists anywhere in this workspace, and none belongs in a protocol
or client crate. `PreparedTransaction` is Ledger-*ready* only in the narrow
sense that it already exposes the exact bytes an external signer would need
and already independently verifies whatever signature comes back; it is not
a Ledger integration. A real integration additionally requires, at minimum: a
dedicated Sunrise Edge Ledger device application (existing Solana or Ethereum
Ledger apps must not be reused for Sunrise transaction signing — they know
nothing about this protocol's canonical framing and would either reject the
payload or, worse, sign it under the wrong domain); an APDU protocol and host
transport to that device application; on-device parsing and clear signing of
the exact Sunrise signature frame (chain/protocol-version/epoch/message-type/
scheme plus the canonical transaction payload) so a user approves what they
are actually signing, not opaque bytes; public-key/address verification
against the device; an explicit derivation-path policy; device/application/
firmware-version checks; explicit on-device user confirmation before signing;
host-side signature verification (which `PreparedTransaction::finalize`
already provides); and hardware-in-the-loop tests. None of this is
implemented or claimed here.

`apps/cli` is a new, additive, Rust-only Developer MVP CLI with exactly one
non-development/runtime dependency: `sunrise-edge-client`. (`Cargo.toml` also
declares a handful of `[dev-dependencies]` — `execution`, `native-http`,
`objects`, `rcgen`, `runtime`, `rustls`, `sunrise-edge-devnet`, `tokio` —
used only to compose a real local devnet, build canonical test fixtures,
build a decoded execution-effects fixture directly in this crate's own test
suite, and (`rcgen`/`rustls`) construct real TLS end-to-end test fixtures;
none of them are reachable from `main`, `lib`, or any non-test build.) It has no
Node/browser runtime, no argument-parsing crate (flags are
parsed by a small hand-written, strict `--flag value` parser that rejects
duplicates, unknown flags, and any non-flag/extra positional token), no
`unsafe` (`#![forbid(unsafe_code)]`), and no independent canonical
encode/decode, signing, or RPC path — every protocol interaction goes
through `sunrise-edge-client`. It provides six
commands: `address` (derives and prints the `AddressIsPublicKey` address
bound to an explicitly named development seed file — never a keystore, never
a home-directory default, and the seed is never accepted on argv or printed);
`context`, `object`, `receipt`, and `next-nonce` (thin wrappers over the
matching `sunrise-edge-client` query methods); and `transfer`, the bounded
devnet asset transfer command. Every network subcommand targets an
explicit `--endpoint`; with neither TLS flag supplied, `--endpoint` must be
loopback and this binary talks the legacy plaintext `LoopbackHttpTransport`
(a non-loopback address is rejected before any connection is attempted). With
both paired `--tls-server-name`/`--tls-ca-cert-der-file` flags supplied,
`--endpoint` is instead treated as an already-resolved `SocketAddr` with no
loopback restriction, and this binary dials `RemoteTlsHttpTransport`; this binary
performs no DNS resolution of its own, so `--endpoint` remains a literal
address either way. Output is deterministic,
line-oriented `key=value` text; every error is a typed, actionable
`CliError`, and every error exits the process non-zero. A successful node
response payload is decoded through `sunrise-edge-client`'s already-generic
`execution::ExecutionEffects` decoder when possible; receipts, object bodies,
and any payload that does not decode as effects are printed as bounded
lowercase hex instead of inventing a claim about their meaning.

`transfer` is the only place in this repository outside `apps/devnet` that
knows the `sunrise.devnet.asset_account.v1` module's fixed `transfer`
entrypoint name and its exact `CanonicalStruct(0xF002, v1){1: u64 amount}`
argument frame — `clients/rust` stays application-agnostic. To build that
frame and the transaction's access manifest without a second direct
dependency, `clients/rust` additively re-exports a small, generic surface
that adds no devnet-specific semantics of its own: `abi::{AccessEntry,
AccessManifest}`, `objects::{AccessMode, Object, ObjectError, Owner,
decode_object}`, `execution::ObjectEffect`, `canonical_encoding::{
CanonicalStruct, CanonicalEncodingError}`, `protocol_types::{AtomicityDomainId,
ChainId, Digest32, Epoch, HashAlgorithmId, HashSuiteId, ProtocolVersion,
SignatureSchemeId, TypeError}`, `NODE_RESULT_MEDIA_TYPE`, and three small
helpers/constants: `current_inline_object_ref` (extracts the exact `ObjectRef`
from a `CurrentInline` object-query result, `None` for every other status —
generic over any object, not asset-specific), the
`ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID` constant (the `AddressBinding::
AddressIsPublicKey` wire value, duplicated as a plain `u16` so a caller can
compare it against `HttpContextQueryResult::address_binding_id()` without a
direct `protocol-config` dependency; `protocol-config` remains a `clients/rust`
dev-dependency only, and a dedicated test pins the two values together so
they cannot silently drift), and the `ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`
constant (the committed `TransactionAuthProfile` id `transfer` checks
`HttpContextQueryResult::transaction_auth_profile_id()` against before
signing, duplicated the same way and for the same reason). `objects::{
ObjectError, Owner, decode_object}` and `execution::ObjectEffect` exist so
`transfer` can decode a queried object's canonical body, check its owner
client-side as defense in depth, and print each object effect from decoded
execution effects, without a direct dependency on either lower crate.

`transfer` queries `/v1/context`, the sender's `/v1/senders/{sender}/next-nonce`,
and both `/v1/objects/{object_id}` results for the caller's exact
`--source-object`/`--destination-object` identifiers; validates the
committed profile is `Ed25519` + `AddressIsPublicKey` and that the context
and next-nonce queries agree on epoch, all before signing; requires both
objects to be `CurrentInline` (any other status is a typed, actionable
rejection); requires the source owner to equal the signer and the destination
owner to equal the separately required `--destination-owner` Address before
signing; constructs the exact two-entry `AccessManifest` with `Write`
access to source then destination, in that order; builds and signs the
transaction through `PreparedTransaction`/`build_signed_transaction`; and
submits it with an explicit, caller-supplied non-zero request id. Every
asset, including this one, uses the same uniform `AssetId`/account/transfer
path — there is no native-coin or fee special case. Cross-owner destination
authorization is available only through DR-0086's exact trusted preinstalled-
module policy; the general owned-effects path remains sender-only.
`transfer` treats the submission itself as fail-closed, not merely the
queries that precede it: an empty submit-result `responses()` list, any
response declaring `NodeResponseStatus::Rejected`, and any response whose
payload decodes to `ExecutionStatus::Failure` (even one the node accepted at
the node-core level) are each a typed, non-zero-exit `CliError` — this
command never reports a rejected or failed transaction as success. Every
response's diagnostics are printed before the command exits — the failure
is detected while iterating, not by inspecting `responses()` up front — and
`--wait` is never entered once any response has failed this way, so a
rejected or failed submission can never be turned into an apparent success
by also requesting `--wait`.
Waiting for the resulting receipt is optional (`--wait`) and, when
requested, every one of `--wait-max-attempts`, `--wait-initial-backoff-ms`,
`--wait-max-backoff-ms`, and `--wait-max-elapsed-ms` must also be supplied —
there is no hidden default poll bound, and supplying a wait-bound flag
without `--wait` is itself rejected.

The development seed file loaded by `address` and `transfer` must be an
explicit path (there is no default or home-directory location), must not be
a symlink, must be a regular file, must on Unix grant no permission bit to
group or other, and must contain exactly 64 hexadecimal digits plus at most
one trailing `\n` — anything else is a typed, actionable rejection before any
key material is derived. This is a development convenience, explicitly not a
keystore.

Current vs. planned: this slice is implemented As-Is except where marked.
`clients/rust`'s two-stage signer API, its small generic re-export surface,
and `apps/cli`'s six commands are implemented and tested, including
adversarial coverage of a mismatched, malformed-length, wrong-signer, and
tampered signature; parser rejection of duplicate/unknown/malformed/
extra-positional arguments; development seed file symlink/permission/length
rejection (Unix); a fake-`Transport` unit test per query command plus
`transfer`'s full success and epoch-mismatch/unsupported-scheme/
non-current-inline-object adversarial paths; and two real loopback-TCP tests
against a composed local devnet router — one exercising `context`/
`next-nonce`/`object`, and one exercising a complete signed `transfer`
against freshly seeded accounts through to a waited, present receipt.
DR-0088 subsequently implements S4a's strict host-side profile, exact
signed-byte clear-signing fixture, and external-signer preflight. DR-0091
records the separate repository's S4b Ledger SDK application and Nano S+
Speculos evidence As-Is. DR-0092 subsequently implements S4c Phase 1's host
APDU/USB/HID transport and CLI signer selection in this repository's own
`clients/ledger` crate — the profile/address checks and USB-descriptor-level
device recognition only, not the active-app/firmware checks — and DR-0093
implements S4c Phase 2a's strict Ledger OS identity/dashboard parsing and
staged dashboard/firmware/open-app/reconnect/active-app sequence, closing
that gap strictly in software. S4c itself, physical-device HIL, and release
evidence remain unimplemented and are not claimed by any of these four
boundaries.

**Development-only residual: no memory zeroization.** `load_dev_seed`'s read
buffer and decoded `[u8; 32]` seed, and `LocalSigner`'s in-memory signing
key, are ordinary Rust values with no `zeroize`-on-drop behavior anywhere in
this slice; a process-memory disclosure (a core dump, swap, or a debugger
attached to the process) can recover them for as long as they, or a copy the
allocator has not yet overwritten, remain resident. This is consistent with
`load_dev_seed`'s and `LocalSigner`'s existing documented status as
explicit, non-keystore, development-only conveniences — not production key
handling — and is called out here rather than silently assumed.
The restart/duplicate E2E is implemented As-Is (see
`apps/cli/tests/devnet_restart_duplicate_e2e.rs` and "Local devnet
architecture" above). Under the CLI-first production-strategy pivot (DR-0085),
`clients/typescript`, `apps/explorer`, and `apps/wallet` remain deferred until
the Software Production Gate (S0-S3 + S5) passes (see
`TODO.md#cli-developer-mvp-gate` and `TODO.md#cli-first-node-production-gate`).

## 46. Hardware Signing Profile v1 and external-signer preflight

S4 is split into four ordered boundaries so a host library cannot become a
surrogate for device-side authorization. S4a is implemented As-Is in this
repository; S4b's separate dedicated Ledger application and Nano S+ Speculos
evidence are implemented As-Is in `sunriselayer/sunrise-edge-ledger-app` by
DR-0091. S4c Phase 1's host APDU/USB and CLI signer selection (profile/address checks
and USB-descriptor-level device recognition) are implemented As-Is in this
repository by DR-0092, and S4c Phase 2a's active-app/firmware identity check
is implemented As-Is by DR-0093 — strictly in software, against
`FakeTransport` only. S4c itself is still not complete: it still needs
Phase 2b's real hardware validation. S4d
completes the remaining physical-device, reproducibility, and
release-evidence gate. S4 is not complete
until S4d passes and the CLI has an actual production signing path replacing
its development-only seed flow.

`crypto::decode_signature_frame` is the strict counterpart to the established
`frame_signature_message` encoder. It accepts only canonical type `0x2001`,
encoding version 1, and exact fields 1-6, and changes no existing bytes.
The new dependency-light `signing-view` crate independently decodes the
signable Transaction v1 shape without depending on `execution`/`wasmi`, applies
Hardware Signing Profile v1's fixed 4 KiB frame and tighter nested bounds, and
re-encodes every accepted value to require byte identity. A dev-only
differential test proves this independent encoder agrees with `execution`.

Clear signing is exact-policy-only. The first policy recognizes only the
reference `sunrise-local-devnet`, protocol 3, epoch 0 asset-account transfer's
exact module id/version/SHA-256 code digest, `transfer` entrypoint, non-zero
`0xF002` v1 amount, three distinct ordered `Write` references, and fee object
equal to source index 0. Unknown module, digest algorithm or bytes, version,
entrypoint, argument schema, access shape, or fee shape is a typed rejection.
There is no raw-argument, blind-signing, or expert-mode fallback. Every
rendered line comes only from the signed frame: `request_id`, destination
owner, transferred-asset symbol/id, module display name, and other queried
metadata are excluded because Transaction v1 does not bind them. Fee asset id
is signed and is displayed.

`PreparedTransaction::clear_signing_view` derives the view only from
`signable_frame`. The additive `ExternalSigner` boundary and
`sign_and_finalize_external` compare the signer's reported scheme and address
to the prepared transaction before invocation, validate the exact frame under
the fixed profile/policy, then pass that same frame to the signer. Existing
`finalize` still independently checks length and Ed25519 validity against the
sender. The host view is only preflight/conformance evidence: the eventual
device app must independently parse and display the received frame.

`docs/signing/hardware-signing.md` is normative for the fixed profile bounds, stable display fixture,
provisional explicitly unregistered development derivation path, and bounded
APDU state machine/status words. The dedicated device app lives in the separate
`sunrise-edge-ledger-app` repository because its custom targets, Rust SDK/C
bindings, Speculos workflow, device matrix, and Ledger release lifecycle cannot
pass or be hidden from this workspace's host-target gate. DR-0091 records that
device-side S4b boundary. DR-0092 places every vendor host dependency in the
new `clients/ledger` crate, never a protocol crate or `clients/rust`, and
explicitly amends the CLI's original one-runtime-dependency invariant
(DR-0084) to two: `sunrise-edge-client` and `sunrise-edge-ledger`. No
physical-device evidence, registered SLIP-0044 allocation, or release
artifact exists yet; `clients/ledger`'s real USB/HID transport is itself
unvalidated against physical hardware (see DR-0092).
