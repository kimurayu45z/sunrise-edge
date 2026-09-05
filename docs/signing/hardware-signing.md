# Sunrise Edge hardware signing

This document specifies Hardware Signing Profile v1, the S4a host/device
conformance boundary. It does not document a released hardware wallet.

S4a is implemented As-Is in this repository: the hardware signing profile,
the clear-signing view derived only from the exact signed frame, and the host
seam. S4b is implemented and validated As-Is in the separate
[`sunriselayer/sunrise-edge-ledger-app`](https://github.com/sunriselayer/sunrise-edge-ledger-app)
repository by merged PR #2 (`6f6f882`): the dedicated device application,
five-target builds, and Nano S+ Speculos evidence. S4c Phase 1 and Phase 2a
are implemented As-Is in this repository's `clients/ledger` crate: the host
APDU/USB/HID transport for the exact contract below, USB-descriptor-level
device-model recognition, and `apps/cli`'s explicit, all-or-none Ledger
signer selection (Phase 1, [DR-0092](../architecture/decisions/0088-0093-hardware-signing.md)); and, by Phase 2a ([DR-0093](../architecture/decisions/0088-0093-hardware-signing.md)), the staged
dashboard/firmware/open-app/reconnect/active-app identity sequence over CLA
`B0` and dashboard-context CLA `E0` (see "Device APDU contract" below), a
required `--ledger-expected-firmware-version` CLI flag, and this app's own
`get configuration` now additionally pinning exact version `0.1.0`.
**S4c is not complete.** Phase 1 satisfied the profile and address checks
and added a device (USB vendor id/model) check. Phase 2a closes the gap
Phase 1 left open — it verifies the active on-device application's name and
version, and the device firmware's target id/OS-Upgrade state and exact
caller-supplied version — but strictly in software, against
`clients/ledger`'s deterministic `FakeTransport` only. **No physical-device
evidence exists for any of S4a/S4b/S4c**, including for Phase 2a's identity/
dashboard commands; `clients/ledger`'s real USB/HID transport (including its
device recognition and the identity/dashboard sequence) is itself
unvalidated against physical hardware, and behind an off-by-default
`usb-hid` Cargo feature. **S4c Phase 2b** — physical-hardware validation of
this exact sequence — is the next slice; only after it is S4c itself
complete, and **S4 is not complete.** `LocalSigner` remains a
development-only, non-keystore in-memory key with no zeroization;
S4a/S4b/S4c do not replace it.

## Signed input and bounds

The device signs the complete output of `crypto::frame_signature_message`,
not a digest or host-created summary. The existing canonical frame is
`CanonicalStruct(0x2001, v1)` with exactly these fields:

1. `chain_id` UTF-8 string
2. `protocol_version` little-endian `u32`
3. `epoch` little-endian `u64`
4. `message_type` UTF-8 string
5. `signature_scheme_id` little-endian `u16`
6. canonical payload bytes

Profile v1 accepts only `message_type=transaction-v1`, Ed25519, and an inner
`CanonicalStruct(0x6001, v1)` containing required fields 1-10 and optional
fee field 11. Field 12 is a signature and is therefore forbidden inside the
signable payload. The outer and inner chain, protocol version, and epoch must
match exactly.

Profile v1 applies these immutable limits before copying or interpreting
attacker-controlled content:

| Item | Limit |
| --- | ---: |
| complete signature frame | 4096 bytes |
| inner transaction payload | 3072 bytes |
| chain id | 64 bytes |
| message type | 32 bytes |
| entrypoint | 64 bytes |
| canonical arguments | 40 bytes |
| access entries | 8 |
| display lines | 64 |
| bytes per ASCII display line | 96 |

These limits are intentionally tighter than the node's generic Transaction
v1 limits. A transaction outside the device profile is rejected; it is never
truncated, hashed in place of clear signing, or routed to blind signing.
Pure Ed25519 verification signs the complete frame, so the device must retain
the bounded frame until the user approves or rejects it.

## Clear-signing policy

Every displayed value is a pure function of the exact signed frame bytes.
Host-supplied display metadata—`request_id`, destination owner, asset symbol,
module name, or a queried label—is excluded and must never be presented as
signed content. The transferred account's `AssetId` is stored in object state
and is not signed directly, so Profile v1 cannot display an asset symbol or
claim that asset identity. The fee `AssetId` is signed and is displayed as raw
hex.

Profile v1 recognizes only the exact local reference transfer identified by:

- the device policy pins exactly chain id `sunrise-local-devnet`, protocol
  version `3`, and epoch `0` (the [local devnet](../guides/devnet.md) reference context) — any other
  outer/inner value is a typed rejection, not a best-effort match;
- module object id
  `0d5dd10aec2c315b1dc564c694439e46bac4b61426d22e0d7ddb764c49197fe7`;
- module version `3`;
- SHA-256 code digest
  `01534128f12eb4cf469bfa29677bbced1344879de2870315847cbb7faec21619`,
  for the committed asset-account WASM under that pinned chain/protocol/
  epoch;
- entrypoint `transfer`;
- argument `CanonicalStruct(0xF002, v1)` with exactly field 1, a non-zero
  little-endian `u64` amount;
- exactly three ordered `Write` references — source, destination, and the
  trusted-composition treasury access — whose three `ObjectId`s the device
  must also check are pairwise distinct; a typed rejection applies if any
  two of the three access entries reference the same `ObjectId`, even when
  every mode/position is otherwise well-formed;
- a present fee payment whose fee object is byte-for-byte the source
  reference at access index 0, and whose fee `AssetId` is byte-for-byte the
  exact devnet fee asset
  `ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8` — the
  normative value is `crates/signing-view/src/policy.rs`'s
  `DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id` field; `crates/signing-view/tests/fixtures.rs` exercises the same bytes only as fixture evidence.

The view displays chain, protocol version, epoch, message type, scheme,
sender, nonce, exact module reference, entrypoint, amount, gas limit, every
ordered access mode/reference, and every signed fee field. The destination
owner is intentionally absent because it is not in Transaction v1. Node-side
owner and module policy remain separate authorization checks.

Any unknown module id/version/digest algorithm/digest, entrypoint, argument
type/version/shape, access shape, or fee shape is a typed rejection. There is
no raw-argument, blind-signing, or "expert mode" fallback. Stable fixture bytes
and display lines live in `crates/signing-view/tests/fixtures.rs`.

## Provisional derivation policy

Sunrise Edge has no entry in the
[SLIP-0044 registered coin-type list](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
as of 2026-09-04.
Profile v1 reserves the development-only path
`m/44'/21333'/account'/0'/0'`, where every component is hardened and
`account` is a caller-selected non-hardened value encoded with the hardened
bit on the wire. `21333` is an explicitly unregistered provisional marker,
not a claim on that SLIP-0044 number. The device must reject another depth,
prefix, unhardened component, change, or address index. For the provisional
devnet path, key derivation itself is pinned to
[SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
Ed25519 (all components hardened, matching SLIP-0010's Ed25519 requirement)
exactly as specified there; this pins the derivation algorithm, not only the
path shape above.

The public key returned by `verify public key` and used internally for the
device-side sender check below is the standard
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) compressed Ed25519
encoding: 32 little-endian bytes of the point's `Y` coordinate with the sign
bit of `X` packed into the most-significant bit of the last byte. Whether app
code must convert to reach that encoding depends on which Ledger SDK
primitive derived the key, and the two paths must not both be applied to the
same value:

- Starting from `ECPrivateKey::public_key`'s raw, uncompressed output (a
  65-byte `04 || X || Y` point, `X`/`Y` each 32 bytes in the SDK's own
  big-endian byte order): this is not the compressed form, and app code must
  convert it by reversing `Y` from big-endian to little-endian and setting
  the compressed sign bit from `X`'s parity (an odd `X` sets the bit).
- Using the current Ledger SDK's `cx_edwards_compress_point_no_throw` helper:
  it already writes the compressed RFC 8032 bytes into `pubkey[1..33]`. This
  output must be used as-is; a second reversal or sign-bit transformation on
  top of it is not permitted and would silently produce a different, wrong
  public key/address rather than a decode error.

Getting the byte order or sign bit wrong on the first path, or re-transforming
the second path's already-compressed output, both silently produce a
different, wrong public key/address rather than a decode error. S4b's separate
device app implements the raw `04 || X || Y` path and pins it under the public
development-only mnemonic `glory promote mansion idle axis finger extra
february uncover one trip resource lawn turtle enact monster seven myth punch
hobby comfort wild raise skin` at `m/44'/21333'/0'/0'/0'` (account 0) to the
exact compressed public key
`df8608651a39745d3ae6eb2d4378619fd033c24eee6962c97b21750ce0fd88fb`.
This mnemonic is public test material and must never hold funds. The vector is
pinned in `tests/speculos/conftest.py` and `tests/speculos/test_device.py` at
device-repository merge commit `6f6f882`; RFC 8032 vectors independently
exercise the conversion. The app does not implement the already-compressed
helper path, so a two-path agreement claim is neither made nor required for the
implemented boundary.

This provisional path may be used only by devnet/Speculos builds. A Ledger
submission or mainnet claim requires a later decision record that pins the
registered allocation and migration policy; changing it requires a new
hardware signing profile rather than silently reinterpreting v1.

## Device APDU contract

S4a freezes the following byte contract, the separate
`sunrise-edge-ledger-app` repository implements its application side under
S4b, and this repository's `clients/ledger` crate implements its host side
under S4c Phase 1 and Phase 2a (Phase 1 is host integration As-Is; Phase 2a
adds the active-app/firmware identity checks described in the CLA `B0`/`E0`
bullets below, also As-Is; neither is physical-hardware evidence, and S4c
itself is not complete — see "Delivery sequence" below).
All multi-byte APDU integers are big-endian, independently of canonical
transaction integers inside the opaque chunk stream.

| Name | CLA | INS | P1 | P2 | Command data | Success data |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| get configuration | `E0` | `00` | `00` | `00` | empty | exactly 6 bytes: profile `u16` (`1`), semver `major`/`minor`/`patch` `u8` each, flags `u8` |
| verify public key | `E0` | `02` | `01` | `00` | derivation path | exact 32-byte Ed25519 public key |
| sign transaction | `E0` | `04` | see below | `00` | header/chunk or chunk | exact 64-byte Ed25519 signature on final approval |
| reset signing | `E0` | `06` | `00` | `00` | empty | empty |

`get configuration`'s six success bytes are, in order: `profile` (`u16`,
pinned to exactly `1` for Hardware Signing Profile v1), `major`/`minor`/
`patch` (one `u8` each), then `flags` (`u8`). Every flags bit defined by
this document is currently `0`; there is no defined non-zero bit. An
unknown flag is any set flag bit that either the host's own supported
version or the responding device's version does not define. A future host
that receives a response with an unknown flag set must reject it as an
unsupported configuration rather than silently ignore the bit.

The path encoding is one depth byte followed by exactly that many big-endian
`u32` hardened components. Profile v1 requires depth five and the provisional
path above, i.e. exactly 21 bytes (1 depth byte + 5 × 4-byte components).
`verify public key` always requires on-device confirmation; P1 `00` is
invalid. The host must compare the returned key with the prepared
transaction sender before sending any signing chunk. The returned 32-byte
value is the raw Ed25519 public key; it is also usable directly as the
Sunrise on-chain address only because the chain's committed
`protocol_config::TransactionAuthProfile` — which Hardware Signing Profile
v1 relies on rather than itself commits — selects the `AddressIsPublicKey`
address binding (see [`core-protocol.md`](../architecture/core-protocol.md)).
This document does not claim public key and address
are equal in general — a future signature scheme or address binding would
require an explicit amendment rather than reusing "public key/address" as
one value.

Each frame chunk carries at most 230 bytes of signed-frame payload.
`sign transaction` uses explicit P1 states:

- `00` FIRST: valid only while idle; data is `total_length: u32` (4 bytes),
  the 21-byte path, then the first non-empty frame chunk (at most 230
  bytes). FIRST's total command data is therefore at most 255 bytes
  (4 + 21 + 230); the device rejects a FIRST APDU whose data exceeds that
  bound.
- `01` CONTINUE: valid only while collecting; data is one non-empty chunk of
  at most 230 bytes.
- `02` LAST: valid only while collecting; data is the final non-empty chunk
  of at most 230 bytes.

FIRST and CONTINUE, on success, return `9000` with empty response data —
no partial signature, echo, or progress indicator; only LAST's success
response carries the 64-byte signature. FIRST declares a non-zero total no
larger than 4096. The application tracks the exact received count with
checked arithmetic. Before rendering any review screen, LAST must derive the
32-byte public key from the path supplied on FIRST (SLIP-0010 Ed25519, RFC
8032 compressed encoding, as above) and compare it byte-for-byte against the
parsed Transaction v1 `sender` field; on any mismatch LAST returns `6A80`
and wipes the buffered frame and derivation state without displaying any
review page. LAST otherwise succeeds only when the count equals the FIRST
declaration, the complete frame and clear-signing policy validate — including
the duplicate-`ObjectId` check in "Clear-signing policy" above — and the user
explicitly approves
every display page. FIRST during collection, CONTINUE/LAST while idle, empty
chunks, overflow, excess bytes, premature LAST, USB reset, timeout,
rejection, parse error, and any status other than success wipe the buffered
frame and derivation state. `reset signing` is idempotent and also wipes
them. No state survives app restart.

Status words are exact:

| Status | Meaning |
| ---: | --- |
| `9000` | success |
| `6985` | user rejected |
| `6986` | invalid signing state |
| `6A80` | invalid or unrecognized data |
| `6A84` | profile bound exceeded |
| `6A86` | invalid P1/P2 |
| `6D00` | unsupported INS |
| `6E00` | unsupported CLA |
| `6F00` | internal failure after state wipe |

Unknown status words are typed host errors, never success or user rejection.
The device application owns this explicit state machine; the host, USB link,
and scheduler are untrusted.

The table above is the app's own status-word contract for its `E0` CLA only.
It is explicitly separate from status words and behavior owned by the Ledger
SDK/OS layer beneath the app, which this document does not define. The separate
S4b repository re-verifies that behavior against its pinned Ledger SDK/platform
tooling rather than assuming it from this table:

- `6E03`: the Ledger I/O framework's own malformed-APDU-length rejection —
  a raw `Lc`/received-length mismatch caught by the SDK's transport layer
  before app dispatch — distinct from the app's own `6A80`, which is only
  returned after the app has received and parsed well-framed data it judges
  invalid/unrecognized.
- `5515`: the Ledger OS's standard locked-device status, returned when the
  device is PIN-locked and therefore unreachable by any CLA, including `E0`.
- `E000`: an unhandled panic/exception caught by the Ledger SDK's own fault
  handling, not a status this app returns deliberately; it indicates the
  app's own state machine did not run to a normal typed outcome.
- `6901`: the current Ledger SDK's in-review command rejection while the
  synchronous confirmation UI is active. It is returned before the app core
  receives the second APDU and therefore cannot be treated as an app-core
  status or proof that the core wiped its pending review state.
- CLA `B0`: Ledger's common CLA for the currently active application's own
  identity — `INS 01` ("get app and version") returns the running app's
  name and version — and other platform-level requests per Ledger's own
  integration guidelines. Ledger devices intercept CLA `B0` before it
  reaches this application's dispatcher; the Sunrise app never receives,
  handles, or redefines CLA `B0` behavior.
- CLA `E0`, dashboard context: while the device is at the dashboard (no
  application open), `INS 01` ("get version") is the Ledger OS's own
  firmware-version query — a distinct, OS-owned use of the same CLA byte
  `E0` the table above uses for the Sunrise application's own commands. It
  is reachable only before the Sunrise application is opened; once the
  Sunrise app is the active app, `E0` is this app's own CLA and the
  dashboard's `INS 01` firmware query is no longer reachable. A host that
  wants the device model, active app name/version, and firmware version
  together must stage the query in that order — dashboard first (CLA
  `B0`/`E0` as above), then open (or have the operator open) the Sunrise
  application and reconnect, then send this document's own `E0` commands —
  never assume a single CLA byte means the same thing across that
  transition. `E0` remains this app's own CLA for every command in the
  table above once the Sunrise application is active, unaffected by CLA
  `B0` interception. `clients/ledger::identity` implements exactly this
  staged sequence, plus CLA `E0` `INS D8` ("open app") to open the Sunrise
  application, as of S4c Phase 2a ([DR-0093](../architecture/decisions/0088-0093-hardware-signing.md); see "Delivery sequence" below
  and "External references"). It is exercised only against `FakeTransport`;
  no physical-device evidence exists for it.

## Delivery sequence

- **S4a (this repository, As-Is):** strict signature-frame decoding,
  device-profile transaction decoding, exact clear-signing policy and stable
  display fixture, plus the Rust client's external-signer seam.
- **S4b (separate repository, implemented and validated As-Is by [DR-0091](../architecture/decisions/0088-0093-hardware-signing.md)):**
  the dedicated Rust Ledger application independently parses the exact frame,
  derives and signs on-device, builds for five Ledger targets, and passes the
  fixed key/signature/rejection/reset suite under Nano S+ Speculos. The exact
  signature uses the sender-substituted canonical-shape fixture; the
  byte-identical copied source fixture is the sender-mismatch case. Solana and
  Ethereum apps are never reused.
- **S4c Phase 1 (this repository, implemented As-Is by [DR-0092](../architecture/decisions/0088-0093-hardware-signing.md)):** a
  separate `clients/ledger` host crate implements the APDU/USB/HID boundary
  above against an injectable transport (a deterministic `FakeTransport`
  used by every protocol test, and a real but not yet hardware-validated
  `HidTransport` behind an off-by-default `usb-hid` Cargo feature), and
  `apps/cli`'s `address`/`transfer` commands add an explicit, all-or-none
  Ledger signer selection that checks the device's reported configuration
  and on-device-confirmed public key/address before every signature. Vendor
  dependencies (`hidapi`) do not enter protocol crates or `clients/rust`;
  they are confined to `clients/ledger`, which `apps/cli` now depends on in
  addition to `clients/rust`. `HidTransport::open` additionally requires the
  target path to resolve, through USB device enumeration, to Ledger's vendor
  id, a recognized product-id model family (the exact S4b five-target build
  list — Nano X, Nano S Plus, Stax, Flex, Apex P), and exactly the Ledger
  APDU usage page `0xFFA0` (the **device** check; no interface-number
  fallback) before ever opening it. If one physical path exposes multiple
  HID top-level collections, the host checks every descriptor at that exact
  path and accepts only when at least one satisfies all three identity
  fields. Programmatic responses have a 30-second total read deadline;
  `verify public key` and signing LAST, which wait for a human, each have a
  bounded 120-second total read deadline. Neither deadline is multiplied by
  the number of HID packets. The current operator flow therefore shows one
  address confirmation for `address`, and three confirmations for
  `transfer`: connect-time address, repeated pre-sign address, then the
  transaction review. The repeated address check is intentional fail-closed
  Phase 1 behavior, not finalized production UX. **S4c is not complete**: this phase does
  not verify the active on-device application's name/version or the device
  firmware version (the **app**/**firmware** checks — see "Device APDU
  contract" above), and none of it — the APDU protocol logic, the USB HID
  framing, or the device recognition — has been validated against physical
  hardware.
- **S4c Phase 2a (this repository, implemented As-Is by [DR-0093](../architecture/decisions/0088-0093-hardware-signing.md)):** add the
  active on-device application identity check and the device firmware
  identity check (the **app**/**firmware** checks) over the CLA `B0`/
  dashboard-context CLA `E0` commands documented in the CLA `B0`/`E0`
  bullets above, strictly in software against `clients/ledger`'s
  `FakeTransport`. `clients/ledger::identity` requires the dashboard to
  report exactly `BOLOS` before ever sending the dashboard firmware query;
  requires the firmware's target id to identify a normal Secure Element OS
  and rejects any `-osu`-marked (OS Upgrade) dashboard or firmware version,
  strictly before comparing firmware versions, so a bootloader-mode or
  mid-upgrade device is always reported as such and never degrades to a
  generic version mismatch; requires the firmware's Secure Element version
  to exactly equal a caller-supplied `ExpectedFirmwareVersion` (validated
  non-empty ASCII, at most 64 bytes, strictly before any transport use);
  sends `open app` with exactly `Sunrise Edge`; and, after a caller
  reconnects, requires the now-active application to report exactly name
  `Sunrise Edge` and exactly version `0.1.0`. The existing six-byte `get
  configuration` response now additionally pins exact version `0.1.0`. The
  existing profile and address preflight (`get configuration` then
  on-device-confirmed `verify public key`) still run only after all of the
  above succeed. `apps/cli`'s all-or-none Ledger signer selection gains a
  required third flag, `--ledger-expected-firmware-version` (validated
  before any device dispatch), and both `address` and `transfer` run this
  complete sequence to completion before `transfer` ever constructs a
  network client. **No physical-device evidence exists for Phase 2a**; it
  is exercised only against `FakeTransport`, exactly like Phase 1.
- **S4c Phase 2b (not yet started):** real hardware validation of Phase 2a's
  exact identity/dashboard sequence, on top of Phase 1's still-unvalidated
  APDU protocol logic, USB HID framing, and device recognition. Only after
  this phase is S4c itself complete.
- **S4d (release gate):** preserve the existing Nano S+ Speculos CI and add
  golden/pixel UI evidence, physical-device HIL for every claimed model
  (including for `clients/ledger`'s own `HidTransport` and identity/
  dashboard sequence, both of which S4c Phase 1/2a leave unvalidated against
  real hardware), broader reset/disconnect/adversarial session evidence,
  verified address/confirmation flows, a pinned, workspace-committed app and
  firmware compatibility matrix across every claimed model — distinct from
  Phase 2a's caller-supplied, per-connection
  `--ledger-expected-firmware-version`, which is not that matrix —
  two-clean-build reproducibility evidence, and release/submission
  evidence.

S4c Phase 1 and Phase 2a are software-only host integration As-Is, and S4c
itself remains incomplete pending Phase 2b's physical-hardware validation.
S4 is complete only after S4c and S4d and after the production signing path
actually replaces the CLI's dev-only `LocalSigner`. Software keystores, OS
keychains, PKCS#11, mTLS client keys, new signature schemes, and general
module registration are outside S4a.

## External references

The separate S4b implementation re-checks and pins its SDK/toolchain against
current primary guidance. Future changes must repeat that check using Ledger's
[device-app getting started guide](https://developers.ledger.com/docs/device-app/getting-started),
[Rust app boilerplate](https://developers.ledger.com/docs/device-app/integration/how-to/app-boilerplate),
[clear-signing transaction guidance](https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions),
[APDU/I/O model](https://developers.ledger.com/docs/device-app/explanation/io), and
[security requirements](https://developers.ledger.com/docs/device-app/integration/requirements/security).
Those references do not weaken the exact Sunrise-specific rules above.

S4c Phase 2a's identity/dashboard commands (CLA `B0` `INS 01`, and
dashboard-context CLA `E0` `INS 01`/`INS D8`) follow the exact
command/response shapes documented by Ledger's own primary-source
TypeScript SDK at a pinned commit
([`LedgerHQ/device-sdk-ts@7f8a719`](https://github.com/LedgerHQ/device-sdk-ts/tree/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d)):
[`GetAppAndVersionCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/GetAppAndVersionCommand.ts),
[`GetOsVersionCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/GetOsVersionCommand.ts),
and
[`OpenAppCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/OpenAppCommand.ts).
These are the primary-source basis for the exact bytes
`clients/ledger::identity` parses and sends; they are not themselves
physical-hardware evidence, and Phase 2a adds none.
