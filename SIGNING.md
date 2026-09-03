# Sunrise Edge hardware signing

This document specifies Hardware Signing Profile v1, the S4a host/device
conformance boundary. It does not document a released hardware wallet.

S4a is implemented As-Is: the hardware signing profile, the clear-signing
view derived only from the exact signed frame, and the host seam. **No Ledger
device application, APDU transport, USB/HID dependency, Speculos evidence, or
physical-device evidence exists in this repository. S4 is not complete.**
`LocalSigner` remains a development-only, non-keystore in-memory key with no
zeroization; S4a does not replace it.

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
  version `3`, and epoch `0` (the README reference context) — any other
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
  `ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8`
  (`DEVNET_ASSET_ID`, the same value used by
  `crates/signing-view/tests/fixtures.rs`).

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
different, wrong public key/address rather than a decode error. **S4b is not
complete until the separate device-app repository adds a pinned,
deterministic test vector** (fixed seed/path in, fixed 32-byte compressed
public key out) **exercising whichever of the two paths above the device app
implements; if the device app implements both, the vector must additionally
show they agree on the same output for the same input.** This document
intentionally does not assert such a vector's bytes, since fabricating one
here would not be verified against a real device or SDK.

This provisional path may be used only by devnet/Speculos builds. A Ledger
submission or mainnet claim requires a later decision record that pins the
registered allocation and migration policy; changing it requires a new
hardware signing profile rather than silently reinterpreting v1.

## Future APDU contract

S4a freezes the following byte contract for the separate
`sunrise-edge-ledger-app` repository. It does not implement transport code.
All multi-byte APDU integers are big-endian, independently of canonical
transaction integers inside the opaque chunk stream.

| Name | CLA | INS | P1 | P2 | Command data | Success data |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| get configuration | `E0` | `00` | `00` | `00` | empty | exactly 6 bytes: profile `u16`, semver `major`/`minor`/`patch` `u8` each, flags `u8` |
| verify public key | `E0` | `02` | `01` | `00` | derivation path | exact 32-byte Ed25519 public key/address |
| sign transaction | `E0` | `04` | see below | `00` | header/chunk or chunk | exact 64-byte Ed25519 signature on final approval |
| reset signing | `E0` | `06` | `00` | `00` | empty | empty |

`get configuration`'s six success bytes are, in order: `profile` (`u16`),
`major`/`minor`/`patch` (one `u8` each), then `flags` (`u8`). Every flags bit
defined by this document is currently `0`; there is no defined non-zero bit.
A future host that recognizes a flags bit its own supported version does not
define must reject the response as an unsupported configuration rather than
silently ignore the unknown bit.

The path encoding is one depth byte followed by exactly that many big-endian
`u32` hardened components. Profile v1 requires depth five and the provisional
path above, i.e. exactly 21 bytes (1 depth byte + 5 × 4-byte components).
`verify public key` always requires on-device confirmation; P1 `00` is
invalid. The host must compare the returned key with the prepared
transaction sender before sending any signing chunk. The returned 32-byte
value is the raw Ed25519 public key; it is also usable directly as the
Sunrise on-chain address only because Profile v1's committed
`TransactionAuthProfile` selects the `AddressIsPublicKey` address binding
(see `ARCHITECTURE.md`). This document does not claim public key and address
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
SDK/OS layer beneath the app, which this document does not define and which
the separate S4b repository must re-verify against current Ledger platform
documentation rather than assume from this table:

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
- CLA `B0`: Ledger's common/dashboard CLA, used for device/app/firmware
  discovery and other platform-level requests per Ledger's own integration
  guidelines. Ledger devices intercept CLA `B0` before it reaches this
  application's dispatcher; the Sunrise app never receives, handles, or
  redefines CLA `B0` behavior. `E0` remains this app's own CLA for every
  command in the table above, unaffected by CLA `B0` interception.

## Delivery sequence

- **S4a (this repository, As-Is):** strict signature-frame decoding,
  device-profile transaction decoding, exact clear-signing policy and stable
  display fixture, plus the Rust client's external-signer seam.
- **S4b (separate repository):** a dedicated Rust Ledger application based
  on Ledger's Rust application tooling, independently parsing the exact frame
  and passing the shared fixtures under Speculos. Solana and Ethereum apps
  are never reused.
- **S4c (this repository):** a separate `clients/ledger` host crate for the
  APDU/USB boundary and an explicit CLI signer choice. Vendor dependencies do
  not enter protocol crates or `clients/rust`.
- **S4d (release gate):** Speculos CI plus physical-device HIL for every
  claimed model, verified address/confirmation flows, pinned app and firmware
  matrix, reproducible device-app build hash, and release/submission evidence.

S4c is only host integration As-Is. S4 is complete only after S4d and after
the production signing path actually replaces the CLI's dev-only
`LocalSigner`. Software keystores, OS keychains, PKCS#11, mTLS client keys,
new signature schemes, and general module registration are outside S4a.

## External references

The separate S4b implementation must re-check current primary guidance before
pinning its SDK/toolchain: Ledger's
[device-app getting started guide](https://developers.ledger.com/docs/device-app/getting-started),
[Rust app boilerplate](https://developers.ledger.com/docs/device-app/integration/how-to/app-boilerplate),
[clear-signing transaction guidance](https://developers.ledger.com/docs/device-app/integration/design-guidelines/transactions),
[APDU/I/O model](https://developers.ledger.com/docs/device-app/explanation/io), and
[security requirements](https://developers.ledger.com/docs/device-app/integration/requirements/security).
Those references do not weaken the exact Sunrise-specific rules above.
