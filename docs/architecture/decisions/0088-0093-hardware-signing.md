# Architecture decisions DR-0088–DR-0093

Hardware-signing profile, Ledger device contract, application, and host
transport decisions.

- DR-0088: Implement only S4a's hardware-signing profile and host preflight in
  this repository, with the dedicated Ledger application isolated in a
  separate repository and S4 completion reserved for physical evidence.

  **Exact signed source.** Hardware Signing Profile v1 interprets only the
  established `0x2001` v1 signature frame and its `0x6001` v1 Transaction
  signable payload. `crypto` adds a strict decoder but changes no encoder,
  canonical identifier, signature domain, transaction byte, or stable
  historical vector. `signing-view` applies immutable device-sized bounds,
  independently decodes and byte-identically re-encodes the transaction shape
  without an `execution`/`wasmi` runtime dependency, and emits bounded ASCII
  lines only after the complete signed value matches one exact policy.

  **No blind signing.** The first policy is limited to the fixed [`docs/guides/devnet.md`](../../guides/devnet.md)
  reference devnet module id/version/code digest, transfer argument schema,
  three ordered `Write` entries, and source-bound fee authorization. Any
  unknown module/digest/entrypoint/arguments/access/fee shape is a typed
  rejection. Unsigned `request_id`, destination owner, transferred asset
  metadata, module names, or host labels never enter the view. The stable
  fixture pins both the exact frame and display lines for the future device
  repository.

  **Host seam and repository boundary.** `clients/rust` adds no USB/HID or
  Ledger dependency. Its external-signer seam verifies reported scheme and
  address, performs exact-frame clear-signing preflight, invokes the signer on
  that same frame, and retains `PreparedTransaction::finalize` as independent
  signature verification. The dedicated Rust device application belongs in a
  separate `sunrise-edge-ledger-app` repository so custom Ledger targets,
  bindings, Speculos, device workflows, and release artifacts cannot be hidden
  from this workspace gate. Later S4c vendor transport code belongs in a
  separate `clients/ledger` crate and requires an explicit amendment to the
  CLI's one-runtime-dependency decision.

  **Completion boundary.** [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md) fixes the future APDU state machine,
  status words, bounds, clear-signing fields, and a provisional explicitly
  unregistered devnet-only derivation path. S4a has no device app, APDU I/O,
  USB/HID, Speculos, physical-device, registered coin-type, or release evidence;
  `LocalSigner` remains development-only and unchanged. S4b implements and
  emulates the dedicated app, S4c integrates the host/CLI, and S4d requires
  Speculos CI, physical HIL for each claimed model, verified address and user
  confirmation, a pinned app/firmware matrix, reproducible build hash, and
  release/submission evidence. S4 remains incomplete until those criteria and
  the real CLI production signer replacement are satisfied.
- DR-0089: Make eight S4b Ledger device-contract clarifications for details
  [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md) left implicit after DR-0088's freeze, and one correction to DR-0088's explicit
  blanket 230-byte whole-APDU data cap for `sign transaction`: FIRST's
  maximum command data rises from 230 to 255 bytes and its first chunk from
  205 to 230 bytes, while CONTINUE/LAST chunks remain capped at 230 bytes,
  unchanged. Neither the clarifications nor this correction change a
  Sunrise canonical transaction/signature byte, encoder, canonical
  identifier, or the `0x2001`/`0x6001` frame shapes DR-0088 already fixed,
  and no implementation code changes because S4b has no implementation in
  this or any other repository yet.

  **Scope.** This is a documentation-only clarification and correction of
  the future S4b APDU/derivation contract in [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md). It changes no
  code, canonical byte, encoder, or historical vector in this repository,
  and it is not itself S4b device-app or Speculos/physical-device evidence.

  **Clarifications and correction.** (1) Pins the provisional devnet derivation path to
  SLIP-0010 Ed25519 exactly, not only the five-component hardened path
  shape DR-0088 already froze. (2) Defines the returned public key as the
  standard RFC 8032 compressed Ed25519 encoding and distinguishes two Ledger
  SDK paths to it, not treating every Ledger SDK output as raw or manual
  conversion as universally required: starting from
  `ECPrivateKey::public_key`'s raw, uncompressed `04 || X || Y` point, app
  code must convert it (`Y` from the SDK's big-endian byte order to
  little-endian, sign bit from `X`'s parity); using the current Ledger SDK's
  `cx_edwards_compress_point_no_throw` helper, its `pubkey[1..33]` output is
  already the compressed RFC 8032 bytes and must be used as-is, with no
  second reversal or sign-bit transformation. It requires the separate S4b
  repository to add a deterministic test vector (fixed seed/path in, fixed
  32-byte compressed public key out) for whichever path it implements
  before S4b can be considered complete, and, if both paths are
  implemented, to show they agree; no such vector is fabricated in this
  repository, since one written here could not be verified against a real
  device or SDK. (3) Fixes `get configuration` success data at exactly six bytes
  (`profile` `u16`, pinned to `1` for Hardware Signing Profile v1; semver
  `major`/`minor`/`patch` `u8` each; `flags` `u8`), states every currently
  defined flags bit is `0`, defines an unknown flag as any set flag bit
  that either the host's own supported version or the responding device's
  version does not define, and requires a future host to reject a response
  with an unknown flag set rather than ignore it. (4) Separates the app's own `E0`-CLA status-word table
  from Ledger SDK/OS-level statuses it does not own or define — `6E03`
  (the SDK I/O layer's malformed-APDU-length rejection, distinct from the
  app's own `6A80`), `5515` (Ledger OS locked-device status), and `E000`
  (an unhandled panic/exception caught by Ledger's own fault handling) —
  and documents that Ledger's common CLA `B0` is intercepted by the
  platform before reaching this app's dispatcher, while `E0` remains this
  app's own CLA for every command in its table. (5) Requires the device to
  derive the public key from the path supplied on FIRST and compare it
  byte-for-byte against the parsed Transaction v1 `sender` before
  rendering any review screen, returning `6A80` and wiping the buffered
  frame/derivation state on mismatch, so a wrong-key session can never
  reach a display page. (6) Pins the device policy's chain id, protocol
  version, and epoch (`sunrise-local-devnet`, `3`, `0`, the same [`docs/guides/devnet.md`](../../guides/devnet.md)
  reference context DR-0088 already used) together with the exact devnet
  fee `AssetId`
  (`ccad27f687338b99953183728647bc1177388eb45a37afd9812c0d286b433ea8`, the
  normative value `crates/signing-view/src/policy.rs`'s
  `DEVNET_ASSET_TRANSFER_POLICY.fee_asset_id` field fixes, which
  `crates/signing-view/tests/fixtures.rs` exercises only as fixture
  evidence) as one policy, rejecting any other combination rather than
  matching fields independently. (7) Requires a typed rejection when any two of the three
  `Write` access entries (source/destination/treasury) share an
  `ObjectId`, even when mode and position are otherwise well-formed;
  DR-0088's "three ordered `Write` entries" language did not previously
  state this explicitly. (8) **Correction, not clarification:** supersedes
  DR-0088's explicit blanket 230-byte whole-APDU data cap for
  `sign transaction`. The 230-byte figure now names the chunk-payload
  bound specifically (not the whole APDU), and CONTINUE/LAST chunks stay
  capped at 230 bytes, unchanged. FIRST's total command data rises from
  230 to 255 bytes: `total_length` (4 bytes) plus the fixed depth-five
  path (21 bytes) plus up to 230 bytes of first chunk — so FIRST's own
  chunk allowance rises from 205 to 230 bytes. This is a normative change
  to the future APDU wire contract, not a restatement of an existing
  implicit bound; it changes no canonical transaction/signature byte and
  no implementation code, since S4b has no implementation to change.
  (9) States FIRST/CONTINUE success responses carry empty data (only LAST
  carries the 64-byte signature), and that the returned public key equals
  the Sunrise address only because the chain's committed
  `protocol_config::TransactionAuthProfile` — which Hardware Signing
  Profile v1 relies on rather than itself commits — selects
  `AddressIsPublicKey`, not as a general equivalence.

  **Evidence boundary unchanged; byte bound corrected.** DR-0088's S4
  evidence/completion criteria are unchanged by this clarification and
  correction: S4a remains implemented and validated As-Is; S4b still has
  no device application, APDU transport, USB/HID dependency, or
  Speculos/physical-device evidence in this or any other repository,
  S4d's Speculos CI/physical-HIL/reproducible-build gate is untouched, and
  S4 remains incomplete. What DR-0089 does change, per (8) above, is
  DR-0088's explicit blanket 230-byte whole-APDU data cap for
  `sign transaction`: this document corrects — not merely clarifies — it
  to a 255-byte FIRST maximum and a 230-byte first-chunk maximum
  (CONTINUE/LAST unchanged at 230). That correction is confined to the
  future wire contract: no canonical transaction/signature byte, encoder,
  canonical identifier, or implementation code changes, since none exists
  yet for S4b. TypeScript client, explorer, wallet, and S5 remain
  deferred, unaffected by this clarification.
- DR-0090: Establish the first separate-repository S4b implementation milestone
  as a host-validated device core without treating it as a Ledger application or
  S4 completion.

  **Implemented boundary.** `sunriselayer/sunrise-edge-ledger-app` PR #1
  introduces an allocation-free `no_std` core with the application-owned E0
  APDU state machine, exact app status words and chunk bounds, an independent
  from-scratch canonical decoder, strict Transaction v1 and nested-object
  decoding, duplicate-`ObjectId` rejection, the exact devnet transfer policy,
  a signed-fields-only bounded review value, and a `PublicKeyDeriver` boundary.
  The core selects the validated path supplied to that boundary and compares
  the returned RFC 8032 public key byte-for-byte with the signed sender before
  emitting a transaction-review outcome. Its copied fixture is byte-identical
  to `signing-view`'s stable frame at source commit `1dd4d2d`, and all 32 pinned
  display facts are checked independently. Twenty-five host tests and pinned
  GitHub CI validate that slice.

  **No canonical or source-workspace change.** This milestone changes no
  Sunrise Edge canonical encoder, transaction/signature byte, identifier,
  policy activation, or code dependency in this repository. The device core is
  deliberately isolated in the separate repository and depends on none of this
  workspace's crates; copied stable data and differential conformance preserve
  the independence required by DR-0088.

  **Completion boundary.** The merged repository still has no Ledger SDK
  binary, device-target build, actual SLIP-0010 derivation, Ed25519 signing,
  on-device address or transaction UI, APDU/USB/HID transport, Speculos/Ragger
  evidence, reproducible device artifact, or physical-device result. It is a
  host-validated Phase-0 core only, not a dedicated device application and not
  S4b, S4, production, or mainnet readiness. The next S4b slice must integrate
  the core into current Ledger Rust tooling and establish deterministic
  derivation/signing and Speculos UX evidence without weakening these bounds.
  S4c/S4d, the TypeScript client/explorer/wallet, and S5 remain deferred in
  their existing order.
- DR-0091: Complete S4b As-Is in the separate Ledger repository without
  claiming S4, production, or mainnet readiness.

  **Implemented device boundary.** Merged
  `sunriselayer/sunrise-edge-ledger-app` PR #2 (merge commit `6f6f882`) pins
  `ledger_device_sdk` 1.37.0 and digest-pinned official builder/dev-tools
  images, then integrates DR-0090's independent allocation-free core into a
  `no_std`/`no_main` Ledger application. It builds cleanly for Nano S+, Nano X,
  Stax, Flex, and Apex P. The device adapter performs exact SLIP-0010 Ed25519
  derivation at the provisional hardened path, converts the SDK's raw
  `04 || X || Y` point once to RFC 8032 compressed bytes, compares that key
  with the signed Transaction sender before review, renders the bounded
  signed-fields-only policy through NBGL, and signs only the session-captured
  path and exact buffered signature frame after approval.

  **Deterministic evidence.** Host conformance pins every one of the 32 review
  facts and RFC 8032 conversion vectors. A fixed public development seed under
  Nano S+ Speculos/Ragger pins the exact six-byte configuration, exact derived
  public key, and exact 64-byte signature for a 1,221-byte canonical-shape
  fixture whose sender is replaced with that derived key. The byte-identical
  copied source fixture retains its original `01…01` sender and proves sender
  mismatch before review; the suite also proves explicit reset recovery in the
  same emulator backend and user rejection. Unknown INS retains `6D00` while
  wiping an active core session. Malformed APDU length, locked-device, SDK
  fault, in-review `6901`, and CLA `B0` behavior remain explicitly SDK/OS-owned
  rather than application status words. The full Python dependency closure is
  version/hash locked and installed with `--require-hashes`; CI runs host
  checks, every target build, and Nano S+ Speculos from clean checkouts.

  **Compatibility and completion boundary.** No file in this workspace and no
  Sunrise canonical transaction, signature, object, receipt, nonce, submit, or
  protocol-activation byte changed to implement the separate device app. S4b
  is implemented and validated As-Is, but S4 is incomplete. S4c is next: a
  separate `clients/ledger` host APDU/USB/HID crate plus explicit CLI signer
  selection and device/app/firmware/profile/address checks. S4d still requires
  golden/pixel UI evidence, broader adversarial device-session and disconnect/
  reset evidence, physical-device HIL for every claimed model, a pinned
  app/firmware compatibility matrix, two-clean-build reproducibility evidence,
  Ledger release/submission, a registered coin-type decision and migration
  policy, and actual replacement of the CLI's development-only `LocalSigner`.
  Nano X/Stax/Flex/Apex P are build-validated only, not emulated or physically
  validated. TypeScript client, explorer, wallet, and S5 remain deferred in the
  existing order.
- DR-0092: Implement S4c Phase 1 As-Is — a separate `clients/ledger` host
  crate for the frozen device APDU/USB/HID contract, plus explicit,
  all-or-none CLI Ledger signer selection — without claiming S4c itself,
  S4, production, mainnet readiness, or physical-hardware validation.
  **S4c is not complete.** The roadmap's device/app/firmware/profile/address
  check set is only partly satisfied: this phase implements the profile and
  address checks in full and adds USB-descriptor-level device-model
  recognition, but it does not verify the active on-device application's
  name/version or the device firmware version, and nothing in it has been
  validated against physical hardware. The next S4c slice must close that
  gap before S4c itself — not just S4 — can be called complete.

  **New `clients/ledger` crate.** `sunrise-edge-ledger` is the only crate in
  this workspace that may depend on Ledger/APDU/USB/HID vendor code
  (`hidapi`, confined to its `hid` module, using the `linux-native-basic-udev`
  feature so it builds without any system package). It implements the exact
  [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md#device-apdu-contract) "Device APDU contract" against an injectable `apdu::Transport`
  trait: `device::LedgerDevice` drives `get configuration`, `verify public
  key`, `sign transaction`, and `reset signing`; `configuration::Configuration`
  decodes the exact six-byte response and rejects any profile id other than
  `1` or any flag bit this host does not define (the **profile check**);
  `path::DerivationPath` encodes the frozen provisional
  `m/44'/21333'/account'/0'/0'` path (rejecting an `account` value that
  already carries the hardened bit); and `error::DeviceError` maps every
  documented status word (`9000`/`6985`/`6986`/`6A80`/`6A84`/`6A86`/`6D00`/
  `6E00`/`6F00`) to a typed variant, with an unrecognized status word a typed
  `UnknownStatus`, never success. `sign transaction`'s host-side chunking
  sends the frame's first ≤230-byte piece as FIRST, every full-size middle
  piece as CONTINUE, and the final piece as LAST; because [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md) states
  LAST is "valid only while collecting" (never the first APDU) and only
  LAST's response carries the signature, a frame that would otherwise fit
  entirely inside FIRST instead reserves its final byte for a dedicated LAST
  call, so every signing session sends at least one FIRST and one separate
  LAST; a frame too short to reserve that byte (fewer than two bytes) is a
  typed `DeviceError::FrameTooSmall`, distinct from `FrameTooLarge` (the
  frame is too small, not too large) and unreachable for any real
  Transaction v1 frame. If FIRST was accepted (status `9000`) and any later step in that same
  call — a further chunk's status, its response length, or the transport
  itself — then fails, `sign_transaction` attempts a best-effort `reset
  signing` before returning that original error; the reset's own outcome is
  always discarded, so it can never mask the primary error or itself surface
  as the result, and no reset is attempted when FIRST itself is what failed
  (the device never entered a session to wipe). `signer::LedgerExternalSigner`
  implements `sunrise_edge_client::ExternalSigner`: `connect` checks `get
  configuration` and fetches (with mandatory on-device confirmation) the
  public key/address before returning it to a caller, and `sign_frame`
  independently repeats both checks immediately before every signature,
  rather than trusting the connect-time result — the **profile and address**
  halves of "device-reported configuration/public key/address checks before
  signing". Every module above `hid` is generic over `Transport`, so
  `fake::FakeTransport` (a deterministic, pre-scripted, request-recording
  fake, analogous to `runtime`'s `Memory*` test adapters) exercises the
  complete protocol — chunking at every documented boundary, exact response
  lengths, every status word, configuration/flag rejection, public
  key/address identity and mismatch, mid-sequence disconnect, and the
  best-effort reset attempt (including when the transport remains usable for
  the reset call and when it does not) — with no native dependency, in the
  crate's default-feature and `usb-hid` all-feature unit tests.

  **`hid::HidTransport`: real, device-checked, but not hardware-validated.**
  This module owns two independent layers. First, USB device identification
  (the **device** check): `HidTransport::open` resolves the caller's exact
  path through `HidApi::device_list`, checks every descriptor record sharing
  that path (one physical device may expose several HID top-level
  collections), and requires at least one record to satisfy all three
  identity fields — Ledger's USB vendor id `0x2c97`, a product-id family in
  the exact S4b five-target build list (Nano X, Nano S Plus, Stax, Flex,
  Apex P — see DR-0091; the plain Nano S is deliberately excluded, since no
  S4b build target covers it), and exactly the Ledger HID usage page
  `0xffa0`. Some host libraries, including the independently published
  Zondax `ledger-go`, also accept a device reporting interface number `0` as
  an alternative to the usage page (a workaround for platforms that report
  an empty/zero usage page); this phase does not implement that fallback —
  without current official primary-source evidence for it and a tested,
  platform-`cfg`-specific policy for when it is safe, a mismatched usage
  page is treated as unrecognized. An unrecognized vendor id, product
  family, or usage page is a typed rejection before `HidApi::open_path` is
  ever called; when every same-path record is invalid, the typed error is
  selected independently of enumeration order. This is USB-descriptor-level
  identity only: it is not, and cannot be over this transport, the active
  on-device application's name/version or the device firmware version.
  Those live on two different CLAs depending on device context, neither of
  which this module sends: the active application's name/version is CLA
  `B0` `INS 01`; the device firmware version is CLA `E0` `INS 01`, but only
  while the device is at the dashboard with no application open — a
  distinct, OS-owned use of the same CLA byte `E0` this workspace's own
  Sunrise application uses for its own signing commands once it is the
  active app (see [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md#device-apdu-contract), "Device APDU contract"). Verifying both
  therefore requires a staged sequence this phase does not implement: probe
  at the dashboard first, then open (or have the operator open) the Sunrise
  application and reconnect, then send this crate's own `E0` commands.
  Verifying the **app** and **firmware** checks is the explicitly
  unimplemented next S4c slice.
  Second, the generic USB HID packet framing every Ledger device application
  uses (fixed 64-byte reports, a `0x0101` channel id, a `0x05` tag, and a
  big-endian sequence index — one layer below, and independent of, the
  APDU-level FIRST/CONTINUE/LAST chunking above): every `hid_write` call
  must report writing the complete packet or the write is a typed
  `ShortWrite`; reassembly distinguishes a genuinely incomplete response
  (needs more packets) from a malformed one (wrong channel/tag, an
  out-of-order sequence index, or a declared length over the bounded
  short-APDU maximum of 260 bytes — up to 258 response-data bytes plus the
  2-byte status word) and fails immediately on the latter
  rather than looping until a timeout; and each complete read is bounded by
  a command-class wall-clock deadline (30 seconds for programmatic commands,
  120 seconds for each `verify public key` or signing LAST command that waits
  for a human), never a per-packet timeout multiplied by a packet-count
  limit, plus a small secondary packet-count bound. Every arithmetic step in this framing (offsets, remaining lengths,
  sequence increments) uses checked arithmetic with a typed
  `FramingBoundsExceeded` fallback in place of a panic or a silent
  saturating/truncating substitute. Its pure encode/decode functions have
  self-consistent round-trip unit tests plus independently hand-built byte
  vectors (not generated by this module's own encoder) matching the
  documented framing; neither proves agreement with real Ledger firmware,
  since no physical device or Speculos bridge was available to validate
  against in this change — real hardware-in-the-loop evidence for
  `HidTransport`, including whether its USB HID framing and device
  identification actually match real hardware, remains explicitly deferred.
  `hidapi`'s `linux-native-basic-udev` feature needs no system package (unlike
  the `linux-static-hidraw`/`linux-static-libusb` features, which need
  `libudev`/`libusb-1.0` development headers this environment lacks), so
  `hid` and the `hidapi` dependency are behind an off-by-default `usb-hid`
  Cargo feature on both `sunrise-edge-ledger` and `sunrise-edge-cli` purely
  to keep the default (non-`--all-features`) build/test/clippy gate free of
  any native dependency; `cargo clippy --workspace --all-targets
  --all-features` and `cargo test --workspace --all-targets --all-features`
  both pass in this environment with no system package installed.

  **CLI signer selection amends the one-runtime-dependency invariant.**
  `apps/cli` now depends on `sunrise-edge-ledger` in addition to
  `sunrise-edge-client` — [DR-0084](0081-0087-cli-first-roadmap.md)'s original "exactly one non-development/
  runtime dependency" is revised to exactly these two, both still owning no
  application-specific (devnet) semantics. A new `apps/cli::signer` module
  adds `--seed-file`, `--ledger-hid-path`, and `--ledger-account` flags to
  `address` and `transfer`; `parse_signer_selection` requires exactly
  `--seed-file` alone or both Ledger flags together, rejecting neither, both
  groups at once, or exactly one Ledger flag, before any network dispatch or
  device connection. A Ledger selection resolves and verifies the signer
  (`signer::connect_ledger_with`, generic over `Transport` and tested with
  `FakeTransport`) strictly before `transfer` ever constructs a network
  `Client`, so a Ledger connection failure or on-device rejection is reported
  before any request reaches the node. Without the `usb-hid` feature, a
  Ledger selection fails closed with a typed `CliError::LedgerTransportFeatureDisabled`
  rather than silently falling back to the local signer. `transfer`'s Ledger
  path builds a `PreparedTransaction` exactly as the local path does, then
  calls `sign_and_finalize_external` with `DeviceSigningProfile::V1` and
  `DEVNET_ASSET_TRANSFER_POLICY` — the same host preflight DR-0088 already
  implements — so canonical transaction/signature bytes and the local-signer
  path are both completely unchanged. A feature-independent `FakeTransport`
  test executes this exact CLI helper with a real policy-conforming
  `PreparedTransaction` and a valid Ed25519 response, compares its canonical
  output with the local signer, and proves a policy mismatch is rejected
  before device signing. The current operator interaction is also explicit:
  `address` requires one on-device address confirmation, while `transfer`
  requires three (connect-time address, repeated pre-sign address, then the
  transaction review). The repeated address prompt is deliberate fail-closed
  Phase 1 behavior, not a production-UX claim.

  **Completion boundary.** This is S4c Phase 1 host integration As-Is only,
  and S4c itself is not complete. It adds no device application, no
  active-app/firmware identity check, no physical-device evidence, no
  registered SLIP-0044 allocation, and no release artifact; `LocalSigner`
  remains the CLI's only actually-replaceable-in-production signing path,
  unchanged. The next S4c slice must add the active on-device application
  name/version check (CLA `B0` `INS 01`) and the device firmware version
  check (CLA `E0` `INS 01` in dashboard context, staged before the Sunrise
  application is opened — see the `hid::HidTransport` discussion above),
  neither of which this app sends today, and real
  hardware validation boundaries for `HidTransport` (confirming its USB HID
  framing, device identification, write/read behavior, and best-effort
  reset actually work against physical devices, not only against
  `FakeTransport`), before S4c can be considered complete. S4 remains
  incomplete until S4c finishes, S4d supplies golden/pixel UI evidence,
  physical-device HIL for every claimed model, broader adversarial
  session/disconnect evidence, a pinned app/firmware compatibility matrix,
  two-clean-build reproducibility evidence, Ledger release/submission
  evidence, and the CLI's default signing path actually replaces
  `LocalSigner`. TypeScript client, explorer, wallet, and S5 remain deferred
  in the existing order.
- DR-0093: Implement S4c Phase 2a As-Is — strict Ledger OS identity/
  dashboard parsing and a staged dashboard/firmware/open-app/reconnect/
  active-app identity sequence in `clients/ledger`, plus a required
  `--ledger-expected-firmware-version` CLI flag — without claiming S4c
  itself, S4, production, mainnet readiness, or physical-hardware
  validation.

  **What Phase 2a adds.** DR-0092 (S4c Phase 1) implemented the profile and
  address checks and USB-descriptor-level device recognition, but explicitly
  did not verify the active on-device application's identity or the device
  firmware, and validated none of it against physical hardware. Phase 2a
  closes the app/firmware identity gap in software: a new
  `clients/ledger::identity` module implements Ledger's own OS-owned
  identity/dashboard commands — CLA `B0` `INS 01` ("Get App And Version")
  and, only in dashboard context, CLA `E0` `INS 01` ("Get OS Version") and
  CLA `E0` `INS D8` ("Open App") — against strict, typed parsers, following
  the exact command/response shapes documented by Ledger's own primary-
  source TypeScript SDK at a pinned commit
  ([`LedgerHQ/device-sdk-ts@7f8a719`](https://github.com/LedgerHQ/device-sdk-ts/tree/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d)):
  [`GetAppAndVersionCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/GetAppAndVersionCommand.ts),
  [`GetOsVersionCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/GetOsVersionCommand.ts),
  and
  [`OpenAppCommand.ts`](https://github.com/LedgerHQ/device-sdk-ts/blob/7f8a71900be5351fcaca2e92f6a877a2bb3d8d7d/packages/device-management-kit/src/api/command/os/OpenAppCommand.ts).
  These citations are the primary-source basis for the exact bytes this
  phase parses and sends; they are not themselves physical-hardware
  evidence, and this phase adds none.

  **Strict identity parsing and bounds.** `get app and version` is decoded as
  a leading format byte (must equal `1`), a non-empty ASCII `u8`-length-
  prefixed name, a non-empty ASCII `u8`-length-prefixed version, and an
  optional trailing `u8`-length-prefixed flags field, with any further byte
  a typed rejection (`TrailingBytes`); the dashboard `get version` (firmware)
  response is decoded as a big-endian `u32` target id, a non-empty ASCII
  `u8`-length-prefixed Secure Element version, a `u8`-length-prefixed flags
  field, and zero or more further complete `u8`-length-prefixed fields
  (accepted but not otherwise interpreted, since Ledger firmware may report
  additional MCU/BLE version fields this host does not need). Both parsers
  reject a response longer than Ledger's own 258-byte short-APDU response-
  data cap (`ResponseTooLong`) before parsing any field, independent of
  whether the transport enforces that bound itself — `FakeTransport` does
  not, so this is exercised with hand-built oversized-but-otherwise-
  well-formed fixtures, not only a bad length prefix.

  **Staged dashboard/firmware/open-app/reconnect/active-app sequence.**
  `verify_dashboard_and_open` requires the device to be at the dashboard
  reporting exactly `BOLOS` over CLA `B0` before it ever sends the OS-owned
  CLA `E0` firmware query — the same CLA byte this app's own frozen `E0`
  contract uses once the Sunrise application is open, reachable only before
  that happens (see [`docs/signing/hardware-signing.md`](../../signing/hardware-signing.md#device-apdu-contract), "Device APDU contract"). It then requires
  the dashboard-reported target id's top nibble to identify a normal Secure
  Element OS response (USB model recognition remains a separate descriptor
  check) and rejects any reported version (dashboard app or
  firmware) containing an `-osu` marker — an OS Upgrade state, not a normal
  operating state — strictly *before* comparing the firmware version, so a
  bootloader-mode or mid-upgrade device is always reported as such and
  never degrades to a generic "firmware mismatch". Only once target id and
  OSU state are both clean does it require the firmware's Secure Element
  version to exactly equal a caller-supplied `ExpectedFirmwareVersion`
  (validated non-empty ASCII, at most 64 bytes, strictly before any
  transport use), then sends `open app` with the exact ASCII bytes `Sunrise
  Edge`. A caller then reconnects — a real `HidTransport` reopens the
  identical explicit path, since this app never itself changes which device
  path an operator selected — and `verify_active_app` requires the now-
  active application to report exactly name `Sunrise Edge` and exactly
  version `0.1.0` over CLA `B0`. Every check is a typed `IdentityError`, and
  the existing profile and address checks (`get configuration` decode/
  require, then on-device-confirmed `verify public key`) still run only
  after all of the above succeed, unchanged from DR-0092.

  **Existing six-byte configuration now also pins `0.1.0`.**
  `configuration::Configuration::require_supported` (the app's own frozen
  `E0` `get configuration` response, distinct from CLA `B0`'s OS-reported
  identity string) previously accepted any semver; it now additionally
  requires the reported major/minor/patch to equal exactly `0.1.0`
  (`ConfigurationError::UnsupportedVersion`), matching the application
  identity this phase now checks over CLA `B0`.

  **CLI: a required third Ledger flag, and same-path reconnect.**
  `apps/cli`'s all-or-none Ledger signer selection gains a required third
  flag, `--ledger-expected-firmware-version`, alongside the existing
  `--ledger-hid-path`/`--ledger-account` pair (all three or none); it is
  validated before any device dispatch. `signer::connect_ledger_staged`
  (generic over `Transport`, unit-tested end to end with `FakeTransport`)
  runs the complete staged sequence above, then the unchanged profile/
  address preflight, before returning a connected `LedgerExternalSigner`.
  Its real `usb-hid` reconnect (`reconnect_same_hid_path`) retries
  `HidTransport::open` at the exact same caller-supplied path with a bounded
  monotonic deadline (30 seconds) and a fixed retry sleep (500 milliseconds)
  between attempts — never an unbounded loop — failing closed with a typed
  `CliError::LedgerReconnectTimedOut` carrying the most recent attempt's
  failure if the device never reappears in time. Both `address` and
  `transfer` run every device check (dashboard, firmware, open app,
  reconnect, active app, profile, address) to completion before `transfer`
  ever constructs its network `Client`, extending DR-0092's "device checks
  before any request reaches the node" property to the fuller check set.

  **Completion boundary.** `S4c` **remains incomplete**, and so does S4.
  Every check this phase adds is exercised only against `FakeTransport`;
  no physical Ledger device, and no Speculos bridge, has been used to
  validate any byte this phase sends or parses — the primary-source SDK
  citations above establish where the shapes come from, not that this host
  has been proven to interoperate with real firmware. **S4c Phase 2b**,
  physical-hardware validation of this exact sequence (and of the
  still-unvalidated `HidTransport` USB HID framing/device recognition from
  DR-0092), is next. The caller-supplied `ExpectedFirmwareVersion` is a
  per-connection operator input, not S4d's still-deferred pinned, workspace-
  committed multi-model app/firmware compatibility matrix — this phase adds
  no such matrix. S4d's remaining golden/pixel UI evidence, physical-device
  HIL for every claimed model, broader adversarial session/disconnect
  evidence, two-clean-build reproducibility evidence, and Ledger release/
  submission evidence are unaffected and still deferred, as are the
  TypeScript client/explorer/wallet surface and S5.
