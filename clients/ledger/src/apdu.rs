//! The frozen `E0`-CLA APDU byte contract (see `SIGNING.md`, "Device APDU
//! contract") and the injectable [`Transport`] boundary every host command
//! is built on.
//!
//! This module defines only the exact command/status bytes `SIGNING.md`
//! freezes; it performs no I/O itself.

/// This application's fixed instruction class.
pub const CLA: u8 = 0xE0;

/// `get configuration` instruction.
pub const INS_GET_CONFIGURATION: u8 = 0x00;
/// `verify public key` instruction.
pub const INS_VERIFY_PUBLIC_KEY: u8 = 0x02;
/// `sign transaction` instruction.
pub const INS_SIGN_TRANSACTION: u8 = 0x04;
/// `reset signing` instruction.
pub const INS_RESET_SIGNING: u8 = 0x06;

/// The only `P1` `get configuration` and `reset signing` ever use.
pub const P1_DEFAULT: u8 = 0x00;

/// `verify public key`'s only valid `P1`; `P1=00` is invalid because the
/// command always requires on-device confirmation.
pub const P1_VERIFY_PUBLIC_KEY: u8 = 0x01;

/// `sign transaction` FIRST: valid only while idle.
pub const P1_SIGN_FIRST: u8 = 0x00;
/// `sign transaction` CONTINUE: valid only while collecting.
pub const P1_SIGN_CONTINUE: u8 = 0x01;
/// `sign transaction` LAST: valid only while collecting.
pub const P1_SIGN_LAST: u8 = 0x02;

/// The only `P2` this application's `E0` CLA ever uses.
pub const P2_DEFAULT: u8 = 0x00;

/// Success.
pub const STATUS_SUCCESS: u16 = 0x9000;
/// User rejected the operation.
pub const STATUS_USER_REJECTED: u16 = 0x6985;
/// Invalid signing state (e.g. FIRST during collection, or CONTINUE/LAST
/// while idle).
pub const STATUS_INVALID_SIGNING_STATE: u16 = 0x6986;
/// Invalid or unrecognized data.
pub const STATUS_INVALID_DATA: u16 = 0x6A80;
/// A declared or accumulated bound of the hardware signing profile was
/// exceeded.
pub const STATUS_PROFILE_BOUND_EXCEEDED: u16 = 0x6A84;
/// Invalid `P1`/`P2`.
pub const STATUS_INVALID_P1P2: u16 = 0x6A86;
/// Unsupported `INS`.
pub const STATUS_UNSUPPORTED_INS: u16 = 0x6D00;
/// Unsupported `CLA`.
pub const STATUS_UNSUPPORTED_CLA: u16 = 0x6E00;
/// Internal failure after the device wiped its state.
pub const STATUS_INTERNAL_FAILURE: u16 = 0x6F00;

/// Maximum accepted short-APDU response data length, excluding the trailing
/// two-byte status word. Higher-level decoders enforce this too so an
/// injected transport cannot bypass the physical framing bound.
pub const MAX_RESPONSE_DATA_LEN: usize = 258;

/// One complete APDU command: `CLA || INS || P1 || P2 || Lc || data`.
///
/// `data` must fit the short (single-byte `Lc`) APDU form: at most 255
/// bytes. Every command this crate builds against the frozen `SIGNING.md`
/// contract satisfies that bound by construction (FIRST's own command data
/// is capped at 255 bytes; every other command is far smaller), so this
/// type does not itself re-validate the bound — [`crate::device::LedgerDevice`]
/// only ever constructs commands within it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApduCommand {
    /// Instruction class. Always [`CLA`] for every command this crate sends.
    pub cla: u8,
    /// Instruction code.
    pub ins: u8,
    /// First parameter byte.
    pub p1: u8,
    /// Second parameter byte.
    pub p2: u8,
    /// Command data.
    pub data: Vec<u8>,
}

/// One complete APDU response: response data followed by a two-byte status
/// word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApduResponse {
    /// Response data. Empty for every success response except `verify public
    /// key` (32 bytes) and `sign transaction` LAST (64 bytes).
    pub data: Vec<u8>,
    /// The exact two-byte status word (see the `STATUS_*` constants above).
    pub status_word: u16,
}

/// An injectable boundary for exchanging one already-framed [`ApduCommand`]
/// for one [`ApduResponse`].
///
/// This is the seam every deterministic test in this crate substitutes with
/// [`crate::fake::FakeTransport`] instead of real USB/HID hardware. A real
/// implementation ([`crate::hid::HidTransport`]) additionally owns whatever
/// lower-level USB/HID packet framing its physical link requires; that
/// framing is entirely opaque to this trait and to every type in
/// [`crate::device`].
pub trait Transport {
    /// Implementation-specific transport failure (a USB/HID I/O error, a
    /// disconnect, or a fake-transport test failure).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sends `command` and returns the device's complete response.
    ///
    /// A transport must never fabricate a status word: it either returns
    /// exactly the bytes the device sent (data plus trailing status word),
    /// or fails with `Self::Error` (for example on disconnect, timeout, or a
    /// malformed/short physical frame).
    fn exchange(&mut self, command: &ApduCommand) -> Result<ApduResponse, Self::Error>;
}
