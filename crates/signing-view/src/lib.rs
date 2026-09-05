#![forbid(unsafe_code)]

//! Host/device conformance types for Sunrise Edge's Hardware Signing Profile
//! v1 (see `docs/signing/hardware-signing.md`).
//!
//! This crate implements the *host and device conformance* boundary a
//! dedicated hardware signer (for example, but not limited to, a future
//! Sunrise Edge Ledger device application; see `docs/architecture/README.md` S4a /
//! DR-0088 and DR-0084) must agree on with this workspace: a strictly
//! bounded [`profile::DeviceSigningProfile`], a strict, independent decoder
//! for the exact signed [`transaction::TransactionSignable`] shape, an
//! exact-match [`policy::ClearSigningPolicy`] for recognizing one
//! preinstalled module's arguments, and a deterministic, bounded ASCII
//! [`view::ClearSigningView`] built only from signed bytes.
//!
//! This crate performs no USB/HID/APDU I/O and has no transport dependency:
//! it is pure parsing and rendering logic that either side of a future wire
//! protocol can share or independently reimplement against the same
//! specification. It also does not depend on `execution` or `wasmi`: the
//! `TransactionSignable` decoder in [`transaction`] is a standalone,
//! from-scratch strict decoder for the same wire shape
//! `execution::encode_transaction_signable`/`decode_transaction` implement,
//! proven byte-identical to them by a differential test
//! (`tests/execution_differential.rs`) rather than by sharing code — a
//! device-side reimplementation in a different language must satisfy the
//! same differential property against this crate's fixtures.

pub mod policy;
pub mod profile;
pub mod transaction;
pub mod view;

pub use policy::{ClearSigningPolicy, ClearSigningPolicyError, DEVNET_ASSET_TRANSFER_POLICY};
pub use profile::DeviceSigningProfile;
pub use transaction::{
    TransactionSignable, decode_transaction_signable, encode_transaction_signable,
};
pub use view::{ClearSigningView, TRANSACTION_V1_MESSAGE_TYPE, build_clear_signing_view};

use canonical_encoding::{CanonicalDecodingError, CanonicalEncodingError};
use core::fmt;
use protocol_types::SignatureSchemeId;
use std::error::Error;

/// Errors returned while decoding, recognizing, or rendering a clear-signing
/// view.
///
/// Every variant is a fail-closed rejection: this crate never truncates a
/// field, substitutes a default, or otherwise partially renders a value it
/// cannot fully and exactly account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningViewError {
    /// The outer signature frame failed to decode.
    Crypto(crypto::CryptoError),
    /// The complete framed message exceeded the device profile.
    FramedMessageTooLarge {
        /// Actual framed byte length.
        actual: usize,
        /// Maximum framed byte length.
        maximum: usize,
    },
    /// The inner transaction payload exceeded the device profile.
    TransactionPayloadTooLarge {
        /// Actual payload byte length.
        actual: usize,
        /// Maximum payload byte length.
        maximum: usize,
    },
    /// Canonical encoding failed while re-deriving bytes for a byte-identity
    /// check.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed while parsing a nested frame.
    CanonicalDecoding(CanonicalDecodingError),
    /// An access-manifest entry failed to decode.
    Abi(abi::AbiError),
    /// An object reference or address failed to decode.
    Object(objects::ObjectError),
    /// A fee payment failed to decode.
    Fee(fees::FeeError),
    /// A decoded protocol identifier failed validation.
    ProtocolType(protocol_types::TypeError),
    /// The transaction was not fully recognized by the exact clear-signing policy.
    Policy(ClearSigningPolicyError),
    /// The outer frame's declared message type is not
    /// [`view::TRANSACTION_V1_MESSAGE_TYPE`].
    UnsupportedMessageType(String),
    /// The outer frame's declared signature scheme is not supported by this
    /// profile.
    UnsupportedSignatureScheme(SignatureSchemeId),
    /// A signed field exceeded this device profile's maximum byte length.
    FieldTooLarge {
        /// Name of the oversized field.
        field: &'static str,
        /// Actual byte length.
        actual: usize,
        /// Maximum permitted byte length.
        maximum: usize,
    },
    /// The declared access-manifest entry count exceeded this device
    /// profile's maximum.
    TooManyManifestEntries {
        /// Actual declared entry count.
        actual: usize,
        /// Maximum permitted entry count.
        maximum: usize,
    },
    /// The transaction's `entrypoint` was empty.
    EmptyEntrypoint,
    /// The outer signature frame's replay-protection context (`chain_id`,
    /// `protocol_version`, or `epoch`) does not exactly match the same
    /// field independently carried by the signed
    /// [`transaction::TransactionSignable`] payload.
    ///
    /// Both copies are part of the signed bytes; a legitimately constructed
    /// `PreparedTransaction` always builds them equal (see `clients/rust`).
    /// A mismatch can only come from a tampered or malformed frame, and
    /// this crate fails closed rather than picking one copy to display and
    /// silently ignoring the other.
    SignedContextMismatch {
        /// Name of the mismatched field.
        field: &'static str,
    },
    /// Re-encoding a decoded [`transaction::TransactionSignable`] did not
    /// reproduce its input bytes, meaning the input was not the unique
    /// canonical encoding of its value.
    NonCanonicalTransactionSignableEncoding,
    /// A rendered display field contained a byte outside the profile's
    /// printable-ASCII display set (`0x20..=0x7E`).
    NonAsciiField(&'static str),
    /// The rendered view would exceed this device profile's maximum
    /// display-line count.
    TooManyDisplayLines {
        /// Actual line count.
        actual: usize,
        /// Maximum permitted line count.
        maximum: usize,
    },
    /// One rendered display line exceeded this device profile's maximum
    /// line length.
    DisplayLineTooLong {
        /// Name of the field whose rendered line was too long.
        field: &'static str,
        /// Actual line byte length.
        actual: usize,
        /// Maximum permitted line byte length.
        maximum: usize,
    },
}

impl fmt::Display for SigningViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(error) => error.fmt(f),
            Self::FramedMessageTooLarge { actual, maximum } => write!(
                f,
                "framed signing message is {actual} bytes, maximum is {maximum}"
            ),
            Self::TransactionPayloadTooLarge { actual, maximum } => write!(
                f,
                "transaction signing payload is {actual} bytes, maximum is {maximum}"
            ),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::CanonicalDecoding(error) => error.fmt(f),
            Self::Abi(error) => error.fmt(f),
            Self::Object(error) => error.fmt(f),
            Self::Fee(error) => error.fmt(f),
            Self::ProtocolType(error) => error.fmt(f),
            Self::Policy(error) => write!(f, "clear-signing policy rejected transaction: {error}"),
            Self::UnsupportedMessageType(message_type) => {
                write!(f, "unsupported signature message type: {message_type}")
            }
            Self::UnsupportedSignatureScheme(scheme) => {
                write!(f, "unsupported signature scheme: {}", scheme.as_u16())
            }
            Self::FieldTooLarge {
                field,
                actual,
                maximum,
            } => write!(f, "field {field} is {actual} bytes, maximum is {maximum}"),
            Self::TooManyManifestEntries { actual, maximum } => write!(
                f,
                "access manifest has {actual} entries, maximum is {maximum}"
            ),
            Self::EmptyEntrypoint => write!(f, "transaction entrypoint must not be empty"),
            Self::SignedContextMismatch { field } => write!(
                f,
                "signed field {field} differs between the outer signature frame and the transaction payload"
            ),
            Self::NonCanonicalTransactionSignableEncoding => write!(
                f,
                "decoded transaction-signable payload does not re-encode to its input bytes"
            ),
            Self::NonAsciiField(field) => {
                write!(f, "field {field} contains a non-printable-ASCII byte")
            }
            Self::TooManyDisplayLines { actual, maximum } => write!(
                f,
                "clear-signing view has {actual} lines, maximum is {maximum}"
            ),
            Self::DisplayLineTooLong {
                field,
                actual,
                maximum,
            } => write!(
                f,
                "display line for field {field} is {actual} bytes, maximum is {maximum}"
            ),
        }
    }
}

impl Error for SigningViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Crypto(error) => Some(error),
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::Abi(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Fee(error) => Some(error),
            Self::ProtocolType(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::FramedMessageTooLarge { .. }
            | Self::TransactionPayloadTooLarge { .. }
            | Self::UnsupportedMessageType(_)
            | Self::UnsupportedSignatureScheme(_)
            | Self::FieldTooLarge { .. }
            | Self::TooManyManifestEntries { .. }
            | Self::EmptyEntrypoint
            | Self::SignedContextMismatch { .. }
            | Self::NonCanonicalTransactionSignableEncoding
            | Self::NonAsciiField(_)
            | Self::TooManyDisplayLines { .. }
            | Self::DisplayLineTooLong { .. } => None,
        }
    }
}

impl From<ClearSigningPolicyError> for SigningViewError {
    fn from(value: ClearSigningPolicyError) -> Self {
        Self::Policy(value)
    }
}

impl From<crypto::CryptoError> for SigningViewError {
    fn from(value: crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<CanonicalEncodingError> for SigningViewError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for SigningViewError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<abi::AbiError> for SigningViewError {
    fn from(value: abi::AbiError) -> Self {
        Self::Abi(value)
    }
}

impl From<objects::ObjectError> for SigningViewError {
    fn from(value: objects::ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<fees::FeeError> for SigningViewError {
    fn from(value: fees::FeeError) -> Self {
        Self::Fee(value)
    }
}

impl From<protocol_types::TypeError> for SigningViewError {
    fn from(value: protocol_types::TypeError) -> Self {
        Self::ProtocolType(value)
    }
}
