//! Typed, fail-closed errors for [`crate::device::LedgerDevice`].

use std::fmt;

use crate::configuration::ConfigurationError;

/// Every way a [`crate::device::LedgerDevice`] operation can fail.
///
/// Every variant is a fail-closed rejection: this crate never retries past
/// an unexpected status word, never treats an unknown status as success, and
/// never returns a partial signature.
#[derive(Debug)]
pub enum DeviceError<E> {
    /// The underlying [`crate::apdu::Transport`] failed (disconnect, I/O
    /// error, or a fake-transport test failure).
    Transport(E),
    /// Device status `6985`: the user rejected the operation on-device.
    UserRejected,
    /// Device status `6986`: invalid signing state (for example FIRST sent
    /// while already collecting, or CONTINUE/LAST sent while idle).
    InvalidSigningState,
    /// Device status `6A80`: invalid or unrecognized data.
    InvalidOrUnrecognizedData,
    /// Device status `6A84`: a hardware signing profile bound was exceeded.
    ProfileBoundExceeded,
    /// Device status `6A86`: invalid `P1`/`P2`.
    InvalidP1P2,
    /// Device status `6D00`: unsupported `INS`.
    UnsupportedIns,
    /// Device status `6E00`: unsupported `CLA`.
    UnsupportedCla,
    /// Device status `6F00`: internal failure after the device wiped its
    /// state.
    InternalFailure,
    /// A status word this host does not recognize. Never treated as success
    /// or as user rejection.
    UnknownStatus(u16),
    /// A response's data length did not match this command's exact
    /// documented shape (for example `verify public key`'s 32 bytes, `sign
    /// transaction` LAST's 64 bytes, or an intermediate response that must
    /// be empty).
    UnexpectedResponseLength {
        /// Expected exact length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// `get configuration` reported an unsupported profile id or an unknown
    /// flag bit.
    UnsupportedConfiguration(ConfigurationError),
    /// The device-returned public key did not equal the address this
    /// signing session expected.
    PublicKeyMismatch,
    /// A signing frame was empty; a frozen Transaction v1 signature frame is
    /// never empty.
    EmptyFrame,
    /// A signing frame exceeded the frozen hardware signing profile's
    /// maximum framed-message size.
    FrameTooLarge {
        /// Actual frame length.
        actual: usize,
        /// Maximum permitted frame length.
        maximum: usize,
    },
    /// A non-empty signing frame was too short to be split into two
    /// non-empty chunks (see [`crate::device::LedgerDevice::sign_transaction`]'s
    /// doc comment on why every signing session needs both a FIRST and a
    /// separate LAST chunk). This is distinct from [`Self::FrameTooLarge`]:
    /// the frame is too *small*, not too large. Unreachable for any real
    /// Transaction v1 signature frame, which is always far larger than one
    /// byte.
    FrameTooSmall {
        /// Actual frame length.
        actual: usize,
        /// Minimum frame length a signing session can chunk.
        minimum: usize,
    },
    /// Internal invariant violation: chunk planning produced no chunks for
    /// a non-empty, correctly bounded frame. This is a typed, defensive
    /// alternative to a panic; it should never actually occur.
    NoChunksPlanned,
}

impl<E: fmt::Display> fmt::Display for DeviceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "ledger transport failed: {error}"),
            Self::UserRejected => f.write_str("user rejected the operation on-device"),
            Self::InvalidSigningState => f.write_str("device reported invalid signing state"),
            Self::InvalidOrUnrecognizedData => {
                f.write_str("device reported invalid or unrecognized data")
            }
            Self::ProfileBoundExceeded => f.write_str("device reported profile bound exceeded"),
            Self::InvalidP1P2 => f.write_str("device reported invalid P1/P2"),
            Self::UnsupportedIns => f.write_str("device reported unsupported instruction"),
            Self::UnsupportedCla => f.write_str("device reported unsupported instruction class"),
            Self::InternalFailure => f.write_str("device reported an internal failure"),
            Self::UnknownStatus(status) => {
                write!(
                    f,
                    "device returned an unrecognized status word {status:#06x}"
                )
            }
            Self::UnexpectedResponseLength { expected, actual } => write!(
                f,
                "device response was {actual} bytes, expected exactly {expected}"
            ),
            Self::UnsupportedConfiguration(error) => {
                write!(f, "device reported an unsupported configuration: {error}")
            }
            Self::PublicKeyMismatch => {
                f.write_str("device-verified public key did not match the expected address")
            }
            Self::EmptyFrame => f.write_str("signing frame must not be empty"),
            Self::FrameTooLarge { actual, maximum } => {
                write!(f, "signing frame is {actual} bytes, maximum is {maximum}")
            }
            Self::FrameTooSmall { actual, minimum } => {
                write!(f, "signing frame is {actual} bytes, minimum is {minimum}")
            }
            Self::NoChunksPlanned => {
                f.write_str("internal error: no signing chunks were planned for a non-empty frame")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for DeviceError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl<E> From<ConfigurationError> for DeviceError<E> {
    fn from(value: ConfigurationError) -> Self {
        Self::UnsupportedConfiguration(value)
    }
}

/// Maps a raw device status word to its typed meaning.
///
/// `0x9000` is deliberately not represented here: callers check for success
/// first and only call this for a non-success status word.
pub(crate) fn status_to_error<E>(status: u16) -> DeviceError<E> {
    match status {
        crate::apdu::STATUS_USER_REJECTED => DeviceError::UserRejected,
        crate::apdu::STATUS_INVALID_SIGNING_STATE => DeviceError::InvalidSigningState,
        crate::apdu::STATUS_INVALID_DATA => DeviceError::InvalidOrUnrecognizedData,
        crate::apdu::STATUS_PROFILE_BOUND_EXCEEDED => DeviceError::ProfileBoundExceeded,
        crate::apdu::STATUS_INVALID_P1P2 => DeviceError::InvalidP1P2,
        crate::apdu::STATUS_UNSUPPORTED_INS => DeviceError::UnsupportedIns,
        crate::apdu::STATUS_UNSUPPORTED_CLA => DeviceError::UnsupportedCla,
        crate::apdu::STATUS_INTERNAL_FAILURE => DeviceError::InternalFailure,
        other => DeviceError::UnknownStatus(other),
    }
}
