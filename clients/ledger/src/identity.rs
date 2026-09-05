//! Ledger OS ("BOLOS") identity/dashboard commands: the currently active
//! application's name/version (CLA `B0` `INS 01`, "get app and version"),
//! the dashboard's own firmware identity (CLA `E0` `INS 01`, reachable only
//! while the device is at the dashboard with no application open), and
//! opening an application (CLA `E0` `INS D8`, "open app"). See `docs/signing/hardware-signing.md`,
//! "Device APDU contract", the CLA `B0`/dashboard `E0` bullets.
//!
//! These are Ledger OS-owned commands, not this app's own frozen `E0`
//! contract in [`crate::apdu`]: CLA `B0` is handled by the Ledger Rust
//! SDK's I/O layer (`Comm::next_command`) before it is ever dispatched to
//! the Sunrise application's own command loop, and dashboard-context
//! `E0` `INS 01`/`INS D8` are reachable only before the Sunrise application
//! is the active app.

use std::fmt;

use crate::apdu::{ApduCommand, ApduResponse, MAX_RESPONSE_DATA_LEN, STATUS_SUCCESS, Transport};

/// CLA Ledger reserves for the currently active application's own identity,
/// handled by the Ledger Rust SDK's I/O layer before it is ever dispatched
/// to this app.
pub const CLA_APP: u8 = 0xB0;
/// `get app and version`.
pub const INS_GET_APP_AND_VERSION: u8 = 0x01;

/// CLA the Ledger OS dashboard uses for its own commands. This is the exact
/// same CLA byte value as [`crate::apdu::CLA`], but a distinct, OS-owned
/// protocol reachable only while the device is at the dashboard with no
/// application open.
pub const CLA_DASHBOARD: u8 = 0xE0;
/// Dashboard `get version` (firmware identity).
pub const INS_DASHBOARD_GET_VERSION: u8 = 0x01;
/// Dashboard `open app`.
pub const INS_DASHBOARD_OPEN_APP: u8 = 0xD8;

const P1_DEFAULT: u8 = 0x00;
const P2_DEFAULT: u8 = 0x00;

/// `get app and version`'s only defined response format.
const APP_AND_VERSION_FORMAT: u8 = 1;

/// This app's own exact expected name, per `get app and version` while it is
/// the active application.
pub const EXPECTED_APP_NAME: &str = "Sunrise Edge";
/// This app's own exact expected version string, per `get app and version`.
pub const EXPECTED_APP_VERSION: &str = "0.1.0";
/// The Ledger OS dashboard's own fixed application name.
pub const DASHBOARD_APP_NAME: &str = "BOLOS";

/// Longest ASCII firmware version string [`ExpectedFirmwareVersion::new`]
/// accepts.
const MAX_FIRMWARE_VERSION_LEN: usize = 64;

/// Top nibble every accepted Ledger target id must have, per Ledger's own
/// target-id convention for a normal Secure Element OS response; any other
/// top nibble (for example a bootloader-mode target id) is rejected. USB
/// product-model recognition remains a separate descriptor check.
const EXPECTED_TARGET_ID_TOP_NIBBLE: u32 = 3;

/// Substring identifying an OS Upgrade (OSU) version — a special mode used
/// only during a firmware update, never a normal operating state this host
/// proceeds past. Matched case-insensitively.
const OSU_MARKER: &str = "-osu";

/// A decoded `get app and version` (CLA `B0` `INS 01`) response identifying
/// the currently active application (which may be the dashboard itself,
/// reported as [`DASHBOARD_APP_NAME`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIdentity {
    /// The active application's exact reported name.
    pub name: String,
    /// The active application's exact reported version string.
    pub version: String,
    /// The optional trailing flags field, if the device reported one.
    pub flags: Option<Vec<u8>>,
}

/// A decoded dashboard `get version` (CLA `E0` `INS 01`, dashboard context
/// only) response identifying the device firmware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareIdentity {
    /// The device's big-endian target id.
    pub target_id: u32,
    /// The Secure Element firmware version string.
    pub se_version: String,
    /// The Secure Element state flags reported by the Ledger OS.
    pub se_flags: Vec<u8>,
}

/// Errors parsing a raw identity/dashboard response's byte shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityParseError {
    /// The response ended before a required field was complete.
    Truncated,
    /// A field required to be non-empty (a name or version) was empty.
    EmptyField,
    /// A field required to be ASCII contained a non-ASCII byte.
    NotAscii,
    /// `get app and version`'s leading format byte was not
    /// [`APP_AND_VERSION_FORMAT`].
    UnsupportedFormat(u8),
    /// Bytes remained after every defined/optional field was consumed.
    TrailingBytes {
        /// Offset the first trailing byte was found at.
        at: usize,
        /// Total response length.
        total: usize,
    },
    /// The response data exceeded [`MAX_RESPONSE_DATA_LEN`].
    ResponseTooLong {
        /// Actual response data length.
        actual: usize,
        /// Maximum permitted response data length.
        maximum: usize,
    },
}

impl fmt::Display for IdentityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("response ended before a required field was complete"),
            Self::EmptyField => f.write_str("a required non-empty field was empty"),
            Self::NotAscii => f.write_str("a required ASCII field contained a non-ASCII byte"),
            Self::UnsupportedFormat(format) => {
                write!(f, "unsupported response format byte {format:#04x}")
            }
            Self::TrailingBytes { at, total } => {
                write!(f, "response had {total} bytes but only {at} were consumed")
            }
            Self::ResponseTooLong { actual, maximum } => write!(
                f,
                "response data is {actual} bytes, exceeding the {maximum}-byte short-APDU cap"
            ),
        }
    }
}

impl std::error::Error for IdentityParseError {}

/// Errors validating a caller-supplied expected firmware version string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedFirmwareVersionError {
    /// The version string was empty.
    Empty,
    /// The version string contained a non-ASCII byte.
    NotAscii,
    /// The version string exceeded [`MAX_FIRMWARE_VERSION_LEN`].
    TooLong {
        /// Actual length.
        actual: usize,
        /// Maximum permitted length.
        maximum: usize,
    },
}

impl fmt::Display for ExpectedFirmwareVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("expected firmware version must not be empty"),
            Self::NotAscii => f.write_str("expected firmware version must be ASCII"),
            Self::TooLong { actual, maximum } => write!(
                f,
                "expected firmware version is {actual} bytes, maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for ExpectedFirmwareVersionError {}

/// A validated expected firmware version string, checked non-empty, ASCII,
/// and within [`MAX_FIRMWARE_VERSION_LEN`] before any transport use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedFirmwareVersion(String);

impl ExpectedFirmwareVersion {
    /// Validates `version` before any transport is ever touched.
    pub fn new(version: impl Into<String>) -> Result<Self, ExpectedFirmwareVersionError> {
        let version = version.into();
        if version.is_empty() {
            return Err(ExpectedFirmwareVersionError::Empty);
        }
        if !version.is_ascii() {
            return Err(ExpectedFirmwareVersionError::NotAscii);
        }
        if version.len() > MAX_FIRMWARE_VERSION_LEN {
            return Err(ExpectedFirmwareVersionError::TooLong {
                actual: version.len(),
                maximum: MAX_FIRMWARE_VERSION_LEN,
            });
        }
        Ok(Self(version))
    }

    /// Returns the validated version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Every way an identity/dashboard command can fail.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityError<E> {
    /// The underlying [`Transport`] failed.
    Transport(E),
    /// `command` returned a status word other than [`STATUS_SUCCESS`].
    UnexpectedStatus {
        /// The command that failed.
        command: &'static str,
        /// The exact status word returned.
        status_word: u16,
    },
    /// `command`'s response could not be parsed.
    Malformed {
        /// The command whose response was malformed.
        command: &'static str,
        /// The parse failure.
        error: IdentityParseError,
    },
    /// The reported application name did not equal the expected name.
    UnexpectedAppName {
        /// Expected name.
        expected: &'static str,
        /// Actual reported name.
        actual: String,
    },
    /// The reported application version did not equal the expected version.
    UnexpectedAppVersion {
        /// Expected version.
        expected: String,
        /// Actual reported version.
        actual: String,
    },
    /// The reported firmware version did not equal the caller-supplied
    /// [`ExpectedFirmwareVersion`].
    UnexpectedFirmwareVersion {
        /// Expected version.
        expected: String,
        /// Actual reported version.
        actual: String,
    },
    /// The reported target id's top nibble was not
    /// [`EXPECTED_TARGET_ID_TOP_NIBBLE`] (for example a bootloader-mode
    /// target id).
    UnsupportedTargetId {
        /// The exact reported target id.
        target_id: u32,
    },
    /// A reported version contained the OS Upgrade (OSU) marker: the device
    /// is mid-firmware-update, not in a normal operating state.
    OsuVersionDetected {
        /// The offending version string.
        version: String,
    },
}

impl<E: fmt::Display> fmt::Display for IdentityError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "ledger transport failed: {error}"),
            Self::UnexpectedStatus {
                command,
                status_word,
            } => write!(f, "{command} returned unexpected status {status_word:#06x}"),
            Self::Malformed { command, error } => {
                write!(f, "{command} response was malformed: {error}")
            }
            Self::UnexpectedAppName { expected, actual } => write!(
                f,
                "expected application name {expected:?}, device reported {actual:?}"
            ),
            Self::UnexpectedAppVersion { expected, actual } => write!(
                f,
                "expected application version {expected:?}, device reported {actual:?}"
            ),
            Self::UnexpectedFirmwareVersion { expected, actual } => write!(
                f,
                "expected firmware version {expected:?}, device reported {actual:?}"
            ),
            Self::UnsupportedTargetId { target_id } => {
                write!(
                    f,
                    "device reported a non-operating-system target id {target_id:#010x}"
                )
            }
            Self::OsuVersionDetected { version } => write!(
                f,
                "device reported an OS Upgrade (OSU) version {version:?}; the device is not in a normal operating state"
            ),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for IdentityError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Malformed { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Rejects response data longer than [`MAX_RESPONSE_DATA_LEN`] before any
/// field-level parsing, independent of whether the transport is real
/// hardware (which enforces this at the framing layer) or a fake.
fn require_bounded_response(data: &[u8]) -> Result<(), IdentityParseError> {
    if data.len() > MAX_RESPONSE_DATA_LEN {
        return Err(IdentityParseError::ResponseTooLong {
            actual: data.len(),
            maximum: MAX_RESPONSE_DATA_LEN,
        });
    }
    Ok(())
}

fn take_u8(data: &[u8], offset: &mut usize) -> Result<u8, IdentityParseError> {
    let value = *data.get(*offset).ok_or(IdentityParseError::Truncated)?;
    *offset += 1;
    Ok(value)
}

fn take_bytes<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], IdentityParseError> {
    let end = offset
        .checked_add(len)
        .ok_or(IdentityParseError::Truncated)?;
    let slice = data
        .get(*offset..end)
        .ok_or(IdentityParseError::Truncated)?;
    *offset = end;
    Ok(slice)
}

/// Reads a big-endian `u32`.
fn take_be_u32(data: &[u8], offset: &mut usize) -> Result<u32, IdentityParseError> {
    let bytes = take_bytes(data, offset, 4)?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| IdentityParseError::Truncated)?;
    Ok(u32::from_be_bytes(array))
}

/// Reads one length-prefixed (`u8` length) byte field, not otherwise
/// validated.
fn take_lv_bytes<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], IdentityParseError> {
    let len = take_u8(data, offset)? as usize;
    take_bytes(data, offset, len)
}

/// Reads one length-prefixed (`u8` length) non-empty ASCII string field.
fn take_lv_ascii(data: &[u8], offset: &mut usize) -> Result<String, IdentityParseError> {
    let bytes = take_lv_bytes(data, offset)?;
    if bytes.is_empty() {
        return Err(IdentityParseError::EmptyField);
    }
    if !bytes.is_ascii() {
        return Err(IdentityParseError::NotAscii);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| IdentityParseError::NotAscii)
}

/// Parses `get app and version`'s exact response shape: a format byte
/// (always [`APP_AND_VERSION_FORMAT`]), a non-empty ASCII name, a non-empty
/// ASCII version, and an optional trailing flags field — no bytes may
/// remain after that.
fn parse_app_and_version(data: &[u8]) -> Result<AppIdentity, IdentityParseError> {
    require_bounded_response(data)?;
    let mut offset = 0_usize;
    let format = take_u8(data, &mut offset)?;
    if format != APP_AND_VERSION_FORMAT {
        return Err(IdentityParseError::UnsupportedFormat(format));
    }
    let name = take_lv_ascii(data, &mut offset)?;
    let version = take_lv_ascii(data, &mut offset)?;
    let flags = if offset < data.len() {
        Some(take_lv_bytes(data, &mut offset)?.to_vec())
    } else {
        None
    };
    if offset != data.len() {
        return Err(IdentityParseError::TrailingBytes {
            at: offset,
            total: data.len(),
        });
    }
    Ok(AppIdentity {
        name,
        version,
        flags,
    })
}

/// Parses the dashboard `get version` response: a big-endian `u32` target
/// id, a non-empty ASCII SE version, a flags field, and a remainder that
/// must consist of zero or more complete length-prefixed fields (their
/// contents are not otherwise interpreted).
fn parse_dashboard_firmware(data: &[u8]) -> Result<FirmwareIdentity, IdentityParseError> {
    require_bounded_response(data)?;
    let mut offset = 0_usize;
    let target_id = take_be_u32(data, &mut offset)?;
    let se_version = take_lv_ascii(data, &mut offset)?;
    let se_flags = take_lv_bytes(data, &mut offset)?.to_vec();
    while offset < data.len() {
        let _ = take_lv_bytes(data, &mut offset)?;
    }
    Ok(FirmwareIdentity {
        target_id,
        se_version,
        se_flags,
    })
}

fn contains_osu_marker(version: &str) -> bool {
    version.to_ascii_lowercase().contains(OSU_MARKER)
}

fn exchange<T: Transport>(
    transport: &mut T,
    command_name: &'static str,
    cla: u8,
    ins: u8,
    data: Vec<u8>,
) -> Result<ApduResponse, IdentityError<T::Error>> {
    let command = ApduCommand {
        cla,
        ins,
        p1: P1_DEFAULT,
        p2: P2_DEFAULT,
        data,
    };
    let response = transport
        .exchange(&command)
        .map_err(IdentityError::Transport)?;
    if response.status_word == STATUS_SUCCESS {
        Ok(response)
    } else {
        Err(IdentityError::UnexpectedStatus {
            command: command_name,
            status_word: response.status_word,
        })
    }
}

fn get_app_and_version<T: Transport>(
    transport: &mut T,
) -> Result<AppIdentity, IdentityError<T::Error>> {
    let response = exchange(
        transport,
        "get app and version",
        CLA_APP,
        INS_GET_APP_AND_VERSION,
        Vec::new(),
    )?;
    parse_app_and_version(&response.data).map_err(|error| IdentityError::Malformed {
        command: "get app and version",
        error,
    })
}

fn get_dashboard_firmware<T: Transport>(
    transport: &mut T,
) -> Result<FirmwareIdentity, IdentityError<T::Error>> {
    let response = exchange(
        transport,
        "dashboard get version",
        CLA_DASHBOARD,
        INS_DASHBOARD_GET_VERSION,
        Vec::new(),
    )?;
    parse_dashboard_firmware(&response.data).map_err(|error| IdentityError::Malformed {
        command: "dashboard get version",
        error,
    })
}

fn open_app<T: Transport>(transport: &mut T, name: &str) -> Result<(), IdentityError<T::Error>> {
    exchange(
        transport,
        "open app",
        CLA_DASHBOARD,
        INS_DASHBOARD_OPEN_APP,
        name.as_bytes().to_vec(),
    )?;
    Ok(())
}

/// Verifies the device is at the dashboard running exactly
/// [`DASHBOARD_APP_NAME`] with no OSU-marked application version, then
/// verifies the dashboard-reported firmware has a normal Secure Element OS
/// target id, no OSU-marked firmware version, and only then that it exactly matches
/// `expected_firmware`, then opens [`EXPECTED_APP_NAME`].
///
/// The target id and OSU checks run strictly before the exact-version
/// comparison so a bootloader-mode or mid-firmware-update (OSU) device is
/// always reported as such, never as a merely mismatched firmware version
/// (which an operator could otherwise mistake for "wrong pinned version,"
/// masking the more serious device-state problem).
///
/// Must be called strictly before [`verify_active_app`], per `docs/signing/hardware-signing.md`'s
/// staged dashboard-probe-then-reconnect sequence: dashboard identity (CLA
/// `B0`) first, then dashboard firmware (CLA `E0`, dashboard context), then
/// `open app`.
pub fn verify_dashboard_and_open<T: Transport>(
    transport: &mut T,
    expected_firmware: &ExpectedFirmwareVersion,
) -> Result<FirmwareIdentity, IdentityError<T::Error>> {
    let app = get_app_and_version(transport)?;
    if app.name != DASHBOARD_APP_NAME {
        return Err(IdentityError::UnexpectedAppName {
            expected: DASHBOARD_APP_NAME,
            actual: app.name,
        });
    }
    if contains_osu_marker(&app.version) {
        return Err(IdentityError::OsuVersionDetected {
            version: app.version,
        });
    }

    let firmware = get_dashboard_firmware(transport)?;
    if firmware.target_id >> 28 != EXPECTED_TARGET_ID_TOP_NIBBLE {
        return Err(IdentityError::UnsupportedTargetId {
            target_id: firmware.target_id,
        });
    }
    if contains_osu_marker(&firmware.se_version) {
        return Err(IdentityError::OsuVersionDetected {
            version: firmware.se_version,
        });
    }
    if firmware.se_version != expected_firmware.as_str() {
        return Err(IdentityError::UnexpectedFirmwareVersion {
            expected: expected_firmware.as_str().to_string(),
            actual: firmware.se_version,
        });
    }

    open_app(transport, EXPECTED_APP_NAME)?;
    Ok(firmware)
}

/// Verifies the currently active application is exactly [`EXPECTED_APP_NAME`]
/// at exactly [`EXPECTED_APP_VERSION`].
///
/// Must be called only after reconnecting once [`verify_dashboard_and_open`]
/// has opened the Sunrise application (`docs/signing/hardware-signing.md`'s staged sequence).
pub fn verify_active_app<T: Transport>(
    transport: &mut T,
) -> Result<AppIdentity, IdentityError<T::Error>> {
    let app = get_app_and_version(transport)?;
    if app.name != EXPECTED_APP_NAME {
        return Err(IdentityError::UnexpectedAppName {
            expected: EXPECTED_APP_NAME,
            actual: app.name,
        });
    }
    if app.version != EXPECTED_APP_VERSION {
        return Err(IdentityError::UnexpectedAppVersion {
            expected: EXPECTED_APP_VERSION.to_string(),
            actual: app.version,
        });
    }
    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeTransport;

    fn ok(data: Vec<u8>) -> ApduResponse {
        ApduResponse {
            data,
            status_word: STATUS_SUCCESS,
        }
    }

    fn lv(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![u8::try_from(bytes.len()).unwrap()];
        out.extend_from_slice(bytes);
        out
    }

    fn app_and_version_response(name: &str, version: &str, flags: Option<&[u8]>) -> Vec<u8> {
        let mut data = vec![APP_AND_VERSION_FORMAT];
        data.extend(lv(name.as_bytes()));
        data.extend(lv(version.as_bytes()));
        if let Some(flags) = flags {
            data.extend(lv(flags));
        }
        data
    }

    fn firmware_response(
        target_id: u32,
        se_version: &str,
        flags: &[u8],
        extra_fields: &[&[u8]],
    ) -> Vec<u8> {
        let mut data = target_id.to_be_bytes().to_vec();
        data.extend(lv(se_version.as_bytes()));
        data.extend(lv(flags));
        for field in extra_fields {
            data.extend(lv(field));
        }
        data
    }

    const VALID_TARGET_ID: u32 = 0x3310_0004;

    fn valid_expected_firmware() -> ExpectedFirmwareVersion {
        ExpectedFirmwareVersion::new("1.6.0").unwrap()
    }

    // ---- parse_app_and_version ----

    #[test]
    fn parses_a_minimal_app_and_version_response() {
        let data = app_and_version_response("BOLOS", "1.6.0", None);
        let identity = parse_app_and_version(&data).unwrap();
        assert_eq!(identity.name, "BOLOS");
        assert_eq!(identity.version, "1.6.0");
        assert_eq!(identity.flags, None);
    }

    #[test]
    fn parses_an_app_and_version_response_with_flags() {
        let data = app_and_version_response("Sunrise Edge", "0.1.0", Some(&[0x01]));
        let identity = parse_app_and_version(&data).unwrap();
        assert_eq!(identity.name, "Sunrise Edge");
        assert_eq!(identity.version, "0.1.0");
        assert_eq!(identity.flags, Some(vec![0x01]));
    }

    #[test]
    fn parses_an_app_and_version_response_with_empty_flags() {
        let data = app_and_version_response("BOLOS", "1.6.0", Some(&[]));
        let identity = parse_app_and_version(&data).unwrap();
        assert_eq!(identity.flags, Some(Vec::new()));
    }

    #[test]
    fn rejects_an_unsupported_format_byte() {
        let mut data = app_and_version_response("BOLOS", "1.6.0", None);
        data[0] = 2;
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::UnsupportedFormat(2)
        );
    }

    #[test]
    fn rejects_an_empty_name() {
        let data = app_and_version_response("", "1.6.0", None);
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::EmptyField
        );
    }

    #[test]
    fn rejects_an_empty_version() {
        let data = app_and_version_response("BOLOS", "", None);
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::EmptyField
        );
    }

    #[test]
    fn rejects_a_non_ascii_name() {
        let mut data = vec![APP_AND_VERSION_FORMAT];
        data.extend(lv("café".as_bytes()));
        data.extend(lv("1.6.0".as_bytes()));
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::NotAscii
        );
    }

    #[test]
    fn rejects_an_oversized_length_prefix() {
        let mut data = vec![APP_AND_VERSION_FORMAT, 0xFF];
        data.extend_from_slice(b"BOLOS");
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::Truncated
        );
    }

    #[test]
    fn rejects_a_response_truncated_before_the_version_field() {
        let mut data = vec![APP_AND_VERSION_FORMAT];
        data.extend(lv(b"BOLOS"));
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::Truncated
        );
    }

    #[test]
    fn rejects_trailing_bytes_after_the_optional_flags_field() {
        let mut data = app_and_version_response("BOLOS", "1.6.0", Some(&[0x00]));
        data.push(0xAA);
        let error = parse_app_and_version(&data).unwrap_err();
        assert!(matches!(error, IdentityParseError::TrailingBytes { .. }));
    }

    #[test]
    fn rejects_trailing_bytes_after_version_when_flags_are_absent_but_malformed() {
        // One stray byte after `version` is interpreted as an attempted
        // flags length prefix declaring more bytes than remain.
        let mut data = app_and_version_response("BOLOS", "1.6.0", None);
        data.push(0x05);
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::Truncated
        );
    }

    #[test]
    fn rejects_an_app_and_version_response_longer_than_the_short_apdu_cap() {
        // A well-formed response (no bad length prefix, no trailing bytes)
        // that is simply too long overall.
        let name = "A".repeat(200);
        let version = "1".repeat(100);
        let data = app_and_version_response(&name, &version, None);
        assert!(data.len() > MAX_RESPONSE_DATA_LEN);
        assert_eq!(
            parse_app_and_version(&data).unwrap_err(),
            IdentityParseError::ResponseTooLong {
                actual: data.len(),
                maximum: MAX_RESPONSE_DATA_LEN,
            }
        );
    }

    // ---- parse_dashboard_firmware ----

    #[test]
    fn parses_a_minimal_firmware_response() {
        let data = firmware_response(VALID_TARGET_ID, "1.6.0", &[0x00], &[]);
        let firmware = parse_dashboard_firmware(&data).unwrap();
        assert_eq!(firmware.target_id, VALID_TARGET_ID);
        assert_eq!(firmware.se_version, "1.6.0");
        assert_eq!(firmware.se_flags, vec![0x00]);
    }

    #[test]
    fn parses_a_firmware_response_with_trailing_complete_lv_fields() {
        let data = firmware_response(
            VALID_TARGET_ID,
            "1.6.0",
            &[0x00],
            &[b"2.30", b"bootloader-1.0"],
        );
        let firmware = parse_dashboard_firmware(&data).unwrap();
        assert_eq!(firmware.se_version, "1.6.0");
    }

    #[test]
    fn rejects_a_firmware_response_truncated_before_the_target_id() {
        let data = vec![0x33, 0x10, 0x00];
        assert_eq!(
            parse_dashboard_firmware(&data).unwrap_err(),
            IdentityParseError::Truncated
        );
    }

    #[test]
    fn rejects_a_firmware_response_with_an_empty_se_version() {
        let data = firmware_response(VALID_TARGET_ID, "", &[0x00], &[]);
        assert_eq!(
            parse_dashboard_firmware(&data).unwrap_err(),
            IdentityParseError::EmptyField
        );
    }

    #[test]
    fn rejects_a_firmware_response_with_an_incomplete_trailing_field() {
        let mut data = firmware_response(VALID_TARGET_ID, "1.6.0", &[0x00], &[]);
        data.push(0x05);
        data.extend_from_slice(b"ab");
        assert_eq!(
            parse_dashboard_firmware(&data).unwrap_err(),
            IdentityParseError::Truncated
        );
    }

    #[test]
    fn rejects_a_firmware_response_longer_than_the_short_apdu_cap() {
        // A well-formed response with several complete trailing fields that
        // is simply too long overall.
        let padding = vec![0xAB_u8; 100];
        let data = firmware_response(
            VALID_TARGET_ID,
            "1.6.0",
            &[0x00],
            &[&padding, &padding, &padding],
        );
        assert!(data.len() > MAX_RESPONSE_DATA_LEN);
        assert_eq!(
            parse_dashboard_firmware(&data).unwrap_err(),
            IdentityParseError::ResponseTooLong {
                actual: data.len(),
                maximum: MAX_RESPONSE_DATA_LEN,
            }
        );
    }

    // ---- ExpectedFirmwareVersion::new ----

    #[test]
    fn expected_firmware_version_accepts_a_valid_string() {
        let version = ExpectedFirmwareVersion::new("1.6.0").unwrap();
        assert_eq!(version.as_str(), "1.6.0");
    }

    #[test]
    fn expected_firmware_version_rejects_empty() {
        assert_eq!(
            ExpectedFirmwareVersion::new("").unwrap_err(),
            ExpectedFirmwareVersionError::Empty
        );
    }

    #[test]
    fn expected_firmware_version_rejects_non_ascii() {
        assert_eq!(
            ExpectedFirmwareVersion::new("1.6.0é").unwrap_err(),
            ExpectedFirmwareVersionError::NotAscii
        );
    }

    #[test]
    fn expected_firmware_version_rejects_too_long() {
        let version = "1".repeat(MAX_FIRMWARE_VERSION_LEN + 1);
        assert_eq!(
            ExpectedFirmwareVersion::new(version).unwrap_err(),
            ExpectedFirmwareVersionError::TooLong {
                actual: MAX_FIRMWARE_VERSION_LEN + 1,
                maximum: MAX_FIRMWARE_VERSION_LEN,
            }
        );
    }

    #[test]
    fn expected_firmware_version_accepts_exactly_the_maximum_length() {
        let version = "1".repeat(MAX_FIRMWARE_VERSION_LEN);
        assert!(ExpectedFirmwareVersion::new(version).is_ok());
    }

    #[test]
    fn expected_firmware_version_is_validated_before_any_transport_use() {
        // No FakeTransport is even constructed: validation happens
        // independently of any device interaction.
        assert!(ExpectedFirmwareVersion::new("").is_err());
    }

    // ---- verify_dashboard_and_open ----

    #[test]
    fn verify_dashboard_and_open_sends_the_exact_apdu_order_and_succeeds() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(VALID_TARGET_ID, "1.6.0", &[0x00], &[])),
            ok(Vec::new()),
        ]);

        let firmware =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap();
        assert_eq!(firmware.target_id, VALID_TARGET_ID);
        assert_eq!(firmware.se_version, "1.6.0");

        let sent = transport.commands();
        assert_eq!(sent.len(), 3);
        assert_eq!(
            sent[0],
            ApduCommand {
                cla: CLA_APP,
                ins: INS_GET_APP_AND_VERSION,
                p1: P1_DEFAULT,
                p2: P2_DEFAULT,
                data: Vec::new(),
            }
        );
        assert_eq!(
            sent[1],
            ApduCommand {
                cla: CLA_DASHBOARD,
                ins: INS_DASHBOARD_GET_VERSION,
                p1: P1_DEFAULT,
                p2: P2_DEFAULT,
                data: Vec::new(),
            }
        );
        assert_eq!(
            sent[2],
            ApduCommand {
                cla: CLA_DASHBOARD,
                ins: INS_DASHBOARD_OPEN_APP,
                p1: P1_DEFAULT,
                p2: P2_DEFAULT,
                data: EXPECTED_APP_NAME.as_bytes().to_vec(),
            }
        );
    }

    #[test]
    fn verify_dashboard_and_open_checks_dashboard_identity_before_firmware() {
        let mut transport = FakeTransport::new(vec![ok(app_and_version_response(
            "SomeOtherApp",
            "1.6.0",
            None,
        ))]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedAppName {
                expected: DASHBOARD_APP_NAME,
                ..
            }
        ));
        // The firmware query and open-app command were never sent.
        assert_eq!(transport.commands().len(), 1);
    }

    #[test]
    fn verify_dashboard_and_open_rejects_an_osu_dashboard_app_version() {
        let mut transport = FakeTransport::new(vec![ok(app_and_version_response(
            "BOLOS",
            "1.6.0-osu",
            None,
        ))]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(error, IdentityError::OsuVersionDetected { .. }));
        assert_eq!(transport.commands().len(), 1);
    }

    #[test]
    fn verify_dashboard_and_open_rejects_a_firmware_version_mismatch() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(VALID_TARGET_ID, "1.5.9", &[0x00], &[])),
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedFirmwareVersion { .. }
        ));
        assert_eq!(transport.commands().len(), 2);
    }

    #[test]
    fn verify_dashboard_and_open_rejects_a_target_id_with_the_wrong_top_nibble() {
        let bootloader_target_id = 0x0100_0004_u32;
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(
                bootloader_target_id,
                "1.6.0",
                &[0x00],
                &[],
            )),
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert_eq!(
            error,
            IdentityError::UnsupportedTargetId {
                target_id: bootloader_target_id,
            }
        );
        // `open app` must never be sent once the target id is rejected.
        assert_eq!(transport.commands().len(), 2);
    }

    #[test]
    fn verify_dashboard_and_open_reports_the_target_id_even_when_the_firmware_version_also_mismatches()
     {
        let bootloader_target_id = 0x0100_0004_u32;
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(
                bootloader_target_id,
                "9.9.9",
                &[0x00],
                &[],
            )),
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert_eq!(
            error,
            IdentityError::UnsupportedTargetId {
                target_id: bootloader_target_id,
            },
            "a bootloader-mode target id must never degrade to a generic firmware mismatch"
        );
    }

    #[test]
    fn verify_dashboard_and_open_reports_osu_even_when_the_firmware_version_also_mismatches() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(
                VALID_TARGET_ID,
                "9.9.9-osu",
                &[0x00],
                &[],
            )),
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert_eq!(
            error,
            IdentityError::OsuVersionDetected {
                version: "9.9.9-osu".to_string(),
            },
            "an OSU-marked firmware version must never degrade to a generic firmware mismatch"
        );
    }

    #[test]
    fn verify_dashboard_and_open_rejects_an_osu_firmware_version() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(
                VALID_TARGET_ID,
                "1.6.0-OSU",
                &[0x00],
                &[],
            )),
        ]);

        let expected = ExpectedFirmwareVersion::new("1.6.0-OSU").unwrap();
        let error = verify_dashboard_and_open(&mut transport, &expected).unwrap_err();
        assert!(matches!(error, IdentityError::OsuVersionDetected { .. }));
        assert_eq!(transport.commands().len(), 2);
    }

    #[test]
    fn verify_dashboard_and_open_propagates_a_dashboard_identity_status_error() {
        let mut transport = FakeTransport::new(vec![ApduResponse {
            data: Vec::new(),
            status_word: 0x6E00,
        }]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedStatus {
                command: "get app and version",
                status_word: 0x6E00,
            }
        ));
    }

    #[test]
    fn verify_dashboard_and_open_propagates_a_firmware_status_error() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ApduResponse {
                data: Vec::new(),
                status_word: 0x6985,
            },
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedStatus {
                command: "dashboard get version",
                status_word: 0x6985,
            }
        ));
    }

    #[test]
    fn verify_dashboard_and_open_propagates_an_open_app_status_error() {
        let mut transport = FakeTransport::new(vec![
            ok(app_and_version_response("BOLOS", "1.6.0", None)),
            ok(firmware_response(VALID_TARGET_ID, "1.6.0", &[0x00], &[])),
            ApduResponse {
                data: Vec::new(),
                status_word: 0x6A80,
            },
        ]);

        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedStatus {
                command: "open app",
                status_word: 0x6A80,
            }
        ));
    }

    #[test]
    fn verify_dashboard_and_open_propagates_a_malformed_dashboard_response() {
        let mut transport = FakeTransport::new(vec![ok(vec![9])]);
        let error =
            verify_dashboard_and_open(&mut transport, &valid_expected_firmware()).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::Malformed {
                command: "get app and version",
                error: IdentityParseError::UnsupportedFormat(9),
            }
        ));
    }

    // ---- verify_active_app ----

    #[test]
    fn verify_active_app_accepts_the_exact_expected_identity() {
        let mut transport = FakeTransport::new(vec![ok(app_and_version_response(
            EXPECTED_APP_NAME,
            EXPECTED_APP_VERSION,
            None,
        ))]);
        let identity = verify_active_app(&mut transport).unwrap();
        assert_eq!(identity.name, EXPECTED_APP_NAME);
        assert_eq!(identity.version, EXPECTED_APP_VERSION);

        let sent = transport.commands();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0],
            ApduCommand {
                cla: CLA_APP,
                ins: INS_GET_APP_AND_VERSION,
                p1: P1_DEFAULT,
                p2: P2_DEFAULT,
                data: Vec::new(),
            }
        );
    }

    #[test]
    fn verify_active_app_rejects_the_wrong_name() {
        let mut transport = FakeTransport::new(vec![ok(app_and_version_response(
            "SomeOtherApp",
            EXPECTED_APP_VERSION,
            None,
        ))]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert_eq!(
            error,
            IdentityError::UnexpectedAppName {
                expected: EXPECTED_APP_NAME,
                actual: "SomeOtherApp".to_string(),
            }
        );
    }

    #[test]
    fn verify_active_app_rejects_the_wrong_version() {
        let mut transport = FakeTransport::new(vec![ok(app_and_version_response(
            EXPECTED_APP_NAME,
            "0.2.0",
            None,
        ))]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert_eq!(
            error,
            IdentityError::UnexpectedAppVersion {
                expected: EXPECTED_APP_VERSION.to_string(),
                actual: "0.2.0".to_string(),
            }
        );
    }

    #[test]
    fn verify_active_app_propagates_a_status_error() {
        let mut transport = FakeTransport::new(vec![ApduResponse {
            data: Vec::new(),
            status_word: 0x6E00,
        }]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert!(matches!(
            error,
            IdentityError::UnexpectedStatus {
                command: "get app and version",
                status_word: 0x6E00,
            }
        ));
    }

    #[test]
    fn verify_active_app_fails_closed_on_a_disconnected_transport() {
        let mut transport = FakeTransport::new(vec![]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert!(matches!(error, IdentityError::Transport(_)));
    }

    // ---- std::error::Error::source ----

    #[test]
    fn transport_errors_expose_their_source() {
        use std::error::Error as _;
        let mut transport = FakeTransport::new(vec![]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert!(error.source().is_some());
    }

    #[test]
    fn malformed_errors_expose_their_source() {
        use std::error::Error as _;
        let mut transport = FakeTransport::new(vec![ok(vec![9])]);
        let error = verify_active_app(&mut transport).unwrap_err();
        let source = error.source().expect("Malformed must expose a source");
        assert_eq!(
            source.downcast_ref::<IdentityParseError>(),
            Some(&IdentityParseError::UnsupportedFormat(9))
        );
    }

    #[test]
    fn status_and_mismatch_errors_expose_no_source() {
        use std::error::Error as _;
        let mut transport = FakeTransport::new(vec![ApduResponse {
            data: Vec::new(),
            status_word: 0x6E00,
        }]);
        let error = verify_active_app(&mut transport).unwrap_err();
        assert!(error.source().is_none());
    }
}
