//! `get configuration`'s exact six-byte response (see `docs/signing/hardware-signing.md`,
//! "Device APDU contract").

use std::fmt;

/// The only `profile` id this host implements (Hardware Signing Profile v1).
pub const SUPPORTED_PROFILE_ID: u16 = 1;

/// The only device application semantic version this host requires, matching
/// [`crate::identity::EXPECTED_APP_VERSION`].
pub const SUPPORTED_MAJOR: u8 = 0;
/// See [`SUPPORTED_MAJOR`].
pub const SUPPORTED_MINOR: u8 = 1;
/// See [`SUPPORTED_MAJOR`].
pub const SUPPORTED_PATCH: u8 = 0;

/// Every currently defined `flags` bit is `0`. A set bit this host does not
/// define here is unknown and must be rejected rather than ignored — see
/// `docs/signing/hardware-signing.md`, "Device APDU contract".
pub const KNOWN_FLAGS_MASK: u8 = 0x00;

/// A decoded `get configuration` response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    /// Hardware signing profile id.
    pub profile: u16,
    /// Device application major version.
    pub major: u8,
    /// Device application minor version.
    pub minor: u8,
    /// Device application patch version.
    pub patch: u8,
    /// Device-reported feature flags.
    pub flags: u8,
}

/// Errors validating a decoded [`Configuration`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The response was not exactly six bytes.
    UnexpectedResponseLength {
        /// Actual response length.
        actual: usize,
    },
    /// `profile` was not [`SUPPORTED_PROFILE_ID`].
    UnsupportedProfile(u16),
    /// `major`/`minor`/`patch` did not exactly equal [`SUPPORTED_MAJOR`],
    /// [`SUPPORTED_MINOR`], [`SUPPORTED_PATCH`].
    UnsupportedVersion {
        /// Reported major version.
        major: u8,
        /// Reported minor version.
        minor: u8,
        /// Reported patch version.
        patch: u8,
    },
    /// `flags` had a bit set this host does not define.
    UnsupportedFlags(u8),
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedResponseLength { actual } => write!(
                f,
                "get configuration response was {actual} bytes, expected exactly 6"
            ),
            Self::UnsupportedProfile(profile) => {
                write!(f, "unsupported hardware signing profile id {profile}")
            }
            Self::UnsupportedVersion {
                major,
                minor,
                patch,
            } => write!(
                f,
                "unsupported device application version {major}.{minor}.{patch}, expected exactly {SUPPORTED_MAJOR}.{SUPPORTED_MINOR}.{SUPPORTED_PATCH}"
            ),
            Self::UnsupportedFlags(flags) => write!(
                f,
                "device reported an unknown configuration flag bit (flags={flags:#04x})"
            ),
        }
    }
}

impl std::error::Error for ConfigurationError {}

impl Configuration {
    /// Decodes the exact six-byte `get configuration` success response.
    pub fn decode(data: &[u8]) -> Result<Self, ConfigurationError> {
        let actual = data.len();
        let bytes: &[u8; 6] = data
            .try_into()
            .map_err(|_| ConfigurationError::UnexpectedResponseLength { actual })?;
        Ok(Self {
            profile: u16::from_be_bytes([bytes[0], bytes[1]]),
            major: bytes[2],
            minor: bytes[3],
            patch: bytes[4],
            flags: bytes[5],
        })
    }

    /// Requires exactly the supported profile id, exactly version
    /// `{SUPPORTED_MAJOR}.{SUPPORTED_MINOR}.{SUPPORTED_PATCH}`, and no
    /// unknown flag bit, before any public key or signing request reaches
    /// the device.
    pub fn require_supported(&self) -> Result<(), ConfigurationError> {
        if self.profile != SUPPORTED_PROFILE_ID {
            return Err(ConfigurationError::UnsupportedProfile(self.profile));
        }
        if (self.major, self.minor, self.patch)
            != (SUPPORTED_MAJOR, SUPPORTED_MINOR, SUPPORTED_PATCH)
        {
            return Err(ConfigurationError::UnsupportedVersion {
                major: self.major,
                minor: self.minor,
                patch: self.patch,
            });
        }
        if self.flags & !KNOWN_FLAGS_MASK != 0 {
            return Err(ConfigurationError::UnsupportedFlags(self.flags));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_exact_six_byte_shape() {
        let configuration = Configuration::decode(&[0x00, 0x01, 1, 2, 3, 0x00]).unwrap();
        assert_eq!(configuration.profile, 1);
        assert_eq!(configuration.major, 1);
        assert_eq!(configuration.minor, 2);
        assert_eq!(configuration.patch, 3);
        assert_eq!(configuration.flags, 0);
    }

    #[test]
    fn rejects_a_short_response() {
        let error = Configuration::decode(&[0x00, 0x01, 1, 2, 3]).unwrap_err();
        assert_eq!(
            error,
            ConfigurationError::UnexpectedResponseLength { actual: 5 }
        );
    }

    #[test]
    fn rejects_a_long_response() {
        let error = Configuration::decode(&[0x00, 0x01, 1, 2, 3, 0, 0]).unwrap_err();
        assert_eq!(
            error,
            ConfigurationError::UnexpectedResponseLength { actual: 7 }
        );
    }

    #[test]
    fn require_supported_accepts_profile_one_with_no_flags() {
        let configuration = Configuration::decode(&[0x00, 0x01, 0, 1, 0, 0x00]).unwrap();
        assert!(configuration.require_supported().is_ok());
    }

    #[test]
    fn require_supported_rejects_an_unrecognized_profile() {
        let configuration = Configuration::decode(&[0x00, 0x02, 0, 1, 0, 0x00]).unwrap();
        assert_eq!(
            configuration.require_supported().unwrap_err(),
            ConfigurationError::UnsupportedProfile(2)
        );
    }

    #[test]
    fn require_supported_rejects_an_unsupported_version() {
        let configuration = Configuration::decode(&[0x00, 0x01, 1, 2, 3, 0x00]).unwrap();
        assert_eq!(
            configuration.require_supported().unwrap_err(),
            ConfigurationError::UnsupportedVersion {
                major: 1,
                minor: 2,
                patch: 3,
            }
        );
    }

    #[test]
    fn require_supported_rejects_any_unknown_flag_bit() {
        for bit in 0_u8..8 {
            let flags = 1_u8 << bit;
            let configuration = Configuration::decode(&[0x00, 0x01, 0, 1, 0, flags]).unwrap();
            assert_eq!(
                configuration.require_supported().unwrap_err(),
                ConfigurationError::UnsupportedFlags(flags)
            );
        }
    }
}
