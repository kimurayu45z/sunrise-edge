//! Strict decimal-integer argument parsing.

use crate::error::CliError;

/// Parses a required `u64` decimal argument.
pub fn parse_u64(flag: &'static str, value: &str) -> Result<u64, CliError> {
    value
        .parse::<u64>()
        .map_err(|source| CliError::InvalidInteger {
            flag,
            value: value.to_string(),
            source,
        })
}

/// Parses a required `u32` decimal argument.
pub fn parse_u32(flag: &'static str, value: &str) -> Result<u32, CliError> {
    value
        .parse::<u32>()
        .map_err(|source| CliError::InvalidInteger {
            flag,
            value: value.to_string(),
            source,
        })
}

/// Parses a required `u16` decimal argument.
pub fn parse_u16(flag: &'static str, value: &str) -> Result<u16, CliError> {
    value
        .parse::<u16>()
        .map_err(|source| CliError::InvalidInteger {
            flag,
            value: value.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_integers() {
        assert_eq!(parse_u64("--x", "42").unwrap(), 42);
        assert_eq!(parse_u32("--x", "42").unwrap(), 42);
        assert_eq!(parse_u16("--x", "42").unwrap(), 42);
    }

    #[test]
    fn rejects_invalid_integers() {
        assert!(matches!(
            parse_u64("--x", "not-a-number"),
            Err(CliError::InvalidInteger { flag: "--x", .. })
        ));
        assert!(matches!(
            parse_u64("--x", "-1"),
            Err(CliError::InvalidInteger { flag: "--x", .. })
        ));
        assert!(matches!(
            parse_u16("--x", "99999"),
            Err(CliError::InvalidInteger { flag: "--x", .. })
        ));
    }
}
