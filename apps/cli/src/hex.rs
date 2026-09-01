//! Strict, bounded hexadecimal encode/decode helpers.

use std::fmt;

/// Errors from strict hexadecimal decoding.
#[derive(Debug)]
pub enum HexError {
    /// The decoded value's length in hex characters did not match what the
    /// caller required.
    WrongLength {
        /// Flag or field name, for an actionable message.
        field: &'static str,
        /// Expected number of hex characters.
        expected: usize,
        /// Actual number of hex characters.
        actual: usize,
    },
    /// A character outside `[0-9a-fA-F]` was present.
    InvalidDigit {
        /// Flag or field name, for an actionable message.
        field: &'static str,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} must be exactly {expected} hexadecimal characters, got {actual}"
            ),
            Self::InvalidDigit { field } => {
                write!(f, "{field} contains a non-hexadecimal character")
            }
        }
    }
}

impl std::error::Error for HexError {}

/// Decodes exactly 64 hexadecimal characters into 32 bytes.
pub fn decode_hex_32(field: &'static str, value: &str) -> Result<[u8; 32], HexError> {
    let bytes = decode_hex_exact(field, value, 32)?;
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decodes exactly `expected_bytes * 2` hexadecimal characters.
pub fn decode_hex_exact(
    field: &'static str,
    value: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, HexError> {
    if value.len() != expected_bytes * 2 {
        return Err(HexError::WrongLength {
            field,
            expected: expected_bytes * 2,
            actual: value.len(),
        });
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HexError::InvalidDigit { field });
    }
    let mut out = Vec::with_capacity(expected_bytes);
    let bytes = value.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]);
        let low = hex_nibble(pair[1]);
        out.push((high << 4) | low);
    }
    Ok(out)
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// Encodes bytes as lowercase hexadecimal.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exact_lowercase_and_uppercase_hex() {
        assert_eq!(
            decode_hex_32("--x", &"ab".repeat(32)).unwrap(),
            [0xAB_u8; 32]
        );
        assert_eq!(
            decode_hex_32("--x", &"AB".repeat(32)).unwrap(),
            [0xAB_u8; 32]
        );
    }

    #[test]
    fn rejects_wrong_length() {
        let error = decode_hex_32("--x", "ab").unwrap_err();
        assert!(matches!(
            error,
            HexError::WrongLength {
                field: "--x",
                expected: 64,
                actual: 2
            }
        ));
    }

    #[test]
    fn rejects_non_hex_digits() {
        let mut value = "a".repeat(64);
        value.replace_range(0..1, "g");
        let error = decode_hex_32("--x", &value).unwrap_err();
        assert!(matches!(error, HexError::InvalidDigit { field: "--x" }));
    }

    #[test]
    fn round_trips_through_encode() {
        let bytes = [0x01, 0x02, 0xFF, 0x00];
        assert_eq!(encode_hex(&bytes), "0102ff00");
    }
}
