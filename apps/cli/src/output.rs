//! Deterministic, line-oriented `key=value` output helpers.

use crate::hex::encode_hex;

/// Maximum number of bytes printed as hex for any one field. This is a
/// display bound only, independent of and smaller than the protocol's own
/// canonical size bounds, so terminal/script output stays bounded even for
/// a maximally sized object or receipt.
pub const MAX_DISPLAY_BYTES: usize = 65_536;

/// Encodes `bytes` as bounded lowercase hex for one output field, returning
/// the hex string and whether the value was truncated to
/// [`MAX_DISPLAY_BYTES`].
#[must_use]
pub fn bounded_hex_field(bytes: &[u8]) -> (String, bool) {
    let limit = bytes.len().min(MAX_DISPLAY_BYTES);
    (encode_hex(&bytes[..limit]), bytes.len() > MAX_DISPLAY_BYTES)
}

/// Replaces control characters (including newlines) with a single space so
/// a value of untrusted or free-form origin cannot break line-oriented
/// `key=value` output.
#[must_use]
pub fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_reports_truncation() {
        let (hex, truncated) = bounded_hex_field(&[0xAB, 0xCD]);
        assert_eq!(hex, "abcd");
        assert!(!truncated);

        let big = vec![0u8; MAX_DISPLAY_BYTES + 1];
        let (hex, truncated) = bounded_hex_field(&big);
        assert_eq!(hex.len(), MAX_DISPLAY_BYTES * 2);
        assert!(truncated);
    }

    #[test]
    fn sanitizes_control_characters() {
        assert_eq!(sanitize_line("a\nb\rc\td"), "a b c d");
    }
}
