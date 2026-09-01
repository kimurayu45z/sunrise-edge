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

/// Maximum number of `char`s printed for one sanitized, free-form error
/// message field (for example an echoed HTTP error response body). This is
/// a display bound only: it keeps an attacker- or server-controlled message
/// from producing unbounded terminal/log output.
pub const MAX_ERROR_MESSAGE_CHARS: usize = 4_096;

/// Replaces control characters (including newlines), Unicode bidirectional
/// and other format characters, and the Unicode line/paragraph separators
/// with a single space, so a value of untrusted or free-form origin cannot
/// break line-oriented `key=value` output or reorder/hide what a terminal
/// displays.
///
/// This neutralizes every character in exactly three closed Unicode
/// `General_Category` classes — not a hand-picked subset of them — so it
/// cannot be bypassed by a format character this module's author simply
/// didn't think of:
///
/// - `Cc` (Control), via `char::is_control`: the C0/C1 control codes,
///   including `\n`/`\r`.
/// - `Zl`/`Zp` (Line/Paragraph Separator): `U+2028`/`U+2029`, the complete
///   membership of both categories (each has exactly one assigned code
///   point).
/// - `Cf` (Format): see [`is_unicode_format_character`] for the full,
///   individually enumerated range table this covers, including the
///   right-to-left override `U+202E` and right-to-left mark `U+200F` that
///   could otherwise visually reorder or hide trailing text, and the
///   invisible tag characters used in some Unicode spoofing/steganography
///   techniques.
#[must_use]
pub fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if is_unsafe_line_character(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Returns whether `character` must never appear in one-line `key=value`
/// output: a control character (`Cc`), a Unicode line/paragraph separator
/// (`Zl`/`Zp`), or a Unicode format character (`Cf`). See [`sanitize_line`]
/// for why each class is unsafe.
#[must_use]
fn is_unsafe_line_character(character: char) -> bool {
    if character.is_control() {
        return true;
    }
    if matches!(character, '\u{2028}' | '\u{2029}') {
        return true;
    }
    is_unicode_format_character(character)
}

/// Returns whether `character` has Unicode `General_Category` value `Cf`
/// (Format).
///
/// This table is a complete, individually verified enumeration of every one
/// of the 170 `Cf` code points in Unicode 16.0 (the version bundled with
/// this repository's validated toolchain: `rustc 1.97.1`, matching CPython
/// 3.14's bundled `unicodedata` database, `unidata_version == "16.0.0"`) —
/// not an approximation by block or script — grouped below by the Unicode
/// block each range/code point belongs to. Rust's `char` type has no
/// built-in `General_Category` query, and this crate takes on no new
/// dependency to get one, so this exact table (independently re-derived by
/// enumerating `unicodedata.category` over every code point, not copied
/// from a prior version of this comment) must be re-verified the same way
/// against whatever Unicode version the toolchain bundles next, any time
/// that version changes; the fail-safe posture of this sanitizer depends on
/// this table staying complete, not merely plausible-looking.
#[must_use]
fn is_unicode_format_character(character: char) -> bool {
    matches!(
        character,
        // U+00AD SOFT HYPHEN (Latin-1 Supplement).
        '\u{00AD}'
            // U+0600..U+0605 ARABIC NUMBER SIGN..ARABIC NUMBER MARK ABOVE,
            // U+061C ARABIC LETTER MARK (Arabic).
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            // U+06DD ARABIC END OF AYAH (Arabic).
            | '\u{06DD}'
            // U+070F SYRIAC ABBREVIATION MARK (Syriac).
            | '\u{070F}'
            // U+0890..U+0891 ARABIC POUND MARK ABOVE..ARABIC PIASTRE MARK
            // ABOVE (Arabic Extended-B).
            | '\u{0890}'..='\u{0891}'
            // U+08E2 ARABIC DISPUTED END OF AYAH (Arabic Extended-A).
            | '\u{08E2}'
            // U+180E MONGOLIAN VOWEL SEPARATOR (Mongolian) — ordinary `Cf`
            // membership, verified directly against the local Unicode 16.0
            // database; not a defensive addition or a reclassified value.
            | '\u{180E}'
            // U+200B..U+200F ZERO WIDTH SPACE, ZERO WIDTH NON-JOINER, ZERO
            // WIDTH JOINER, LEFT-TO-RIGHT MARK, RIGHT-TO-LEFT MARK; and
            // U+202A..U+202E the explicit bidirectional-embedding/override
            // controls (General Punctuation).
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            // U+2060..U+2064 WORD JOINER, FUNCTION APPLICATION, INVISIBLE
            // TIMES, INVISIBLE SEPARATOR, INVISIBLE PLUS; and
            // U+2066..U+206F the bidirectional-isolate controls plus the
            // deprecated symmetric-swapping/Arabic-form-shaping/digit-shape
            // format controls (General Punctuation).
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            // U+FEFF ZERO WIDTH NO-BREAK SPACE / byte-order mark
            // (Arabic Presentation Forms-B).
            | '\u{FEFF}'
            // U+FFF9..U+FFFB INTERLINEAR ANNOTATION ANCHOR/SEPARATOR/
            // TERMINATOR (Specials).
            | '\u{FFF9}'..='\u{FFFB}'
            // U+110BD, U+110CD KAITHI NUMBER SIGN, KAITHI NUMBER SIGN ABOVE
            // (Kaithi, supplementary plane).
            | '\u{110BD}'
            | '\u{110CD}'
            // U+13430..U+1343F the Egyptian Hieroglyph format controls —
            // the full Unicode 16.0 block, including the U+13439..U+1343F
            // enclosure/insertion/mirroring controls added after Unicode
            // 15.0's initial U+13430..U+13438 (Egyptian Hieroglyph Format
            // Controls, supplementary plane).
            | '\u{13430}'..='\u{1343F}'
            // U+1BCA0..U+1BCA3 the Duployan shorthand format controls
            // (Shorthand Format Controls, supplementary plane).
            | '\u{1BCA0}'..='\u{1BCA3}'
            // U+1D173..U+1D17A the musical-notation format controls
            // (Musical Symbols, supplementary plane).
            | '\u{1D173}'..='\u{1D17A}'
            // U+E0001 LANGUAGE TAG (deprecated), U+E0020..U+E007F the TAG
            // characters used in emoji-flag-style sequences (Tags,
            // supplementary plane).
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Sanitizes `value` with [`sanitize_line`] and bounds its length to
/// [`MAX_ERROR_MESSAGE_CHARS`], returning the (possibly truncated) sanitized
/// text and whether it was truncated.
///
/// Truncation is applied to the already-sanitized text and counts `char`s
/// (not bytes), so the result never splits a multi-byte code point and never
/// reintroduces an unsafe character.
#[must_use]
pub fn bounded_sanitized_line(value: &str) -> (String, bool) {
    let sanitized = sanitize_line(value);
    if sanitized.chars().count() <= MAX_ERROR_MESSAGE_CHARS {
        (sanitized, false)
    } else {
        let truncated: String = sanitized.chars().take(MAX_ERROR_MESSAGE_CHARS).collect();
        (truncated, true)
    }
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

    #[test]
    fn sanitizes_bidi_control_characters() {
        // U+202E RIGHT-TO-LEFT OVERRIDE could otherwise visually reverse
        // trailing text; U+200F RIGHT-TO-LEFT MARK could otherwise reorder
        // adjacent text without being visible itself.
        assert_eq!(sanitize_line("a\u{202E}b"), "a b");
        assert_eq!(sanitize_line("a\u{200F}b"), "a b");
        assert_eq!(sanitize_line("a\u{200E}b"), "a b");
        assert_eq!(sanitize_line("a\u{061C}b"), "a b");
        assert_eq!(sanitize_line("a\u{2066}b\u{2069}c"), "a b c");
    }

    #[test]
    fn sanitizes_unicode_line_and_paragraph_separators() {
        assert_eq!(sanitize_line("a\u{2028}b"), "a b");
        assert_eq!(sanitize_line("a\u{2029}b"), "a b");
    }

    #[test]
    fn sanitizes_zero_width_and_other_format_characters() {
        assert_eq!(sanitize_line("a\u{200B}b"), "a b");
        assert_eq!(sanitize_line("a\u{FEFF}b"), "a b");
        assert_eq!(sanitize_line("a\u{00AD}b"), "a b");
    }

    #[test]
    fn sanitizes_previously_omitted_bmp_format_characters() {
        // Representative code points from `Cf` ranges an earlier version of
        // this table did not cover.
        assert_eq!(sanitize_line("a\u{0600}b"), "a b"); // ARABIC NUMBER SIGN
        assert_eq!(sanitize_line("a\u{0605}b"), "a b"); // ARABIC NUMBER MARK ABOVE
        assert_eq!(sanitize_line("a\u{06DD}b"), "a b"); // ARABIC END OF AYAH
        assert_eq!(sanitize_line("a\u{070F}b"), "a b"); // SYRIAC ABBREVIATION MARK
        assert_eq!(sanitize_line("a\u{0890}b"), "a b"); // ARABIC POUND MARK ABOVE
        assert_eq!(sanitize_line("a\u{0891}b"), "a b"); // ARABIC PIASTRE MARK ABOVE
        assert_eq!(sanitize_line("a\u{08E2}b"), "a b"); // ARABIC DISPUTED END OF AYAH
        assert_eq!(sanitize_line("a\u{180E}b"), "a b"); // MONGOLIAN VOWEL SEPARATOR
        assert_eq!(sanitize_line("a\u{206A}b"), "a b"); // INHIBIT SYMMETRIC SWAPPING
        assert_eq!(sanitize_line("a\u{206F}b"), "a b"); // NOMINAL DIGIT SHAPES
    }

    #[test]
    fn sanitizes_supplementary_plane_format_characters() {
        // Representative code points outside the Basic Multilingual Plane,
        // which a BMP-only table would silently miss.
        assert_eq!(sanitize_line("a\u{110BD}b"), "a b"); // KAITHI NUMBER SIGN
        assert_eq!(sanitize_line("a\u{110CD}b"), "a b"); // KAITHI NUMBER SIGN ABOVE
        assert_eq!(sanitize_line("a\u{13430}b"), "a b"); // EGYPTIAN HIEROGLYPH VERTICAL JOINER (block start)
        assert_eq!(sanitize_line("a\u{13439}b"), "a b"); // first Unicode-16.0 extension code point
        assert_eq!(sanitize_line("a\u{1343F}b"), "a b"); // EGYPTIAN HIEROGLYPH format controls block end
        assert_eq!(sanitize_line("a\u{1BCA0}b"), "a b"); // SHORTHAND FORMAT LETTER OVERLAP
        assert_eq!(sanitize_line("a\u{1D173}b"), "a b"); // MUSICAL SYMBOL BEGIN BEAM
        assert_eq!(sanitize_line("a\u{E0001}b"), "a b"); // LANGUAGE TAG
        assert_eq!(sanitize_line("a\u{E0041}b"), "a b"); // TAG LATIN CAPITAL LETTER A
    }

    #[test]
    fn leaves_ordinary_unicode_text_unchanged() {
        assert_eq!(sanitize_line("héllo日本語"), "héllo日本語");
        // Ordinary text drawn from blocks that also contain `Cf` code
        // points must not be over-sanitized: real Arabic letters sit right
        // next to the Arabic-block format controls covered above.
        assert_eq!(
            sanitize_line("\u{0627}\u{0644}\u{0633}\u{0644}\u{0627}\u{0645}"),
            "\u{0627}\u{0644}\u{0633}\u{0644}\u{0627}\u{0645}"
        );
    }

    #[test]
    fn bounded_sanitized_line_passes_through_short_sanitized_text() {
        let (text, truncated) = bounded_sanitized_line("a\nb");
        assert_eq!(text, "a b");
        assert!(!truncated);
    }

    #[test]
    fn bounded_sanitized_line_truncates_long_text_and_reports_it() {
        let long = "x".repeat(MAX_ERROR_MESSAGE_CHARS + 10);
        let (text, truncated) = bounded_sanitized_line(&long);
        assert_eq!(text.chars().count(), MAX_ERROR_MESSAGE_CHARS);
        assert!(truncated);
    }

    #[test]
    fn bounded_sanitized_line_truncation_never_reintroduces_an_unsafe_character() {
        // A bidi override sitting exactly at the truncation boundary must
        // already have been sanitized to a space before truncation runs.
        let mut long = "x".repeat(MAX_ERROR_MESSAGE_CHARS - 1);
        long.push('\u{202E}');
        long.push_str(&"y".repeat(10));
        let (text, truncated) = bounded_sanitized_line(&long);
        assert!(truncated);
        assert!(!text.contains('\u{202E}'));
        assert_eq!(text.chars().count(), MAX_ERROR_MESSAGE_CHARS);
    }
}
