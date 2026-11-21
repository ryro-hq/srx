//! Byte encodings shared by Syrox crates.
//!
//! Every digest, identifier and pin that Syrox prints or persists as text is
//! canonical lowercase hexadecimal. Parsers of binary formats (ELF, qcow2, GPT)
//! read fixed-width integers at known offsets. Keeping both here gives every
//! crate the same canonical form and the same bounds behaviour.
//!
//! Readers return `None` instead of panicking when a field does not fit, so
//! each caller maps the failure to its own domain error.

use std::fmt::Write as _;

/// Encode bytes as lowercase hexadecimal, two characters per byte.
pub fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

/// Whether `text` is exactly `length` characters of lowercase hexadecimal.
pub fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Decode canonical lowercase hexadecimal.
///
/// Returns `None` for an odd length or any character outside `0-9a-f`.
/// Callers enforce their own size bounds before decoding.
pub fn decode_lower_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|pair| Some((lower_digit(pair[0])? << 4) | lower_digit(pair[1])?))
        .collect()
}

fn lower_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn field<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Little-endian `u16` at byte offset `at`, or `None` when it does not fit.
pub fn u16_le_at(bytes: &[u8], at: usize) -> Option<u16> {
    field(bytes, at).map(u16::from_le_bytes)
}

/// Little-endian `u32` at byte offset `at`, or `None` when it does not fit.
pub fn u32_le_at(bytes: &[u8], at: usize) -> Option<u32> {
    field(bytes, at).map(u32::from_le_bytes)
}

/// Little-endian `u64` at byte offset `at`, or `None` when it does not fit.
pub fn u64_le_at(bytes: &[u8], at: usize) -> Option<u64> {
    field(bytes, at).map(u64::from_le_bytes)
}

/// Big-endian `u32` at byte offset `at`, or `None` when it does not fit.
pub fn u32_be_at(bytes: &[u8], at: usize) -> Option<u32> {
    field(bytes, at).map(u32::from_be_bytes)
}

/// Big-endian `u64` at byte offset `at`, or `None` when it does not fit.
pub fn u64_be_at(bytes: &[u8], at: usize) -> Option<u64> {
    field(bytes, at).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_round_trips() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(hex(&bytes), "000fa5ff");
        assert_eq!(
            decode_lower_hex("000fa5ff").as_deref(),
            Some(&bytes[..])
        );
        assert_eq!(hex(&[]), "");
        assert_eq!(decode_lower_hex(""), Some(Vec::new()));
    }

    #[test]
    fn noncanonical_hex_is_rejected() {
        assert_eq!(decode_lower_hex("abc"), None);
        assert_eq!(decode_lower_hex("AB"), None);
        assert_eq!(decode_lower_hex("0g"), None);
        assert!(is_lower_hex("00ff", 4));
        assert!(!is_lower_hex("00FF", 4));
        assert!(!is_lower_hex("00ff", 6));
    }

    #[test]
    fn integer_fields_respect_endianness_and_bounds() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16_le_at(&bytes, 0), Some(0x0201));
        assert_eq!(u32_le_at(&bytes, 4), Some(0x0807_0605));
        assert_eq!(u64_le_at(&bytes, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u32_be_at(&bytes, 0), Some(0x0102_0304));
        assert_eq!(u64_be_at(&bytes, 0), Some(0x0102_0304_0506_0708));
        assert_eq!(u32_le_at(&bytes, 5), None);
        assert_eq!(u64_be_at(&bytes, usize::MAX), None);
    }
}
