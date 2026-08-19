//! Tiny shared lowercase-hex encoder.
//!
//! No dependency pulls this in on its own — sha256 digests are the only thing that needs it,
//! in a handful of otherwise-unrelated modules — so it's a plain hand-rolled loop rather than
//! a `hex` crate dependency.

use std::fmt::Write;

/// Encodes `bytes` as a lowercase hex string, e.g. `[0xab, 0x01]` -> `"ab01"`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // `write!` into a `String` never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::encode;

    #[test]
    fn encodes_lowercase_hex() {
        assert_eq!(encode(&[0xab, 0x01, 0x00, 0xff]), "ab0100ff");
    }

    #[test]
    fn empty_input_is_empty_string() {
        assert_eq!(encode(&[]), "");
    }
}
