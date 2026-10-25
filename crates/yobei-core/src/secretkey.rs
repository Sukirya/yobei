//! Secret key material (DESIGN.md §3): an optional device-held secret
//! that participates in KEK derivation as the HKDF salt (see keys.rs).
//! Users see it as a base32 string grouped in fours, like a recovery key;
//! it is shown once at vault creation and required to unlock on any
//! device that does not hold it in its keychain.

use data_encoding::BASE32_NOPAD;

use crate::keys::{self, KEY_LEN};

/// Generate a fresh secret key and return its user-facing string form.
pub fn generate_secret_key() -> String {
    format_secret_key(&keys::random_bytes(KEY_LEN))
}

/// Format raw secret key bytes as grouped base32: `XXXX-XXXX-...`.
pub fn format_secret_key(bytes: &[u8]) -> String {
    let encoded = BASE32_NOPAD.encode(bytes);
    encoded
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a user-provided secret key string. Tolerant of dashes, spaces
/// and lowercase; strict about the decoded length.
pub fn parse_secret_key(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| "invalid secret key format".to_string())?;
    if bytes.len() != KEY_LEN {
        return Err(format!(
            "secret key must decode to {KEY_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_format_parse_roundtrip() {
        let shown = generate_secret_key();
        // 32 bytes -> 52 base32 chars -> 13 groups of 4.
        assert_eq!(shown.matches('-').count(), 12);
        let parsed = parse_secret_key(&shown).unwrap();
        assert_eq!(parsed.len(), KEY_LEN);
        assert_eq!(format_secret_key(&parsed), shown);
        // Tolerant parsing: lowercase, spaces, no dashes.
        let messy = shown.replace('-', " ").to_lowercase();
        assert_eq!(parse_secret_key(&messy).unwrap(), parsed);
        assert!(parse_secret_key("AAAA").is_err());
        assert!(parse_secret_key("not!base32").is_err());
    }
}
