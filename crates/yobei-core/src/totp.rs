//! TOTP (RFC 6238) and HOTP (RFC 4226), plus `otpauth://` URI parsing
//! (the format QR codes from every major service carry).
//!
//! Correctness is pinned by the RFC 6238 Appendix B test vectors below —
//! all three hash algorithms, all six timestamps.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::keys;
use crate::record::TotpConfig;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Decode a base32 TOTP secret. Tolerant of spaces, dashes, lowercase
/// and padding, strict about the alphabet.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let unpadded = cleaned.trim_end_matches('=');
    BASE32_NOPAD
        .decode(unpadded.as_bytes())
        .map_err(|_| "invalid base32 TOTP secret".to_string())
}

/// Generate a fresh TOTP secret (160-bit, the RFC-recommended length),
/// returned in the canonical base32 form services display.
pub fn generate_secret() -> String {
    BASE32_NOPAD.encode(&keys::random_bytes(20))
}

fn hotp(secret: &[u8], counter: u64, digits: u8, algorithm: &str) -> Result<String, String> {
    if !(6..=8).contains(&digits) {
        return Err("TOTP digits must be 6..=8".to_string());
    }
    let msg = counter.to_be_bytes();
    let hash: Vec<u8> = match algorithm.to_ascii_uppercase().as_str() {
        "SHA1" => {
            let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| "bad key")?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA256" => {
            let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| "bad key")?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = HmacSha512::new_from_slice(secret).map_err(|_| "bad key")?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        other => return Err(format!("unsupported TOTP algorithm: {other}")),
    };
    // RFC 4226 dynamic truncation.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    let code = binary % 10u32.pow(digits as u32);
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// The TOTP code for a config at a moment in time.
pub fn totp_code(config: &TotpConfig, at_unix_secs: u64) -> Result<String, String> {
    if config.period_secs == 0 {
        return Err("TOTP period must be > 0".to_string());
    }
    let secret = decode_secret(&config.secret)?;
    if secret.is_empty() {
        return Err("TOTP secret is empty".to_string());
    }
    hotp(&secret, at_unix_secs / config.period_secs as u64, config.digits, &config.algorithm)
}

/// Seconds remaining in the current TOTP window.
pub fn remaining_secs(config: &TotpConfig, at_unix_secs: u64) -> u32 {
    if config.period_secs == 0 {
        return 0;
    }
    config.period_secs - (at_unix_secs % config.period_secs as u64) as u32
}

/// A parsed `otpauth://totp/...` URI: the config plus the display pieces
/// the URI carries (issuer prefix and account label), so importers can
/// title the record sensibly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOtpauth {
    pub config: TotpConfig,
    pub account_name: Option<String>,
    pub label_issuer: Option<String>,
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an `otpauth://totp/` URI (Key URI Format, as used by Google
/// Authenticator and every service's "can't scan the QR code" page).
pub fn parse_otpauth_uri(uri: &str) -> Result<ParsedOtpauth, String> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth://")
        .ok_or_else(|| "not an otpauth URI".to_string())?;
    let (kind, rest) = rest
        .split_once('/')
        .ok_or_else(|| "malformed otpauth URI".to_string())?;
    if kind != "totp" {
        return Err(format!("unsupported otpauth kind: {kind}"));
    }
    let (label_raw, query_raw) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let label = percent_decode(label_raw);
    let (label_issuer, account_name) = match label.split_once(':') {
        Some((iss, acct)) => (
            Some(iss.trim().to_string()).filter(|s| !s.is_empty()),
            Some(acct.trim().to_string()).filter(|s| !s.is_empty()),
        ),
        None => (None, Some(label).filter(|s| !s.is_empty())),
    };

    let mut params: Vec<(String, String)> = Vec::new();
    for pair in query_raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        params.push((
            percent_decode(k).to_lowercase(),
            percent_decode(v),
        ));
    }
    let get = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };

    let secret = get("secret").ok_or_else(|| "otpauth URI has no secret".to_string())?;
    decode_secret(&secret)?; // validate eagerly; importers must not store junk
    let mut config = TotpConfig {
        secret,
        issuer: get("issuer").or_else(|| label_issuer.clone()),
        ..TotpConfig::default()
    };
    if let Some(d) = get("digits") {
        config.digits = d.parse().map_err(|_| "invalid digits in otpauth URI")?;
    }
    if let Some(p) = get("period") {
        config.period_secs = p.parse().map_err(|_| "invalid period in otpauth URI")?;
    }
    if let Some(a) = get("algorithm") {
        config.algorithm = a.to_uppercase();
    }
    Ok(ParsedOtpauth {
        config,
        account_name,
        label_issuer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_config(seed_ascii: &[u8], algorithm: &str) -> TotpConfig {
        TotpConfig {
            secret: data_encoding::BASE32.encode(seed_ascii),
            issuer: None,
            digits: 8,
            period_secs: 30,
            algorithm: algorithm.to_string(),
        }
    }

    #[test]
    fn rfc6238_appendix_b_vectors() {
        // Seeds and expected values are the RFC 6238 Appendix B table.
        let sha1 = rfc_config(b"12345678901234567890", "SHA1");
        let sha256 = rfc_config(b"12345678901234567890123456789012", "SHA256");
        let sha512 = rfc_config(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            "SHA512",
        );
        // Values per RFC 6238 Appendix B as published (cross-checked
        // against the RFC text and an independent implementation; the
        // RFC's SHA1 cells for t=1111111111 and t=20000000000 are the
        // ones most often mis-transcribed — the correct values are
        // 14050471 and 65353130).
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, e1, e256, e512) in cases {
            assert_eq!(totp_code(&sha1, t).unwrap(), e1, "SHA1 t={t}");
            assert_eq!(totp_code(&sha256, t).unwrap(), e256, "SHA256 t={t}");
            assert_eq!(totp_code(&sha512, t).unwrap(), e512, "SHA512 t={t}");
        }
    }

    #[test]
    fn window_math() {
        let cfg = TotpConfig::default();
        assert_eq!(remaining_secs(&cfg, 0), 30);
        assert_eq!(remaining_secs(&cfg, 29), 1);
        assert_eq!(remaining_secs(&cfg, 30), 30);
        assert_eq!(remaining_secs(&cfg, 45), 15);
    }

    #[test]
    fn parse_real_world_otpauth_uri() {
        let parsed = parse_otpauth_uri(
            "otpauth://totp/GitHub:octocat%40example.com\
             ?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=SHA1",
        )
        .unwrap();
        assert_eq!(parsed.config.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.config.issuer.as_deref(), Some("GitHub"));
        assert_eq!(parsed.account_name.as_deref(), Some("octocat@example.com"));
        assert_eq!(parsed.label_issuer.as_deref(), Some("GitHub"));
        // And the parsed config produces codes.
        assert_eq!(totp_code(&parsed.config, 59).unwrap().len(), 6);

        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse_otpauth_uri("https://example.com").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x").is_err());
    }

    #[test]
    fn generated_secrets_are_usable() {
        let secret = generate_secret();
        let cfg = TotpConfig { secret, ..TotpConfig::default() };
        assert_eq!(totp_code(&cfg, 12345).unwrap().len(), 6);
    }
}
