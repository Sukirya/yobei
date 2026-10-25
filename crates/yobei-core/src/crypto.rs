//! Cryptographic choices and parameters.
//!
//! Rule: never roll your own. Implementations in this project wrap audited
//! libraries only (RustCrypto / libsodium). This module pins the algorithm
//! identifiers and parameters so vaults stay self-describing and upgradable
//! (parameters are stored in the vault header). See docs/DESIGN.md §3.

use serde::{Deserialize, Serialize};

/// Key derivation function for the master password (+ optional secret key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Argon2id parameters. Floors follow the OWASP Password Storage Cheat
/// Sheet (19 MiB, t=2, p=1); defaults target ~0.5–1s unlock on a low-end
/// Android phone and must be benchmarked on real hardware before release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2idParams {
    pub const OWASP_MINIMUM: Self = Self {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };
}

/// AEAD for record/vault encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AeadAlgorithm {
    /// 192-bit nonce: safe with random nonces at vault scale. Default.
    XChaCha20Poly1305,
    /// Kept for a possible FIPS-oriented profile; 96-bit nonce needs
    /// strict nonce management.
    Aes256Gcm,
}

/// Key hierarchy (see DESIGN.md §3):
/// master password (+ optional secret key, combined via HKDF)
///   -> Argon2id -> KEK -> unwraps Vault Key -> unwraps per-record keys
///   -> AEAD encrypts record plaintext.
/// Sharing (reserved, not implemented): a vault key can later be wrapped
/// to another member's X25519 public key without changing this hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoProfile {
    pub kdf: KdfAlgorithm,
    pub kdf_params: Argon2idParams,
    pub aead: AeadAlgorithm,
    /// Whether a device-local secret key participates in derivation.
    pub secret_key_enabled: bool,
}

impl Default for CryptoProfile {
    fn default() -> Self {
        Self {
            kdf: KdfAlgorithm::Argon2id,
            kdf_params: Argon2idParams::DEFAULT,
            aead: AeadAlgorithm::XChaCha20Poly1305,
            secret_key_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_do_not_go_below_owasp_floor() {
        assert!(Argon2idParams::DEFAULT.memory_kib >= Argon2idParams::OWASP_MINIMUM.memory_kib);
    }
}
