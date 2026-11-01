//! Bootstrap material derived from the mandatory Secret Key (ADR-0001,
//! ADR-0002).
//!
//! The sync server must be able to hand a brand-new device everything it needs
//! to start unlocking — without ever being able to read it, and without being
//! able to use it as an oracle for guessing the master password. Both
//! properties come from one rule: the server only ever stores material that is
//! encrypted under a key derived from the Secret Key, which never leaves the
//! user's devices.
//!
//! ```text
//! vault_address = BASE32(HKDF-SHA256(Secret Key, "yobei-vault-address-v1"))
//! bootstrap_key = HKDF-SHA256(Secret Key, "yobei-bootstrap-key-v1")
//! bootstrap     = XChaCha20-Poly1305(bootstrap_key, AAD = vault_address, header)
//! auth_key      = HKDF-SHA256(Vault Key,    "yobei-auth-v1")
//! ```

use argon2::Params;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::Argon2idParams;
use crate::keys::{self, KEY_LEN};

/// HKDF info domains. Every purpose gets its own; never reuse one derivation
/// for two jobs (ADR-0001).
pub const INFO_BOOTSTRAP_KEY: &[u8] = b"yobei-bootstrap-key-v1";
pub const INFO_AUTH: &[u8] = b"yobei-auth-v1";
pub const INFO_VAULT_ADDRESS: &[u8] = b"yobei-vault-address-v1";

const NONCE_LEN: usize = 24;

// Upper bounds for KDF parameters read from untrusted files (vault headers,
// encrypted exports). Without these a malicious file could ask for a
// multi-terabyte Argon2 allocation (ADR-0001 §4).
const MAX_MEMORY_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 8;

/// Header carried by the encrypted bootstrap package. Everything a fresh
/// device needs before it has the vault key. No user content lives here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapHeader {
    pub format_version: u32,
    /// The vault's local UUID. Preserved across devices so entries keep the
    /// same `vault_id`.
    pub vault_id: String,
    /// The sync address derived from the Secret Key. Also used as the AEAD
    /// AAD, so a package cannot be replayed under a different address.
    pub address: String,
    pub kdf_params: Argon2idParams,
    pub kdf_salt: Vec<u8>,
    /// Vault key wrapped under the KEK (password + Secret Key).
    pub wrapped_vault_key: Vec<u8>,
    pub created_at_ms: i64,
}

/// Derive the Sync Address from the Secret Key. It is safe to publish: it is
/// one-way with respect to the Secret Key, but only someone holding the Secret
/// Key can compute it in the first place.
pub fn vault_address(secret_key: &[u8]) -> Result<String, String> {
    let key = secret_key_of(secret_key)?;
    let hk = Hkdf::<Sha256>::new(None, &*key);
    let mut out = [0u8; KEY_LEN];
    hk.expand(INFO_VAULT_ADDRESS, &mut out)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(BASE32_NOPAD.encode(&out))
}

/// Derive the key that encrypts the bootstrap package.
pub fn derive_bootstrap_key(secret_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let key = secret_key_of(secret_key)?;
    let hk = Hkdf::<Sha256>::new(None, &*key);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_BOOTSTRAP_KEY, &mut *out)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(out)
}

/// Encrypt a bootstrap header for storage on the sync server.
/// Output is `nonce ‖ ciphertext`.
pub fn seal_bootstrap(secret_key: &[u8], header: &BootstrapHeader) -> Result<Vec<u8>, String> {
    let key = derive_bootstrap_key(secret_key)?;
    let plaintext = serde_json::to_vec(header).map_err(|e| format!("serialize bootstrap: {e}"))?;
    let key_ref: &[u8; KEY_LEN] = &key;
    let cipher = XChaCha20Poly1305::new(key_ref.into());
    let nonce = keys::random_bytes(NONCE_LEN);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: header.address.as_bytes(),
            },
        )
        .map_err(|_| "bootstrap encrypt failed".to_string())?;
    let mut out = nonce;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a bootstrap package fetched from the server.
pub fn open_bootstrap(
    secret_key: &[u8],
    vault_address: &str,
    blob: &[u8],
) -> Result<BootstrapHeader, String> {
    if blob.len() <= NONCE_LEN {
        return Err("bootstrap package too short".to_string());
    }
    let key = derive_bootstrap_key(secret_key)?;
    let key_ref: &[u8; KEY_LEN] = &key;
    let cipher = XChaCha20Poly1305::new(key_ref.into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&blob[..NONCE_LEN]),
            Payload {
                msg: &blob[NONCE_LEN..],
                aad: vault_address.as_bytes(),
            },
        )
        .map_err(|_| "wrong secret key or corrupt bootstrap package".to_string())?;
    let header: BootstrapHeader =
        serde_json::from_slice(&plaintext).map_err(|e| format!("parse bootstrap header: {e}"))?;
    if header.address != vault_address {
        return Err("bootstrap package does not match this address".to_string());
    }
    validate_kdf_params(&header.kdf_params)?;
    Ok(header)
}

/// Derive the credential a device presents to the sync server. The server
/// stores only its SHA-256, and cannot derive it without the vault key.
pub fn derive_auth_key(vault_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let key = key_of(vault_key)?;
    let hk = Hkdf::<Sha256>::new(None, &*key);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_AUTH, &mut *out)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(out)
}

/// What the server stores: a one-way hash of the auth key.
pub fn auth_key_hash(auth_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let digest = Sha256::digest(auth_key);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Reject KDF parameters that are outside the safe envelope. Used for every
/// parameter set that comes from a file or the network.
pub fn validate_kdf_params(params: &Argon2idParams) -> Result<(), String> {
    if params.memory_kib < Argon2idParams::OWASP_MINIMUM.memory_kib {
        return Err(format!(
            "KDF memory below the OWASP floor: {} KiB",
            params.memory_kib
        ));
    }
    if params.memory_kib > MAX_MEMORY_KIB {
        return Err(format!(
            "KDF memory exceeds the safe cap: {} KiB",
            params.memory_kib
        ));
    }
    if params.iterations == 0 || params.iterations > MAX_ITERATIONS {
        return Err(format!("invalid KDF iterations: {}", params.iterations));
    }
    if params.parallelism == 0 || params.parallelism > MAX_PARALLELISM {
        return Err(format!("invalid KDF parallelism: {}", params.parallelism));
    }
    // Let the argon2 crate perform its own structural validation as well.
    Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| format!("invalid Argon2id params: {e}"))?;
    Ok(())
}

fn secret_key_of(secret_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if secret_key.len() != KEY_LEN {
        return Err(format!(
            "secret key must be {KEY_LEN} bytes, got {}",
            secret_key.len()
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(secret_key);
    Ok(key)
}

fn key_of(key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if key.len() != KEY_LEN {
        return Err(format!("key must be {KEY_LEN} bytes, got {}", key.len()));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(key);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Argon2idParams {
        Argon2idParams::DEFAULT
    }

    fn header(address: &str) -> BootstrapHeader {
        BootstrapHeader {
            format_version: 1,
            vault_id: "vault-uuid".to_string(),
            address: address.to_string(),
            kdf_params: params(),
            kdf_salt: keys::random_bytes(16),
            wrapped_vault_key: keys::random_bytes(56),
            created_at_ms: 1_000,
        }
    }

    #[test]
    fn address_is_stable_and_key_dependent() {
        let a = keys::random_bytes(KEY_LEN);
        let b = keys::random_bytes(KEY_LEN);
        let addr_a = vault_address(&a).unwrap();
        assert_eq!(addr_a, vault_address(&a).unwrap());
        assert_ne!(addr_a, vault_address(&b).unwrap());
        // 32 bytes of base32 without padding.
        assert_eq!(addr_a.len(), 52);
        assert!(vault_address(&a[..16]).is_err());
    }

    #[test]
    fn bootstrap_roundtrip_and_wrong_key_fails() {
        let sk = keys::random_bytes(KEY_LEN);
        let addr = vault_address(&sk).unwrap();
        let sealed = seal_bootstrap(&sk, &header(&addr)).unwrap();
        let opened = open_bootstrap(&sk, &addr, &sealed).unwrap();
        assert_eq!(opened.address, addr);
        assert_eq!(opened.vault_id, "vault-uuid");

        let wrong = keys::random_bytes(KEY_LEN);
        assert!(open_bootstrap(&wrong, &addr, &sealed).is_err());
        // A package cannot be replayed under a different address.
        let other_addr = vault_address(&wrong).unwrap();
        assert!(open_bootstrap(&sk, &other_addr, &sealed).is_err());
    }

    #[test]
    fn auth_key_differs_from_vault_key_and_hashes_stably() {
        let vault_key = keys::random_bytes(KEY_LEN);
        let auth = derive_auth_key(&vault_key).unwrap();
        let auth_bytes: &[u8] = &*auth;
        assert_ne!(auth_bytes, vault_key.as_slice());
        let hash = auth_key_hash(&auth);
        assert_eq!(hash, auth_key_hash(&auth));
        assert_eq!(hash.len(), 32); // 32-byte SHA-256
    }

    #[test]
    fn kdf_bounds_are_enforced() {
        assert!(validate_kdf_params(&Argon2idParams::DEFAULT).is_ok());
        assert!(validate_kdf_params(&Argon2idParams::OWASP_MINIMUM).is_ok());

        let too_big = Argon2idParams {
            memory_kib: u32::MAX,
            ..Argon2idParams::DEFAULT
        };
        assert!(validate_kdf_params(&too_big).is_err());

        let too_small = Argon2idParams {
            memory_kib: 1024,
            ..Argon2idParams::DEFAULT
        };
        assert!(validate_kdf_params(&too_small).is_err());

        let too_many = Argon2idParams {
            iterations: 100,
            ..Argon2idParams::DEFAULT
        };
        assert!(validate_kdf_params(&too_many).is_err());
    }
}
