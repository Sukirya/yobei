//! Key hierarchy implementation (DESIGN.md §3), wrapping audited
//! RustCrypto crates only — no home-grown cryptography.
//!
//! master password ──Argon2id(salt, params)──> master key
//!   └─ if a secret key is enabled: HKDF-SHA256(salt = secret key,
//!      info = "yobei-kek-v1") ──> KEK
//! KEK ──XChaCha20-Poly1305 wrap──> vault key (random 32 bytes)
//! vault key ──HKDF-SHA256(info = "yobei-record-v1:<id>")──> per-record key
//! per-record key ──XChaCha20-Poly1305, AAD = record id──> record ciphertext
//!
//! Because records are encrypted under the vault key (never the KEK),
//! changing the master password only re-wraps the vault key.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::Argon2idParams;
use crate::record::Record;

pub const KEY_LEN: usize = 32;
pub const KDF_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305
const WRAP_AAD: &[u8] = b"yobei-vault-key-wrap-v1";
const KEK_INFO: &[u8] = b"yobei-kek-v1";
const RECORD_INFO_PREFIX: &str = "yobei-record-v1:";

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("OS RNG must be available");
    buf
}

/// Derive the key-encryption key from the master password.
///
/// The optional secret key participates as the HKDF salt (the design
/// borrowed from the reference project): a load-bearing test below proves
/// the same password with a different secret key cannot unwrap a vault.
pub fn derive_kek(
    password: &str,
    salt: &[u8],
    params: Argon2idParams,
    secret_key: Option<&[u8]>,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| format!("invalid Argon2id params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *master)
        .map_err(|e| format!("Argon2id failed: {e}"))?;
    match secret_key {
        None => Ok(master),
        Some(sk) => {
            let hk = Hkdf::<Sha256>::new(Some(sk), &*master);
            let mut kek = Zeroizing::new([0u8; KEY_LEN]);
            hk.expand(KEK_INFO, &mut *kek)
                .map_err(|_| "HKDF expand failed".to_string())?;
            Ok(kek)
        }
    }
}

fn aead_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = random_bytes(NONCE_LEN);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: plaintext, aad },
        )
        .map_err(|_| "AEAD encrypt failed".to_string())?;
    let mut out = nonce;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_decrypt(key: &[u8; KEY_LEN], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() <= NONCE_LEN {
        return Err("ciphertext too short".to_string());
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&blob[..NONCE_LEN]),
            Payload { msg: &blob[NONCE_LEN..], aad },
        )
        .map_err(|_| "AEAD decrypt failed (wrong key or corrupted data)".to_string())
}

/// Wrap (encrypt) an arbitrary 32-byte key under the KEK.
pub fn wrap_key(kek: &[u8; KEY_LEN], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    aead_encrypt(kek, key, WRAP_AAD)
}

/// Unwrap a key previously wrapped with [`wrap_key`].
pub fn unwrap_key(kek: &[u8; KEY_LEN], blob: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let pt = aead_decrypt(kek, blob, WRAP_AAD)?;
    let arr: [u8; KEY_LEN] = pt
        .as_slice()
        .try_into()
        .map_err(|_| "wrapped key has wrong length".to_string())?;
    Ok(Zeroizing::new(arr))
}

const BLOB_AAD: &[u8] = b"yobei-blob-v1";

/// Encrypt an arbitrary blob under a 32-byte key (used for encrypted
/// export files). Output is `nonce ‖ ciphertext`.
pub fn encrypt_blob(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    aead_encrypt(key, plaintext, BLOB_AAD)
}

/// Decrypt a blob produced by [`encrypt_blob`].
pub fn decrypt_blob(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, String> {
    aead_decrypt(key, blob, BLOB_AAD)
}

/// Per-record key: HKDF from the vault key, bound to the record id, so a
/// ciphertext copied onto another record's row cannot be decrypted there.
pub fn record_key(vault_key: &[u8; KEY_LEN], record_id: &str) -> [u8; KEY_LEN] {
    let info = format!("{RECORD_INFO_PREFIX}{record_id}");
    let hk = Hkdf::<Sha256>::new(None, vault_key);
    let mut key = [0u8; KEY_LEN];
    hk.expand(info.as_bytes(), &mut key)
        .expect("32-byte HKDF output is always valid");
    key
}

/// Encrypt a record for storage/sync. Output is `nonce ‖ ciphertext`.
pub fn encrypt_record(vault_key: &[u8; KEY_LEN], record: &Record) -> Result<Vec<u8>, String> {
    let key = record_key(vault_key, &record.id);
    let json = serde_json::to_vec(record).map_err(|e| format!("serialize record: {e}"))?;
    aead_encrypt(&key, &json, record.id.as_bytes())
}

/// Decrypt a record blob. Fails if the blob was stored under a different
/// record id (AAD and key derivation both bind to the id).
pub fn decrypt_record(
    vault_key: &[u8; KEY_LEN],
    record_id: &str,
    blob: &[u8],
) -> Result<Record, String> {
    let key = record_key(vault_key, record_id);
    let json = aead_decrypt(&key, blob, record_id.as_bytes())?;
    let record: Record =
        serde_json::from_slice(&json).map_err(|e| format!("deserialize record: {e}"))?;
    if record.id != record_id {
        return Err("record id mismatch after decrypt".to_string());
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2idParams;

    fn fast_params() -> Argon2idParams {
        Argon2idParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_wrong_password_fails() {
        let salt = random_bytes(KDF_SALT_LEN);
        let kek = derive_kek("correct horse", &salt, fast_params(), None).unwrap();
        let vault_key: [u8; KEY_LEN] = random_bytes(KEY_LEN).try_into().unwrap();
        let wrapped = wrap_key(&kek, &vault_key).unwrap();
        assert_eq!(*unwrap_key(&kek, &wrapped).unwrap(), vault_key);

        let wrong = derive_kek("wrong horse", &salt, fast_params(), None).unwrap();
        assert!(unwrap_key(&wrong, &wrapped).is_err());
    }

    #[test]
    fn secret_key_is_load_bearing() {
        // Borrowed from the reference project: with a secret key enabled,
        // the password alone (or the wrong secret key) must not unwrap.
        let salt = random_bytes(KDF_SALT_LEN);
        let sk_a = random_bytes(32);
        let sk_b = random_bytes(32);
        let vault_key: [u8; KEY_LEN] = random_bytes(KEY_LEN).try_into().unwrap();
        let kek = derive_kek("pw", &salt, fast_params(), Some(&sk_a)).unwrap();
        let wrapped = wrap_key(&kek, &vault_key).unwrap();
        assert_eq!(*unwrap_key(&kek, &wrapped).unwrap(), vault_key);

        let no_sk = derive_kek("pw", &salt, fast_params(), None).unwrap();
        assert!(unwrap_key(&no_sk, &wrapped).is_err());
        let wrong_sk = derive_kek("pw", &salt, fast_params(), Some(&sk_b)).unwrap();
        assert!(unwrap_key(&wrong_sk, &wrapped).is_err());
    }

    #[test]
    fn record_ciphertext_is_bound_to_its_id() {
        let vault_key: [u8; KEY_LEN] = random_bytes(KEY_LEN).try_into().unwrap();
        let record = Record::new_account("id-a".into(), "v1".into(), "GitHub".into(), 1_000);
        let blob = encrypt_record(&vault_key, &record).unwrap();
        assert_eq!(decrypt_record(&vault_key, "id-a", &blob).unwrap(), record);
        // Same blob presented as another record must fail, not migrate.
        assert!(decrypt_record(&vault_key, "id-b", &blob).is_err());
    }
}
