//! Vault file and unlocked session (ADR-0001, ADR-0003).
//!
//! A vault is one SQLite database. The `meta` table holds the vault
//! header — format version, the [`CryptoProfile`] (KDF params live here,
//! not in constants, so they can be raised later), the KDF salt and the
//! vault key wrapped under the KEK. Each entry row keeps only the
//! columns list/sync logic needs in the clear (id, kind, timestamps,
//! version, tombstone) plus the AEAD ciphertext blob produced by
//! [`crate::keys`]. Titles and everything else stay encrypted; listing
//! decrypts in memory, which is fine at personal-vault scale.
//!
//! This module is the reference storage adapter: SQLite via rusqlite
//! (bundled), identical on Android and desktop.

use std::path::Path;

use data_encoding::BASE64;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::CryptoProfile;
use crate::entry::{
    AccountPayload, CardPayload, Entry, EntryKind, EntryPayload, IdentityPayload, NotePayload,
};
use crate::keys::{self, KDF_SALT_LEN, KEY_LEN};
use crate::sync::SyncOp;

pub const VAULT_FORMAT_VERSION: u32 = 1;
const HEADER_META_KEY: &str = "vault_header";

const ENTRY_UPSERT_SQL: &str = "INSERT INTO entries
        (id, kind, created_at_ms, updated_at_ms, version, hlc, deleted, deleted_at_ms, ciphertext)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
    ON CONFLICT(id) DO UPDATE SET
        kind = excluded.kind,
        created_at_ms = excluded.created_at_ms,
        updated_at_ms = excluded.updated_at_ms,
        version = excluded.version,
        hlc = excluded.hlc,
        deleted = excluded.deleted,
        deleted_at_ms = excluded.deleted_at_ms,
        ciphertext = excluded.ciphertext";

const SCHEMA_SQL: &str = "PRAGMA secure_delete = ON;
     CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
     CREATE TABLE entries (
         id TEXT PRIMARY KEY,
         kind TEXT NOT NULL,
         created_at_ms INTEGER NOT NULL,
         updated_at_ms INTEGER NOT NULL,
         version INTEGER NOT NULL,
         hlc INTEGER NOT NULL,
         deleted INTEGER NOT NULL DEFAULT 0,
         deleted_at_ms INTEGER,
         ciphertext BLOB NOT NULL
     );
     CREATE INDEX idx_entries_updated ON entries(updated_at_ms);
     CREATE TABLE outbox (
         op_id TEXT PRIMARY KEY,
         entry_id TEXT NOT NULL,
         op_json TEXT NOT NULL,
         created_at_ms INTEGER NOT NULL
     );
     CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format_version: u32,
    pub vault_id: String,
    pub profile: CryptoProfile,
    /// Argon2id salt (fresh random on create and on every password change).
    pub kdf_salt: Vec<u8>,
    /// Vault key wrapped under the KEK (see keys.rs).
    pub wrapped_vault_key: Vec<u8>,
    /// Vault key wrapped under the password-only KEK (Argon2id output,
    /// no Secret Key) so daily unlock needs only the master password
    /// (ADR-0010). Absent on vaults created before this existed; `open`
    /// writes it on the first unlock with the Secret Key.
    #[serde(default)]
    pub wrapped_vault_key_password_only: Option<Vec<u8>>,
    pub created_at_ms: i64,
    /// Sync address derived from the Secret Key (ADR-0002). Safe to publish;
    /// only holders of the Secret Key can compute it.
    #[serde(default)]
    pub sync_address: Option<String>,
    /// Sealed bootstrap package (ADR-0002), stored locally so the shell can
    /// upload it without keeping the Secret Key in memory.
    #[serde(default)]
    pub bootstrap_package: Option<Vec<u8>>,
    /// Fingerprint of this vault's key (ADR-0012), written at creation and
    /// backfilled on the next unlock with the Secret Key. `open_with_key`
    /// compares the presented check against this value, so a
    /// self-consistent key+check pair from another vault is rejected
    /// instead of opening this vault under the wrong key. Absent on
    /// vaults created before this existed.
    #[serde(default)]
    pub vault_key_check: Option<Vec<u8>>,
}

/// Sync-relevant metadata of one stored row (no decryption needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    pub id: String,
    pub version: u64,
    pub hlc: u64,
    pub updated_at_ms: i64,
    pub deleted: bool,
}

/// Result of a tolerant listing: decrypted entries plus the ids of rows
/// that could not be decrypted (ADR-0003 §7).
#[derive(Debug, Default)]
pub struct ListReport {
    pub entries: Vec<Entry>,
    pub skipped: Vec<String>,
}

/// A zero-byte file at the vault path cannot hold a vault: it is a leftover
/// from a partial init. Removing it is safe; a non-empty file is never
/// touched here.
fn remove_empty_file(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.is_file() && meta.len() == 0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Refuse to overwrite a real vault, but tolerate a zero-byte leftover file.
fn ensure_no_vault(path: &Path) -> Result<(), String> {
    remove_empty_file(path);
    if path.exists() {
        return Err("vault file already exists".to_string());
    }
    Ok(())
}

/// An unlocked vault. Holds the vault key in memory (zeroized on drop);
/// dropping the `Vault` is locking it.
pub struct Vault {
    conn: Connection,
    header: VaultHeader,
    vault_key: Zeroizing<[u8; KEY_LEN]>,
}

impl Vault {
    /// Generate a fresh entry/vault id (UUIDv7: time-ordered, unique).
    pub fn new_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Sync address derived from the Secret Key (ADR-0002).
    pub fn sync_address(&self) -> Option<&str> {
        self.header.sync_address.as_deref()
    }

    /// Sealed bootstrap package to upload to the sync server (ADR-0002).
    pub fn bootstrap_package(&self) -> Option<&[u8]> {
        self.header.bootstrap_package.as_deref()
    }

    /// The raw vault key. Only the platform unlock adapter (ADR-0009) may
    /// take it out, to store it under the device keystore; it never leaves
    /// the app process and never enters the webview.
    pub fn vault_key(&self) -> &[u8; KEY_LEN] {
        &self.vault_key
    }

    /// Fingerprint of a vault key: SHA-256 of the auth key (ADR-0002), the
    /// same value the sync server stores. A platform adapter records it
    /// next to a stored vault key, and the vault header records it too
    /// (ADR-0012), so `open_with_key` can tell a stale key from the right
    /// one. It is one-way: it cannot recover the vault key.
    pub fn vault_key_check(vault_key: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], String> {
        let auth = crate::bootstrap::derive_auth_key(vault_key)?;
        Ok(crate::bootstrap::auth_key_hash(&auth))
    }

    /// Base64 of the auth key: the enrollment credential sent to the sync
    /// server. Never log it.
    pub fn auth_key_b64(&self) -> Result<String, String> {
        let auth = crate::bootstrap::derive_auth_key(&*self.vault_key)?;
        Ok(BASE64.encode(&*auth))
    }

    /// Base64 of SHA-256(auth key): what the server stores on first upload.
    pub fn auth_hash_b64(&self) -> Result<String, String> {
        let auth = crate::bootstrap::derive_auth_key(&*self.vault_key)?;
        Ok(BASE64.encode(&crate::bootstrap::auth_key_hash(&auth)))
    }

    /// Create a new vault file. Fails if a vault already exists at the path.
    pub fn create(
        path: &Path,
        password: &str,
        secret_key: Option<&[u8]>,
        profile: CryptoProfile,
        now_ms: i64,
    ) -> Result<Vault, String> {
        ensure_no_vault(path)?;
        // Every externally supplied parameter set is validated before use
        // (ADR-0001 §4).
        crate::bootstrap::validate_kdf_params(&profile.kdf_params)?;
        // The Secret Key is mandatory (ADR-0001).
        let secret_key = secret_key.ok_or_else(|| "a Secret Key is required".to_string())?;
        let mut profile = profile;
        profile.secret_key_enabled = true;

        let mut conn = Connection::open(path).map_err(|e| format!("open vault db: {e}"))?;
        // Any failure below must remove the partial file, or the next
        // create attempt is blocked by "vault file already exists".
        let built: Result<(VaultHeader, [u8; KEY_LEN]), String> = (|| {
            conn.execute_batch(SCHEMA_SQL)
                .map_err(|e| format!("init vault schema: {e}"))?;
            let salt = keys::random_bytes(KDF_SALT_LEN);
            let kek = keys::derive_kek(password, &salt, profile.kdf_params, Some(secret_key))?;
            let vault_key_bytes: [u8; KEY_LEN] = keys::random_bytes(KEY_LEN)
                .try_into()
                .expect("random_bytes returns the requested length");
            let wrapped = keys::wrap_key(&kek, &vault_key_bytes)?;
            // Second wrapping under the password-only KEK (ADR-0010), so
            // daily unlock needs only the master password.
            let pw_kek = keys::derive_kek(password, &salt, profile.kdf_params, None)?;
            let wrapped_pw = keys::wrap_key(&pw_kek, &vault_key_bytes)?;
            let sync_address = crate::bootstrap::vault_address(secret_key)?;
            let mut header = VaultHeader {
                format_version: VAULT_FORMAT_VERSION,
                vault_id: Self::new_id(),
                profile,
                kdf_salt: salt,
                wrapped_vault_key: wrapped,
                wrapped_vault_key_password_only: Some(wrapped_pw),
                created_at_ms: now_ms,
                sync_address: Some(sync_address),
                bootstrap_package: None,
                vault_key_check: Some(Self::vault_key_check(&vault_key_bytes)?.to_vec()),
            };
            let package = Self::seal_package(&header, secret_key)?;
            header.bootstrap_package = Some(package);
            Self::store_header(&mut conn, &header)?;
            Ok((header, vault_key_bytes))
        })();
        let (header, vault_key_bytes) = match built {
            Ok(v) => v,
            Err(e) => {
                drop(conn);
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        };
        Ok(Vault {
            conn,
            header,
            vault_key: Zeroizing::new(vault_key_bytes),
        })
    }

    /// Open the SQLite file and read + validate the header, without
    /// authenticating. Shared by `open` and `open_with_key`.
    fn open_db(path: &Path) -> Result<(Connection, VaultHeader), String> {
        // Connection::open creates a zero-byte file when the path does not
        // exist; never open a missing vault, or the next create is blocked.
        if !path.exists() {
            return Err("no vault found".to_string());
        }
        let conn = Connection::open(path).map_err(|e| format!("open vault db: {e}"))?;
        conn.execute_batch("PRAGMA secure_delete = ON;")
            .map_err(|e| format!("configure vault db: {e}"))?;
        let header_json: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![HEADER_META_KEY],
                |row| row.get(0),
            )
            .map_err(|_| "not a yobei vault (missing header)".to_string())?;
        let header: VaultHeader =
            serde_json::from_str(&header_json).map_err(|e| format!("corrupt vault header: {e}"))?;
        if header.format_version != VAULT_FORMAT_VERSION {
            return Err(format!(
                "unsupported vault format version {}",
                header.format_version
            ));
        }
        crate::bootstrap::validate_kdf_params(&header.profile.kdf_params)?;
        Ok((conn, header))
    }

    /// Vaults created before the sync tables existed gain them here.
    fn ensure_sync_schema(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                 op_id TEXT PRIMARY KEY,
                 entry_id TEXT NOT NULL,
                 op_json TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .map_err(|e| format!("ensure sync schema: {e}"))?;
        Ok(())
    }

    /// Open an existing vault. A wrong password (or wrong/missing secret
    /// key) fails at unwrapping the vault key, before any entry is read.
    ///
    /// With a Secret Key this is the original path (ADR-0001), and it also
    /// migrates the vault: if the password-only wrapping (ADR-0010) is
    /// missing, it is written so the next unlock needs only the password.
    /// Without a Secret Key, only the password-only wrapping is tried;
    /// vaults created before ADR-0010 need one unlock with the Secret Key
    /// first.
    pub fn open(path: &Path, password: &str, secret_key: Option<&[u8]>) -> Result<Vault, String> {
        let (mut conn, mut header) = Self::open_db(path)?;
        let mut dirty = false;
        let vault_key = match secret_key {
            Some(secret_key) => {
                let kek = keys::derive_kek(
                    password,
                    &header.kdf_salt,
                    header.profile.kdf_params,
                    Some(secret_key),
                )?;
                let vault_key = keys::unwrap_key(&kek, &header.wrapped_vault_key)
                    .map_err(|_| "wrong password or secret key".to_string())?;
                // Derive the sync address and (re)seal the bootstrap
                // package. The Secret Key is available here, so a package
                // missing from an older header is repaired in place
                // (ADR-0002).
                let expected_address = crate::bootstrap::vault_address(secret_key)?;
                if header.sync_address.as_deref() != Some(expected_address.as_str())
                    || header.bootstrap_package.is_none()
                {
                    header.sync_address = Some(expected_address);
                    let package = Self::seal_package(&header, secret_key)?;
                    header.bootstrap_package = Some(package);
                    dirty = true;
                }
                // Migration (ADR-0010): write the password-only wrapping
                // so daily unlock needs only the master password.
                if header.wrapped_vault_key_password_only.is_none() {
                    let pw_kek = keys::derive_kek(
                        password,
                        &header.kdf_salt,
                        header.profile.kdf_params,
                        None,
                    )?;
                    header.wrapped_vault_key_password_only =
                        Some(keys::wrap_key(&pw_kek, &vault_key)?);
                    dirty = true;
                }
                // Migration (ADR-0012): record the vault key check in the
                // header so open_with_key can tell a stale key from the
                // right one.
                if header.vault_key_check.is_none() {
                    header.vault_key_check = Some(Self::vault_key_check(&vault_key)?.to_vec());
                    dirty = true;
                }
                vault_key
            }
            None => {
                let wrapping =
                    header
                        .wrapped_vault_key_password_only
                        .as_ref()
                        .ok_or_else(|| {
                            "this vault requires its Secret Key once to enable password-only unlock"
                                .to_string()
                        })?;
                let pw_kek =
                    keys::derive_kek(password, &header.kdf_salt, header.profile.kdf_params, None)?;
                keys::unwrap_key(&pw_kek, wrapping).map_err(|_| "wrong password".to_string())?
            }
        };
        if dirty {
            Self::store_header(&mut conn, &header)?;
        }
        Self::ensure_sync_schema(&conn)?;
        Ok(Vault {
            conn,
            header,
            vault_key,
        })
    }

    /// Open an existing vault with a previously derived vault key, e.g. the
    /// one a platform adapter (biometric unlock, ADR-0009) recovered from
    /// the device keystore. Skips the password KDF entirely.
    ///
    /// `key_check` is the fingerprint from `vault_key_check`, recorded when
    /// the key was stored. Two checks: the key must be self-consistent
    /// with the check, and — when the header carries one (ADR-0012) — the
    /// check must match the header's. The second check is what proves the
    /// key belongs to *this* vault: a self-consistent pair from another
    /// vault is rejected here, so a stale blob (vault recreated after the
    /// blob was written) fails loudly instead of opening the vault under
    /// the wrong key. The sync address / bootstrap package are left
    /// untouched: they were written at creation and only repaired on a
    /// password unlock, which has the Secret Key.
    pub fn open_with_key(
        path: &Path,
        vault_key: &[u8; KEY_LEN],
        key_check: &[u8; KEY_LEN],
    ) -> Result<Vault, String> {
        if Self::vault_key_check(vault_key)? != *key_check {
            return Err("biometric key does not match this vault".to_string());
        }
        let (conn, header) = Self::open_db(path)?;
        // The header records the check (ADR-0012): a self-consistent pair
        // from another vault must not open this one. Vaults created before
        // the header carried the check have none; they gain it on the next
        // unlock with the Secret Key.
        if let Some(stored) = &header.vault_key_check {
            if stored.as_slice() != key_check {
                return Err("biometric key does not match this vault".to_string());
            }
        }
        Self::ensure_sync_schema(&conn)?;
        Ok(Vault {
            conn,
            header,
            vault_key: Zeroizing::new(*vault_key),
        })
    }

    // ---------------------------------------------------------- adoption ---

    /// Adopt an existing vault on a new device from its bootstrap package
    /// (ADR-0002). Creates a local vault file with the same vault id and
    /// vault key; the old device is not needed.
    pub fn adopt(
        path: &Path,
        password: &str,
        secret_key: &[u8],
        bootstrap: &[u8],
        address: &str,
    ) -> Result<Vault, String> {
        ensure_no_vault(path)?;
        let wire = crate::bootstrap::open_bootstrap(secret_key, address, bootstrap)?;
        if wire.format_version != VAULT_FORMAT_VERSION {
            return Err(format!(
                "unsupported vault format version {}",
                wire.format_version
            ));
        }
        crate::bootstrap::validate_kdf_params(&wire.kdf_params)?;
        let kek = keys::derive_kek(password, &wire.kdf_salt, wire.kdf_params, Some(secret_key))?;
        let vault_key = keys::unwrap_key(&kek, &wire.wrapped_vault_key)
            .map_err(|_| "wrong password or secret key".to_string())?;
        // Second wrapping under the password-only KEK (ADR-0010), so the
        // joined device supports password-only unlock from the start.
        let pw_kek = keys::derive_kek(password, &wire.kdf_salt, wire.kdf_params, None)?;
        let wrapped_pw = keys::wrap_key(&pw_kek, &vault_key)?;

        let mut conn = Connection::open(path).map_err(|e| format!("open vault db: {e}"))?;
        let header = VaultHeader {
            format_version: wire.format_version,
            vault_id: wire.vault_id,
            profile: CryptoProfile {
                kdf_params: wire.kdf_params,
                secret_key_enabled: true,
                ..CryptoProfile::default()
            },
            kdf_salt: wire.kdf_salt,
            wrapped_vault_key: wire.wrapped_vault_key,
            wrapped_vault_key_password_only: Some(wrapped_pw),
            created_at_ms: wire.created_at_ms,
            sync_address: Some(address.to_string()),
            bootstrap_package: Some(bootstrap.to_vec()),
            vault_key_check: Some(Self::vault_key_check(&vault_key)?.to_vec()),
        };
        // Any failure below must remove the partial file (see create).
        let stored: Result<(), String> = (|| {
            conn.execute_batch(SCHEMA_SQL)
                .map_err(|e| format!("init vault schema: {e}"))?;
            Self::store_header(&mut conn, &header)
        })();
        if let Err(e) = stored {
            drop(conn);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(Vault {
            conn,
            header,
            vault_key,
        })
    }

    /// Read just the header of a vault file without unlocking it, so the
    /// app shell can tell whether a secret key is required before asking
    /// for credentials. Returns None if the file is not a yobei vault.
    pub fn peek_header(path: &Path) -> Option<VaultHeader> {
        // Connection::open creates a zero-byte file when the path does not
        // exist; never probe a missing file, or the next create is blocked
        // by "vault file already exists".
        if !path.exists() {
            return None;
        }
        let conn = Connection::open(path).ok()?;
        let header_json: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![HEADER_META_KEY],
                |row| row.get(0),
            )
            .ok()?;
        serde_json::from_str(&header_json).ok()
    }

    /// Encrypt an entry with this vault's key, producing the exact blob that
    /// is stored locally and pushed to the sync server.
    pub fn encrypt_entry(&self, entry: &Entry) -> Result<Vec<u8>, String> {
        keys::encrypt_entry(&self.vault_key, entry)
    }

    /// Decrypt a blob with this vault's key (sync ingest verification).
    pub fn decrypt_entry(&self, entry_id: &str, blob: &[u8]) -> Result<Entry, String> {
        keys::decrypt_entry(&self.vault_key, entry_id, blob)
    }

    /// Insert or replace an entry, encrypting it under its per-entry key.
    /// Callers manage version/timestamp semantics (see `service.rs`).
    pub fn put(&mut self, entry: &Entry) -> Result<(), String> {
        let blob = self.encrypt_entry(entry)?;
        self.put_entry_blob(entry, &blob)
    }

    /// Store a pre-encrypted blob together with the entry's sync metadata.
    /// Used by the sync ingest path, where the blob came from the server.
    pub fn put_entry_blob(&mut self, entry: &Entry, blob: &[u8]) -> Result<(), String> {
        self.conn
            .execute(
                ENTRY_UPSERT_SQL,
                params![
                    entry.id,
                    entry.kind.as_str(),
                    entry.created_at_ms,
                    entry.updated_at_ms,
                    entry.version as i64,
                    entry.hlc as i64,
                    entry.deleted as i64,
                    entry.deleted_at_ms,
                    blob,
                ],
            )
            .map_err(|e| format!("store entry: {e}"))?;
        Ok(())
    }

    /// Insert/replace a row from raw parts — the sync ingest path, where
    /// the blob arrives from the server rather than from local encryption.
    #[allow(clippy::too_many_arguments)]
    pub fn put_raw(
        &mut self,
        entry_id: &str,
        kind: &EntryKind,
        created_at_ms: i64,
        updated_at_ms: i64,
        version: u64,
        hlc: u64,
        deleted: bool,
        deleted_at_ms: Option<i64>,
        blob: &[u8],
    ) -> Result<(), String> {
        self.conn
            .execute(
                ENTRY_UPSERT_SQL,
                params![
                    entry_id,
                    kind.as_str(),
                    created_at_ms,
                    updated_at_ms,
                    version as i64,
                    hlc as i64,
                    deleted as i64,
                    deleted_at_ms,
                    blob,
                ],
            )
            .map_err(|e| format!("store raw entry: {e}"))?;
        Ok(())
    }

    /// Write an entry and its outbox op in one local transaction (ADR-0003
    /// §5). Either both land or neither does.
    pub fn write_entry_and_op(
        &mut self,
        entry: &Entry,
        blob: &[u8],
        op: &SyncOp,
        now_ms: i64,
    ) -> Result<(), String> {
        let op_json = serde_json::to_string(op).map_err(|e| format!("serialize op: {e}"))?;
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("begin transaction: {e}"))?;
        tx.execute(
            ENTRY_UPSERT_SQL,
            params![
                entry.id,
                entry.kind.as_str(),
                entry.created_at_ms,
                entry.updated_at_ms,
                entry.version as i64,
                entry.hlc as i64,
                entry.deleted as i64,
                entry.deleted_at_ms,
                blob,
            ],
        )
        .map_err(|e| format!("store entry: {e}"))?;
        tx.execute(
            "INSERT OR REPLACE INTO outbox (op_id, entry_id, op_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![op.op_id, op.entry_id, op_json, now_ms],
        )
        .map_err(|e| format!("enqueue op: {e}"))?;
        tx.commit()
            .map_err(|e| format!("commit transaction: {e}"))?;
        Ok(())
    }

    /// Fetch one entry by id (tombstones included).
    pub fn get_entry(&self, id: &str) -> Result<Option<Entry>, String> {
        let blob = self.get_blob(id)?;
        match blob {
            None => Ok(None),
            Some(b) => Ok(Some(keys::decrypt_entry(&self.vault_key, id, &b)?)),
        }
    }

    /// The stored ciphertext blob for an entry, exactly as pushed to and
    /// fetched from the sync server (nonce ‖ ciphertext).
    pub fn get_blob(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        self.conn
            .query_row(
                "SELECT ciphertext FROM entries WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("read entry blob: {e}"))
    }

    /// Sync metadata for every row, without decrypting anything.
    pub fn entry_metas(&self) -> Result<Vec<EntryMeta>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, version, hlc, updated_at_ms, deleted FROM entries")
            .map_err(|e| format!("prepare metas: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(EntryMeta {
                    id: row.get(0)?,
                    version: row.get::<_, i64>(1)? as u64,
                    hlc: row.get::<_, i64>(2)? as u64,
                    updated_at_ms: row.get(3)?,
                    deleted: row.get::<_, i64>(4)? != 0,
                })
            })
            .map_err(|e| format!("read metas: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("read meta row: {e}"))?);
        }
        Ok(out)
    }

    /// Decrypt every row, skipping (and reporting) rows that fail. One
    /// corrupt row must not make the whole vault unreadable (ADR-0003 §7).
    pub fn list_report(&self, include_deleted: bool) -> Result<ListReport, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ciphertext FROM entries
                 WHERE deleted = 0 OR ?1
                 ORDER BY updated_at_ms DESC",
            )
            .map_err(|e| format!("prepare list: {e}"))?;
        let rows = stmt
            .query_map(params![include_deleted as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| format!("list entries: {e}"))?;
        let mut report = ListReport::default();
        for row in rows {
            let (id, blob) = row.map_err(|e| format!("read entry row: {e}"))?;
            match keys::decrypt_entry(&self.vault_key, &id, &blob) {
                Ok(entry) => report.entries.push(entry),
                Err(_) => report.skipped.push(id),
            }
        }
        Ok(report)
    }

    /// All decrypted entries, newest-updated first.
    pub fn list(&self, include_deleted: bool) -> Result<Vec<Entry>, String> {
        Ok(self.list_report(include_deleted)?.entries)
    }

    // ------------------------------------------------------------ sync ---

    /// Append an op to the local outbox.
    pub fn enqueue_op(&mut self, op: &SyncOp, now_ms: i64) -> Result<(), String> {
        let json = serde_json::to_string(op).map_err(|e| format!("serialize op: {e}"))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO outbox (op_id, entry_id, op_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![op.op_id, op.entry_id, json, now_ms],
            )
            .map_err(|e| format!("enqueue op: {e}"))?;
        Ok(())
    }

    /// All queued ops, oldest first (push order).
    pub fn outbox_ops(&self) -> Result<Vec<SyncOp>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT op_json FROM outbox ORDER BY created_at_ms, rowid")
            .map_err(|e| format!("prepare outbox: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("read outbox: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row.map_err(|e| format!("read outbox row: {e}"))?;
            out.push(serde_json::from_str(&json).map_err(|e| format!("corrupt outbox op: {e}"))?);
        }
        Ok(out)
    }

    pub fn remove_op(&mut self, op_id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM outbox WHERE op_id = ?1", params![op_id])
            .map_err(|e| format!("remove op: {e}"))?;
        Ok(())
    }

    /// Drop every queued op for an entry (conflict resolution supersedes
    /// them). Returns how many were dropped.
    pub fn remove_ops_for_entry(&mut self, entry_id: &str) -> Result<usize, String> {
        let n = self
            .conn
            .execute("DELETE FROM outbox WHERE entry_id = ?1", params![entry_id])
            .map_err(|e| format!("remove entry ops: {e}"))?;
        Ok(n)
    }

    pub fn pending_entry_ids(&self) -> Result<std::collections::HashSet<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT entry_id FROM outbox")
            .map_err(|e| format!("prepare pending: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("read pending: {e}"))?;
        let mut out = std::collections::HashSet::new();
        for row in rows {
            out.insert(row.map_err(|e| format!("read pending row: {e}"))?);
        }
        Ok(out)
    }

    pub fn get_sync_state(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM sync_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .ok()
    }

    pub fn set_sync_state(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO sync_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|e| format!("set sync state: {e}"))?;
        Ok(())
    }

    /// Forget a sync state entry (e.g. after this device is revoked).
    pub fn clear_sync_state(&mut self, key: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM sync_meta WHERE key = ?1", params![key])
            .map_err(|e| format!("clear sync state: {e}"))?;
        Ok(())
    }

    /// Remove the content of an already-deleted entry while keeping its
    /// tombstone metadata (ADR-0003 §4). Called after the 30-day window.
    /// Returns true if the entry existed.
    pub fn purge_content(&mut self, id: &str) -> Result<bool, String> {
        let Some(mut entry) = self.get_entry(id)? else {
            return Ok(false);
        };
        if !entry.deleted {
            return Err("refusing to purge a live entry".to_string());
        }
        entry.title.clear();
        entry.favorite = false;
        entry.tags.clear();
        entry.notes.clear();
        entry.payload = blank_payload(entry.kind);
        self.put(&entry)?;
        // Drop the free pages that still hold the old ciphertext.
        self.conn
            .execute_batch("VACUUM;")
            .map_err(|e| format!("vacuum vault: {e}"))?;
        Ok(true)
    }

    /// Change the master password. Entries are untouched: only the vault
    /// key is re-wrapped under a KEK from the new password (fresh salt).
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        secret_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let secret_key = secret_key.ok_or_else(|| "the Secret Key is required".to_string())?;
        let old_kek = keys::derive_kek(
            old_password,
            &self.header.kdf_salt,
            self.header.profile.kdf_params,
            Some(secret_key),
        )?;
        let check = keys::unwrap_key(&old_kek, &self.header.wrapped_vault_key)
            .map_err(|_| "wrong current password".to_string())?;
        if *check != *self.vault_key {
            return Err("wrong current password".to_string());
        }
        let new_salt = keys::random_bytes(KDF_SALT_LEN);
        let new_kek = keys::derive_kek(
            new_password,
            &new_salt,
            self.header.profile.kdf_params,
            Some(secret_key),
        )?;
        self.header.kdf_salt = new_salt;
        self.header.wrapped_vault_key = keys::wrap_key(&new_kek, &self.vault_key)?;
        // Both wrappings move to the new password (ADR-0010); the vault
        // key itself is unchanged, so biometric unlock keeps working
        // (ADR-0009).
        let new_pw_kek = keys::derive_kek(
            new_password,
            &self.header.kdf_salt,
            self.header.profile.kdf_params,
            None,
        )?;
        self.header.wrapped_vault_key_password_only =
            Some(keys::wrap_key(&new_pw_kek, &self.vault_key)?);
        // The bootstrap package wraps the same vault key under the same
        // Secret Key, but the salt and wrapped key changed; reseal it so a
        // new device can still join (ADR-0002).
        self.header.bootstrap_package = None;
        let package = Self::seal_package(&self.header, secret_key)?;
        self.header.bootstrap_package = Some(package);
        Self::store_header(&mut self.conn, &self.header)
    }

    /// Build and seal the bootstrap package from this vault's header.
    fn seal_package(header: &VaultHeader, secret_key: &[u8]) -> Result<Vec<u8>, String> {
        let address = header
            .sync_address
            .as_deref()
            .ok_or_else(|| "vault has no sync address".to_string())?;
        let wire = crate::bootstrap::BootstrapHeader {
            format_version: header.format_version,
            vault_id: header.vault_id.clone(),
            address: address.to_string(),
            kdf_params: header.profile.kdf_params,
            kdf_salt: header.kdf_salt.clone(),
            wrapped_vault_key: header.wrapped_vault_key.clone(),
            created_at_ms: header.created_at_ms,
        };
        crate::bootstrap::seal_bootstrap(secret_key, &wire)
    }

    fn store_header(conn: &mut Connection, header: &VaultHeader) -> Result<(), String> {
        let json = serde_json::to_string(header).map_err(|e| format!("serialize header: {e}"))?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![HEADER_META_KEY, json],
        )
        .map_err(|e| format!("store header: {e}"))?;
        Ok(())
    }
}

fn blank_payload(kind: EntryKind) -> EntryPayload {
    match kind {
        EntryKind::Account => EntryPayload::Account(AccountPayload::default()),
        EntryKind::Card => EntryPayload::Card(CardPayload::default()),
        EntryKind::Identity => EntryPayload::Identity(IdentityPayload::default()),
        EntryKind::Note => EntryPayload::Note(NotePayload::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2idParams;

    fn test_profile() -> CryptoProfile {
        CryptoProfile {
            kdf_params: Argon2idParams::OWASP_MINIMUM,
            ..CryptoProfile::default()
        }
    }

    fn temp_vault_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("yobei-test-{}-{}.db", tag, Vault::new_id()))
    }

    #[test]
    fn peek_header_does_not_create_a_file() {
        let path = temp_vault_path("peek-no-create");
        assert!(!path.exists());
        assert!(Vault::peek_header(&path).is_none());
        assert!(
            !path.exists(),
            "peek_header must not plant a zero-byte file"
        );
    }

    #[test]
    fn create_succeeds_after_peek_header() {
        // Regression test: the app calls vault_status (peek_header) on
        // startup, then the user taps Create. The peek must not block it.
        let path = temp_vault_path("peek-then-create");
        let sk = keys::random_bytes(KEY_LEN);
        assert!(Vault::peek_header(&path).is_none());
        Vault::create(&path, "pw-1", Some(&sk), test_profile(), 1_000).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_refuses_a_real_existing_vault() {
        let path = temp_vault_path("create-twice");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "pw-1", Some(&sk), test_profile(), 1_000).unwrap();
        drop(vault);
        let err = Vault::create(&path, "pw-2", Some(&sk), test_profile(), 2_000).err();
        assert_eq!(err.as_deref(), Some("vault file already exists"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_and_adopt_tolerate_a_zero_byte_leftover_file() {
        let path = temp_vault_path("empty-leftover");
        std::fs::write(&path, []).unwrap();
        let sk = keys::random_bytes(KEY_LEN);
        Vault::create(&path, "pw-1", Some(&sk), test_profile(), 1_000).unwrap();

        let path_a = temp_vault_path("adopt-empty-a");
        let path_b = temp_vault_path("adopt-empty-b");
        let vault = Vault::create(&path_a, "pw", Some(&sk), test_profile(), 0).unwrap();
        let address = vault.sync_address().unwrap().to_string();
        let package = vault.bootstrap_package().unwrap().to_vec();
        drop(vault);
        std::fs::write(&path_b, []).unwrap();
        let adopted = Vault::adopt(&path_b, "pw", &sk, &package, &address).unwrap();
        assert_eq!(adopted.sync_address(), Some(address.as_str()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn open_missing_vault_does_not_create_a_file() {
        let path = temp_vault_path("open-missing");
        let sk = keys::random_bytes(KEY_LEN);
        assert!(Vault::open(&path, "pw-1", Some(&sk)).is_err());
        assert!(!path.exists(), "open must not plant a zero-byte file");
    }

    #[test]
    fn create_open_roundtrip_with_entries() {
        let path = temp_vault_path("roundtrip");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "pw-1", Some(&sk), test_profile(), 1_000).unwrap();
        let mut entry = Entry::new_account(
            Vault::new_id(),
            vault.vault_id().to_string(),
            "GitHub".into(),
            1_000,
        );
        if let EntryPayload::Account(account) = &mut entry.payload {
            account.username = "octocat".into();
        }
        vault.put(&entry).unwrap();
        let entry_id = entry.id.clone();
        drop(vault);

        let reopened = Vault::open(&path, "pw-1", Some(&sk)).unwrap();
        let loaded = reopened.get_entry(&entry_id).unwrap().unwrap();
        match loaded.payload {
            EntryPayload::Account(account) => assert_eq!(account.username, "octocat"),
            _ => panic!("expected an account entry"),
        }
        assert_eq!(reopened.list(false).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_cannot_open() {
        let path = temp_vault_path("wrongpw");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "right", Some(&sk), test_profile(), 0).unwrap();
        drop(vault);
        assert!(Vault::open(&path, "wrong", Some(&sk)).is_err());
        // The Secret Key is load-bearing: the right password with a wrong
        // Secret Key must also fail.
        let wrong_sk = keys::random_bytes(KEY_LEN);
        assert!(Vault::open(&path, "right", Some(&wrong_sk)).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_with_key_roundtrip() {
        let path = temp_vault_path("open-with-key");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "pw-1", Some(&sk), test_profile(), 1_000).unwrap();
        let entry = Entry::new_account(
            Vault::new_id(),
            vault.vault_id().to_string(),
            "GitHub".into(),
            1_000,
        );
        let entry_id = entry.id.clone();
        vault.put(&entry).unwrap();
        let key = *vault.vault_key();
        let check = Vault::vault_key_check(&key).unwrap();
        let vault_id = vault.vault_id().to_string();
        drop(vault);

        let reopened = Vault::open_with_key(&path, &key, &check).unwrap();
        assert_eq!(reopened.vault_id(), vault_id);
        assert!(reopened.get_entry(&entry_id).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_with_key_rejects_a_stale_key() {
        // A blob recorded for another vault (or a recreated one) must fail
        // here, not open this vault under the wrong key.
        let path = temp_vault_path("stale-key");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "pw", Some(&sk), test_profile(), 0).unwrap();
        let check = Vault::vault_key_check(vault.vault_key()).unwrap();
        drop(vault);

        let other_key: [u8; KEY_LEN] = keys::random_bytes(KEY_LEN).try_into().unwrap();
        assert!(Vault::open_with_key(&path, &other_key, &check).is_err());

        // ...and a tampered check fails even with the right key.
        let vault = Vault::open(&path, "pw", Some(&sk)).unwrap();
        let key = *vault.vault_key();
        drop(vault);
        let mut bad_check = check;
        bad_check[0] ^= 1;
        assert!(Vault::open_with_key(&path, &key, &bad_check).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_with_key_rejects_a_self_consistent_pair_from_another_vault() {
        // A key+check pair recorded for vault B must not open vault A,
        // even though the pair is self-consistent (ADR-0012).
        let path_a = temp_vault_path("check-a");
        let path_b = temp_vault_path("check-b");
        let sk_a = keys::random_bytes(KEY_LEN);
        let sk_b = keys::random_bytes(KEY_LEN);
        let vault_a = Vault::create(&path_a, "pw", Some(&sk_a), test_profile(), 0).unwrap();
        drop(vault_a);
        let vault_b = Vault::create(&path_b, "pw", Some(&sk_b), test_profile(), 0).unwrap();
        let key_b = *vault_b.vault_key();
        let check_b = Vault::vault_key_check(&key_b).unwrap();
        drop(vault_b);

        assert!(Vault::open_with_key(&path_a, &key_b, &check_b).is_err());
        // ...and vault B still opens with its own pair.
        assert!(Vault::open_with_key(&path_b, &key_b, &check_b).is_ok());
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn vault_key_check_is_backfilled_from_old_header() {
        // Simulate a vault created before ADR-0012: strip the check from
        // the stored header.
        let path = temp_vault_path("migrate-check");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "pw", Some(&sk), test_profile(), 0).unwrap();
        let key = *vault.vault_key();
        let check = Vault::vault_key_check(&key).unwrap();
        drop(vault);
        {
            let conn = Connection::open(&path).unwrap();
            let json: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    params![HEADER_META_KEY],
                    |row| row.get(0),
                )
                .unwrap();
            let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
            value.as_object_mut().unwrap().remove("vault_key_check");
            conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = ?2",
                params![value.to_string(), HEADER_META_KEY],
            )
            .unwrap();
        }
        // Before migration the header has no check, so only the
        // self-consistency layer applies...
        assert!(Vault::open_with_key(&path, &key, &check).is_ok());
        // ...one unlock with the Secret Key backfills it...
        let vault = Vault::open(&path, "pw", Some(&sk)).unwrap();
        drop(vault);
        // ...and now a foreign pair is rejected.
        let other_key: [u8; KEY_LEN] = keys::random_bytes(KEY_LEN).try_into().unwrap();
        let other_check = Vault::vault_key_check(&other_key).unwrap();
        assert!(Vault::open_with_key(&path, &other_key, &other_check).is_err());
        assert!(Vault::open_with_key(&path, &key, &check).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_with_key_survives_a_password_change() {
        // The vault key is stable across password changes (ADR-0001): a
        // biometric blob recorded before the change still opens the vault.
        let path = temp_vault_path("key-stable");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "old-pw", Some(&sk), test_profile(), 0).unwrap();
        let key = *vault.vault_key();
        let check = Vault::vault_key_check(&key).unwrap();
        vault
            .change_password("old-pw", "new-pw", Some(&sk))
            .unwrap();
        drop(vault);
        assert!(Vault::open_with_key(&path, &key, &check).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_with_password_only_after_create() {
        let path = temp_vault_path("pw-only");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "pw-1", Some(&sk), test_profile(), 0).unwrap();
        drop(vault);
        // No Secret Key needed for daily unlock (ADR-0010)...
        assert!(Vault::open(&path, "pw-1", None).is_ok());
        // ...but a wrong password still fails.
        assert!(Vault::open(&path, "wrong", None).is_err());
        // The Secret Key path keeps working too.
        assert!(Vault::open(&path, "pw-1", Some(&sk)).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn password_only_migration_from_old_header() {
        // Simulate a vault created before ADR-0010: strip the
        // password-only wrapping from the stored header.
        let path = temp_vault_path("migrate-old");
        let sk = keys::random_bytes(KEY_LEN);
        let vault = Vault::create(&path, "pw", Some(&sk), test_profile(), 0).unwrap();
        drop(vault);
        {
            let conn = Connection::open(&path).unwrap();
            let json: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    params![HEADER_META_KEY],
                    |row| row.get(0),
                )
                .unwrap();
            let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .remove("wrapped_vault_key_password_only");
            conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = ?2",
                params![value.to_string(), HEADER_META_KEY],
            )
            .unwrap();
        }
        // Password-only unlock fails until the vault is migrated...
        assert!(Vault::open(&path, "pw", None).is_err());
        // ...one unlock with the Secret Key migrates it...
        let vault = Vault::open(&path, "pw", Some(&sk)).unwrap();
        drop(vault);
        // ...and now password-only unlock works.
        assert!(Vault::open(&path, "pw", None).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn change_password_rewraps_password_only() {
        let path = temp_vault_path("changepw-only");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "old-pw", Some(&sk), test_profile(), 0).unwrap();
        vault
            .change_password("old-pw", "new-pw", Some(&sk))
            .unwrap();
        drop(vault);
        assert!(Vault::open(&path, "new-pw", None).is_ok());
        assert!(Vault::open(&path, "old-pw", None).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn change_password_keeps_entries_readable() {
        let path = temp_vault_path("changepw");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "old-pw", Some(&sk), test_profile(), 0).unwrap();
        let entry = Entry::new_account(
            Vault::new_id(),
            vault.vault_id().to_string(),
            "Mail".into(),
            0,
        );
        let entry_id = entry.id.clone();
        vault.put(&entry).unwrap();
        vault
            .change_password("old-pw", "new-pw", Some(&sk))
            .unwrap();
        drop(vault);

        assert!(Vault::open(&path, "old-pw", Some(&sk)).is_err());
        let reopened = Vault::open(&path, "new-pw", Some(&sk)).unwrap();
        assert!(reopened.get_entry(&entry_id).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn adopt_rebuilds_the_same_vault_from_the_bootstrap_package() {
        let sk = keys::random_bytes(KEY_LEN);
        let path_a = temp_vault_path("adopt-a");
        let path_b = temp_vault_path("adopt-b");
        let vault = Vault::create(&path_a, "pw", Some(&sk), test_profile(), 0).unwrap();
        let address = vault.sync_address().unwrap().to_string();
        let package = vault.bootstrap_package().unwrap().to_vec();
        let vault_id = vault.vault_id().to_string();
        drop(vault);

        let adopted = Vault::adopt(&path_b, "pw", &sk, &package, &address).unwrap();
        assert_eq!(adopted.vault_id(), vault_id);
        assert_eq!(adopted.sync_address(), Some(address.as_str()));

        // A wrong password cannot adopt the vault.
        let path_c = temp_vault_path("adopt-c");
        assert!(Vault::adopt(&path_c, "wrong", &sk, &package, &address).is_err());

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn auth_key_is_stable_across_adoption() {
        let sk = keys::random_bytes(KEY_LEN);
        let path_a = temp_vault_path("auth-a");
        let path_b = temp_vault_path("auth-b");
        let vault = Vault::create(&path_a, "pw", Some(&sk), test_profile(), 0).unwrap();
        let address = vault.sync_address().unwrap().to_string();
        let package = vault.bootstrap_package().unwrap().to_vec();
        let auth_key = vault.auth_key_b64().unwrap();
        let auth_hash = vault.auth_hash_b64().unwrap();
        drop(vault);

        let adopted = Vault::adopt(&path_b, "pw", &sk, &package, &address).unwrap();
        assert_eq!(adopted.auth_key_b64().unwrap(), auth_key);
        assert_eq!(adopted.auth_hash_b64().unwrap(), auth_hash);

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn password_change_refreshes_the_bootstrap_package() {
        let sk = keys::random_bytes(KEY_LEN);
        let path_a = temp_vault_path("rotate-a");
        let path_b = temp_vault_path("rotate-b");
        let path_c = temp_vault_path("rotate-c");
        let mut vault = Vault::create(&path_a, "old", Some(&sk), test_profile(), 0).unwrap();
        let vault_id = vault.vault_id().to_string();
        let address = vault.sync_address().unwrap().to_string();
        let before = vault.bootstrap_package().unwrap().to_vec();
        vault.change_password("old", "new", Some(&sk)).unwrap();
        let after = vault.bootstrap_package().unwrap().to_vec();
        assert_ne!(before, after);
        drop(vault);

        // The refreshed package unlocks with the new password.
        let adopted = Vault::adopt(&path_b, "new", &sk, &after, &address).unwrap();
        assert_eq!(adopted.vault_id(), vault_id);
        // The stale package must not unlock with the new password.
        assert!(Vault::adopt(&path_c, "new", &sk, &before, &address).is_err());

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn tombstones_are_listed_only_when_requested() {
        let path = temp_vault_path("delete");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "pw", Some(&sk), test_profile(), 0).unwrap();
        let mut entry =
            Entry::new_account(Vault::new_id(), vault.vault_id().to_string(), "X".into(), 0);
        entry.deleted = true;
        entry.deleted_at_ms = Some(5_000);
        vault.put(&entry).unwrap();

        assert!(vault.list(false).unwrap().is_empty());
        let all = vault.list(true).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].deleted);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn purge_content_blanks_payload_but_keeps_tombstone() {
        let path = temp_vault_path("purge");
        let sk = keys::random_bytes(KEY_LEN);
        let mut vault = Vault::create(&path, "pw", Some(&sk), test_profile(), 0).unwrap();
        let mut entry = Entry::new_account(
            Vault::new_id(),
            vault.vault_id().to_string(),
            "Old".into(),
            0,
        );
        if let EntryPayload::Account(account) = &mut entry.payload {
            account.password = Some("secret".into());
        }
        entry.deleted = true;
        entry.deleted_at_ms = Some(1_000);
        let entry_id = entry.id.clone();
        vault.put(&entry).unwrap();

        assert!(vault.purge_content(&entry_id).unwrap());
        let purged = vault.get_entry(&entry_id).unwrap().unwrap();
        assert!(purged.deleted);
        match purged.payload {
            EntryPayload::Account(account) => assert!(account.password.is_none()),
            _ => panic!("expected an account entry"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
