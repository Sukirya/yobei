//! Vault file and unlocked session (DESIGN.md §7 storage ADR).
//!
//! A vault is one SQLite database. The `meta` table holds the vault
//! header — format version, the [`CryptoProfile`] (KDF params live here,
//! not in constants, so they can be raised later), the KDF salt and the
//! vault key wrapped under the KEK. Each record row keeps only the
//! columns list/sync logic needs in the clear (id, kind, timestamps,
//! version, tombstone) plus the AEAD ciphertext blob produced by
//! [`crate::keys`]. Titles and everything else stay encrypted; listing
//! decrypts in memory, which is fine at personal-vault scale.
//!
//! This module is the reference storage adapter for v0.1: SQLite via
//! rusqlite (bundled), identical on Android and desktop.

use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::CryptoProfile;
use crate::keys::{self, KDF_SALT_LEN, KEY_LEN};
use crate::record::{Record, RecordKind};

pub const VAULT_FORMAT_VERSION: u32 = 1;
const HEADER_META_KEY: &str = "vault_header";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub format_version: u32,
    pub vault_id: String,
    pub profile: CryptoProfile,
    /// Argon2id salt (fresh random on create and on every password change).
    pub kdf_salt: Vec<u8>,
    /// Vault key wrapped under the KEK (see keys.rs).
    pub wrapped_vault_key: Vec<u8>,
    pub created_at_ms: i64,
}

/// Sync-relevant metadata of one stored row (no decryption needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMeta {
    pub id: String,
    pub version: u64,
    pub hlc: u64,
    pub updated_at_ms: i64,
    pub deleted: bool,
}

/// An unlocked vault. Holds the vault key in memory (zeroized on drop);
/// dropping the `Vault` is locking it.
pub struct Vault {
    conn: Connection,
    header: VaultHeader,
    vault_key: Zeroizing<[u8; KEY_LEN]>,
}

fn kind_to_str(kind: &RecordKind) -> &'static str {
    match kind {
        RecordKind::Account => "account",
        RecordKind::ApiKey => "api_key",
        RecordKind::Card => "card",
        RecordKind::Identity => "identity",
        RecordKind::Note => "note",
        RecordKind::SshKey => "ssh_key",
        RecordKind::Custom => "custom",
    }
}

impl Vault {
    /// Generate a fresh record/vault id (UUIDv7: time-ordered, unique).
    pub fn new_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    pub fn vault_id(&self) -> &str {
        &self.header.vault_id
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Create a new vault file. Fails if the file already exists.
    pub fn create(
        path: &Path,
        password: &str,
        secret_key: Option<&[u8]>,
        profile: CryptoProfile,
        now_ms: i64,
    ) -> Result<Vault, String> {
        if path.exists() {
            return Err("vault file already exists".to_string());
        }
        let mut conn =
            Connection::open(path).map_err(|e| format!("open vault db: {e}"))?;
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE records (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 version INTEGER NOT NULL,
                 hlc INTEGER NOT NULL,
                 deleted INTEGER NOT NULL DEFAULT 0,
                 ciphertext BLOB NOT NULL
             );
             CREATE INDEX idx_records_updated ON records(updated_at_ms);
             CREATE TABLE outbox (
                 op_id TEXT PRIMARY KEY,
                 record_id TEXT NOT NULL,
                 op_json TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .map_err(|e| format!("init vault schema: {e}"))?;

        let salt = keys::random_bytes(KDF_SALT_LEN);
        let kek = keys::derive_kek(password, &salt, profile.kdf_params, secret_key)?;
        let vault_key_bytes: [u8; KEY_LEN] = keys::random_bytes(KEY_LEN)
            .try_into()
            .expect("random_bytes returns the requested length");
        let wrapped = keys::wrap_key(&kek, &vault_key_bytes)?;
        let header = VaultHeader {
            format_version: VAULT_FORMAT_VERSION,
            vault_id: Self::new_id(),
            profile,
            kdf_salt: salt,
            wrapped_vault_key: wrapped,
            created_at_ms: now_ms,
        };
        // On any failure after file creation, remove the partial file so a
        // retry is not blocked by a half-initialized vault.
        let result = Self::store_header(&mut conn, &header);
        if let Err(e) = result {
            drop(conn);
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        Ok(Vault {
            conn,
            header,
            vault_key: Zeroizing::new(vault_key_bytes),
        })
    }

    /// Open an existing vault. A wrong password (or wrong/missing secret
    /// key) fails at unwrapping the vault key, before any record is read.
    pub fn open(path: &Path, password: &str, secret_key: Option<&[u8]>) -> Result<Vault, String> {
        let conn = Connection::open(path).map_err(|e| format!("open vault db: {e}"))?;
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
        let kek = keys::derive_kek(
            password,
            &header.kdf_salt,
            header.profile.kdf_params,
            secret_key,
        )?;
        let vault_key = keys::unwrap_key(&kek, &header.wrapped_vault_key)
            .map_err(|_| "wrong password or secret key".to_string())?;
        // Vaults created before the sync tables existed gain them here.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                 op_id TEXT PRIMARY KEY,
                 record_id TEXT NOT NULL,
                 op_json TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .map_err(|e| format!("ensure sync schema: {e}"))?;
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

    /// Permanently remove a record row (no tombstone). Used for trash
    /// purge and for wiping conflict copies the user resolved manually.
    pub fn purge(&mut self, id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM records WHERE id = ?1", params![id])
            .map_err(|e| format!("purge record: {e}"))?;
        Ok(())
    }

    // ------------------------------------------------------------ sync ---

    /// Decrypt a blob with this vault's key (sync ingest verification).
    pub fn decrypt(&self, record_id: &str, blob: &[u8]) -> Result<Record, String> {
        keys::decrypt_record(&self.vault_key, record_id, blob)
    }

    /// The stored ciphertext blob for a record, exactly as pushed to and
    /// fetched from the sync server (nonce ‖ ciphertext).
    pub fn get_blob(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT ciphertext FROM records WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .ok();
        Ok(blob)
    }

    /// Sync metadata for every row, without decrypting anything.
    pub fn record_metas(&self) -> Result<Vec<RecordMeta>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, version, hlc, updated_at_ms, deleted FROM records")
            .map_err(|e| format!("prepare metas: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RecordMeta {
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

    /// Insert/replace a row from raw parts — the sync ingest path, where
    /// the blob arrives from the server rather than from local encryption.
    #[allow(clippy::too_many_arguments)]
    pub fn put_raw(
        &mut self,
        record_id: &str,
        kind: &RecordKind,
        created_at_ms: i64,
        updated_at_ms: i64,
        version: u64,
        hlc: u64,
        deleted: bool,
        blob: &[u8],
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO records (id, kind, created_at_ms, updated_at_ms, version, hlc, deleted, ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET kind = excluded.kind,
                     created_at_ms = excluded.created_at_ms,
                     updated_at_ms = excluded.updated_at_ms, version = excluded.version,
                     hlc = excluded.hlc, deleted = excluded.deleted,
                     ciphertext = excluded.ciphertext",
                params![
                    record_id,
                    kind_to_str(kind),
                    created_at_ms,
                    updated_at_ms,
                    version as i64,
                    hlc as i64,
                    deleted as i64,
                    blob,
                ],
            )
            .map_err(|e| format!("store raw record: {e}"))?;
        Ok(())
    }

    /// Append an op to the local outbox. Ops are enqueued at mutation
    /// time (see service.rs) and removed only when the server accepts
    /// them (or a conflict resolution supersedes them).
    pub fn enqueue_op(&mut self, op: &crate::sync::SyncOp, now_ms: i64) -> Result<(), String> {
        let json = serde_json::to_string(op).map_err(|e| format!("serialize op: {e}"))?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO outbox (op_id, record_id, op_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![op.op_id, op.record_id, json, now_ms],
            )
            .map_err(|e| format!("enqueue op: {e}"))?;
        Ok(())
    }

    /// All queued ops, oldest first (push order).
    pub fn outbox_ops(&self) -> Result<Vec<crate::sync::SyncOp>, String> {
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
            out.push(
                serde_json::from_str(&json).map_err(|e| format!("corrupt outbox op: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn remove_op(&mut self, op_id: &str) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM outbox WHERE op_id = ?1", params![op_id])
            .map_err(|e| format!("remove op: {e}"))?;
        Ok(())
    }

    /// Drop every queued op for a record (conflict resolution supersedes
    /// them). Returns how many were dropped.
    pub fn remove_ops_for_record(&mut self, record_id: &str) -> Result<usize, String> {
        let n = self
            .conn
            .execute(
                "DELETE FROM outbox WHERE record_id = ?1",
                params![record_id],
            )
            .map_err(|e| format!("remove record ops: {e}"))?;
        Ok(n)
    }

    pub fn pending_record_ids(&self) -> Result<std::collections::HashSet<String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT record_id FROM outbox")
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

    /// Insert or replace a record, encrypting it under its per-record key.
    /// Callers manage `version`/`updated_at_ms` semantics via the record
    /// they pass in (see `touch` in higher layers); this stores as given.
    pub fn put(&mut self, record: &Record) -> Result<(), String> {
        let blob = keys::encrypt_record(&self.vault_key, record)?;
        self.conn
            .execute(
                "INSERT INTO records (id, kind, created_at_ms, updated_at_ms, version, hlc, deleted, ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET kind = excluded.kind,
                     updated_at_ms = excluded.updated_at_ms, version = excluded.version,
                     hlc = excluded.hlc, deleted = excluded.deleted,
                     ciphertext = excluded.ciphertext",
                params![
                    record.id,
                    kind_to_str(&record.kind),
                    record.created_at_ms,
                    record.updated_at_ms,
                    record.version as i64,
                    record.hlc as i64,
                    record.deleted as i64,
                    blob,
                ],
            )
            .map_err(|e| format!("store record: {e}"))?;
        Ok(())
    }

    /// Fetch one record by id (tombstones included).
    pub fn get(&self, id: &str) -> Result<Option<Record>, String> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT ciphertext FROM records WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .ok();
        match blob {
            None => Ok(None),
            Some(b) => Ok(Some(keys::decrypt_record(&self.vault_key, id, &b)?)),
        }
    }

    /// All records, newest-updated first. Tombstones only when requested.
    pub fn list(&self, include_deleted: bool) -> Result<Vec<Record>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, ciphertext FROM records
                 WHERE deleted = 0 OR ?1
                 ORDER BY updated_at_ms DESC",
            )
            .map_err(|e| format!("prepare list: {e}"))?;
        let rows = stmt
            .query_map(params![include_deleted as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| format!("list records: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, blob) = row.map_err(|e| format!("read record row: {e}"))?;
            out.push(keys::decrypt_record(&self.vault_key, &id, &blob)?);
        }
        Ok(out)
    }

    /// Soft-delete: the record becomes a tombstone (kept for sync delete
    /// propagation), bumping version and timestamp like any mutation.
    pub fn soft_delete(&mut self, id: &str, now_ms: i64) -> Result<(), String> {
        let mut record = self
            .get(id)?
            .ok_or_else(|| "record not found".to_string())?;
        record.deleted = true;
        record.updated_at_ms = now_ms;
        record.version += 1;
        self.put(&record)
    }

    /// Change the master password. Records are untouched: only the vault
    /// key is re-wrapped under a KEK from the new password (fresh salt).
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        secret_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let old_kek = keys::derive_kek(
            old_password,
            &self.header.kdf_salt,
            self.header.profile.kdf_params,
            secret_key,
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
            secret_key,
        )?;
        self.header.kdf_salt = new_salt;
        self.header.wrapped_vault_key = keys::wrap_key(&new_kek, &self.vault_key)?;
        Self::store_header(&mut self.conn, &self.header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Argon2idParams;

    fn test_profile() -> CryptoProfile {
        CryptoProfile {
            kdf_params: Argon2idParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 },
            ..CryptoProfile::default()
        }
    }

    fn temp_vault_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("yobei-test-{}-{}.db", tag, Vault::new_id()))
    }

    #[test]
    fn create_open_roundtrip_with_records() {
        let path = temp_vault_path("roundtrip");
        let mut vault =
            Vault::create(&path, "pw-1", None, test_profile(), 1_000).unwrap();
        let mut record =
            Record::new_account(Vault::new_id(), vault.vault_id().to_string(), "GitHub".into(), 1_000);
        record.account.as_mut().unwrap().username = "octocat".into();
        vault.put(&record).unwrap();
        let record_id = record.id.clone();
        drop(vault);

        let reopened = Vault::open(&path, "pw-1", None).unwrap();
        let loaded = reopened.get(&record_id).unwrap().unwrap();
        assert_eq!(loaded.account.unwrap().username, "octocat");
        assert_eq!(reopened.list(false).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_cannot_open() {
        let path = temp_vault_path("wrongpw");
        let vault = Vault::create(&path, "right", None, test_profile(), 0).unwrap();
        drop(vault);
        assert!(Vault::open(&path, "wrong", None).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn change_password_keeps_records_readable() {
        let path = temp_vault_path("changepw");
        let mut vault = Vault::create(&path, "old-pw", None, test_profile(), 0).unwrap();
        let record = Record::new_account(
            Vault::new_id(),
            vault.vault_id().to_string(),
            "Mail".into(),
            0,
        );
        let record_id = record.id.clone();
        vault.put(&record).unwrap();
        vault.change_password("old-pw", "new-pw", None).unwrap();
        drop(vault);

        assert!(Vault::open(&path, "old-pw", None).is_err());
        let reopened = Vault::open(&path, "new-pw", None).unwrap();
        assert!(reopened.get(&record_id).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn soft_delete_leaves_a_tombstone() {
        let path = temp_vault_path("delete");
        let mut vault = Vault::create(&path, "pw", None, test_profile(), 0).unwrap();
        let record =
            Record::new_account(Vault::new_id(), vault.vault_id().to_string(), "X".into(), 0);
        let record_id = record.id.clone();
        vault.put(&record).unwrap();
        vault.soft_delete(&record_id, 5_000).unwrap();

        assert!(vault.list(false).unwrap().is_empty());
        let all = vault.list(true).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].deleted);
        assert_eq!(all[0].version, 2);
        let _ = std::fs::remove_file(&path);
    }
}
