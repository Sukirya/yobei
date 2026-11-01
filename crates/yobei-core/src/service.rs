//! Application service layer over an unlocked [`Vault`]: the mutation
//! semantics the app shell (Tauri commands, CLI, tests) shares — entry
//! creation, touch (version + HLC discipline), search, favorites and the
//! trash lifecycle (delete → restore within 30 days → purge content).
//! Keeping this in the core means every platform gets identical behavior.

use data_encoding::BASE64;

use crate::entry::{Entry, EntryKind, EntryPayload};
use crate::sync::SyncOp;
use crate::vault::Vault;

/// How long a deleted entry stays restorable (ADR-0003 §4).
pub const TRASH_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Advance an entry's mutation metadata. Every mutation bumps `version`
/// by exactly 1 (sync conflict detection depends on it) and sets `hlc`
/// monotonically: wall-clock millis, but never backwards for this entry.
pub fn touch(entry: &mut Entry, now_ms: i64) {
    entry.updated_at_ms = now_ms;
    entry.version += 1;
    let now_hlc = now_ms.max(0) as u64;
    entry.hlc = now_hlc.max(entry.hlc + 1);
}

pub struct Service {
    vault: Vault,
}

impl Service {
    pub fn new(vault: Vault) -> Self {
        Self { vault }
    }

    pub fn vault_id(&self) -> &str {
        self.vault.vault_id()
    }

    /// Sync address (ADR-0002). The server keys every vault by this value.
    pub fn sync_address(&self) -> Result<&str, String> {
        self.vault
            .sync_address()
            .ok_or_else(|| "vault has no sync address".to_string())
    }

    /// Sealed bootstrap package for upload to the sync server.
    pub fn bootstrap_package(&self) -> Result<&[u8], String> {
        self.vault
            .bootstrap_package()
            .ok_or_else(|| "vault has no bootstrap package".to_string())
    }

    pub fn auth_key_b64(&self) -> Result<String, String> {
        self.vault.auth_key_b64()
    }

    pub fn auth_hash_b64(&self) -> Result<String, String> {
        self.vault.auth_hash_b64()
    }

    pub fn into_vault(self) -> Vault {
        self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// Create and store a new entry of the given kind.
    pub fn create_entry(
        &mut self,
        kind: EntryKind,
        title: String,
        now_ms: i64,
    ) -> Result<Entry, String> {
        let id = Vault::new_id();
        let vault_id = self.vault_id().to_string();
        let entry = match kind {
            EntryKind::Account => Entry::new_account(id, vault_id, title, now_ms),
            EntryKind::Card => Entry::new_card(id, vault_id, title, now_ms),
            EntryKind::Identity => Entry::new_identity(id, vault_id, title, now_ms),
            EntryKind::Note => Entry::new_note(id, vault_id, title, now_ms),
        };
        self.put_and_enqueue(&entry, 0, now_ms)?;
        Ok(entry)
    }

    /// Save an edited entry: applies touch discipline, then persists.
    pub fn save_entry(&mut self, entry: &mut Entry, now_ms: i64) -> Result<Entry, String> {
        let base_version = entry.version;
        touch(entry, now_ms);
        self.put_and_enqueue(entry, base_version, now_ms)?;
        Ok(entry.clone())
    }

    /// Persist an entry and enqueue its sync op in the outbox. Entry and op
    /// land in one local transaction (ADR-0003 §5), so a saved change is
    /// never silently missing from the sync queue.
    fn put_and_enqueue(
        &mut self,
        entry: &Entry,
        base_version: u64,
        now_ms: i64,
    ) -> Result<(), String> {
        entry.validate()?;
        let blob = self.vault.encrypt_entry(entry)?;
        // Sync ops are keyed by the sync address, not the local vault UUID
        // (ADR-0002).
        let address = self.sync_address()?.to_string();
        let op = SyncOp {
            op_id: Vault::new_id(),
            vault_id: address,
            entry_id: entry.id.clone(),
            base_version,
            new_version: entry.version,
            hlc: entry.hlc,
            deleted: entry.deleted,
            deleted_at_ms: entry.deleted_at_ms,
            ciphertext_b64: BASE64.encode(&blob),
        };
        self.vault.write_entry_and_op(entry, &blob, &op, now_ms)
    }

    pub fn get_entry(&self, id: &str) -> Result<Option<Entry>, String> {
        self.vault.get_entry(id)
    }

    /// Case-insensitive substring search over everything a user would
    /// look for: title, tags, notes, usernames, URLs, cardholder names,
    /// identity names and custom field contents. An empty query lists
    /// everything (newest first).
    pub fn search(&self, query: &str, include_deleted: bool) -> Result<Vec<Entry>, String> {
        let all = self.vault.list(include_deleted)?;
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(all);
        }
        Ok(all.into_iter().filter(|e| entry_matches(e, &q)).collect())
    }

    pub fn set_favorite(&mut self, id: &str, favorite: bool, now_ms: i64) -> Result<(), String> {
        let mut entry = self
            .vault
            .get_entry(id)?
            .ok_or_else(|| "entry not found".to_string())?;
        entry.favorite = favorite;
        self.save_entry(&mut entry, now_ms)?;
        Ok(())
    }

    /// Move to trash (tombstone; sync-propagatable, restorable for 30 days).
    pub fn trash(&mut self, id: &str, now_ms: i64) -> Result<(), String> {
        let mut entry = self
            .vault
            .get_entry(id)?
            .ok_or_else(|| "entry not found".to_string())?;
        if entry.deleted {
            return Ok(());
        }
        entry.deleted = true;
        entry.deleted_at_ms = Some(now_ms);
        self.save_entry(&mut entry, now_ms)?;
        Ok(())
    }

    /// Bring an entry back from trash within the 30-day window.
    pub fn restore(&mut self, id: &str, now_ms: i64) -> Result<(), String> {
        let mut entry = self
            .vault
            .get_entry(id)?
            .ok_or_else(|| "entry not found".to_string())?;
        if !entry.deleted {
            return Ok(());
        }
        let deleted_at = entry
            .deleted_at_ms
            .ok_or_else(|| "deleted entry has no deletion timestamp".to_string())?;
        if now_ms.saturating_sub(deleted_at) > TRASH_RETENTION_MS {
            return Err("the 30-day restore window has expired".to_string());
        }
        entry.deleted = false;
        entry.deleted_at_ms = None;
        self.save_entry(&mut entry, now_ms)?;
        Ok(())
    }

    /// Physically remove the content of tombstones older than the retention
    /// window. Their metadata stays so late offline writes cannot revive
    /// them (ADR-0003 §4). Returns how many entries were purged.
    pub fn purge_expired(&mut self, now_ms: i64) -> Result<usize, String> {
        let mut purged = 0;
        for entry in self.vault.list(true)? {
            if !entry.deleted {
                continue;
            }
            let Some(deleted_at) = entry.deleted_at_ms else {
                continue;
            };
            if now_ms.saturating_sub(deleted_at) > TRASH_RETENTION_MS
                && self.vault.purge_content(&entry.id)?
            {
                purged += 1;
            }
        }
        Ok(purged)
    }

    /// Commit entries produced by an importer: assigns real ids, this
    /// vault's id, and fresh timestamps/version. Returns how many were
    /// imported.
    pub fn import_entries(&mut self, entries: Vec<Entry>, now_ms: i64) -> Result<usize, String> {
        let mut count = 0;
        for mut entry in entries {
            entry.id = Vault::new_id();
            entry.vault_id = self.vault_id().to_string();
            entry.created_at_ms = now_ms;
            entry.updated_at_ms = now_ms;
            entry.version = 1;
            entry.hlc = now_ms.max(0) as u64;
            entry.deleted = false;
            entry.deleted_at_ms = None;
            self.put_and_enqueue(&entry, 0, now_ms)?;
            count += 1;
        }
        Ok(count)
    }

    /// All live entries (used by exports).
    pub fn all_entries(&self) -> Result<Vec<Entry>, String> {
        self.vault.list(false)
    }

    /// Preserve a divergent local entry as a conflict copy (ADR-0003 §3).
    /// The copy is a brand-new entry — new id, version 1, marker pointing at
    /// the source — holding the source's content. The title is unchanged:
    /// the "(conflict copy)" label is localized by the UI, never stored in
    /// the data (ADR-0008).
    pub fn add_conflict_copy(&mut self, source: &Entry, now_ms: i64) -> Result<Entry, String> {
        let mut copy = source.clone();
        copy.id = Vault::new_id();
        copy.conflict_copy_of = Some(source.id.clone());
        copy.version = 1;
        copy.created_at_ms = now_ms;
        copy.updated_at_ms = now_ms;
        copy.hlc = now_ms.max(0) as u64;
        copy.deleted = false;
        copy.deleted_at_ms = None;
        self.put_and_enqueue(&copy, 0, now_ms)?;
        Ok(copy)
    }
}

fn entry_matches(entry: &Entry, q: &str) -> bool {
    let contains = |s: &str| s.to_lowercase().contains(q);
    if contains(&entry.title) || contains(&entry.notes) {
        return true;
    }
    if entry.tags.iter().any(|t| contains(t)) {
        return true;
    }
    if entry
        .payload
        .custom_fields()
        .iter()
        .any(|f| contains(&f.name) || contains(&f.value))
    {
        return true;
    }
    match &entry.payload {
        EntryPayload::Account(account) => {
            if contains(&account.username) {
                return true;
            }
            if account.urls.iter().any(|u| contains(&u.url)) {
                return true;
            }
            account
                .totp
                .as_ref()
                .and_then(|t| t.issuer.as_deref())
                .is_some_and(contains)
        }
        EntryPayload::Card(card) => contains(&card.cardholder_name) || contains(&card.number),
        EntryPayload::Identity(identity) => {
            contains(&identity.full_name)
                || contains(&identity.first_name)
                || contains(&identity.last_name)
                || identity.emails.iter().any(|e| contains(e))
                || identity.phones.iter().any(|p| contains(p))
                || identity.addresses.iter().any(|a| contains(&a.city))
        }
        EntryPayload::Note(note) => contains(&note.content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2idParams, CryptoProfile};

    fn test_service(tag: &str) -> (Service, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("yobei-svc-{}-{}.db", tag, Vault::new_id()));
        let profile = CryptoProfile {
            kdf_params: Argon2idParams::OWASP_MINIMUM,
            ..CryptoProfile::default()
        };
        let sk = crate::keys::random_bytes(crate::keys::KEY_LEN);
        let vault = Vault::create(&path, "pw", Some(&sk), profile, 0).unwrap();
        (Service::new(vault), path)
    }

    #[test]
    fn crud_search_and_trash_lifecycle() {
        let (mut svc, path) = test_service("crud");
        let mut gh = svc
            .create_entry(EntryKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        if let EntryPayload::Account(account) = &mut gh.payload {
            account.username = "octocat".into();
        }
        gh.tags = vec!["dev".into()];
        svc.save_entry(&mut gh, 2_000).unwrap();
        assert_eq!(gh.version, 2);
        assert!(gh.hlc >= 2_000);

        let mail = svc
            .create_entry(EntryKind::Account, "Fastmail".into(), 3_000)
            .unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 2);
        assert_eq!(svc.search("octo", false).unwrap().len(), 1);
        assert_eq!(svc.search("DEV", false).unwrap().len(), 1);
        assert_eq!(svc.search("fast", false).unwrap()[0].id, mail.id);

        svc.set_favorite(&mail.id, true, 4_000).unwrap();
        assert!(svc.get_entry(&mail.id).unwrap().unwrap().favorite);

        svc.trash(&gh.id, 5_000).unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 1);
        assert_eq!(svc.search("", true).unwrap().len(), 2);
        svc.restore(&gh.id, 6_000).unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 2);

        svc.trash(&gh.id, 7_000).unwrap();
        let purged = svc.purge_expired(7_000 + TRASH_RETENTION_MS + 1).unwrap();
        assert_eq!(purged, 1);
        let tombstone = svc.get_entry(&gh.id).unwrap().unwrap();
        assert!(tombstone.deleted);
        assert!(svc.restore(&gh.id, 7_000 + TRASH_RETENTION_MS + 1).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn touch_never_moves_hlc_backwards() {
        let mut entry = Entry::new_account("id".into(), "v".into(), "T".into(), 10_000);
        entry.hlc = 50_000;
        touch(&mut entry, 20_000);
        assert_eq!(entry.hlc, 50_001);
        assert_eq!(entry.version, 2);
    }

    #[test]
    fn conflict_copy_gets_a_new_id_and_suffix() {
        let (mut svc, path) = test_service("conflict");
        let source = svc
            .create_entry(EntryKind::Note, "Draft".into(), 1_000)
            .unwrap();
        let copy = svc.add_conflict_copy(&source, 2_000).unwrap();
        assert_ne!(copy.id, source.id);
        assert_eq!(copy.title, "Draft");
        assert_eq!(copy.conflict_copy_of.as_deref(), Some(source.id.as_str()));
        assert_eq!(copy.version, 1);
        let _ = std::fs::remove_file(&path);
    }
}
