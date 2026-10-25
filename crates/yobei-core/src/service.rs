//! Application service layer over an unlocked [`Vault`]: the mutation
//! semantics the app shell (Tauri commands, CLI, tests) shares — record
//! creation, touch (version + HLC discipline), search, favorites and the
//! trash lifecycle (soft delete → restore or purge). Keeping this in the
//! core means every platform gets identical behavior.

use crate::record::{AccountData, Record, RecordKind};
use crate::vault::Vault;

/// Advance a record's mutation metadata. Every mutation bumps `version`
/// by exactly 1 (sync conflict detection depends on it) and sets `hlc`
/// monotonically: wall-clock millis, but never backwards for this record.
pub fn touch(record: &mut Record, now_ms: i64) {
    record.updated_at_ms = now_ms;
    record.version += 1;
    let now_hlc = now_ms.max(0) as u64;
    record.hlc = now_hlc.max(record.hlc + 1);
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

    pub fn into_vault(self) -> Vault {
        self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    /// Create and store a new record of the given kind.
    pub fn create_record(
        &mut self,
        kind: RecordKind,
        title: String,
        now_ms: i64,
    ) -> Result<Record, String> {
        let mut record = if kind == RecordKind::Account {
            Record::new_account(Vault::new_id(), self.vault_id().to_string(), title, now_ms)
        } else {
            Record {
                id: Vault::new_id(),
                vault_id: self.vault_id().to_string(),
                kind,
                title,
                favorite: false,
                tags: Vec::new(),
                fields: Vec::new(),
                account: None,
                notes: String::new(),
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
                version: 1,
                hlc: now_ms.max(0) as u64,
                deleted: false,
            }
        };
        if record.kind == RecordKind::Account && record.account.is_none() {
            record.account = Some(AccountData::default());
        }
        record.hlc = now_ms.max(0) as u64;
        self.vault.put(&record)?;
        Ok(record)
    }

    /// Save an edited record: applies touch discipline, then persists.
    pub fn save_record(&mut self, record: &mut Record, now_ms: i64) -> Result<(), String> {
        touch(record, now_ms);
        self.vault.put(record)
    }

    pub fn get_record(&self, id: &str) -> Result<Option<Record>, String> {
        self.vault.get(id)
    }

    /// Case-insensitive substring search over everything a user would
    /// look for: title, tags, notes, username, URLs and field contents.
    /// An empty query lists everything (newest first).
    pub fn search(&self, query: &str, include_deleted: bool) -> Result<Vec<Record>, String> {
        let all = self.vault.list(include_deleted)?;
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(all);
        }
        Ok(all
            .into_iter()
            .filter(|r| record_matches(r, &q))
            .collect())
    }

    pub fn set_favorite(&mut self, id: &str, favorite: bool, now_ms: i64) -> Result<(), String> {
        let mut record = self
            .vault
            .get(id)?
            .ok_or_else(|| "record not found".to_string())?;
        record.favorite = favorite;
        self.save_record(&mut record, now_ms)
    }

    /// Move to trash (tombstone; sync-propagatable).
    pub fn trash(&mut self, id: &str, now_ms: i64) -> Result<(), String> {
        let mut record = self
            .vault
            .get(id)?
            .ok_or_else(|| "record not found".to_string())?;
        record.deleted = true;
        self.save_record(&mut record, now_ms)
    }

    /// Bring a record back from trash.
    pub fn restore(&mut self, id: &str, now_ms: i64) -> Result<(), String> {
        let mut record = self
            .vault
            .get(id)?
            .ok_or_else(|| "record not found".to_string())?;
        record.deleted = false;
        self.save_record(&mut record, now_ms)
    }

    /// Delete permanently (row removed, no tombstone).
    pub fn purge(&mut self, id: &str) -> Result<(), String> {
        self.vault.purge(id)
    }
}

fn record_matches(record: &Record, q: &str) -> bool {
    let contains = |s: &str| s.to_lowercase().contains(q);
    if contains(&record.title) || contains(&record.notes) {
        return true;
    }
    if record.tags.iter().any(|t| contains(t)) {
        return true;
    }
    if record.fields.iter().any(|f| contains(&f.name) || contains(&f.value)) {
        return true;
    }
    if let Some(acct) = &record.account {
        if contains(&acct.username) {
            return true;
        }
        if acct.urls.iter().any(|u| contains(&u.url)) {
            return true;
        }
        if let Some(totp) = &acct.totp {
            if totp.issuer.as_deref().is_some_and(contains) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2idParams, CryptoProfile};

    fn test_service(tag: &str) -> (Service, std::path::PathBuf) {
        let path = std::env::temp_dir()
            .join(format!("yobei-svc-{}-{}.db", tag, Vault::new_id()));
        let profile = CryptoProfile {
            kdf_params: Argon2idParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 },
            ..CryptoProfile::default()
        };
        let vault = Vault::create(&path, "pw", None, profile, 0).unwrap();
        (Service::new(vault), path)
    }

    #[test]
    fn crud_search_and_trash_lifecycle() {
        let (mut svc, path) = test_service("crud");
        let mut gh = svc
            .create_record(RecordKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        gh.account.as_mut().unwrap().username = "octocat".into();
        gh.tags = vec!["dev".into()];
        svc.save_record(&mut gh, 2_000).unwrap();
        assert_eq!(gh.version, 2);
        assert!(gh.hlc >= 2_000);

        let mail = svc
            .create_record(RecordKind::Account, "Fastmail".into(), 3_000)
            .unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 2);
        assert_eq!(svc.search("octo", false).unwrap().len(), 1);
        assert_eq!(svc.search("DEV", false).unwrap().len(), 1);
        assert_eq!(svc.search("fast", false).unwrap()[0].id, mail.id);

        svc.set_favorite(&mail.id, true, 4_000).unwrap();
        assert!(svc.get_record(&mail.id).unwrap().unwrap().favorite);

        svc.trash(&gh.id, 5_000).unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 1);
        assert_eq!(svc.search("", true).unwrap().len(), 2);
        svc.restore(&gh.id, 6_000).unwrap();
        assert_eq!(svc.search("", false).unwrap().len(), 2);
        svc.trash(&gh.id, 7_000).unwrap();
        svc.purge(&gh.id).unwrap();
        assert_eq!(svc.search("", true).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn touch_never_moves_hlc_backwards() {
        let mut r = Record::new_account("id".into(), "v".into(), "T".into(), 10_000);
        r.hlc = 50_000;
        touch(&mut r, 20_000);
        assert_eq!(r.hlc, 50_001);
        assert_eq!(r.version, 2);
    }
}
