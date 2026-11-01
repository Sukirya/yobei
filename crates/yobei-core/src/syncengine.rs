//! Sync engine: reconciles the local vault with the sync server via a
//! [`SyncTransportPort`]. The server (workers/sync) is dumb storage; all
//! decisions happen here. See ADR-0003.
//!
//! One `sync_now` run:
//! 1. **Pull.** Fetch the manifest. Entries the server has newer:
//!    fast-forward if we have no unpushed changes; if we do, our local
//!    version is first preserved as a conflict copy, then the canonical
//!    row becomes the remote version. A remote tombstone always wins
//!    (delete dominance): local late edits are discarded, never turned
//!    into a conflict copy that would resurrect the entry.
//! 2. **Push.** Replay the outbox in order. Accepted/duplicate ops are
//!    dropped. A conflict means another device advanced the entry after
//!    our pull started: resolve it the same way as a pull conflict.
//! 3. **Retention.** Locally purge content of tombstones older than the
//!    30-day window.
//!
//! Local edits are never lost silently and never overwrite remote data;
//! the worst case is an extra entry marked as a conflict copy.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::entry::Entry;
use crate::ports::SyncTransportPort;
use crate::service::Service;
use crate::sync::OpOutcome;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SyncReport {
    pub pushed: usize,
    pub duplicates: usize,
    pub pulled_new: usize,
    pub pulled_updated: usize,
    pub conflicts: usize,
    pub conflict_copies: usize,
    /// Local edits discarded because the remote entry was deleted
    /// (delete dominance, ADR-0003 §3).
    pub discarded: usize,
}

#[derive(Deserialize)]
struct ManifestWire {
    entries: Vec<ManifestEntryWire>,
}

#[derive(Deserialize, Clone)]
struct ManifestEntryWire {
    entry_id: String,
    version: u64,
    hlc: u64,
    updated_at_ms: i64,
    /// D1 returns 0/1 integers; some adapters may give real booleans.
    deleted: serde_json::Value,
    #[serde(default)]
    deleted_at_ms: Option<i64>,
}

impl ManifestEntryWire {
    fn is_deleted(&self) -> bool {
        match &self.deleted {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::Number(n) => n.as_i64().unwrap_or(0) != 0,
            _ => false,
        }
    }
}

#[derive(Deserialize)]
struct PushResultsWire {
    results: Vec<OpResultWire>,
}

#[derive(Deserialize)]
struct OpResultWire {
    op_id: String,
    outcome: OpOutcome,
}

fn fetch_manifest(
    service: &Service,
    transport: &dyn SyncTransportPort,
) -> Result<Vec<ManifestEntryWire>, String> {
    let json = transport.fetch_manifest(service.sync_address()?)?;
    let parsed: ManifestWire =
        serde_json::from_str(&json).map_err(|e| format!("parse manifest: {e}"))?;
    Ok(parsed.entries)
}

/// Make the canonical local row match a remote manifest entry.
///
/// For live entries the downloaded ciphertext is stored verbatim; the
/// version inside the ciphertext must match the manifest, otherwise the
/// server is trying to roll content back (ADR-0003 §1).
fn apply_remote(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    remote: &ManifestEntryWire,
    now_ms: i64,
) -> Result<(), String> {
    let address = service.sync_address()?.to_string();
    let vault_id = service.vault_id().to_string();
    if remote.is_deleted() {
        // Keep local content for the 30-day restore window; if we never had
        // the entry, store a minimal decryptable tombstone.
        let mut tombstone = match service.get_entry(&remote.entry_id)? {
            Some(mut existing) => {
                existing.deleted = true;
                existing.deleted_at_ms = remote.deleted_at_ms.or(Some(now_ms));
                existing
            }
            None => {
                let mut created =
                    Entry::new_note(remote.entry_id.clone(), vault_id, String::new(), now_ms);
                created.deleted = true;
                created.deleted_at_ms = remote.deleted_at_ms.or(Some(now_ms));
                created
            }
        };
        tombstone.version = remote.version;
        tombstone.hlc = remote.hlc;
        tombstone.updated_at_ms = remote.updated_at_ms;
        tombstone.validate()?;
        service.vault_mut().put(&tombstone)?;
        return Ok(());
    }

    let blob = transport.fetch_entry(&address, &remote.entry_id)?;
    let entry = service.vault_mut().decrypt_entry(&remote.entry_id, &blob)?;
    if entry.version != remote.version {
        return Err(format!(
            "integrity check failed for entry {}: manifest version {} != ciphertext version {}",
            remote.entry_id, remote.version, entry.version
        ));
    }
    if entry.deleted {
        return Err(format!(
            "integrity check failed for entry {}: manifest says live, ciphertext says deleted",
            remote.entry_id
        ));
    }
    service.vault_mut().put_entry_blob(&entry, &blob)?;
    Ok(())
}

pub fn sync_now(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    now_ms: i64,
) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();

    // ------------------------------------------------------------ pull ---
    let manifest = fetch_manifest(service, transport)?;
    let local_metas: HashMap<String, crate::vault::EntryMeta> = service
        .vault_mut()
        .entry_metas()?
        .into_iter()
        .map(|m| (m.id.clone(), m))
        .collect();
    let pending = service.vault_mut().pending_entry_ids()?;

    for remote in &manifest {
        match local_metas.get(&remote.entry_id) {
            None => {
                if !remote.is_deleted() {
                    apply_remote(service, transport, remote, now_ms)?;
                    report.pulled_new += 1;
                }
            }
            Some(local) if remote.version > local.version => {
                if pending.contains(&remote.entry_id) {
                    if remote.is_deleted() {
                        // Delete dominance: discard local late edits.
                        service.vault_mut().remove_ops_for_entry(&remote.entry_id)?;
                        apply_remote(service, transport, remote, now_ms)?;
                        report.discarded += 1;
                    } else {
                        if let Some(local_entry) = service.get_entry(&remote.entry_id)? {
                            service.add_conflict_copy(&local_entry, now_ms)?;
                            report.conflict_copies += 1;
                        }
                        service.vault_mut().remove_ops_for_entry(&remote.entry_id)?;
                        apply_remote(service, transport, remote, now_ms)?;
                        report.conflicts += 1;
                    }
                } else {
                    apply_remote(service, transport, remote, now_ms)?;
                }
                report.pulled_updated += 1;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ push ---
    // The worker caps a batch at 100 ops / 2 MB; batch on the client so a
    // long offline period cannot produce an un-pushable request.
    let ops = service.vault_mut().outbox_ops()?;
    let address = service.sync_address()?.to_string();
    let mut batch: Vec<crate::sync::SyncOp> = Vec::new();
    let mut batch_bytes = 0usize;
    for op in ops {
        let size = op.ciphertext_b64.len() + 512;
        if !batch.is_empty() && (batch.len() >= 50 || batch_bytes + size > 1_500_000) {
            push_batch(
                service,
                transport,
                &address,
                std::mem::take(&mut batch),
                now_ms,
                &mut report,
            )?;
            batch_bytes = 0;
        }
        batch_bytes += size;
        batch.push(op);
    }
    if !batch.is_empty() {
        push_batch(service, transport, &address, batch, now_ms, &mut report)?;
    }

    // ------------------------------------------------------- retention ---
    service.purge_expired(now_ms)?;

    Ok(report)
}

/// Push one bounded batch and apply the per-op outcomes.
fn push_batch(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    address: &str,
    ops: Vec<crate::sync::SyncOp>,
    now_ms: i64,
    report: &mut SyncReport,
) -> Result<(), String> {
    let payload = serde_json::json!({ "ops": &ops }).to_string();
    let response = transport.push_ops(address, &payload)?;
    let parsed: PushResultsWire =
        serde_json::from_str(&response).map_err(|e| format!("parse push results: {e}"))?;
    let op_by_id: HashMap<String, crate::sync::SyncOp> =
        ops.into_iter().map(|op| (op.op_id.clone(), op)).collect();
    let mut conflicted_entries: HashSet<String> = HashSet::new();
    for result in parsed.results {
        match result.outcome {
            OpOutcome::Accepted => {
                service.vault_mut().remove_op(&result.op_id)?;
                report.pushed += 1;
            }
            OpOutcome::Duplicate => {
                service.vault_mut().remove_op(&result.op_id)?;
                report.duplicates += 1;
            }
            OpOutcome::Conflict => {
                if let Some(op) = op_by_id.get(&result.op_id) {
                    conflicted_entries.insert(op.entry_id.clone());
                }
            }
        }
    }
    for entry_id in conflicted_entries {
        resolve_push_conflict(service, transport, &entry_id, now_ms, report)?;
    }
    Ok(())
}

/// A push conflict raced the pull (another device pushed in between).
/// Same rules as pull conflicts; a remote tombstone wins.
fn resolve_push_conflict(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    entry_id: &str,
    now_ms: i64,
    report: &mut SyncReport,
) -> Result<(), String> {
    let manifest = fetch_manifest(service, transport)?;
    let remote = manifest.iter().find(|e| e.entry_id == entry_id);
    match remote {
        Some(remote) if remote.is_deleted() => {
            service.vault_mut().remove_ops_for_entry(entry_id)?;
            apply_remote(service, transport, remote, now_ms)?;
            report.discarded += 1;
            report.conflicts += 1;
        }
        Some(remote) => {
            if let Some(local) = service.get_entry(entry_id)? {
                service.add_conflict_copy(&local, now_ms)?;
                report.conflict_copies += 1;
            }
            report.conflicts += 1;
            service.vault_mut().remove_ops_for_entry(entry_id)?;
            apply_remote(service, transport, remote, now_ms)?;
        }
        None => {
            // The server no longer knows this entry (e.g. it was never
            // accepted). Preserve our content rather than dropping it.
            if let Some(local) = service.get_entry(entry_id)? {
                service.add_conflict_copy(&local, now_ms)?;
                report.conflict_copies += 1;
            }
            report.conflicts += 1;
            service.vault_mut().remove_ops_for_entry(entry_id)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2idParams, CryptoProfile};
    use crate::entry::{EntryKind, EntryPayload};
    use crate::ports::SyncTransportPort;
    use crate::sync::SyncOp;
    use crate::vault::Vault;
    use data_encoding::BASE64;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeRecord {
        version: u64,
        hlc: u64,
        updated_at_ms: i64,
        deleted: bool,
        deleted_at_ms: Option<i64>,
        blob: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeServer {
        records: HashMap<String, FakeRecord>,
        seen_ops: HashSet<String>,
    }

    struct FakeTransport {
        server: Rc<RefCell<FakeServer>>,
    }

    impl SyncTransportPort for FakeTransport {
        fn push_ops(&self, _vault_id: &str, ops_json: &str) -> Result<String, String> {
            let parsed: serde_json::Value = serde_json::from_str(ops_json).unwrap();
            let ops: Vec<SyncOp> = serde_json::from_value(parsed["ops"].clone()).unwrap();
            let mut server = self.server.borrow_mut();
            let mut results = Vec::new();
            for op in ops {
                if server.seen_ops.contains(&op.op_id) {
                    results.push(serde_json::json!({"op_id": op.op_id, "outcome": "duplicate"}));
                    continue;
                }
                let current = server
                    .records
                    .get(&op.entry_id)
                    .map(|r| r.version)
                    .unwrap_or(0);
                if current != op.base_version || op.new_version != op.base_version + 1 {
                    results.push(serde_json::json!({"op_id": op.op_id, "outcome": "conflict"}));
                    continue;
                }
                server.seen_ops.insert(op.op_id.clone());
                let blob = BASE64.decode(op.ciphertext_b64.as_bytes()).unwrap();
                server.records.insert(
                    op.entry_id.clone(),
                    FakeRecord {
                        version: op.new_version,
                        hlc: op.hlc,
                        updated_at_ms: 9_999,
                        deleted: op.deleted,
                        deleted_at_ms: op.deleted_at_ms,
                        blob,
                    },
                );
                results.push(serde_json::json!({"op_id": op.op_id, "outcome": "accepted"}));
            }
            Ok(serde_json::json!({ "results": results }).to_string())
        }

        fn fetch_manifest(&self, _vault_id: &str) -> Result<String, String> {
            let server = self.server.borrow();
            let entries: Vec<serde_json::Value> = server
                .records
                .iter()
                .map(|(id, record)| {
                    serde_json::json!({
                        "entry_id": id,
                        "version": record.version,
                        "hlc": record.hlc,
                        "updated_at_ms": record.updated_at_ms,
                        "deleted": if record.deleted { 1 } else { 0 },
                        "deleted_at_ms": record.deleted_at_ms,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "entries": entries }).to_string())
        }

        fn fetch_entry(&self, _vault_id: &str, entry_id: &str) -> Result<Vec<u8>, String> {
            let server = self.server.borrow();
            server
                .records
                .get(entry_id)
                .map(|r| r.blob.clone())
                .ok_or_else(|| "not found".to_string())
        }
    }

    fn test_profile() -> CryptoProfile {
        CryptoProfile {
            kdf_params: Argon2idParams::OWASP_MINIMUM,
            ..CryptoProfile::default()
        }
    }

    /// Two devices = two vault files cloned from one origin (same vault
    /// key), like restoring the same vault on a second phone.
    fn two_devices(
        tag: &str,
    ) -> (
        Service,
        Service,
        Rc<RefCell<FakeServer>>,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let dir = std::env::temp_dir();
        let path_a = dir.join(format!("yobei-sync-{tag}-a.db"));
        let path_b = dir.join(format!("yobei-sync-{tag}-b.db"));
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
        let sk = crate::keys::random_bytes(crate::keys::KEY_LEN);
        let vault_a = Vault::create(&path_a, "pw", Some(&sk), test_profile(), 0).unwrap();
        drop(vault_a);
        std::fs::copy(&path_a, &path_b).unwrap();
        let a = Service::new(Vault::open(&path_a, "pw", Some(&sk)).unwrap());
        let b = Service::new(Vault::open(&path_b, "pw", Some(&sk)).unwrap());
        (
            a,
            b,
            Rc::new(RefCell::new(FakeServer::default())),
            path_a,
            path_b,
        )
    }

    fn account_title(entry: &Entry) -> String {
        entry.title.clone()
    }

    #[test]
    fn push_then_pull_replicates_entries() {
        let (mut a, mut b, server, pa, pb) = two_devices("basic");
        let ta = FakeTransport {
            server: server.clone(),
        };
        let tb = FakeTransport {
            server: server.clone(),
        };

        let entry = a
            .create_entry(EntryKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        let report = sync_now(&mut a, &ta, 2_000).unwrap();
        assert_eq!(report.pushed, 1);

        let report_b = sync_now(&mut b, &tb, 3_000).unwrap();
        assert_eq!(report_b.pulled_new, 1);
        let on_b = b.get_entry(&entry.id).unwrap().unwrap();
        assert_eq!(account_title(&on_b), "GitHub");
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    #[test]
    fn divergent_edits_become_conflict_copies_not_data_loss() {
        let (mut a, mut b, server, pa, pb) = two_devices("conflict");
        let ta = FakeTransport {
            server: server.clone(),
        };
        let tb = FakeTransport {
            server: server.clone(),
        };

        let mut entry = a
            .create_entry(EntryKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        sync_now(&mut a, &ta, 2_000).unwrap();
        sync_now(&mut b, &tb, 3_000).unwrap();

        // Both edit offline.
        entry.title = "GitHub (A edit)".into();
        a.save_entry(&mut entry, 4_000).unwrap();
        let mut entry_b = b.get_entry(&entry.id).unwrap().unwrap();
        entry_b.title = "GitHub (B edit)".into();
        b.save_entry(&mut entry_b, 5_000).unwrap();

        sync_now(&mut a, &ta, 6_000).unwrap(); // A wins the race to push.
        let report_b = sync_now(&mut b, &tb, 7_000).unwrap();
        assert_eq!(report_b.conflicts, 1);
        assert_eq!(report_b.conflict_copies, 1);

        let all_b = b.search("", false).unwrap();
        assert_eq!(all_b.len(), 2);
        let canonical = all_b.iter().find(|e| e.id == entry.id).unwrap();
        assert_eq!(canonical.title, "GitHub (A edit)");
        let copy = all_b.iter().find(|e| e.id != entry.id).unwrap();
        assert_eq!(copy.title, "GitHub (B edit)");
        assert_eq!(copy.conflict_copy_of.as_deref(), Some(entry.id.as_str()));

        // The copy itself syncs back to A on the next rounds.
        sync_now(&mut b, &tb, 8_000).unwrap();
        sync_now(&mut a, &ta, 9_000).unwrap();
        assert_eq!(a.search("", false).unwrap().len(), 2);
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    #[test]
    fn deletes_propagate_as_tombstones() {
        let (mut a, mut b, server, pa, pb) = two_devices("delete");
        let ta = FakeTransport {
            server: server.clone(),
        };
        let tb = FakeTransport {
            server: server.clone(),
        };
        let entry = a
            .create_entry(EntryKind::Note, "Old".into(), 1_000)
            .unwrap();
        sync_now(&mut a, &ta, 2_000).unwrap();
        sync_now(&mut b, &tb, 3_000).unwrap();
        a.trash(&entry.id, 4_000).unwrap();
        sync_now(&mut a, &ta, 5_000).unwrap();
        sync_now(&mut b, &tb, 6_000).unwrap();
        assert!(b.search("", false).unwrap().is_empty());
        assert_eq!(b.search("", true).unwrap().len(), 1);
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    #[test]
    fn delete_dominates_late_offline_edits() {
        let (mut a, mut b, server, pa, pb) = two_devices("dominance");
        let ta = FakeTransport {
            server: server.clone(),
        };
        let tb = FakeTransport {
            server: server.clone(),
        };
        let entry = a
            .create_entry(EntryKind::Account, "Bank".into(), 1_000)
            .unwrap();
        sync_now(&mut a, &ta, 2_000).unwrap();
        sync_now(&mut b, &tb, 3_000).unwrap();

        // B edits offline; A deletes and pushes.
        let mut entry_b = b.get_entry(&entry.id).unwrap().unwrap();
        entry_b.title = "Bank (edited offline)".into();
        b.save_entry(&mut entry_b, 4_000).unwrap();
        a.trash(&entry.id, 5_000).unwrap();
        sync_now(&mut a, &ta, 6_000).unwrap();

        let report_b = sync_now(&mut b, &tb, 7_000).unwrap();
        assert_eq!(report_b.discarded, 1);
        assert_eq!(report_b.conflict_copies, 0);
        assert!(b.search("", false).unwrap().is_empty());
        let tombstone = b.get_entry(&entry.id).unwrap().unwrap();
        assert!(tombstone.deleted);
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    struct RollbackTransport {
        manifest: String,
        blob: Vec<u8>,
    }

    impl SyncTransportPort for RollbackTransport {
        fn push_ops(&self, _vault_id: &str, _ops_json: &str) -> Result<String, String> {
            Ok(serde_json::json!({ "results": [] }).to_string())
        }
        fn fetch_manifest(&self, _vault_id: &str) -> Result<String, String> {
            Ok(self.manifest.clone())
        }
        fn fetch_entry(&self, _vault_id: &str, _entry_id: &str) -> Result<Vec<u8>, String> {
            Ok(self.blob.clone())
        }
    }

    #[test]
    fn server_cannot_roll_content_back_as_a_new_version() {
        let (mut a, mut b, _server, pa, pb) = two_devices("rollback");
        let entry = a
            .create_entry(EntryKind::Account, "Mail".into(), 1_000)
            .unwrap();
        let old_blob = a.vault_mut().get_blob(&entry.id).unwrap().unwrap();
        let mut updated = entry.clone();
        a.save_entry(&mut updated, 2_000).unwrap();

        let manifest = serde_json::json!({
            "entries": [{
                "entry_id": entry.id,
                "version": 2,
                "hlc": 2_000,
                "updated_at_ms": 2_000,
                "deleted": 0,
                "deleted_at_ms": null
            }]
        })
        .to_string();
        let transport = RollbackTransport {
            manifest,
            blob: old_blob,
        };
        let err = sync_now(&mut b, &transport, 3_000).unwrap_err();
        assert!(err.contains("integrity"), "unexpected error: {err}");
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    #[test]
    fn note_entries_never_take_part_in_login_autofill() {
        let (mut a, _b, _server, pa, _pb) = two_devices("autofill");
        let mut note = a
            .create_entry(EntryKind::Note, "API key".into(), 1_000)
            .unwrap();
        if let EntryPayload::Note(payload) = &mut note.payload {
            payload.content = "https://example.com\npassword: secret".into();
        }
        assert!(!note.may_participate_in_autofill());
        let _ = std::fs::remove_file(&pa);
    }
}
