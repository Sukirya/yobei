//! Sync engine: reconciles the local vault with the sync server via a
//! [`SyncTransportPort`]. The server (workers/sync) is dumb storage; all
//! decisions happen here.
//!
//! One `sync_now` run:
//! 1. **Pull.** Fetch the manifest. Records the server has newer:
//!    fast-forward if we have no unpushed changes; if we do, our local
//!    version is first preserved as a conflict copy, then the canonical
//!    row becomes the remote version. Unknown tombstones are ignored.
//! 2. **Push.** Replay the outbox in order. Accepted/duplicate ops are
//!    dropped. A conflict means another device advanced the record
//!    after our pull started: resolve it the same way — local content
//!    becomes a conflict copy, canonical becomes remote, stale ops for
//!    that record are dropped, and the copy's create op goes out in a
//!    later run.
//!
//! Local edits are never lost and never silently overwritten; the worst
//! case is an extra record titled "…（冲突副本）" for the user to merge.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::ports::SyncTransportPort;
use crate::record::RecordKind;
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
}

#[derive(Deserialize)]
struct ManifestWire {
    entries: Vec<ManifestEntryWire>,
}

#[derive(Deserialize, Clone)]
struct ManifestEntryWire {
    record_id: String,
    version: u64,
    hlc: u64,
    updated_at_ms: i64,
    /// D1 returns 0/1 integers; some adapters may give real booleans.
    deleted: serde_json::Value,
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
    let json = transport.fetch_manifest(service.vault_id())?;
    let parsed: ManifestWire =
        serde_json::from_str(&json).map_err(|e| format!("parse manifest: {e}"))?;
    Ok(parsed.entries)
}

/// Make the canonical local row match a remote manifest entry.
fn apply_remote(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    entry: &ManifestEntryWire,
) -> Result<(), String> {
    if entry.is_deleted() {
        // Keep whatever blob/kind we already have (the tombstone's
        // content stays recoverable locally); only state advances.
        let vault = service.vault_mut();
        let existing_blob = vault.get_blob(&entry.record_id)?.unwrap_or_default();
        let local = vault.decrypt(&entry.record_id, &existing_blob).ok();
        let kind = local
            .as_ref()
            .map(|r| r.kind.clone())
            .unwrap_or(RecordKind::Custom);
        let created = local
            .as_ref()
            .map(|r| r.created_at_ms)
            .unwrap_or(entry.updated_at_ms);
        vault.put_raw(
            &entry.record_id,
            &kind,
            created,
            entry.updated_at_ms,
            entry.version,
            entry.hlc,
            true,
            &existing_blob,
        )
    } else {
        let vault_id = service.vault_id().to_string();
        let blob = transport.fetch_record(&vault_id, &entry.record_id)?;
        let vault = service.vault_mut();
        let record = vault.decrypt(&entry.record_id, &blob)?;
        vault.put_raw(
            &entry.record_id,
            &record.kind,
            record.created_at_ms,
            record.updated_at_ms,
            entry.version,
            entry.hlc,
            false,
            &blob,
        )
    }
}

pub fn sync_now(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    now_ms: i64,
) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();

    // ------------------------------------------------------------ pull ---
    let entries = fetch_manifest(service, transport)?;
    let local_metas: HashMap<String, crate::vault::RecordMeta> = service
        .vault_mut()
        .record_metas()?
        .into_iter()
        .map(|m| (m.id.clone(), m))
        .collect();
    let pending = service.vault_mut().pending_record_ids()?;

    for entry in &entries {
        let local = local_metas.get(&entry.record_id);
        match local {
            None => {
                if !entry.is_deleted() {
                    apply_remote(service, transport, entry)?;
                    report.pulled_new += 1;
                }
            }
            Some(meta) if entry.version > meta.version => {
                if pending.contains(&entry.record_id) {
                    // We have unpushed changes and the server moved on:
                    // preserve ours as a copy, then take the remote.
                    if let Some(local_record) = service.get_record(&entry.record_id)? {
                        service.add_conflict_copy(&local_record, now_ms)?;
                        report.conflict_copies += 1;
                        report.conflicts += 1;
                    }
                    service.vault_mut().remove_ops_for_record(&entry.record_id)?;
                }
                apply_remote(service, transport, entry)?;
                report.pulled_updated += 1;
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ push ---
    let ops = service.vault_mut().outbox_ops()?;
    if !ops.is_empty() {
        let payload = serde_json::json!({ "ops": ops }).to_string();
        let response = transport.push_ops(service.vault_id(), &payload)?;
        let parsed: PushResultsWire =
            serde_json::from_str(&response).map_err(|e| format!("parse push results: {e}"))?;
        let op_by_id: HashMap<String, crate::sync::SyncOp> =
            ops.into_iter().map(|op| (op.op_id.clone(), op)).collect();
        let mut conflicted_records: HashSet<String> = HashSet::new();
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
                        conflicted_records.insert(op.record_id.clone());
                    }
                }
            }
        }
        for record_id in conflicted_records {
            resolve_push_conflict(service, transport, &record_id, now_ms, &mut report)?;
        }
    }

    Ok(report)
}

/// A push conflict raced the pull (another device pushed in between).
/// Same rule as pull conflicts: local content becomes a conflict copy,
/// canonical becomes the remote state, stale ops are dropped.
fn resolve_push_conflict(
    service: &mut Service,
    transport: &dyn SyncTransportPort,
    record_id: &str,
    now_ms: i64,
    report: &mut SyncReport,
) -> Result<(), String> {
    let entries = fetch_manifest(service, transport)?;
    let entry = entries.iter().find(|e| e.record_id == record_id);
    if let Some(local_record) = service.get_record(record_id)? {
        service.add_conflict_copy(&local_record, now_ms)?;
        report.conflict_copies += 1;
    }
    report.conflicts += 1;
    service.vault_mut().remove_ops_for_record(record_id)?;
    if let Some(entry) = entry {
        apply_remote(service, transport, entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Argon2idParams, CryptoProfile};
    use crate::ports::SyncTransportPort;
    use crate::record::RecordKind;
    use crate::sync::{SyncOp, SyncOpKind};
    use crate::vault::Vault;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    /// In-memory stand-in implementing the worker's exact semantics:
    /// op-id dedup, base_version check, nonce‖ciphertext blob store.
    #[derive(Default)]
    struct FakeServer {
        records: HashMap<String, (u64, u64, i64, bool, Vec<u8>)>,
        seen_ops: HashSet<String>,
    }

    struct FakeTransport {
        server: Rc<RefCell<FakeServer>>,
    }

    impl SyncTransportPort for FakeTransport {
        fn push_ops(&self, _vault_id: &str, ops_json: &str) -> Result<String, String> {
            let parsed: serde_json::Value = serde_json::from_str(ops_json).unwrap();
            let ops: Vec<SyncOp> =
                serde_json::from_value(parsed["ops"].clone()).unwrap();
            let mut server = self.server.borrow_mut();
            let mut results = Vec::new();
            for op in ops {
                if server.seen_ops.contains(&op.op_id) {
                    results.push(serde_json::json!({"op_id": op.op_id, "outcome": "duplicate"}));
                    continue;
                }
                let current = server
                    .records
                    .get(&op.record_id)
                    .map(|r| r.0)
                    .unwrap_or(0);
                if current != op.base_version {
                    results.push(serde_json::json!({"op_id": op.op_id, "outcome": "conflict"}));
                    continue;
                }
                server.seen_ops.insert(op.op_id.clone());
                match op.kind {
                    SyncOpKind::Upsert => {
                        let nonce = data_encoding::BASE64
                            .decode(op.nonce_b64.as_bytes())
                            .unwrap();
                        let ct = data_encoding::BASE64
                            .decode(op.ciphertext_b64.as_bytes())
                            .unwrap();
                        let mut blob = nonce;
                        blob.extend_from_slice(&ct);
                        server.records.insert(
                            op.record_id.clone(),
                            (op.new_version, op.hlc, 9_999, false, blob),
                        );
                    }
                    SyncOpKind::Delete => {
                        let prev = server.records.get(&op.record_id);
                        let blob = prev.map(|r| r.4.clone()).unwrap_or_default();
                        server.records.insert(
                            op.record_id.clone(),
                            (op.new_version, op.hlc, 9_999, true, blob),
                        );
                    }
                }
                results.push(serde_json::json!({"op_id": op.op_id, "outcome": "accepted"}));
            }
            Ok(serde_json::json!({ "results": results }).to_string())
        }

        fn fetch_manifest(&self, _vault_id: &str) -> Result<String, String> {
            let server = self.server.borrow();
            let entries: Vec<serde_json::Value> = server
                .records
                .iter()
                .map(|(id, (v, h, u, d, _))| {
                    serde_json::json!({
                        "record_id": id, "version": v, "hlc": h,
                        "updated_at_ms": u, "deleted": if *d { 1 } else { 0 },
                    })
                })
                .collect();
            Ok(serde_json::json!({ "entries": entries }).to_string())
        }

        fn fetch_record(&self, _vault_id: &str, record_id: &str) -> Result<Vec<u8>, String> {
            let server = self.server.borrow();
            server
                .records
                .get(record_id)
                .filter(|r| !r.3)
                .map(|r| r.4.clone())
                .ok_or_else(|| "not found".to_string())
        }
    }

    fn test_profile() -> CryptoProfile {
        CryptoProfile {
            kdf_params: Argon2idParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 },
            ..CryptoProfile::default()
        }
    }

    /// Two devices = two vault files cloned from one origin (same vault
    /// key), like restoring the same vault on a second phone.
    fn two_devices(tag: &str) -> (Service, Service, Rc<RefCell<FakeServer>>, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir();
        let path_a = dir.join(format!("yobei-sync-{tag}-a.db"));
        let path_b = dir.join(format!("yobei-sync-{tag}-b.db"));
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
        let vault_a = Vault::create(&path_a, "pw", None, test_profile(), 0).unwrap();
        drop(vault_a);
        std::fs::copy(&path_a, &path_b).unwrap();
        let a = Service::new(Vault::open(&path_a, "pw", None).unwrap());
        let b = Service::new(Vault::open(&path_b, "pw", None).unwrap());
        (a, b, Rc::new(RefCell::new(FakeServer::default())), path_a, path_b)
    }

    #[test]
    fn push_then_pull_replicates_records() {
        let (mut a, mut b, server, pa, pb) = two_devices("basic");
        let ta = FakeTransport { server: server.clone() };
        let tb = FakeTransport { server: server.clone() };

        let rec = a
            .create_record(RecordKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        let report = sync_now(&mut a, &ta, 2_000).unwrap();
        assert_eq!(report.pushed, 1);

        let report_b = sync_now(&mut b, &tb, 3_000).unwrap();
        assert_eq!(report_b.pulled_new, 1);
        let on_b = b.get_record(&rec.id).unwrap().unwrap();
        assert_eq!(on_b.title, "GitHub");
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }

    #[test]
    fn divergent_edits_become_conflict_copies_not_data_loss() {
        let (mut a, mut b, server, pa, pb) = two_devices("conflict");
        let ta = FakeTransport { server: server.clone() };
        let tb = FakeTransport { server: server.clone() };

        let mut rec = a
            .create_record(RecordKind::Account, "GitHub".into(), 1_000)
            .unwrap();
        sync_now(&mut a, &ta, 2_000).unwrap();
        sync_now(&mut b, &tb, 3_000).unwrap();

        // Both edit offline.
        rec.title = "GitHub (A edit)".into();
        a.save_record(&mut rec.clone(), 4_000).unwrap();
        let mut rec_b = b.get_record(&rec.id).unwrap().unwrap();
        rec_b.title = "GitHub (B edit)".into();
        b.save_record(&mut rec_b, 5_000).unwrap();

        sync_now(&mut a, &ta, 6_000).unwrap(); // A wins the race to push.
        let report_b = sync_now(&mut b, &tb, 7_000).unwrap();
        assert_eq!(report_b.conflicts, 1);
        assert_eq!(report_b.conflict_copies, 1);

        let all_b = b.search("", false).unwrap();
        assert_eq!(all_b.len(), 2);
        let canonical = all_b.iter().find(|r| r.id == rec.id).unwrap();
        assert_eq!(canonical.title, "GitHub (A edit)");
        let copy = all_b.iter().find(|r| r.id != rec.id).unwrap();
        assert_eq!(copy.title, "GitHub (B edit)（冲突副本）");

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
        let ta = FakeTransport { server: server.clone() };
        let tb = FakeTransport { server: server.clone() };
        let rec = a
            .create_record(RecordKind::Account, "Old".into(), 1_000)
            .unwrap();
        sync_now(&mut a, &ta, 2_000).unwrap();
        sync_now(&mut b, &tb, 3_000).unwrap();
        a.trash(&rec.id, 4_000).unwrap();
        sync_now(&mut a, &ta, 5_000).unwrap();
        sync_now(&mut b, &tb, 6_000).unwrap();
        assert!(b.search("", false).unwrap().is_empty());
        assert_eq!(b.search("", true).unwrap().len(), 1);
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
    }
}
