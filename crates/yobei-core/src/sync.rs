//! Sync protocol types, shared in shape with the Cloudflare Workers sync
//! server (workers/sync). The server is deliberately "dumb": it stores
//! ciphertext, dedupes by op id, and checks entry versions. It never sees
//! plaintext and never merges. See ADR-0003.
//!
//! Deletion is not a separate op shape: every op stores the next version of
//! an entry, and the entry's `deleted` flag lives inside the ciphertext.
//! The server mirrors only the flag it needs for the manifest.

use serde::{Deserialize, Serialize};

/// One idempotent sync operation, produced in the client's local outbox
/// before any network call (sync must never block local vault use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOp {
    /// UUID, globally unique. Re-pushing the same op_id is a no-op
    /// (server-side dedup), which makes retries safe.
    pub op_id: String,
    /// The sync address (derived from the Secret Key), not the local vault
    /// UUID (ADR-0002).
    pub vault_id: String,
    pub entry_id: String,
    /// The entry version this op is based on. The server accepts the op
    /// only if its current version equals base_version; otherwise the
    /// result is a conflict.
    pub base_version: u64,
    /// Entry version after this op (must be base_version + 1).
    pub new_version: u64,
    /// Hybrid logical clock value at mutation time (metadata only).
    pub hlc: u64,
    /// Mirror of the entry's tombstone flag. The server needs it for the
    /// manifest but cannot read it from the ciphertext (ADR-0003 §2).
    pub deleted: bool,
    #[serde(default)]
    pub deleted_at_ms: Option<i64>,
    /// AEAD ciphertext of the entry (nonce ‖ ciphertext), base64 in JSON.
    /// Carries the entry's `deleted` state inside the plaintext.
    pub ciphertext_b64: String,
}

/// One line of a vault manifest: the minimum metadata needed for
/// incremental sync, and all the server ever learns about an entry
/// beyond its ciphertext size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub entry_id: String,
    pub version: u64,
    pub hlc: u64,
    pub updated_at_ms: i64,
    pub deleted: bool,
    #[serde(default)]
    pub deleted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    Accepted,
    /// Server version != base_version. The client keeps the remote copy and
    /// preserves its own content as a conflict copy.
    Conflict,
    /// Same op_id already applied.
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_roundtrip() {
        let op = SyncOp {
            op_id: "op-1".into(),
            vault_id: "vault-1".into(),
            entry_id: "entry-1".into(),
            base_version: 3,
            new_version: 4,
            hlc: 42,
            deleted: false,
            deleted_at_ms: None,
            ciphertext_b64: "AA==".into(),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(op, serde_json::from_str(&json).unwrap());
    }

    #[test]
    fn manifest_roundtrip_including_tombstone_time() {
        let line = ManifestEntry {
            entry_id: "entry-1".into(),
            version: 5,
            hlc: 7,
            updated_at_ms: 1_000,
            deleted: true,
            deleted_at_ms: Some(1_000),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert_eq!(line, serde_json::from_str(&json).unwrap());
    }
}
