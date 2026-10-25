//! Sync protocol types, shared in shape with the Cloudflare Workers sync
//! server (workers/sync). The server is deliberately "dumb": it stores
//! ciphertext, dedupes by op id, and checks record versions. It never sees
//! plaintext and never merges. See docs/DESIGN.md §4.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOpKind {
    Upsert,
    Delete, // tombstone
}

/// One idempotent sync operation, produced in the client's local outbox
/// before any network call (sync must never block local vault use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOp {
    /// UUID, globally unique. Re-pushing the same op_id is a no-op
    /// (server-side dedup), which makes retries safe.
    pub op_id: String,
    pub vault_id: String,
    pub record_id: String,
    /// The record version this op is based on. The server accepts the op
    /// only if its current version equals base_version; otherwise the
    /// result is a conflict and both versions are preserved.
    pub base_version: u64,
    /// Record version after this op.
    pub new_version: u64,
    /// Hybrid logical clock value at mutation time.
    pub hlc: u64,
    pub kind: SyncOpKind,
    /// AEAD ciphertext of the record (empty for deletes), base64 in JSON.
    pub ciphertext_b64: String,
    /// AEAD nonce, base64 in JSON.
    pub nonce_b64: String,
}

/// One line of a vault manifest: the minimum metadata needed for
/// incremental sync, and all the server ever learns about a record
/// beyond its ciphertext size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub record_id: String,
    pub version: u64,
    pub hlc: u64,
    pub updated_at_ms: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpOutcome {
    Accepted,
    /// Server version != base_version. Client keeps the remote copy as a
    /// conflict copy; nothing is overwritten silently.
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
            vault_id: "default".into(),
            record_id: "rec-1".into(),
            base_version: 3,
            new_version: 4,
            hlc: 42,
            kind: SyncOpKind::Upsert,
            ciphertext_b64: "AA==".into(),
            nonce_b64: "BB==".into(),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(op, serde_json::from_str(&json).unwrap());
    }
}
