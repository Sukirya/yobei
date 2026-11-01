//! Hexagonal ports: everything the core needs from the outside world.
//! Adapters live outside this crate (Tauri shell, Android, a CLI, tests).
//!
//! The v0 file also declared `VaultStoragePort`, `RandomPort`, `ClockPort`
//! and `KeychainPort`. None had an implementation, and an empty interface
//! does not make a future replacement cheaper — it makes readers believe one
//! already exists (ADR-0007). They were removed. Storage is the SQLite
//! adapter in `vault.rs`, randomness is the OS RNG in `keys.rs`, and time is
//! injected as a parameter.

/// Sync transport: pushes/pulls ciphertext ops to the sync server
/// (Cloudflare Workers in production). The core's sync engine depends on
/// this trait, never on HTTP details.
pub trait SyncTransportPort {
    /// Push a batch of encrypted ops; returns per-op accepted/conflict
    /// results as raw JSON from the server (parsed by the sync module).
    fn push_ops(&self, vault_id: &str, ops_json: &str) -> Result<String, String>;
    /// Fetch the manifest JSON for a vault.
    fn fetch_manifest(&self, vault_id: &str) -> Result<String, String>;
    /// Download one entry's ciphertext blob (nonce ‖ ciphertext,
    /// exactly as stored), for pull and conflict resolution.
    fn fetch_entry(&self, vault_id: &str, entry_id: &str) -> Result<Vec<u8>, String>;
}
