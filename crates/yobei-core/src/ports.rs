//! Hexagonal ports: everything the core needs from the outside world.
//! Adapters live outside this crate (Tauri shell, Android, a CLI, tests).
//! The core never calls platform APIs directly, so it stays testable and
//! auditable in isolation.

/// Encrypted vault persistence (an adapter may be a file, an encrypted
/// SQLite store, or an in-memory fake in tests). The core hands the
/// adapter ciphertext only. The v0.1 reference implementation is the
/// SQLite store in `vault.rs` (row-level ciphertext, see DESIGN.md
/// ADR-001); this whole-blob port remains for alternate adapters.
pub trait VaultStoragePort {
    fn load(&self, vault_id: &str) -> Result<Option<Vec<u8>>, String>;
    fn save(&self, vault_id: &str, ciphertext: &[u8]) -> Result<(), String>;
}

/// Source of randomness (OS RNG in adapters).
pub trait RandomPort {
    fn fill(&self, buf: &mut [u8]);
}

/// Wall clock (injected so sync/HLC logic is testable).
pub trait ClockPort {
    fn now_ms(&self) -> i64;
}

/// OS keychain / biometric gate (Android Keystore, Windows Hello, ...).
/// Used to protect an optional locally-wrapped copy of the vault key for
/// biometric unlock. The core only learns success/failure.
pub trait KeychainPort {
    fn biometric_unlock_available(&self) -> bool;
}

/// Sync transport: pushes/pulls ciphertext ops to the sync server
/// (Cloudflare Workers in production). The core's sync engine depends on
/// this trait, never on HTTP details.
pub trait SyncTransportPort {
    /// Push a batch of encrypted ops; returns per-op accepted/conflict
    /// results as raw JSON from the server (parsed by the sync module).
    fn push_ops(&self, vault_id: &str, ops_json: &str) -> Result<String, String>;
    /// Fetch the manifest JSON for a vault.
    fn fetch_manifest(&self, vault_id: &str) -> Result<String, String>;
}
