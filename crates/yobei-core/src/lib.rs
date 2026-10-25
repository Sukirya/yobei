//! yobei-core — the portable core of the yobei password manager.
//!
//! Hexagonal (ports & adapters) rule: this crate must not depend on Tauri,
//! Android, Windows, Cloudflare, or any other platform/framework types.
//! Platforms are adapters around the ports defined in [`ports`].
//!
//! Modules:
//! - [`record`]: the unified record model. One account record holds its
//!   password + TOTP + passkeys + recovery codes together.
//! - [`crypto`]: algorithm identifiers and KDF parameters (no home-grown
//!   cryptography; implementations wrap audited libraries).
//! - [`ports`]: traits the core needs from the outside world.
//! - [`sync`]: sync protocol types shared with the Cloudflare Workers
//!   sync server (idempotent ops, version checks, conflict copies).

pub mod crypto;
pub mod keys;
pub mod ports;
pub mod record;
pub mod sync;
pub mod vault;
