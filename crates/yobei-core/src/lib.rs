//! yobei-core — the portable core of the yobei password manager.
//!
//! Hexagonal (ports & adapters) rule: this crate must not depend on Tauri,
//! Android, Windows, Cloudflare, or any other platform/framework types.
//! Platforms are adapters around the ports defined in [`ports`].
//!
//! Modules:
//! - [`bootstrap`]: Secret-Key-derived sync address, bootstrap package and
//!   sync auth key (ADR-0001, ADR-0002).
//! - [`entry`]: the unified entry model (four kinds only, see ADR-0004).
//! - [`crypto`]: algorithm identifiers and KDF parameters (no home-grown
//!   cryptography; implementations wrap audited libraries).
//! - [`ports`]: traits the core needs from the outside world.
//! - [`sync`]: sync protocol types shared with the Cloudflare Workers
//!   sync server (idempotent ops, version checks, conflict copies).

pub mod bootstrap;
pub mod crypto;
pub mod entry;
pub mod keepass;
pub mod keys;
pub mod passwords;
pub mod ports;
pub mod secretkey;
pub mod service;
pub mod sync;
pub mod syncengine;
pub mod totp;
pub mod transfer;
pub mod vault;
pub mod webauthn;
