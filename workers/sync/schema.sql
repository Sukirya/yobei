-- yobei sync server, D1 schema (see docs/adr/0002 and docs/adr/0003)
-- Single store: this database holds BOTH the sync metadata and the
-- ciphertext itself. No plaintext, no passwords, no keys ever reach it.
--
-- Why no object storage (R2)? Enabling R2 requires a payment card on
-- file even on the free tier, which breaks yobei's "deploy it yourself,
-- free, no card" promise. D1's free tier (5 GB, no card) fits personal
-- vaults easily: a vault is thousands of entries, and one encrypted
-- entry is typically a few KB at most — far under D1's ~1 MB row limit.

-- One row per vault, keyed by the sync address derived from the Secret
-- Key. `auth_hash` is SHA-256(auth key); the auth key itself never leaves
-- the client. `bootstrap` is the bootstrap package sealed under a key
-- derived from the Secret Key, so the server cannot read or verify it.
CREATE TABLE IF NOT EXISTS vaults (
  vault_id      TEXT PRIMARY KEY,
  auth_hash     TEXT NOT NULL,
  bootstrap     BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

-- Revocable device tokens. Only a hash is stored; a token can never
-- decrypt anything.
CREATE TABLE IF NOT EXISTS devices (
  device_id     TEXT PRIMARY KEY,
  vault_id      TEXT NOT NULL,
  name          TEXT NOT NULL DEFAULT '',
  token_hash    TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  last_seen_ms  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_devices_vault ON devices(vault_id);

-- One current version per entry. `ciphertext` is nonce ‖ ciphertext and is
-- NULLed after the 30-day trash window while the tombstone metadata stays,
-- so late offline writes cannot revive a deleted entry.
CREATE TABLE IF NOT EXISTS entries (
  vault_id      TEXT NOT NULL,
  entry_id      TEXT NOT NULL,
  version       INTEGER NOT NULL,
  hlc           INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  deleted       INTEGER NOT NULL DEFAULT 0,
  deleted_at_ms INTEGER,
  ciphertext    BLOB,
  PRIMARY KEY (vault_id, entry_id)
);

-- Applied operation ids, for idempotent pushes (retries are no-ops).
CREATE TABLE IF NOT EXISTS ops (
  op_id         TEXT PRIMARY KEY,
  vault_id      TEXT NOT NULL,
  entry_id      TEXT NOT NULL,
  applied_at_ms INTEGER NOT NULL
);
