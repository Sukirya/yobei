-- yobei sync server, D1 schema (see docs/DESIGN.md §4)
-- Single store: this database holds BOTH the sync metadata and the
-- ciphertext itself. No plaintext, no passwords, no keys ever reach it.
--
-- Why no object storage (R2)? Enabling R2 requires a payment card on
-- file even on the free tier, which breaks yobei's "deploy it yourself,
-- free, no card" promise. D1's free tier (5 GB, no card) fits personal
-- vaults easily: a vault is thousands of records, and one encrypted
-- record is typically a few KB at most — far under D1's ~1 MB row
-- limit. If large attachments are ever added, they will be chunked
-- across rows (record_chunks) rather than moving to object storage.

CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  vault_id    TEXT NOT NULL,
  -- Only a hash of the device token is stored. The token authenticates
  -- sync access; it can never decrypt anything.
  token_hash  TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
  vault_id      TEXT NOT NULL,
  record_id     TEXT NOT NULL,
  version       INTEGER NOT NULL,
  hlc           INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  deleted       INTEGER NOT NULL DEFAULT 0,
  -- AEAD ciphertext of the current record version, stored inline:
  -- nonce bytes followed by ciphertext bytes. NULL for tombstones.
  ciphertext    BLOB,
  PRIMARY KEY (vault_id, record_id)
);

-- Applied operation ids, for idempotent pushes (retries are no-ops).
CREATE TABLE IF NOT EXISTS ops (
  op_id        TEXT PRIMARY KEY,
  vault_id     TEXT NOT NULL,
  record_id    TEXT NOT NULL,
  applied_at_ms INTEGER NOT NULL
);
