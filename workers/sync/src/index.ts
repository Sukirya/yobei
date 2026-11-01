/**
 * yobei sync server (Cloudflare Workers) — see docs/adr/0002 and
 * docs/adr/0003.
 *
 * Deliberately "dumb": it stores AEAD ciphertext in D1 next to the sync
 * metadata. It never sees plaintext, never merges, and rejects pushes whose
 * base_version is stale instead of overwriting — the client keeps both
 * versions and the user resolves the conflict.
 *
 * The vault is keyed by its sync address (derived from the Secret Key), not
 * by a local UUID. Enrollment is proved by the auth key (derived from the
 * vault key); the server stores only its hash, so a database leak cannot be
 * used to forge writes or to guess the master password.
 */

export interface Env {
  DB: D1Database;
}

interface SyncOp {
  op_id: string;
  vault_id: string;
  entry_id: string;
  base_version: number;
  new_version: number;
  hlc: number;
  deleted: boolean;
  deleted_at_ms?: number | null;
  ciphertext_b64: string;
}

const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_OPS = 100;
const MAX_OP_BYTES = 256 * 1024;
const MAX_BOOTSTRAP_BYTES = 8 * 1024;
const MAX_BOOTSTRAP_B64 = 12 * 1024;

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });

// ------------------------------------------------------------ encoding ---

function bytesToB64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256B64(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return bytesToB64(new Uint8Array(digest));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function bearer(req: Request): string {
  const header = req.headers.get("authorization") ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

async function readJson(req: Request, maxBytes: number): Promise<any | null> {
  const text = await req.text();
  if (text.length > maxBytes) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isUint(value: unknown): value is number {
  return (
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0
  );
}

// ---------------------------------------------------------------- auth ---

/** The auth key proves knowledge of the vault key (ADR-0002).
 *
 * The Bearer value is the base64 encoding of the 32-byte auth key; the
 * server hashes the decoded bytes, so it can compare against the
 * `auth_hash_b64` the client computed (`base64(SHA-256(auth key bytes))`).
 */
async function ownerAuth(req: Request, env: Env, vaultId: string) {
  const token = bearer(req);
  if (!token) return false;
  let raw: Uint8Array;
  try {
    raw = b64ToBytes(token);
  } catch {
    return false;
  }
  const digest = await crypto.subtle.digest("SHA-256", raw);
  const hash = bytesToB64(new Uint8Array(digest));
  const row = await env.DB.prepare(
    "SELECT auth_hash FROM vaults WHERE vault_id = ?",
  )
    .bind(vaultId)
    .first<{ auth_hash: string }>();
  if (!row) return false;
  return timingSafeEqual(row.auth_hash, hash);
}

/** Device tokens are revocable and never decrypt anything. */
async function deviceAuth(req: Request, env: Env, vaultId: string) {
  const token = bearer(req);
  if (!token) return false;
  const hash = await sha256B64(token);
  const row = await env.DB.prepare(
    "SELECT device_id FROM devices WHERE vault_id = ? AND token_hash = ?",
  )
    .bind(vaultId, hash)
    .first();
  if (!row) return false;
  await env.DB.prepare(
    "UPDATE devices SET last_seen_ms = ? WHERE vault_id = ? AND token_hash = ?",
  )
    .bind(Date.now(), vaultId, hash)
    .run();
  return true;
}

// ------------------------------------------------------------- parsing ---

const OP_KEYS = new Set([
  "op_id",
  "vault_id",
  "entry_id",
  "base_version",
  "new_version",
  "hlc",
  "deleted",
  "deleted_at_ms",
  "ciphertext_b64",
]);

function parseOp(raw: unknown, vaultId: string): SyncOp | string {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return "invalid op";
  }
  for (const key of Object.keys(raw)) {
    if (!OP_KEYS.has(key)) return `unknown field: ${key}`;
  }
  const op = raw as Partial<SyncOp>;
  if (typeof op.op_id !== "string" || !op.op_id || op.op_id.length > 80) {
    return "invalid op_id";
  }
  if (op.vault_id !== vaultId) return "vault id mismatch";
  if (
    typeof op.entry_id !== "string" ||
    !op.entry_id ||
    op.entry_id.length > 80
  ) {
    return "invalid entry_id";
  }
  if (
    !isUint(op.base_version) ||
    !isUint(op.new_version) ||
    !isUint(op.hlc)
  ) {
    return "invalid version";
  }
  if (typeof op.deleted !== "boolean") return "invalid deleted";
  if (
    op.deleted_at_ms !== null &&
    op.deleted_at_ms !== undefined &&
    !isUint(op.deleted_at_ms)
  ) {
    return "invalid deleted_at_ms";
  }
  if (typeof op.ciphertext_b64 !== "string") return "invalid ciphertext";
  let size = 0;
  try {
    size = b64ToBytes(op.ciphertext_b64).length;
  } catch {
    return "invalid base64";
  }
  if (size === 0 || size > MAX_OP_BYTES) return "ciphertext size";
  return op as SyncOp;
}

const BOOTSTRAP_KEYS = new Set(["bootstrap_b64", "auth_hash_b64"]);

function parseBootstrap(
  body: any,
): { package: Uint8Array; authHash: string } | string {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "invalid body";
  }
  for (const key of Object.keys(body)) {
    if (!BOOTSTRAP_KEYS.has(key)) return `unknown field: ${key}`;
  }
  if (
    typeof body.bootstrap_b64 !== "string" ||
    typeof body.auth_hash_b64 !== "string"
  ) {
    return "missing fields";
  }
  if (body.bootstrap_b64.length > MAX_BOOTSTRAP_B64) {
    return "bootstrap too large";
  }
  let pkg: Uint8Array;
  try {
    pkg = b64ToBytes(body.bootstrap_b64);
  } catch {
    return "invalid bootstrap encoding";
  }
  if (pkg.length === 0 || pkg.length > MAX_BOOTSTRAP_BYTES) {
    return "bootstrap size";
  }
  let hash: Uint8Array;
  try {
    hash = b64ToBytes(body.auth_hash_b64);
  } catch {
    return "invalid auth hash encoding";
  }
  if (hash.length !== 32) return "invalid auth hash";
  return { package: pkg, authHash: body.auth_hash_b64 };
}

// -------------------------------------------------------------- routes ---

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handle(req, env);
    } catch (error) {
      return json({ error: String(error) }, 500);
    }
  },
};

async function handle(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (req.method === "GET" && url.pathname === "/v1/health") {
    return json({ ok: true, service: "yobei-sync", version: 2 });
  }

  if (parts[0] !== "v1" || parts[1] !== "vaults" || !parts[2]) {
    return json({ error: "not found" }, 404);
  }
  const vaultId = decodeURIComponent(parts[2]);

  // --- bootstrap package: encrypted with the Secret Key (ADR-0002) ---
  if (parts[3] === "bootstrap") {
    if (req.method === "GET") {
      const row = await env.DB.prepare(
        "SELECT bootstrap FROM vaults WHERE vault_id = ?",
      )
        .bind(vaultId)
        .first<{ bootstrap: ArrayBuffer }>();
      if (!row || !row.bootstrap) return json({ error: "not found" }, 404);
      return json({
        bootstrap_b64: bytesToB64(new Uint8Array(row.bootstrap)),
      });
    }
    if (req.method === "PUT") {
      const body = await readJson(req, MAX_BODY_BYTES);
      const parsed = parseBootstrap(body);
      if (typeof parsed === "string") return json({ error: parsed }, 400);

      const existing = await env.DB.prepare(
        "SELECT auth_hash FROM vaults WHERE vault_id = ?",
      )
        .bind(vaultId)
        .first<{ auth_hash: string }>();
      if (!existing) {
        // TOFU: the first upload binds the address to this auth key. The
        // address is derived from the Secret Key, so guessing it is infeasible.
        await env.DB.prepare(
          "INSERT INTO vaults (vault_id, auth_hash, bootstrap, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?)",
        )
          .bind(vaultId, parsed.authHash, parsed.package, Date.now(), Date.now())
          .run();
        return json({ ok: true, created: true }, 201);
      }
      if (!(await ownerAuth(req, env, vaultId))) {
        return json({ error: "unauthorized" }, 401);
      }
      if (!timingSafeEqual(existing.auth_hash, parsed.authHash)) {
        return json({ error: "auth hash mismatch" }, 403);
      }
      await env.DB.prepare(
        "UPDATE vaults SET bootstrap = ?, updated_at_ms = ? WHERE vault_id = ?",
      )
        .bind(parsed.package, Date.now(), vaultId)
        .run();
      return json({ ok: true });
    }
    return json({ error: "not found" }, 404);
  }

  // --- device enrollment (owner auth only) ---
  if (req.method === "POST" && parts[3] === "devices") {
    if (!(await ownerAuth(req, env, vaultId))) {
      return json({ error: "unauthorized" }, 401);
    }
    const body = (await readJson(req, 4096)) ?? {};
    if (body && typeof body !== "object") {
      return json({ error: "invalid body" }, 400);
    }
    const name =
      typeof body.name === "string" ? body.name.slice(0, 64) : "device";
    const deviceId = crypto.randomUUID();
    const token = crypto.randomUUID() + crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO devices (device_id, vault_id, name, token_hash, created_at_ms) VALUES (?, ?, ?, ?, ?)",
    )
      .bind(deviceId, vaultId, name, await sha256B64(token), Date.now())
      .run();
    return json({ device_id: deviceId, token }, 201);
  }

  // --- device list / revocation (owner auth only) ---
  if (req.method === "GET" && parts[3] === "devices") {
    if (!(await ownerAuth(req, env, vaultId))) {
      return json({ error: "unauthorized" }, 401);
    }
    const { results } = await env.DB.prepare(
      "SELECT device_id, name, created_at_ms, last_seen_ms FROM devices WHERE vault_id = ? ORDER BY created_at_ms",
    )
      .bind(vaultId)
      .all();
    return json({ vault_id: vaultId, devices: results });
  }

  if (req.method === "DELETE" && parts[3] === "devices" && parts[4]) {
    if (!(await ownerAuth(req, env, vaultId))) {
      return json({ error: "unauthorized" }, 401);
    }
    const deviceId = decodeURIComponent(parts[4]);
    const result = await env.DB.prepare(
      "DELETE FROM devices WHERE vault_id = ? AND device_id = ?",
    )
      .bind(vaultId, deviceId)
      .run();
    if ((result.meta?.changes ?? 0) === 0) {
      return json({ error: "not found" }, 404);
    }
    return json({ ok: true });
  }

  // --- everything below needs a device token ---
  if (!(await deviceAuth(req, env, vaultId))) {
    return json({ error: "unauthorized" }, 401);
  }

  if (req.method === "GET" && parts[3] === "manifest") {
    // Tombstone content is kept for 30 days so any device can restore it;
    // afterwards only the metadata survives, preventing revival.
    const cutoff = Date.now() - TRASH_RETENTION_MS;
    await env.DB.prepare(
      "UPDATE entries SET ciphertext = NULL WHERE vault_id = ? AND deleted = 1 AND deleted_at_ms IS NOT NULL AND deleted_at_ms < ?",
    )
      .bind(vaultId, cutoff)
      .run();
    const { results } = await env.DB.prepare(
      "SELECT entry_id, version, hlc, updated_at_ms, deleted, deleted_at_ms FROM entries WHERE vault_id = ?",
    )
      .bind(vaultId)
      .all();
    return json({ vault_id: vaultId, entries: results });
  }

  if (req.method === "GET" && parts[3] === "entries" && parts[4]) {
    const entryId = decodeURIComponent(parts[4]);
    const row = await env.DB.prepare(
      "SELECT ciphertext FROM entries WHERE vault_id = ? AND entry_id = ?",
    )
      .bind(vaultId, entryId)
      .first<{ ciphertext: ArrayBuffer | null }>();
    const ciphertext = row?.ciphertext;
    if (!ciphertext) return json({ error: "not found" }, 404);
    return new Response(ciphertext, {
      headers: { "content-type": "application/octet-stream" },
    });
  }

  if (req.method === "POST" && parts[3] === "ops") {
    return handleOps(req, env, vaultId);
  }

  return json({ error: "not found" }, 404);
}

async function handleOps(
  req: Request,
  env: Env,
  vaultId: string,
): Promise<Response> {
  const body = await readJson(req, MAX_BODY_BYTES);
  if (!body || !Array.isArray(body.ops)) {
    return json({ error: "ops required" }, 400);
  }
  if (body.ops.length > MAX_OPS) {
    return json({ error: "too many ops" }, 400);
  }

  const results: Array<Record<string, unknown>> = [];
  const now = Date.now();

  for (const raw of body.ops) {
    const parsed = parseOp(raw, vaultId);
    if (typeof parsed === "string") {
      const opId =
        raw && typeof raw === "object" && typeof raw.op_id === "string"
          ? raw.op_id
          : "";
      results.push({ op_id: opId, outcome: "conflict", error: parsed });
      continue;
    }
    const op = parsed;

    const seen = await env.DB.prepare("SELECT op_id FROM ops WHERE op_id = ?")
      .bind(op.op_id)
      .first();
    if (seen) {
      results.push({ op_id: op.op_id, outcome: "duplicate" });
      continue;
    }

    const current = await env.DB.prepare(
      "SELECT version FROM entries WHERE vault_id = ? AND entry_id = ?",
    )
      .bind(vaultId, op.entry_id)
      .first<{ version: number }>();
    const currentVersion = current?.version ?? 0;
    if (
      currentVersion !== op.base_version ||
      op.new_version !== op.base_version + 1
    ) {
      // No silent overwrite: the client preserves both copies.
      results.push({ op_id: op.op_id, outcome: "conflict" });
      continue;
    }

    const cipher = b64ToBytes(op.ciphertext_b64);
    const deleted = op.deleted ? 1 : 0;
    const deletedAt = op.deleted_at_ms ?? null;

    // The entry write and the op-id insert run in one D1 batch (a
    // transaction). The op row is only inserted if the entry actually
    // reached this op's new version, so a crash cannot record an op that
    // was never applied.
    const entryStatement =
      currentVersion === 0
        ? env.DB.prepare(
            `INSERT INTO entries (vault_id, entry_id, version, hlc, updated_at_ms, deleted, deleted_at_ms, ciphertext)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?
             WHERE NOT EXISTS (SELECT 1 FROM entries WHERE vault_id = ? AND entry_id = ?)`,
          ).bind(
            vaultId,
            op.entry_id,
            op.new_version,
            op.hlc,
            now,
            deleted,
            deletedAt,
            cipher,
            vaultId,
            op.entry_id,
          )
        : env.DB.prepare(
            `UPDATE entries
                SET version = ?, hlc = ?, updated_at_ms = ?, deleted = ?, deleted_at_ms = ?, ciphertext = ?
              WHERE vault_id = ? AND entry_id = ? AND version = ?`,
          ).bind(
            op.new_version,
            op.hlc,
            now,
            deleted,
            deletedAt,
            cipher,
            vaultId,
            op.entry_id,
            op.base_version,
          );

    const opStatement = env.DB.prepare(
      `INSERT OR IGNORE INTO ops (op_id, vault_id, entry_id, applied_at_ms)
       SELECT ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM entries WHERE vault_id = ? AND entry_id = ? AND version = ?)`,
    ).bind(
      op.op_id,
      vaultId,
      op.entry_id,
      now,
      vaultId,
      op.entry_id,
      op.new_version,
    );

    const outcomes = await env.DB.batch([entryStatement, opStatement]);
    const changes = outcomes[0]?.meta?.changes ?? 0;

    if (changes === 0) {
      // A concurrent request may have applied the same op; distinguish.
      const again = await env.DB.prepare(
        "SELECT op_id FROM ops WHERE op_id = ?",
      )
        .bind(op.op_id)
        .first();
      results.push({
        op_id: op.op_id,
        outcome: again ? "duplicate" : "conflict",
      });
      continue;
    }

    results.push({ op_id: op.op_id, outcome: "accepted" });
  }

  return json({ results });
}
