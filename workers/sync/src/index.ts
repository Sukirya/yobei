/**
 * yobei sync server (Cloudflare Workers) — see docs/DESIGN.md §4.
 *
 * Deliberately "dumb": it stores AEAD ciphertext in D1 next to the sync
 * metadata. It never sees plaintext, never merges, and rejects pushes
 * whose base_version is stale instead of overwriting — the client keeps
 * both versions and the user resolves the conflict.
 *
 * Single store (D1): devices, records manifest, per-record ciphertext
 * (inline BLOB), applied op ids (idempotency). No object storage: R2
 * requires a payment card on file even on the free tier, and a personal
 * vault's ciphertext fits D1's free tier easily.
 */

export interface Env {
  DB: D1Database;
}

interface SyncOp {
  op_id: string;
  vault_id: string;
  record_id: string;
  base_version: number;
  new_version: number;
  hlc: number;
  kind: "upsert" | "delete";
  ciphertext_b64: string;
  nonce_b64: string;
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Device-token auth. The token gates sync access only; leaking it can
 * expose ciphertext, never plaintext (that still needs the vault keys). */
async function authorized(req: Request, env: Env, vaultId: string) {
  const header = req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return false;
  const row = await env.DB.prepare(
    "SELECT device_id FROM devices WHERE vault_id = ? AND token_hash = ?",
  )
    .bind(vaultId, await sha256Hex(token))
    .first();
  return row !== null;
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["v1", ...]

    if (req.method === "GET" && url.pathname === "/v1/health") {
      return json({ ok: true, service: "yobei-sync", version: 1 });
    }

    // POST /v1/devices — register a device for a vault, returns its token.
    // (Enrollment UX / owner approval is a client concern; the token is
    // shown once here and stored only as a hash in D1.)
    if (req.method === "POST" && url.pathname === "/v1/devices") {
      const body = (await req.json().catch(() => null)) as {
        vault_id?: string;
      } | null;
      if (!body?.vault_id) return json({ error: "vault_id required" }, 400);
      const deviceId = crypto.randomUUID();
      const token = crypto.randomUUID() + crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO devices (device_id, vault_id, token_hash, created_at_ms) VALUES (?, ?, ?, ?)",
      )
        .bind(deviceId, body.vault_id, await sha256Hex(token), Date.now())
        .run();
      return json({ device_id: deviceId, token }, 201);
    }

    // Vault-scoped routes: /v1/vaults/:vaultId/...
    if (parts[0] === "v1" && parts[1] === "vaults" && parts[2]) {
      const vaultId = parts[2];
      if (!(await authorized(req, env, vaultId))) {
        return json({ error: "unauthorized" }, 401);
      }

      // GET /v1/vaults/:vaultId/manifest
      if (req.method === "GET" && parts[3] === "manifest") {
        const { results } = await env.DB.prepare(
          "SELECT record_id, version, hlc, updated_at_ms, deleted FROM records WHERE vault_id = ?",
        )
          .bind(vaultId)
          .all();
        return json({ vault_id: vaultId, entries: results });
      }

      // GET /v1/vaults/:vaultId/records/:recordId — download ciphertext.
      // Body is the stored blob verbatim: nonce bytes || ciphertext bytes.
      if (req.method === "GET" && parts[3] === "records" && parts[4]) {
        const row = await env.DB.prepare(
          "SELECT ciphertext FROM records WHERE vault_id = ? AND record_id = ?",
        )
          .bind(vaultId, parts[4])
          .first<{ ciphertext: ArrayBuffer | null }>();
        if (!row?.ciphertext) return json({ error: "not found" }, 404);
        return new Response(row.ciphertext, {
          headers: { "content-type": "application/octet-stream" },
        });
      }

      // POST /v1/vaults/:vaultId/ops — batch push with dedup + versions.
      if (req.method === "POST" && parts[3] === "ops") {
        const body = (await req.json().catch(() => null)) as {
          ops?: SyncOp[];
        } | null;
        if (!body?.ops) return json({ error: "ops required" }, 400);

        const results = [];
        for (const op of body.ops) {
          if (op.vault_id !== vaultId) {
            results.push({ op_id: op.op_id, outcome: "conflict" });
            continue;
          }
          const seen = await env.DB.prepare(
            "SELECT op_id FROM ops WHERE op_id = ?",
          )
            .bind(op.op_id)
            .first();
          if (seen) {
            results.push({ op_id: op.op_id, outcome: "duplicate" });
            continue;
          }
          const current = await env.DB.prepare(
            "SELECT version FROM records WHERE vault_id = ? AND record_id = ?",
          )
            .bind(vaultId, op.record_id)
            .first<{ version: number }>();
          const currentVersion = current?.version ?? 0;
          if (currentVersion !== op.base_version) {
            // No silent overwrite: the client preserves both copies.
            results.push({ op_id: op.op_id, outcome: "conflict" });
            continue;
          }

          // Stored blob = nonce bytes followed by ciphertext bytes,
          // kept inline in the records row (D1). Tombstones store NULL.
          let blob: Uint8Array | null = null;
          if (op.kind === "upsert") {
            const nonce = b64ToBytes(op.nonce_b64);
            const cipher = b64ToBytes(op.ciphertext_b64);
            blob = new Uint8Array(nonce.length + cipher.length);
            blob.set(nonce);
            blob.set(cipher, nonce.length);
          }

          await env.DB.prepare(
            `INSERT INTO records (vault_id, record_id, version, hlc, updated_at_ms, deleted, ciphertext)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(vault_id, record_id) DO UPDATE SET
               version = excluded.version, hlc = excluded.hlc,
               updated_at_ms = excluded.updated_at_ms,
               deleted = excluded.deleted, ciphertext = excluded.ciphertext`,
          )
            .bind(
              vaultId,
              op.record_id,
              op.new_version,
              op.hlc,
              Date.now(),
              op.kind === "delete" ? 1 : 0,
              blob,
            )
            .run();
          await env.DB.prepare(
            "INSERT INTO ops (op_id, vault_id, record_id, applied_at_ms) VALUES (?, ?, ?, ?)",
          )
            .bind(op.op_id, vaultId, op.record_id, Date.now())
            .run();
          results.push({ op_id: op.op_id, outcome: "accepted" });
        }
        return json({ results });
      }
    }

    return json({ error: "not found" }, 404);
  },
};
