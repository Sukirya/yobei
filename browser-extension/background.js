// Yobei 浏览器扩展 service worker：只做桌面端 loopback API 的调用层。
// 凭证（token / 端口）存在 chrome.storage.local；条目与主密码永不落盘。

const DEFAULT_PORT = 19445;
const PENDING_SAVE_KEY = "pendingSave";
// 待保存登录里的明文密码最多留一天（ADR-0011：扩展只存 token）。
const PENDING_SAVE_TTL_MS = 24 * 60 * 60 * 1000;

async function getSettings() {
  const { token = "", port = DEFAULT_PORT } = await chrome.storage.local.get([
    "token",
    "port",
  ]);
  return { token, port: Number(port) || DEFAULT_PORT };
}

// 读待保存登录：超过一天的直接丢掉，不让明文密码在扩展存储里无限期躺着。
async function getPendingSave() {
  const { [PENDING_SAVE_KEY]: pending = null } =
    await chrome.storage.local.get(PENDING_SAVE_KEY);
  if (!pending) return null;
  if (
    typeof pending.savedAt !== "number" ||
    Date.now() - pending.savedAt > PENDING_SAVE_TTL_MS
  ) {
    await chrome.storage.local.remove(PENDING_SAVE_KEY);
    return null;
  }
  return pending;
}

// 待保存登录只是下次打开弹窗时的一次提醒，浏览器重启就不再留着。
chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.remove(PENDING_SAVE_KEY);
});

// 调桌面端 API。path 含前导斜杠。ping 不需要认证，其余接口带 Bearer token。
async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const { token, port } = await getSettings();
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(auth && token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    // 非 JSON 响应按空处理
  }
  if (!res.ok) {
    throw new ApiError(res.status, data?.error || `请求失败（${res.status}）`);
  }
  return data;
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// 把桌面端返回的状态码翻译成中文提示。
function friendlyError(err) {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 401:
        return "令牌无效，请在设置里重新粘贴桌面端的令牌";
      case 403:
        return "请求被桌面端拒绝";
      case 409:
        return "保险库已锁定，请先解锁";
      default:
        return err.message;
    }
  }
  return "桌面端未运行";
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "ping": {
          const data = await api("/v1/ping", { auth: false });
          sendResponse({ ok: data?.ok === true });
          break;
        }
        case "getStatus": {
          const data = await api("/v1/status");
          sendResponse({
            ok: true,
            locked: data.locked,
            vaultExists: data.vault_exists,
          });
          break;
        }
        case "unlock": {
          const body = { password: msg.password };
          if (msg.secretKey) body.secret_key = msg.secretKey;
          const data = await api("/v1/unlock", { method: "POST", body });
          sendResponse({ ok: true, vaultId: data.vault_id });
          break;
        }
        case "lock": {
          await api("/v1/lock", { method: "POST" });
          sendResponse({ ok: true });
          break;
        }
        case "getEntries": {
          const data = await api(
            `/v1/entries?url=${encodeURIComponent(msg.url)}`,
          );
          sendResponse({ ok: true, entries: data.entries ?? [] });
          break;
        }
        case "getCredentials": {
          const data = await api(`/v1/entries/${msg.id}`);
          sendResponse({
            ok: true,
            entry: {
              id: data.id,
              title: data.title,
              username: data.username,
              password: data.password,
              totpCode: data.totp_code ?? null,
              totpRemainingSecs: data.totp_remaining_secs ?? null,
            },
          });
          break;
        }
        case "generatePassword": {
          const data = await api("/v1/generate-password", {
            method: "POST",
            body: {},
          });
          sendResponse({ ok: true, password: data.password });
          break;
        }
        case "saveLogin": {
          const body = {
            url: msg.url,
            username: msg.username,
            password: msg.password,
          };
          if (msg.title) body.title = msg.title;
          const data = await api("/v1/entries", { method: "POST", body });
          sendResponse({
            ok: true,
            id: data.id,
            title: data.title,
            updated: data.updated,
          });
          break;
        }
        case "pendingSave": {
          // content script 上报的待保存登录：持久化，service worker 被杀也不丢。
          await chrome.storage.local.set({
            [PENDING_SAVE_KEY]: {
              url: msg.url,
              username: msg.username,
              password: msg.password,
              savedAt: Date.now(),
            },
          });
          sendResponse({ ok: true });
          break;
        }
        case "getPendingSave": {
          const pendingSave = await getPendingSave();
          sendResponse({ ok: true, pendingSave });
          break;
        }
        case "clearPendingSave": {
          await chrome.storage.local.remove(PENDING_SAVE_KEY);
          sendResponse({ ok: true });
          break;
        }
        case "getSettings": {
          const settings = await getSettings();
          sendResponse({ ok: true, ...settings });
          break;
        }
        case "saveSettings": {
          const port = Number(msg.port);
          await chrome.storage.local.set({
            token: String(msg.token ?? "").trim(),
            port: Number.isFinite(port) && port > 0 ? port : DEFAULT_PORT,
          });
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: "未知的消息类型" });
      }
    } catch (err) {
      sendResponse({ ok: false, error: friendlyError(err) });
    }
  })();
  return true; // 异步回复
});
