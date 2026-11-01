// Yobei popup：三种状态——桌面端未运行 / 保险库已锁定 / 已解锁。
// popup 本身不直接调网络，所有请求都经 background 的 service worker。

const $ = (id) => document.getElementById(id);

function send(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

function showMessage(text, isError = false) {
  const el = $("message");
  el.textContent = text;
  el.classList.toggle("error", isError);
  el.hidden = !text;
}

function showOnly(...ids) {
  for (const id of ["viewUnreachable", "viewLocked", "viewUnlocked"]) {
    $(id).hidden = !ids.includes(id);
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function loadPendingSave() {
  const { ok, pendingSave, error } = await send("getPendingSave");
  if (!ok) {
    showMessage(error, true);
    return;
  }
  const box = $("pendingSave");
  if (!pendingSave) {
    box.hidden = true;
    return;
  }
  $("pendingSaveText").textContent = pendingSave.username
    ? `${new URL(pendingSave.url).hostname} · ${pendingSave.username}`
    : new URL(pendingSave.url).hostname;
  box.hidden = false;
  box.dataset.url = pendingSave.url;
  box.dataset.username = pendingSave.username;
  box.dataset.password = pendingSave.password;
}

async function loadEntries() {
  const tab = await getActiveTab();
  const list = $("entryList");
  list.innerHTML = "";
  $("noEntries").hidden = true;
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    $("noEntries").textContent = "当前标签页不是网页，无法填充。";
    $("noEntries").hidden = false;
    return;
  }
  const { ok, entries, error } = await send("getEntries", { url: tab.url });
  if (!ok) {
    showMessage(error, true);
    return;
  }
  if (entries.length === 0) {
    $("noEntries").textContent = "这个网站没有保存的账号。";
    $("noEntries").hidden = false;
    return;
  }
  for (const entry of entries) {
    const li = document.createElement("li");
    const fillBtn = document.createElement("button");
    fillBtn.type = "button";
    fillBtn.className = "entry";
    fillBtn.textContent = entry.username
      ? `${entry.title} · ${entry.username}`
      : entry.title;
    fillBtn.addEventListener("click", () => fillEntry(entry.id));
    li.append(fillBtn);
    if (entry.has_totp) {
      const totpBtn = document.createElement("button");
      totpBtn.type = "button";
      totpBtn.textContent = "复制验证码";
      totpBtn.addEventListener("click", () => copyTotp(entry.id, totpBtn));
      li.append(totpBtn);
    }
    list.append(li);
  }
}

async function fillEntry(id) {
  const { ok, entry, error } = await send("getCredentials", { id });
  if (!ok) {
    showMessage(error, true);
    return;
  }
  const tab = await getActiveTab();
  if (!tab?.id) {
    showMessage("当前没有可填充的标签页", true);
    return;
  }
  const res = await chrome.tabs.sendMessage(tab.id, {
    type: "fill",
    username: entry.username,
    password: entry.password,
    totp: entry.totpCode,
  });
  if (res?.ok) {
    showMessage("已填充");
    window.close();
  } else {
    showMessage(res?.error ?? "填充失败", true);
  }
}

async function copyTotp(id, button) {
  const { ok, entry, error } = await send("getCredentials", { id });
  if (!ok || !entry.totpCode) {
    showMessage(error ?? "没有可用的验证码", true);
    return;
  }
  await navigator.clipboard.writeText(entry.totpCode);
  const remaining = entry.totpRemainingSecs;
  button.textContent =
    remaining != null ? `已复制（${remaining} 秒内有效）` : "已复制";
  setTimeout(() => (button.textContent = "复制验证码"), 3000);
}

async function refresh() {
  showMessage("");
  $("viewUnreachable").hidden = true;
  $("viewLocked").hidden = true;
  $("viewUnlocked").hidden = true;
  const ping = await send("ping");
  if (!ping.ok) {
    showOnly("viewUnreachable");
    return;
  }
  const status = await send("getStatus");
  if (!status.ok) {
    // ping 通但带认证的接口失败：多半是令牌不对，提示去设置里重配。
    showMessage(status.error, true);
    showOnly("viewUnreachable");
    return;
  }
  if (status.locked) {
    showOnly("viewLocked");
    $("unlockPassword").focus();
    return;
  }
  showOnly("viewUnlocked");
  await loadPendingSave();
  await loadEntries();
}

// --- 事件绑定 ---

$("settingsToggle").addEventListener("click", async () => {
  const section = $("settings");
  section.hidden = !section.hidden;
  if (!section.hidden) {
    const { ok, port, token } = await send("getSettings");
    if (ok) {
      $("portInput").value = port;
      $("tokenInput").value = token;
    }
  }
});

$("saveSettingsBtn").addEventListener("click", async () => {
  const res = await send("saveSettings", {
    port: $("portInput").value,
    token: $("tokenInput").value,
  });
  showMessage(res.ok ? "设置已保存" : (res.error ?? "保存失败"), !res.ok);
  if (res.ok) refresh();
});

$("unlockBtn").addEventListener("click", async () => {
  const password = $("unlockPassword").value;
  if (!password) {
    showMessage("请输入主密码", true);
    return;
  }
  const res = await send("unlock", {
    password,
    secretKey: $("unlockSecretKey").value,
  });
  if (!res.ok) {
    showMessage(res.error, true);
    return;
  }
  $("unlockPassword").value = "";
  $("unlockSecretKey").value = "";
  refresh();
});
$("unlockPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("unlockBtn").click();
});

$("lockBtn").addEventListener("click", async () => {
  const res = await send("lock");
  if (!res.ok) {
    showMessage(res.error, true);
    return;
  }
  refresh();
});

$("generateBtn").addEventListener("click", async () => {
  const res = await send("generatePassword");
  if (!res.ok) {
    showMessage(res.error, true);
    return;
  }
  $("generatedPassword").textContent = res.password;
  $("generated").hidden = false;
  await navigator.clipboard.writeText(res.password);
  showMessage("密码已生成并复制到剪贴板");
});

$("copyGeneratedBtn").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("generatedPassword").textContent);
  showMessage("已复制");
});

$("pendingSaveBtn").addEventListener("click", async () => {
  const box = $("pendingSave");
  const res = await send("saveLogin", {
    url: box.dataset.url,
    username: box.dataset.username,
    password: box.dataset.password,
  });
  if (!res.ok) {
    showMessage(res.error, true);
    return;
  }
  await send("clearPendingSave");
  showMessage(res.updated ? "已更新已保存的密码" : "已保存");
  refresh();
});

$("pendingDiscardBtn").addEventListener("click", async () => {
  await send("clearPendingSave");
  refresh();
});

refresh();
