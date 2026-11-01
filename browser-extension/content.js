// Yobei content script：只在有密码框的页面工作。
// 凭证只发往扩展后台（进而只到桌面端 loopback API），不记日志，不上报页面内容。

// manifest 只匹配 http/https，这里再守一道。
if (location.protocol === "http:" || location.protocol === "https:") {
  init();
}

function isVisible(el) {
  if (!el || el.disabled || el.type === "hidden") return false;
  const rect = el.getBoundingClientRect();
  const style = getComputedStyle(el);
  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.visibility !== "hidden" &&
    style.display !== "none"
  );
}

// 页面上第一个可见的密码框。
function findPasswordField() {
  return [...document.querySelectorAll('input[type="password"]')].find(
    isVisible,
  );
}

// 同一表单内的用户名框：优先 autocomplete="username"，
// 否则取密码框之前最后一个可见的文本/邮箱输入框。
function findUsernameField(passwordField) {
  const form = passwordField.form ?? document;
  const candidates = [
    ...form.querySelectorAll(
      'input[autocomplete="username"], input[type="text"], input[type="email"]',
    ),
  ].filter(isVisible);
  const withAutocomplete = candidates.find(
    (el) => el.getAttribute("autocomplete") === "username",
  );
  if (withAutocomplete) return withAutocomplete;
  const before = candidates.filter(
    (el) =>
      el !== passwordField &&
      el.compareDocumentPosition(passwordField) &
        Node.DOCUMENT_POSITION_FOLLOWING,
  );
  return before.at(-1) ?? null;
}

// 用原生 setter 赋值并派发事件，让 React/Vue 之类框架能感知到变化。
function setFieldValue(field, value) {
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  ).set;
  setter.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type !== "fill") return;
  const passwordField = findPasswordField();
  if (!passwordField) {
    sendResponse({ ok: false, error: "当前页面没有找到密码框" });
    return;
  }
  const usernameField = findUsernameField(passwordField);
  if (usernameField && msg.username != null) {
    setFieldValue(usernameField, msg.username);
  }
  if (msg.password != null) setFieldValue(passwordField, msg.password);
  if (msg.totp) {
    const totpField = document.querySelector(
      'input[autocomplete="one-time-code"]',
    );
    if (totpField && isVisible(totpField)) {
      setFieldValue(totpField, msg.totp);
    }
  }
  sendResponse({ ok: true });
});

// 表单提交（捕获阶段，抢在页面跳转前）：密码框非空就上报待保存登录。
document.addEventListener(
  "submit",
  (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const passwordField = [...form.querySelectorAll('input[type="password"]')].find(
      isVisible,
    );
    if (!passwordField || !passwordField.value) return;
    const usernameField = findUsernameField(passwordField);
    chrome.runtime.sendMessage({
      type: "pendingSave",
      url: location.href,
      username: usernameField?.value ?? "",
      password: passwordField.value,
    });
  },
  true,
);
