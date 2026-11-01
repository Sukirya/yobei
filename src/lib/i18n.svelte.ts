/**
 * Internationalization (ADR-0008).
 *
 * All user-facing text lives here. The core returns stable codes and
 * structured values; this module turns them into localized sentences.
 * The English dictionary is the source of truth for keys: every other
 * locale is typed as Record<MessageKey, string>, so a missing key fails
 * type checking.
 */

export const SUPPORTED_LOCALES = ["en", "zh-CN"] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];

const en = {
  "app.title": "Yobei",
  "app.subtitle": "placeholder UI · for feature verification",
  "app.loading": "Loading…",
  "app.language": "Language",

  "vault.created.title": "Vault created",
  "vault.created.body":
    "This is your Secret Key. It is shown only once. Save it together with your master password and the sync address below — a new device needs all of them (plus your sync server URL) to unlock:",
  "vault.created.saved": "I saved it",
  "vault.created.addressLabel": "Sync address",
  "vault.create.title": "Create vault",
  "vault.create.password": "Master password",
  "vault.create.confirm": "Confirm master password",
  "vault.create.warning":
    "A Secret Key will be generated. It is required to unlock on any device; losing it means losing the vault.",
  "vault.create.submit": "Create",
  "vault.unlock.title": "Unlock vault",
  "vault.unlock.password": "Master password",
  "vault.unlock.secretKey": "Secret Key",
  "vault.unlock.submit": "Unlock",
  "vault.unlock.needSecretKeyOnce":
    "Enter the Secret Key once to enable password-only unlock.",
  "vault.info": "Vault {id}…",
  "vault.changePassword": "Change master password",
  "vault.lock": "Lock",

  "biometric.unlock.button": "Unlock with biometrics",
  "biometric.unlock.title": "Unlock Yobei",
  "biometric.unlock.subtitle": "Use your fingerprint, face, or lock screen credential",
  "biometric.enroll.title": "Enable biometric unlock",
  "biometric.enroll.subtitle": "Verify once; afterwards you can unlock with biometrics",
  "biometric.enable": "Enable biometrics",
  "biometric.disable": "Disable biometrics",
  "biometric.invalidated":
    "Biometric unlock stopped working (for example, a new fingerprint was added). Unlock with your master password and Secret Key, then enable it again.",
  "biometric.lockedOut":
    "Too many failed attempts; biometrics are locked for a while. Use your master password and Secret Key.",

  "join.title": "Join an existing vault",
  "join.hint": "Use the sync address and Secret Key from your recovery kit.",
  "join.serverUrl": "Sync server URL",
  "join.address": "Sync address",
  "join.password": "Master password",
  "join.secretKey": "Secret Key",
  "join.submit": "Join",
  "join.switchToJoin": "Join an existing vault instead",
  "join.switchToCreate": "Create a new vault instead",

  "changePassword.current": "Current password",
  "changePassword.new": "New password",
  "changePassword.secretKey": "Secret Key",
  "changePassword.confirm": "Confirm",
  "changePassword.done": "Master password changed",

  "search.placeholder": "Search title, username, tags…",
  "search.trash": "Trash",
  "newEntry.title": "New entry title",
  "newEntry.submit": "Create",

  "kind.account": "Account",
  "kind.card": "Card",
  "kind.identity": "Identity",
  "kind.note": "Note",

  "list.favorite": "Favorite",
  "list.unfavorite": "Unfavorite",
  "list.delete": "Delete",
  "list.restore": "Restore",
  "list.empty": "(no entries)",
  "list.conflictCopy": "conflict copy",

  "editor.title": "Title",
  "editor.username": "Username",
  "editor.password": "Password",
  "editor.generatePassword": "Generate password",
  "editor.generatePhrase": "Generate phrase",
  "editor.strength": "Strength: {score} · {bits} bits · offline crack ≈ {time}",
  "editor.url": "URL",
  "editor.totpSecret": "TOTP secret",
  "editor.secondsLeft": "{seconds}s left",
  "editor.issuer": "Issuer",
  "editor.otpauthPlaceholder": "Paste an otpauth:// URI",
  "editor.import": "Import",
  "editor.addTotp": "Add TOTP",
  "editor.passkeys": "Passkeys",
  "editor.signCount": "sign count {count}",
  "editor.cardholder": "Cardholder",
  "editor.number": "Number",
  "editor.expMonth": "Exp month",
  "editor.expYear": "Exp year",
  "editor.cvc": "CVC",
  "editor.pin": "PIN",
  "editor.fullName": "Full name",
  "editor.firstName": "First name",
  "editor.lastName": "Last name",
  "editor.email": "Email",
  "editor.phone": "Phone",
  "editor.content": "Content",
  "editor.tags": "Tags (comma separated)",
  "editor.notes": "Notes",
  "editor.save": "Save",
  "editor.close": "Close",

  "score.0": "very weak",
  "score.1": "weak",
  "score.2": "fair",
  "score.3": "strong",
  "score.4": "excellent",

  "warning.empty": "password is empty",
  "warning.commonPassword": "this is one of the most common passwords",
  "warning.commonWord": "contains the common word \"{word}\"",
  "warning.sequence": "contains a sequence (e.g. abcd / 1234)",
  "warning.repeatedCharacters": "contains repeated characters (e.g. aaa)",
  "warning.year": "contains a year",

  "crack.instant": "instantly",
  "crack.seconds": "{value} s",
  "crack.minutes": "{value} min",
  "crack.hours": "{value} h",
  "crack.days": "{value} days",
  "crack.years": "{value} years",
  "crack.millionYears": "{value} million years",
  "crack.universe": "longer than the age of the universe",

  "import.title": "Import",
  "import.formatCsv": "CSV (Bitwarden / Chrome / generic)",
  "import.formatBitwardenJson": "Bitwarden JSON",
  "import.formatKeepass": "KeePass XML",
  "import.formatYobeiJson": "Yobei JSON",
  "import.formatYobeiEncrypted": "Yobei encrypted export",
  "import.exportPassword": "Export password",
  "import.paste":
    "Paste the file contents here (the placeholder UI has no file picker yet)",
  "import.preview": "Preview",
  "import.submit": "Import",
  "import.commit": "Commit import of {count}",
  "import.done": "Imported {count} entries",
  "import.previewLine": "({kind} · {flags}urls {urls} · fields {fields})",
  "import.flagUsername": "username",
  "import.flagPassword": "password",
  "import.flagTotp": "TOTP",

  "export.title": "Export",
  "export.csv": "Export CSV",
  "export.json": "Export JSON",
  "export.encrypted": "Encrypted export (recommended)",
  "export.password": "Encrypted export password",
  "export.plaintextWarning":
    "CSV / JSON exports are plaintext. Use them only for migration, and delete them afterwards.",

  "sync.title": "Sync",
  "sync.server": "Server: {url}",
  "sync.device": "Device: {id}… · pending ops: {pending}",
  "sync.now": "Sync now",
  "sync.refresh": "Refresh status",
  "sync.urlPlaceholder":
    "Sync server URL (e.g. https://yobei-sync.example.workers.dev)",
  "sync.register": "Register this device",
  "sync.deployWarning":
    "Deploy the worker yourself (workers/sync); it only stores ciphertext.",
  "sync.registered": "Device registered; sync is configured.",
  "sync.devices": "Devices",
  "sync.revoke": "Revoke",
  "sync.revokeConfirm":
    "Revoke \"{name}\"? Sync will stop on that device; its local vault remains.",
  "sync.currentDevice": "this device",
  "sync.lastSeen": "last seen {time}",
  "sync.never": "never",
  "sync.revoked": "Device revoked",
  "sync.done":
    "Sync done: pushed {pushed}, pulled {new} new / {updated} updated, conflicts {conflicts} (copies {copies}), discarded {discarded}",

  "error.passwordMismatch": "The two passwords do not match.",
} as const;

export type MessageKey = keyof typeof en;

const zhCN: Record<MessageKey, string> = {
  "app.title": "Yobei",
  "app.subtitle": "占位界面 · 功能验证用",
  "app.loading": "加载中…",
  "app.language": "语言",

  "vault.created.title": "保险库已创建",
  "vault.created.body":
    "这是你的 Secret Key，只显示这一次。请和主密码、下方的同步地址一起保存——新设备解锁需要它们（以及你的同步服务器地址）：",
  "vault.created.saved": "我已保存",
  "vault.created.addressLabel": "同步地址",
  "vault.create.title": "创建保险库",
  "vault.create.password": "主密码",
  "vault.create.confirm": "确认主密码",
  "vault.create.warning":
    "将生成 Secret Key。任何设备解锁都需要它；丢失即丢失整个保险库。",
  "vault.create.submit": "创建",
  "vault.unlock.title": "解锁保险库",
  "vault.unlock.password": "主密码",
  "vault.unlock.secretKey": "Secret Key",
  "vault.unlock.submit": "解锁",
  "vault.unlock.needSecretKeyOnce": "输入一次 Secret Key，即可启用仅密码解锁。",
  "vault.info": "保险库 {id}…",
  "vault.changePassword": "修改主密码",
  "vault.lock": "锁定",

  "biometric.unlock.button": "使用生物识别解锁",
  "biometric.unlock.title": "解锁 Yobei",
  "biometric.unlock.subtitle": "使用指纹、面容或锁屏凭据解锁",
  "biometric.enroll.title": "启用生物识别解锁",
  "biometric.enroll.subtitle": "验证一次，之后即可用生物识别解锁",
  "biometric.enable": "启用生物识别",
  "biometric.disable": "停用生物识别",
  "biometric.invalidated":
    "生物识别解锁已失效（例如新增了指纹）。请用主密码和 Secret Key 解锁，然后重新启用。",
  "biometric.lockedOut":
    "尝试次数过多，生物识别已暂时锁定。请用主密码和 Secret Key 解锁。",

  "join.title": "加入已有保险库",
  "join.hint": "使用恢复套件里的同步地址和 Secret Key。",
  "join.serverUrl": "同步服务器地址",
  "join.address": "同步地址",
  "join.password": "主密码",
  "join.secretKey": "Secret Key",
  "join.submit": "加入",
  "join.switchToJoin": "改为加入已有保险库",
  "join.switchToCreate": "改为创建新保险库",

  "changePassword.current": "当前密码",
  "changePassword.new": "新密码",
  "changePassword.secretKey": "Secret Key",
  "changePassword.confirm": "确认",
  "changePassword.done": "主密码已修改",

  "search.placeholder": "搜索标题、用户名、标签…",
  "search.trash": "回收站",
  "newEntry.title": "新条目标题",
  "newEntry.submit": "创建",

  "kind.account": "账号",
  "kind.card": "银行卡",
  "kind.identity": "身份",
  "kind.note": "笔记",

  "list.favorite": "收藏",
  "list.unfavorite": "取消收藏",
  "list.delete": "删除",
  "list.restore": "恢复",
  "list.empty": "（暂无条目）",
  "list.conflictCopy": "冲突副本",

  "editor.title": "标题",
  "editor.username": "用户名",
  "editor.password": "密码",
  "editor.generatePassword": "生成密码",
  "editor.generatePhrase": "生成短语",
  "editor.strength": "强度：{score} · {bits} 位 · 离线破解约 {time}",
  "editor.url": "网址",
  "editor.totpSecret": "TOTP 密钥",
  "editor.secondsLeft": "剩余 {seconds} 秒",
  "editor.issuer": "发行方",
  "editor.otpauthPlaceholder": "粘贴 otpauth:// 链接",
  "editor.import": "导入",
  "editor.addTotp": "添加 TOTP",
  "editor.passkeys": "通行密钥",
  "editor.signCount": "签名计数 {count}",
  "editor.cardholder": "持卡人",
  "editor.number": "卡号",
  "editor.expMonth": "月",
  "editor.expYear": "年",
  "editor.cvc": "CVC",
  "editor.pin": "PIN",
  "editor.fullName": "姓名",
  "editor.firstName": "名",
  "editor.lastName": "姓",
  "editor.email": "邮箱",
  "editor.phone": "电话",
  "editor.content": "内容",
  "editor.tags": "标签（逗号分隔）",
  "editor.notes": "备注",
  "editor.save": "保存",
  "editor.close": "关闭",

  "score.0": "很弱",
  "score.1": "弱",
  "score.2": "一般",
  "score.3": "强",
  "score.4": "极强",

  "warning.empty": "密码为空",
  "warning.commonPassword": "这是最常见的密码之一",
  "warning.commonWord": "包含常见词「{word}」",
  "warning.sequence": "包含连续序列（如 abcd / 1234）",
  "warning.repeatedCharacters": "包含重复字符（如 aaa）",
  "warning.year": "包含年份",

  "crack.instant": "瞬间",
  "crack.seconds": "{value} 秒",
  "crack.minutes": "{value} 分钟",
  "crack.hours": "{value} 小时",
  "crack.days": "{value} 天",
  "crack.years": "{value} 年",
  "crack.millionYears": "{value} 百万年",
  "crack.universe": "宇宙年龄级别",

  "import.title": "导入",
  "import.formatCsv": "CSV（Bitwarden / Chrome / 通用）",
  "import.formatBitwardenJson": "Bitwarden JSON",
  "import.formatKeepass": "KeePass XML",
  "import.formatYobeiJson": "Yobei JSON",
  "import.formatYobeiEncrypted": "Yobei 加密导出",
  "import.exportPassword": "导出密码",
  "import.paste": "把文件内容粘贴到这里（占位界面暂无文件选择器）",
  "import.preview": "预览",
  "import.submit": "导入",
  "import.commit": "确认导入 {count} 条",
  "import.done": "已导入 {count} 条",
  "import.previewLine": "（{kind} · {flags}网址 {urls} · 字段 {fields}）",
  "import.flagUsername": "有用户名",
  "import.flagPassword": "有密码",
  "import.flagTotp": "有TOTP",

  "export.title": "导出",
  "export.csv": "导出 CSV",
  "export.json": "导出 JSON",
  "export.encrypted": "加密导出（推荐）",
  "export.password": "加密导出密码",
  "export.plaintextWarning":
    "CSV / JSON 导出是明文，只用于迁移，存好后请删除。",

  "sync.title": "同步",
  "sync.server": "服务器：{url}",
  "sync.device": "设备：{id}… · 待推送操作：{pending}",
  "sync.now": "立即同步",
  "sync.refresh": "刷新状态",
  "sync.urlPlaceholder": "同步服务器地址（如 https://yobei-sync.xxx.workers.dev）",
  "sync.register": "注册本设备",
  "sync.deployWarning": "服务器需自行部署（workers/sync），它只保存密文。",
  "sync.registered": "设备已注册，同步已配置",
  "sync.devices": "设备",
  "sync.revoke": "撤销",
  "sync.revokeConfirm": "撤销「{name}」？该设备将停止同步，本地保险库仍会保留。",
  "sync.currentDevice": "本设备",
  "sync.lastSeen": "最近同步 {time}",
  "sync.never": "从未",
  "sync.revoked": "设备已撤销",
  "sync.done":
    "同步完成：推送 {pushed}，拉取新增 {new}、更新 {updated}，冲突 {conflicts}（副本 {copies}），丢弃 {discarded}",

  "error.passwordMismatch": "两次输入的主密码不一致",
};

const DICTS: Record<Locale, Record<MessageKey, string>> = {
  en,
  "zh-CN": zhCN,
};

function isLocale(value: string | null | undefined): value is Locale {
  return value === "en" || value === "zh-CN";
}

function detectLocale(): Locale {
  try {
    const stored = localStorage.getItem("yobei.locale");
    if (isLocale(stored)) return stored;
  } catch {
    // localStorage may be unavailable (privacy mode); fall through.
  }
  const nav = typeof navigator !== "undefined" ? navigator.language : "en";
  return nav.toLowerCase().startsWith("zh") ? "zh-CN" : "en";
}

let current = $state<Locale>(detectLocale());

if (typeof document !== "undefined") {
  document.documentElement.lang = current;
}

export function getLocale(): Locale {
  return current;
}

export function setLocale(next: Locale): void {
  current = next;
  try {
    localStorage.setItem("yobei.locale", next);
  } catch {
    // Ignore persistence failures; the choice still applies to this session.
  }
  if (typeof document !== "undefined") {
    document.documentElement.lang = next;
  }
}

/** Translate a key and interpolate `{name}` placeholders. */
export function t(
  key: MessageKey,
  vars?: Record<string, string | number>,
): string {
  const template = DICTS[current][key] ?? key;
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, name: string) =>
    String(vars[name] ?? `{${name}}`),
  );
}

/** Locale-aware number formatting for values interpolated into messages. */
export function formatNumber(value: number, maximumFractionDigits = 0): string {
  return new Intl.NumberFormat(current, { maximumFractionDigits }).format(
    value,
  );
}
