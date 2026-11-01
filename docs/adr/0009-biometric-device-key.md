# ADR-0009：生物识别解锁的设备密钥实现

- **状态**：已采纳
- **日期**：2026-11-01
- **决策者**：Sukirya
- **依赖**：ADR-0001（密钥层级）、ADR-0006（平台解锁能力阶梯）

## 背景 / 上下文

ADR-0006 定了阶梯（日常解锁靠设备认证，Secret Key 只用于新设备和回退），
但没定实现。当前版本解锁每次都要主密码 + Secret Key（`Vault::open`
强制要求 Secret Key），且应用里一行生物识别代码都没有——阶梯只停留在纸上。

要实现日常解锁，需要回答：本地存什么、存在哪、谁能动用、失效了怎么办。

## 决策

### 1. 存什么：只存 Vault Key，不存主密码和 Secret Key

- 启用生物识别时，把当前内存里的 **Vault Key（32 字节随机密钥）**
  用设备密钥加密后存为 blob，放在应用私有目录（`biometric_vault_key.bin`）。
- Vault Key 之下的密钥层级不变（条目密钥仍由 Vault Key 派生，见 ADR-0001）。
- **改主密码不使 blob 失效**：改主密码只是把同一个 Vault Key
  重新包在新 KEK 之下（`Vault::change_password`），Vault Key 本身不变。
- 主密码和 Secret Key 永远不落盘、不进 blob。

### 2. 设备密钥：Android Keystore 的 AES/GCM 密钥，认证绑定

- 密钥参数：`AES/GCM/NoPadding`，256 位，`setUserAuthenticationRequired(true)`，
  `setInvalidatedByBiometricEnrollment(true)`。
- 每次使用都必须经过一次系统认证，且认证必须通过
  `BiometricPrompt.CryptoObject` 绑定到本次密钥操作——
  只弹认证框、不绑 CryptoObject 的提示不能动用密钥。
- blob 格式：12 字节 GCM IV + 密文（含认证标签），无自定义密码学。
- Keystore 密钥不参与推导（ADR-0006 的区分）：它只是
  “允许这台设备动用本地保存的钥匙”的手续。

### 3. 认证方式：强生物识别或设备凭据

- `BiometricPrompt` 允许 `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`
  （Android 11 以下用旧的 `setDeviceCredentialAllowed(true)`）。
- 系统自己按设备能力选：有强生物识别就用它，否则退到锁屏 PIN/密码。
  这就是 ADR-0006 阶梯的前三档；没有屏幕锁的设备
  `BiometricManager` 直接报无可用方式，功能不出现。

### 4. 失效与回退（ADR-0006 §3）

- 新增/删除指纹、恢复出厂设置、Keystore 失效 → 解密时抛
  `KeyPermanentlyInvalidatedException`：删 blob 和 Keystore 密钥，
  界面回到主密码 + Secret Key，并提示重新启用。不视为数据丢失。
- blob 被删、被改、解密失败 → 同样回退到主密码 + Secret Key。
- blob 只属于这台设备：不参与同步、不进备份（`allowBackup=false`），
  新设备没有 blob，必须用恢复套件加入（ADR-0002）。

### 5. 钥匙不进 WebView

- Vault Key 从 Kotlin 回到 Rust 只走插件通道（`run_mobile_plugin_async`），
  再由 core 的 `Vault::open_with_key` 直接开库。
- 前端（Svelte）只发“开始认证/启用/停用”的指令，永远看不到密钥。

### 6. 实现位置：仓库内最小插件，不引入第三方生物识别插件

- 新建 `crates/tauri-plugin-yobei-biometric`，照抄
  `tauri-plugin-opener` 的布局（Rust 侧 `PluginHandle` +
  `register_android_plugin`，Kotlin 侧 `@TauriPlugin` + `@Command`）。
- 只支持 Android；其它平台命令直接返回“不支持”，前端据此隐藏入口。
- ADR-0006 §4 的短会话与管理操作分离（填充会话 5 分钟、管理操作要主密码）
  **本次不做**：当前应用只有“锁定/解锁”二态，引入会话模型是另一项改动，
  留待后续 ADR。

## 考虑过的其它选项

| 选项 | 否决原因 |
|---|---|
| A. 官方 `tauri-plugin-biometric` | 只有 `authenticate()` 弹框，没有 CryptoObject 绑定和安全存储；认证结果与密钥动用脱节，不符合 §2 的绑定要求。 |
| B. 社区 `tauri-plugin-biometry`（带 `setData/getData`） | 0.3.0-rc.1，单一维护者，未审计；密码管理器的密钥存储不能交给未经审计的第三方实现（AGENTS.md：只用经过审计的库）。 |
| C. blob 里存主密码 + Secret Key | 核心层就不用改，但等于把恢复套件明文（加密后）放在设备上；Vault Key 已足够开库，没必要多存。 |
| D. blob 里存 KEK | KEK 随主密码改变而改变，改一次密码就要重新登记一次；Vault Key 稳定，见 §1。 |

## 取舍与后果

**得到：**

- 日常解锁一次指纹/面容，不再每天输 Secret Key；Secret Key
  回到它本来的位置：新设备和救急。
- 密钥层级不改：Vault Key 仍是唯一数据密钥，改密码、同步、恢复套件
  的行为都不变。

**付出：**

- 新增一个插件 crate 与约 200 行 Kotlin；Kotlin 侧本地无法编译
  （本环境无 Android SDK），靠 CI 验证。
- 用户换指纹后会遇到一次“生物识别已失效，请用主密码解锁后重新启用”，
  这是 ADR-0006 规定的正常路径，但第一次遇到仍会觉得是故障——
  文案必须写清楚原因。
