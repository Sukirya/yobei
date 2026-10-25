# yobei 设计稿 v0（持续修订）

标识符：`com.sukirya.yobei` · 客户端：Tauri 2 + Svelte 5 + TypeScript（Bun）· 核心：Rust · 同步：Cloudflare Workers

本稿落实的已定决策（2026-10-25，用户拍板）：
- 平台优先级：Android 一等 → Windows 第二 → 其他平台靠后
- 服务端基于 Cloudflare Workers，无需自备服务器、免费额度可用，从一开始与客户端同步开发
- TOTP、passkey 提前做，不推迟到后期版本
- 统一记录模型（见 §2）；家人分享不做，只在数据模型预留接入路径；不做 AI 功能
- UI 先用普通占位实现，单独成层、方便整层删除替换（正式 UI 后续专门设计）

## 1. 架构原则（源自 awesome-software-architecture 提炼，见调研汇报）

1. **核心可移植（Ports & Adapters）**：Rust 核心（`crates/yobei-core`）不依赖 Tauri 或任何平台类型。
   存储、随机数、时钟、钥匙串/生物识别、同步传输、平台 passkey/autofill 都是核心定义的 port，
   Android / Windows / 浏览器扩展 / Workers 都是 adapter。核心可独立 `cargo test` 与独立审计。
2. **模块化单体优先**：一个核心 crate + 一个 Worker，内部模块 crypto / vault / record / sync / import。
   出现真实的独立伸缩或团队边界之前禁止拆服务。
3. **本地优先、最终一致、无静默丢失**：离线永远可解锁、可编辑；同步冲突按记录检测，
   冲突时保留冲突副本由用户裁决，服务端不做合并裁决。
4. **同步按不可靠设计**：操作幂等（op_id）、本地 outbox 先行、服务端去重、失败指数退避；
   同步子系统故障与保险库本地可用性完全隔离（绝不阻塞开库）。
5. **边界防腐**：导入格式（Bitwarden / KeePass / 1Password）、同步协议版本、OS passkey/autofill 差异
   都只存在于 adapter / 转换层，不渗入统一记录模型与保险库格式。
6. **YAGNI + 预留扩展点**：家人分享只预留密钥包装位置（见 §2.4），不写任何分享逻辑；
   高风险功能（passkey 等）用 feature toggle 灰度，先在 Android 单平台验证。
7. **决策留痕**：重大取舍（KDF 参数、加密算法、冲突策略、格式版本）写 ADR 存 `docs/adr/`，随代码版本化。

## 2. 数据模型：统一 Record

### 2.1 为什么合并卡片 / 身份 / 安全笔记

三者底层相同：一个加密条目 + 一组字段。区别仅在模板（预置字段、图标、校验、填表用途）。
因此存储层、加密层、同步层只认一种 `Record`；“类型”只是模板，不构成数据孤岛。

### 2.2 Record 结构（明文域模型，只存在于加密边界内）

- `id`：全局唯一 ID（UUIDv7，自带时间序，利于同步排序）
- `kind`：记录类型（模板）：`account` / `api_key` / `card` / `identity` / `note` / `ssh_key` / `custom`
- `title`、`icon`（可选）、`favorite`、`tags[]`
- `fields[]`：自定义字段（name / kind / value），类型模板之外的补充都走这里
- `created_at` / `updated_at`（毫秒时间戳）、`version`（记录级版本号）、`hlc`（混合逻辑时钟，冲突检测）
- `deleted`：墓碑标记（同步删除语义，不立即物理删除）

类型模板（仅 UI 与校验层关心）：
- **account（核心类型）**：见 §2.3
- **api_key**：key_id、secret、环境（prod/test）、接口地址、备注
- **card**：持卡人、卡号、有效期、CVC、PIN（可选）
- **identity**：姓名、邮箱、电话、地址（填表用）
- **note**：自由文本 content
- **ssh_key**：私钥材料、公钥、指纹、口令

### 2.3 账号记录：一处装齐（用户核心诉求）

一个网站/服务 = 一条 account 记录，内聚它所需的全部凭据，避免在多处拼凑：

- `username`、`password`、密码历史（改密留痕，供恢复旧密码）
- `urls[]`：网址 + 匹配方式（域名精确 / 前缀 / 正则，防钓鱼填充）
- `totp`：TOTP 种子、发行方、位数/周期/算法（RFC 6238），与密码同条目存储；
  文档中明确提示：密码与 TOTP 同库会弱化“双因素”的隔离性，由用户知情选择
- `passkeys[]`：passkey 元数据与密钥材料引用（RP ID、credential ID、公私钥、计数器、可发现性）
- `recovery_codes[]`：恢复代码列表 + 每条的已用标记
- `notes`：与该账号相关的自由备注

### 2.4 预留但不实现

- **分享/家人**：密钥层级预留“把 vault key 用 X25519 包给另一个成员公钥”的位置（见 §3），
  数据模型预留 `owner` / 成员包装字段；不写任何分享 UI、流程或服务端逻辑。
- **组织/多保险库**：`vault_id` 从第一天就存在于每条记录与同步协议中（默认只有一个默认库）。

## 3. 密钥层级与加密（不自造算法）

```
主密码 (+ 可选 Secret Key, HKDF 合并)
  └─ Argon2id ─→ KEK（密钥加密密钥）
       └─ 解包 Vault Key（随机生成）
            └─ 解包每条记录的 Record Key（随机生成）
                 └─ XChaCha20-Poly1305 加密记录明文（每条独立 nonce）
```

- KDF：Argon2id。参数下限遵循 OWASP（19 MiB, t=2, p=1），默认目标在低端安卓机解锁约 0.5–1 秒
  （建议默认 64 MiB, t=3 起调），参数随保险库头存储，支持以后升级。
- 对称加密：XChaCha20-Poly1305（192-bit nonce 可安全随机）；备选 AES-256-GCM（需 FIPS 叙事时）。
- 只用经审计的库：RustCrypto（`argon2`、`chacha20poly1305`、`hkdf` 等）/ libsodium 绑定；
  禁止自研密码算法、自研 PAKE、自研同步加密协议。
- Secret Key：可选但鼓励。设备本地生成的高熵秘密，永不上传服务器，
  与主密码经 HKDF 合并后再过 KDF；以 Recovery Kit 形式让用户离线保存。
  作用：服务器数据被偷时，攻击者没有 Secret Key 连验证密码猜测都做不到（防 LastPass 式离线破解）。
- 认证与加密分离：服务器永远不接触主密码与任何解密密钥；登录校验值与加密密钥独立派生。

## 4. 同步协议（Cloudflare Workers）

### 4.1 部署模型：用用户自己的免费额度

- 提供一键部署（Wrangler / Deploy Button），用户把同步 Worker 部署到**自己的 Cloudflare 账号**：
  开发者不承担服务器成本，用户数据在自己账号里，免费额度对个人同步足够。
- 同时保留自托管同一 Worker 到任意兼容运行时的可能（协议不绑定 Cloudflare 专有能力之外的东西）。
- 存储：**只用 D1 一个库**——账号、设备、op 日志、清单（manifest）都是表，记录密文以 BLOB 形式
  直接存在 records 行里（nonce‖密文）。不用 R2：开 R2 要先绑支付卡（免费额度也要绑），违背
  "免费、自部署、无需绑卡"的承诺；也不用 KV（最终一致、免费版写额度低，不适合做同步真相源）。
  个人保险库一般几千条记录、每条密文几 KB，D1 免费 5 GB 绰绰有余，且单行远低于 D1 的行大小
  上限（约 1 MB）；将来若做大文件附件，再把附件密文按块拆行存（record_chunks），不迁对象存储。

### 4.2 同步语义（哑服务端）

- 服务端只存：账号/设备注册信息、记录密文（D1 行内 BLOB）、每条记录的版本号与 HLC、op 日志。**不见明文、不做合并**。
- 客户端本地 outbox：所有变更先落本地并生成操作 `{ op_id (UUID), vault_id, record_id, base_version, hlc, type: upsert|delete, ciphertext, nonce }`。
- 推送：批量提交 ops → 服务端按 `op_id` 去重（幂等，重试安全）→ 版本校验：
  `base_version` 与服务端当前版本一致才接受；不一致返回冲突，客户端把远端版本存为**冲突副本**，不覆盖本地。
- 拉取：按清单（record_id → version/hlc/更新时间）增量对比，只拉变化的记录密文。
- 删除：墓碑 op 同步，保留期过后才允许物理清除（防离线设备复活已删记录）。
- 冲突呈现：UI 层（占位 UI 先做列表呈现）让用户二选一或手动合并；核心只负责检测与保留双方版本。

### 4.3 接口草案（v1，前缀 /v1）

- `GET  /v1/health` — 存活检查（无鉴权）
- `POST /v1/devices` — 注册设备（返回设备令牌；令牌只用于同步鉴权，与解密无关）
- `GET  /v1/vaults/:vaultId/manifest` — 拉清单
- `PUT  /v1/vaults/:vaultId/records/:recordId` — 上传单条密文（带 version/hlc/op_id 头，幂等）
- `GET  /v1/vaults/:vaultId/records/:recordId` — 下载单条密文
- `POST /v1/vaults/:vaultId/ops` — 批量提交 ops（去重 + 版本校验，返回逐条 accepted/conflict）

鉴权：设备令牌（Bearer）+ 请求签名为后续 ADR 预留；令牌泄露最坏后果是密文被下载，
解密仍需要主密码（+ Secret Key），这是 E2EE 的兜底。

## 5. 仓库结构（与本稿同步落地）

```
yobei/
  crates/yobei-core/     # Rust 核心（无 Tauri 依赖）：record / crypto(接口与参数) / ports / sync 类型
  src/                   # Svelte 前端（占位 UI，独立一层，可整层替换）
  src-tauri/             # Tauri 壳（adapter：把核心 port 接到平台能力）
  workers/sync/          # Cloudflare Workers 同步服务端（TypeScript + Wrangler）
  docs/                  # 本稿与 ADR
```

## 6. 参考项目评审结论（旧 yobei / Akiraph/yobei-client-test，2026-10-25 调研）

同名的已弃坑项目，其实质问题与可借鉴点，写成我们的硬性约束：

**避坑（它踩过，我们不踩）：**
- 同步冲突禁止"本地优先、静默丢弃远端改动"（它正是这样丢数据的）；我们坚持冲突副本（见 §4.2）。
- passkey 必须是结构化 WebAuthn 凭据（credential ID / 私钥 / RP / 签名计数器），不能学它存一串不透明字符串；
  凭据相关路径禁止 `filter_map` 式静默丢弃格式错误的数据。
- 新秘密类型不准靠"新增加密列 + 特殊分支"扩展；统一走 records 的 `fields[]` 类型化模型（见 §2）。
  它的导入器把所有非笔记类型压成 login、卡片/身份在导入时被毁，正是无类型模型的后果。
- KDF 参数与格式版本必须进保险库头（见 §3）；它的参数是编译期常量，改参数会困死旧库。
- 同步服务端与客户端同仓公开（见 §5）；零知识产品把服务端藏起来等于砍掉一半可审计性。CI 必须跑测试再谈发布。

**借鉴（它做对的，我们采纳）：**
- Secret Key 作 HKDF salt 参与包裹主密钥的构造，并写"Secret Key 是承重墙"的回归测试。
- 同步报文纪律：带版本与 context 字符串的信封、入站严格校验（拒未知字段、大小上限、版本号单调），
  并有测试断言报文线上不出现明文与记录类型等元数据。
- 导入预览只展示"有无密码 / 有无 TOTP"这类存在性标记，绝不展示值。
- 生物识别解锁 = 平台密钥库保护的随机凭据包裹主密钥，并要求定期用主密码复确认（过期策略可配）。
- 浏览器扩展路线（未来）：扩展永不持有主密钥，只向已解锁的桌面端逐条取。

## 7. 待决（不阻塞脚手架与核心）

- passkey 在 Android 的落地路径细节（Credential Manager, Android 14+）需专项验证后再定版
- Secret Key 默认开还是默认关（UX 与安全的取舍）——v0.1 先做可选、引导开启
- 同步鉴权是否在 v1 就上请求签名（先用设备令牌，签名留 ADR）
- 保险库本地存储形态：加密 SQLite vs 追加日志文件（核心 port 已隔离此选择，下个里程碑前定）
