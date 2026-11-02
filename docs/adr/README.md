# 架构决策记录（ADR）

本目录记录 yobei 的重要架构决策：**为什么这么定、放弃了什么、代价是什么**。
代码说"是什么"，ADR 说"为什么"——后者一旦丢失就再也找不回来。

规则：

- 一个决策一份，一页纸。
- 追加，不修改：决策变了就写新的一份，并在上一条标记「被 ADR-XXXX 取代」。
- 与代码同仓、同版本管理。
- 条目格式遵循 `docs/DESIGN.md` 与 `awesome-architecture/tutorial/08` 的六块模板：
  标题 / 状态 / 日期 / 背景 / 决策 / 考虑过的其它选项 / 取舍与后果。

## 决策清单

| 编号 | 标题 | 状态 | 取代了 |
|---|---|---|---|
| [0001](0001-master-key-hierarchy-and-recovery-kit.md) | 密钥层级、强制 Secret Key 与恢复套件 | 已采纳 | DESIGN §3 的"可选 Secret Key" |
| [0002](0002-vault-bootstrap-and-device-enrollment.md) | 引导包、同步地址与新设备加入 | 已采纳 | DESIGN §4.3 的开放设备注册 |
| [0003](0003-sync-integrity-and-deletion.md) | 同步完整性、幂等与删除终态 | 已采纳 | DESIGN §4.2 的删除清空密文 |
| [0004](0004-entry-model.md) | 条目模型：四种类型与统一载荷 | 已采纳 | DESIGN §2 的七种类型 |
| [0005](0005-secret-attribution-and-autosave.md) | 秘密归属与自动保存 | 已采纳 | — |
| [0006](0006-platform-unlock-ladder.md) | 平台解锁能力阶梯 | 已采纳 | — |
| [0007](0007-engineering-guardrails.md) | 工程护栏：规格、ADR 与 CI 门禁 | 已采纳 | — |
| [0008](0008-internationalization.md) | 国际化：用户可见文字只属于展示层 | 已采纳 | — |
| [0009](0009-biometric-device-key.md) | 生物识别解锁的设备密钥实现 | 已采纳 | — |
| [0010](0010-password-only-unlock.md) | 日常解锁只用主密码 | 已采纳 | ADR-0001 的“解锁强制 Secret Key”（仅解锁路径） |
| [0011](0011-desktop-tray-and-browser-extension.md) | 桌面端（托盘常驻）与浏览器扩展 | 已采纳 | — |
| [0012](0012-vault-header-key-check.md) | 库头存 Vault Key 指纹，生物识别过期检查不再空洞 | 已采纳 | ADR-0009 的 `open_with_key` 检查语义 |

> 本目录中的决策优先于 `docs/DESIGN.md` 的 v0 草稿。冲突时以 ADR 为准。
