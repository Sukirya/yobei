# yobei

开源免费的密码管理器（开发中，尚未发布）。

- 桌面/移动：Tauri 2 + Svelte 5 + TypeScript，包标识 `com.sukirya.yobei`
  （平台优先级：Android 一等 → Windows 第二）
- 核心：独立的 Rust crate `crates/yobei-core`（六边形架构，不依赖任何平台框架）
- 同步：Cloudflare Workers 服务端 `workers/sync`，部署在用户自己的
  Cloudflare 账号上，端到端加密，服务端只存密文
- 记录模型是统一的：一张账号记录内聚密码 + TOTP + passkey + 恢复代码

设计与决策见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 本地开发

全程只用 Bun 作为 JS 包管理器：

```bash
bun install
bun run tauri dev          # 桌面
bun run tauri android dev  # Android（需先 bun run tauri android init 与安卓工具链）
```

Rust 核心单独验证（不需要 Tauri 环境）：

```bash
cargo test --manifest-path crates/yobei-core/Cargo.toml
```

同步服务端见 `workers/sync/README.md`。
