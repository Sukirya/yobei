# yobei-sync — Cloudflare Workers 同步服务端

端到端加密的“哑”同步服务端：密文与同步元数据都只存 D1，不见明文、
不做合并、版本冲突时拒绝覆盖。设计见 `docs/adr/0002`、`docs/adr/0003` 与
`../../docs/DESIGN.md` §4。

为什么只用 D1、不用 R2：开 R2 需先在 Cloudflare 绑支付卡（免费
额度也要绑），违背本项目“自部署、免费、无需绑卡”的承诺；而个人
保险库通常只有几千条记录、每条密文几 KB，D1 免费额度（5 GB，
无需绑卡）绰绰有余。

## 部署到你自己的 Cloudflare 账号（免费额度足够个人使用）

全程用 Bun：

```bash
cd workers/sync
bun install
bunx wrangler login
bunx wrangler d1 create yobei-sync-db          # 把输出的 database_id 填进 wrangler.toml
bunx wrangler d1 execute yobei-sync-db --file=schema.sql
bun run deploy
```

## 接口（/v1）

同步地址（`:address`）由 Secret Key 派生，服务器只把它当作库的标识。

- `GET  /v1/health`
- `GET  /v1/vaults/:address/bootstrap` — 取回加密引导包（公开，内容用 Secret Key 派生密钥加密）
- `PUT  /v1/vaults/:address/bootstrap` — 上传/更新引导包；首次上传为 TOFU，之后需 Bearer auth key
- `POST /v1/vaults/:address/devices` — 用 Bearer auth key 注册设备，返回一次性展示的设备令牌（库里只存哈希）
- `GET  /v1/vaults/:address/devices` — 列出已注册设备（需 Bearer auth key）
- `DELETE /v1/vaults/:address/devices/:deviceId` — 撤销设备（需 Bearer auth key）；只停止同步，不删除本地保险库
- `GET  /v1/vaults/:address/manifest` — 拉同步清单（需设备令牌）
- `GET  /v1/vaults/:address/entries/:entryId` — 下载单条密文（nonce‖密文原始字节，需设备令牌）
- `POST /v1/vaults/:address/ops` — 批量推送（op_id 幂等去重 + base_version 校验，
  逐条返回 accepted / duplicate / conflict；需设备令牌）

鉴权分两层：

- **auth key**（由 Vault Key 派生，客户端持有）只用于上传引导包和注册设备；
  服务器只存它的 SHA-256。
- **设备令牌**用于日常同步，可在服务器上单独撤销；撤销只停止同步，
  不会删除该设备本地的保险库。
