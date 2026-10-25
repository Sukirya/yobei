<!--
  PLACEHOLDER UI — functional but deliberately plain.
  This whole file is a disposable test harness for the yobei-core
  commands; the real UI will be designed later and replace it wholesale.
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  interface VaultStatus {
    exists: boolean;
    unlocked: boolean;
    secret_key_enabled: boolean;
    vault_id: string | null;
  }
  interface TotpConfig {
    secret: string;
    issuer: string | null;
    digits: number;
    period_secs: number;
    algorithm: string;
  }
  interface AccountData {
    username: string;
    password: string;
    password_history: string[];
    urls: { url: string; match_rule: string }[];
    totp: TotpConfig | null;
    passkeys: unknown[];
    recovery_codes: { code: string; used: boolean }[];
  }
  interface Field {
    name: string;
    kind: string;
    value: string;
  }
  interface VaultRecord {
    id: string;
    vault_id: string;
    kind: string;
    title: string;
    favorite: boolean;
    tags: string[];
    fields: Field[];
    account: AccountData | null;
    notes: string;
    created_at_ms: number;
    updated_at_ms: number;
    version: number;
    hlc: number;
    deleted: boolean;
  }

  let status = $state<VaultStatus | null>(null);
  let error = $state("");
  let busy = $state(false);

  // create / unlock forms
  let password = $state("");
  let password2 = $state("");
  let useSecretKey = $state(false);
  let secretKeyInput = $state("");
  let generatedSecretKey = $state<string | null>(null);

  // vault screen
  let records = $state<VaultRecord[]>([]);
  let query = $state("");
  let showTrash = $state(false);
  let selected = $state<VaultRecord | null>(null);
  let newTitle = $state("");
  let newKind = $state("account");
  let showPassword = $state(false);
  let oldPw = $state("");
  let newPw = $state("");
  let showChangePw = $state(false);

  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    busy = true;
    error = "";
    try {
      return await fn();
    } catch (e) {
      error = String(e);
      return undefined;
    } finally {
      busy = false;
    }
  }

  async function refreshStatus() {
    const s = await run(() => invoke<VaultStatus>("vault_status"));
    if (s) {
      status = s;
      if (s.unlocked) await refreshRecords();
    }
  }

  async function refreshRecords() {
    const list = await run(() =>
      invoke<VaultRecord[]>("list_records", {
        query,
        includeDeleted: showTrash,
      }),
    );
    if (list) records = list;
  }

  async function createVault() {
    if (password !== password2) {
      error = "两次输入的主密码不一致";
      return;
    }
    const res = await run(() =>
      invoke<{ vault_id: string; secret_key: string | null }>("create_vault", {
        password,
        useSecretKey,
      }),
    );
    if (res) {
      generatedSecretKey = res.secret_key;
      password = "";
      password2 = "";
      await refreshStatus();
    }
  }

  async function unlock() {
    const res = await run(() =>
      invoke<string>("unlock_vault", {
        password,
        secretKey: secretKeyInput || null,
      }),
    );
    if (res) {
      password = "";
      secretKeyInput = "";
      await refreshStatus();
    }
  }

  async function lock() {
    await run(() => invoke("lock_vault"));
    selected = null;
    records = [];
    await refreshStatus();
  }

  async function changePassword() {
    const ok = await run(() =>
      invoke("change_master_password", {
        oldPassword: oldPw,
        newPassword: newPw,
        secretKey: secretKeyInput || null,
      }),
    );
    if (ok !== undefined) {
      oldPw = "";
      newPw = "";
      showChangePw = false;
      error = "";
      alert("主密码已修改");
    }
  }

  async function createRecord() {
    if (!newTitle.trim()) return;
    const rec = await run(() =>
      invoke<VaultRecord>("create_record", { kind: newKind, title: newTitle }),
    );
    if (rec) {
      newTitle = "";
      selected = rec;
      await refreshRecords();
    }
  }

  async function saveSelected() {
    if (!selected) return;
    const rec = await run(() =>
      invoke<VaultRecord>("save_record", { record: selected }),
    );
    if (rec) {
      selected = rec;
      await refreshRecords();
    }
  }

  async function toggleFavorite(r: VaultRecord) {
    await run(() =>
      invoke("set_favorite", { id: r.id, favorite: !r.favorite }),
    );
    await refreshRecords();
  }

  async function trash(r: VaultRecord) {
    await run(() => invoke("delete_record", { id: r.id }));
    if (selected?.id === r.id) selected = null;
    await refreshRecords();
  }

  async function restore(r: VaultRecord) {
    await run(() => invoke("restore_record", { id: r.id }));
    await refreshRecords();
  }

  async function purge(r: VaultRecord) {
    if (!confirm(`彻底删除「${r.title}」？此操作不可恢复。`)) return;
    await run(() => invoke("purge_record", { id: r.id }));
    if (selected?.id === r.id) selected = null;
    await refreshRecords();
  }

  function select(r: VaultRecord) {
    // deep copy so edits don't mutate the list behind our back
    selected = JSON.parse(JSON.stringify(r)) as VaultRecord;
    showPassword = false;
  }

  // --- TOTP live preview (recomputed every second from the editor's
  // current config, so it works before saving too) ---
  interface TotpNow {
    code: string;
    remaining_secs: number;
    period_secs: number;
  }
  let liveCode = $state("");
  let liveRemaining = $state(0);
  let otpauthInput = $state("");

  $effect(() => {
    const cfg = selected?.account?.totp;
    if (!cfg || !cfg.secret) {
      liveCode = "";
      return;
    }
    let alive = true;
    const tick = async () => {
      const r = await invoke<TotpNow>("totp_preview", { config: cfg }).catch(
        () => null,
      );
      if (alive && r) {
        liveCode = r.code;
        liveRemaining = r.remaining_secs;
      }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  });

  // --- password generator + strength (editor) ---
  interface StrengthReport {
    entropy_bits: number;
    score: number;
    warnings: string[];
    offline_crack_estimate: string;
  }
  const SCORE_LABELS = ["很弱", "弱", "一般", "强", "极强"];
  let genLength = $state(20);
  let genSymbols = $state(true);
  let strength = $state<StrengthReport | null>(null);

  $effect(() => {
    const pw = selected?.account?.password ?? "";
    if (!pw) {
      strength = null;
      return;
    }
    let alive = true;
    invoke<StrengthReport>("password_strength", { password: pw })
      .then((r) => {
        if (alive) strength = r;
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  });

  async function genPassword() {
    if (!selected?.account) return;
    const pw = await run(() =>
      invoke<string>("generate_password", {
        options: {
          length: genLength,
          lowercase: true,
          uppercase: true,
          digits: true,
          symbols: genSymbols,
          exclude_ambiguous: false,
        },
      }),
    );
    if (pw && selected?.account) selected.account.password = pw;
  }

  async function genPassphrase() {
    if (!selected?.account) return;
    const pw = await run(() =>
      invoke<string>("generate_passphrase", {
        wordCount: 5,
        separator: "-",
      }),
    );
    if (pw && selected?.account) selected.account.password = pw;
  }

  async function genTotpSecret() {
    if (!selected?.account?.totp) return;
    selected.account.totp.secret = await invoke<string>(
      "generate_totp_secret",
    );
  }

  async function importOtpauth() {
    if (!selected?.account || !otpauthInput.trim()) return;
    const parsed = await run(() =>
      invoke<{
        config: TotpConfig;
        account_name: string | null;
        label_issuer: string | null;
      }>("parse_otpauth", { uri: otpauthInput }),
    );
    if (parsed && selected?.account) {
      selected.account.totp = parsed.config;
      if (!selected.account.username && parsed.account_name) {
        selected.account.username = parsed.account_name;
      }
      otpauthInput = "";
    }
  }

  // editor helpers (operate on `selected`)
  function firstUrl(): string {
    return selected?.account?.urls[0]?.url ?? "";
  }
  function setFirstUrl(v: string) {
    if (!selected?.account) return;
    if (selected.account.urls.length === 0) {
      selected.account.urls = [{ url: v, match_rule: "exact_domain" }];
    } else {
      selected.account.urls[0].url = v;
    }
  }
  function enableTotp() {
    if (!selected?.account) return;
    selected.account.totp = {
      secret: "",
      issuer: null,
      digits: 6,
      period_secs: 30,
      algorithm: "SHA1",
    };
  }
  function addField() {
    selected?.fields.push({ name: "", kind: "text", value: "" });
  }
  function removeField(i: number) {
    selected?.fields.splice(i, 1);
  }
  function tagsText(): string {
    return selected?.tags.join(", ") ?? "";
  }
  function setTags(v: string) {
    if (!selected) return;
    selected.tags = v
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
  }

  refreshStatus();
</script>

<main>
  <h1>yobei <small>（占位界面 · 功能验证用）</small></h1>

  {#if error}<p class="error">{error}</p>{/if}

  {#if status === null}
    <p>加载中…</p>
  {:else if generatedSecretKey}
    <section>
      <h2>保险库已创建</h2>
      <p>你启用了 Secret Key。它只显示这一次，请保存到安全的地方——解锁时需要它 + 主密码：</p>
      <code class="secret">{generatedSecretKey}</code>
      <button onclick={() => (generatedSecretKey = null)}>我已保存</button>
    </section>
  {:else if !status.exists}
    <section>
      <h2>创建保险库</h2>
      <input type="password" placeholder="主密码" bind:value={password} />
      <input type="password" placeholder="确认主密码" bind:value={password2} />
      <label>
        <input type="checkbox" bind:checked={useSecretKey} />
        启用 Secret Key（多一层设备外密钥，更安全）
      </label>
      <button disabled={busy || !password} onclick={createVault}>创建</button>
    </section>
  {:else if !status.unlocked}
    <section>
      <h2>解锁保险库</h2>
      <input type="password" placeholder="主密码" bind:value={password} />
      {#if status.secret_key_enabled}
        <input type="text" placeholder="Secret Key" bind:value={secretKeyInput} />
      {/if}
      <button disabled={busy || !password} onclick={unlock}>解锁</button>
    </section>
  {:else}
    <section>
      <div class="row">
        <span>保险库 {status.vault_id?.slice(0, 8)}…</span>
        <button onclick={() => (showChangePw = !showChangePw)}>改主密码</button>
        <button onclick={lock}>锁定</button>
      </div>
      {#if showChangePw}
        <div class="row">
          <input type="password" placeholder="当前主密码" bind:value={oldPw} />
          <input type="password" placeholder="新主密码" bind:value={newPw} />
          {#if status.secret_key_enabled}
            <input type="text" placeholder="Secret Key" bind:value={secretKeyInput} />
          {/if}
          <button disabled={!oldPw || !newPw} onclick={changePassword}>确认修改</button>
        </div>
      {/if}

      <div class="row">
        <input
          type="search"
          placeholder="搜索标题 / 用户名 / 标签…"
          bind:value={query}
          oninput={refreshRecords}
        />
        <label>
          <input type="checkbox" bind:checked={showTrash} onchange={refreshRecords} />
          回收站
        </label>
      </div>
      <div class="row">
        <input type="text" placeholder="新记录标题" bind:value={newTitle} />
        <select bind:value={newKind}>
          <option value="account">账号</option>
          <option value="card">银行卡</option>
          <option value="identity">身份</option>
          <option value="note">笔记</option>
          <option value="api_key">API 密钥</option>
          <option value="ssh_key">SSH 密钥</option>
          <option value="custom">自定义</option>
        </select>
        <button disabled={!newTitle.trim()} onclick={createRecord}>新建</button>
      </div>

      <ul class="list">
        {#each records as r (r.id)}
          <li class:deleted={r.deleted}>
            <button class="title" onclick={() => select(r)}>
              {r.favorite ? "★ " : ""}{r.title}
              <small>（{r.kind}{r.account ? ` · ${r.account.username}` : ""}）</small>
            </button>
            <button onclick={() => toggleFavorite(r)}>{r.favorite ? "取消收藏" : "收藏"}</button>
            {#if r.deleted}
              <button onclick={() => restore(r)}>恢复</button>
              <button onclick={() => purge(r)}>彻底删除</button>
            {:else}
              <button onclick={() => trash(r)}>删除</button>
            {/if}
          </li>
        {/each}
        {#if records.length === 0}<li>（暂无记录）</li>{/if}
      </ul>

      {#if selected}
        <section class="editor">
          <h2>编辑</h2>
          <label>标题 <input type="text" bind:value={selected.title} /></label>
          {#if selected.account}
            <label>
              用户名
              <input type="text" bind:value={selected.account.username} />
            </label>
            <label>
              密码
              <input
                type={showPassword ? "text" : "password"}
                bind:value={selected.account.password}
              />
              <button onclick={() => (showPassword = !showPassword)}>
                {showPassword ? "隐藏" : "显示"}
              </button>
            </label>
            <div class="row">
              <span>长度</span>
              <input type="number" min="6" max="128" bind:value={genLength} />
              <label>
                <input type="checkbox" bind:checked={genSymbols} /> 符号
              </label>
              <button onclick={genPassword}>生成密码</button>
              <button onclick={genPassphrase}>生成短语</button>
            </div>
            {#if strength}
              <p class="strength">
                强度：{SCORE_LABELS[strength.score]}（{strength.entropy_bits.toFixed(
                  0,
                )} bits · 离线破解约 {strength.offline_crack_estimate}）
                {#if strength.warnings.length}
                  <br />⚠ {strength.warnings.join("；")}
                {/if}
              </p>
            {/if}
            <label>
              网址
              <input
                type="text"
                value={firstUrl()}
                oninput={(e) => setFirstUrl((e.target as HTMLInputElement).value)}
              />
            </label>
            {#if selected.account.totp}
              <label>
                TOTP 密钥
                <input type="text" bind:value={selected.account.totp.secret} />
              </label>
              <div class="row">
                <button onclick={genTotpSecret}>生成密钥</button>
                {#if liveCode}
                  <span class="totp-code">{liveCode}</span>
                  <span>（{liveRemaining} 秒后刷新）</span>
                {/if}
              </div>
              <label>
                TOTP 发行方
                <input
                  type="text"
                  bind:value={selected.account.totp.issuer}
                />
              </label>
              <div class="row">
                <input
                  type="text"
                  placeholder="粘贴 otpauth:// 链接导入"
                  bind:value={otpauthInput}
                />
                <button disabled={!otpauthInput.trim()} onclick={importOtpauth}>
                  导入
                </button>
              </div>
            {:else}
              <button onclick={enableTotp}>添加 TOTP</button>
            {/if}
          {/if}
          <label>
            标签（逗号分隔）
            <input
              type="text"
              value={tagsText()}
              oninput={(e) => setTags((e.target as HTMLInputElement).value)}
            />
          </label>
          <label>备注 <textarea bind:value={selected.notes} rows="3"></textarea></label>

          <h3>自定义字段</h3>
          {#each selected.fields as f, i}
            <div class="row">
              <input type="text" placeholder="名称" bind:value={f.name} />
              <input type="text" placeholder="值" bind:value={f.value} />
              <button onclick={() => removeField(i)}>移除</button>
            </div>
          {/each}
          <button onclick={addField}>加字段</button>

          <div class="row">
            <button disabled={busy} onclick={saveSelected}>保存</button>
            <button onclick={() => (selected = null)}>关闭</button>
          </div>
        </section>
      {/if}
    </section>
  {/if}
</main>

<style>
  :root {
    font-family: system-ui, sans-serif;
  }
  main {
    max-width: 720px;
    margin: 0 auto;
    padding: 16px;
  }
  section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 12px;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .error {
    color: #b00020;
  }
  .secret {
    word-break: break-all;
    background: #f3f3f3;
    padding: 8px;
  }
  .list {
    list-style: none;
    padding: 0;
  }
  .list li {
    display: flex;
    gap: 8px;
    align-items: center;
    padding: 4px 0;
  }
  .list li.deleted {
    opacity: 0.55;
  }
  .title {
    flex: 1;
    text-align: left;
  }
  .editor label {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .totp-code {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 3px;
    font-variant-numeric: tabular-nums;
  }
  input,
  select,
  textarea,
  button {
    padding: 6px 8px;
    font-size: 14px;
  }
</style>
