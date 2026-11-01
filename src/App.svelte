<!--
  PLACEHOLDER UI — functional but deliberately plain.
  This whole file is a disposable test harness for the yobei-core
  commands; the real UI will be designed later and replace it wholesale.
  All user-facing text comes from src/lib/i18n.svelte.ts (ADR-0008).
-->
<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import {
    SUPPORTED_LOCALES,
    formatNumber,
    getLocale,
    setLocale,
    t,
    type Locale,
  } from "./lib/i18n.svelte";

  interface VaultStatus {
    exists: boolean;
    unlocked: boolean;
    secret_key_enabled: boolean;
    password_only_available: boolean;
    vault_id: string | null;
  }
  interface TotpConfig {
    secret: string;
    issuer: string | null;
    account_name: string | null;
    digits: number;
    period_secs: number;
    algorithm: string;
  }
  interface CustomField {
    name: string;
    kind: string;
    value: string;
  }
  interface EntryUrl {
    url: string;
    match_rule: string;
  }
  interface AccountPayload {
    type: "account";
    username: string;
    password: string | null;
    password_history: { password: string; changed_at_ms: number }[];
    urls: EntryUrl[];
    totp: TotpConfig | null;
    passkeys: { rp_id: string; sign_count: number }[];
    recovery_codes: { code: string; used: boolean }[];
    custom_fields: CustomField[];
  }
  interface CardPayload {
    type: "card";
    cardholder_name: string;
    number: string;
    expiry_month: number | null | undefined;
    expiry_year: number | null | undefined;
    cvc: string | null;
    pin: string | null;
    billing_address: unknown | null;
    custom_fields: CustomField[];
  }
  interface IdentityPayload {
    type: "identity";
    full_name: string;
    first_name: string;
    last_name: string;
    emails: string[];
    phones: string[];
    addresses: unknown[];
    custom_fields: CustomField[];
  }
  interface NotePayload {
    type: "note";
    content: string;
    custom_fields: CustomField[];
  }
  type EntryPayload =
    | AccountPayload
    | CardPayload
    | IdentityPayload
    | NotePayload;
  interface Entry {
    id: string;
    vault_id: string;
    kind: "account" | "card" | "identity" | "note";
    title: string;
    favorite: boolean;
    tags: string[];
    notes: string;
    created_at_ms: number;
    updated_at_ms: number;
    version: number;
    hlc: number;
    deleted: boolean;
    deleted_at_ms: number | null;
    conflict_copy_of: string | null;
    payload: EntryPayload;
  }

  let status = $state<VaultStatus | null>(null);
  let error = $state("");
  let busy = $state(false);

  // biometric unlock (ADR-0009)
  interface BiometricStatus {
    state: string;
    enrolled: boolean;
  }
  let biometric = $state<BiometricStatus | null>(null);

  async function refreshBiometric() {
    const b = await run(() => invoke<BiometricStatus>("biometric_status"));
    if (b) biometric = b;
  }

  async function unlockBiometric() {
    const res = await run(() =>
      invoke<string>("biometric_unlock", {
        title: t("biometric.unlock.title"),
        subtitle: t("biometric.unlock.subtitle"),
      }),
    );
    if (res) {
      password = "";
      secretKeyInput = "";
      await refreshStatus();
      return;
    }
    if (error === "biometric_cancelled") {
      error = ""; // the user backed out; stay on the password form.
    } else if (error === "biometric_key_invalidated") {
      error = t("biometric.invalidated");
    } else if (error === "biometric_locked_out") {
      error = t("biometric.lockedOut");
    }
    await refreshBiometric();
  }

  async function enableBiometric() {
    await run(() =>
      invoke("biometric_enable", {
        title: t("biometric.enroll.title"),
        subtitle: t("biometric.enroll.subtitle"),
      }),
    );
    if (!error) await refreshBiometric();
  }

  async function disableBiometric() {
    await run(() => invoke("biometric_disable"));
    if (!error) await refreshBiometric();
  }

  // create / unlock forms
  let password = $state("");
  let password2 = $state("");
  let secretKeyInput = $state("");
  let generatedSecretKey = $state<string | null>(null);
  let generatedAddress = $state<string | null>(null);

  // join-existing-vault form
  let showJoin = $state(false);
  let joinServer = $state("");
  let joinAddress = $state("");
  let joinPassword = $state("");
  let joinSecretKey = $state("");

  // vault screen
  let entries = $state<Entry[]>([]);
  let query = $state("");
  let showTrash = $state(false);
  let selected = $state<Entry | null>(null);
  let newTitle = $state("");
  let newKind = $state("account");

  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    busy = true;
    error = "";
    try {
      return await fn();
    } catch (e) {
      // Command errors are still English strings from the core; full
      // localization waits for the CoreError refactor (ADR-0008 §6).
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
      if (s.unlocked) {
        await refreshEntries();
        await refreshSyncStatus();
      }
    }
    await refreshBiometric();
  }

  async function refreshEntries() {
    const list = await run(() =>
      invoke<Entry[]>("list_entries", {
        query,
        includeDeleted: showTrash,
      }),
    );
    if (list) entries = list;
  }

  async function createVault() {
    if (password !== password2) {
      error = t("error.passwordMismatch");
      return;
    }
    const res = await run(() =>
      invoke<{ vault_id: string; secret_key: string; sync_address: string }>(
        "create_vault",
        { password },
      ),
    );
    if (res) {
      generatedSecretKey = res.secret_key;
      generatedAddress = res.sync_address;
      password = "";
      password2 = "";
      await refreshStatus();
    }
  }

  async function joinVault() {
    // Even if the first pull fails, the vault may have been adopted and
    // unlocked locally; refresh so the UI reflects that.
    await run(() =>
      invoke<string>("join_vault", {
        serverUrl: joinServer,
        address: joinAddress,
        password: joinPassword,
        secretKey: joinSecretKey,
      }),
    );
    joinPassword = "";
    joinSecretKey = "";
    await refreshStatus();
  }

  async function unlock() {
    const res = await run(() =>
      invoke<string>("unlock_vault", {
        password,
        secretKey: secretKeyInput,
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
    entries = [];
    await refreshStatus();
  }

  async function createEntry() {
    if (!newTitle.trim()) return;
    const entry = await run(() =>
      invoke<Entry>("create_entry", { kind: newKind, title: newTitle }),
    );
    if (entry) {
      newTitle = "";
      selected = entry;
      await refreshEntries();
    }
  }

  async function saveSelected() {
    if (!selected) return;
    const entry = await run(() =>
      invoke<Entry>("save_entry", { entry: selected }),
    );
    if (entry) {
      selected = entry;
      await refreshEntries();
    }
  }

  async function toggleFavorite(entry: Entry) {
    await run(() =>
      invoke("set_favorite", { id: entry.id, favorite: !entry.favorite }),
    );
    await refreshEntries();
  }

  async function trashEntry(entry: Entry) {
    await run(() => invoke("delete_entry", { id: entry.id }));
    if (selected?.id === entry.id) selected = null;
    await refreshEntries();
  }

  async function restoreEntry(entry: Entry) {
    await run(() => invoke("restore_entry", { id: entry.id }));
    await refreshEntries();
  }

  function select(entry: Entry) {
    // deep copy so edits don't mutate the list behind our back
    selected = JSON.parse(JSON.stringify(entry)) as Entry;
  }

  function accountOf(): AccountPayload | null {
    return selected && selected.payload.type === "account"
      ? selected.payload
      : null;
  }

  function kindLabel(kind: string): string {
    switch (kind) {
      case "account":
        return t("kind.account");
      case "card":
        return t("kind.card");
      case "identity":
        return t("kind.identity");
      case "note":
        return t("kind.note");
      default:
        return kind;
    }
  }

  // --- TOTP live preview ---
  interface TotpNow {
    code: string;
    remaining_secs: number;
    period_secs: number;
  }
  let liveCode = $state("");
  let liveRemaining = $state(0);
  let otpauthInput = $state("");

  $effect(() => {
    const cfg = accountOf()?.totp ?? null;
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
    const timer = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  });

  // --- password generator + strength ---
  type WarningCode =
    | { code: "empty" }
    | { code: "common_password" }
    | { code: "common_word"; word: string }
    | { code: "sequence" }
    | { code: "repeated_characters" }
    | { code: "year" };

  interface StrengthReport {
    entropy_bits: number;
    score: number;
    warnings: WarningCode[];
    offline_crack_seconds: number;
  }

  const SCORE_KEYS = [
    "score.0",
    "score.1",
    "score.2",
    "score.3",
    "score.4",
  ] as const;

  function warningText(warning: WarningCode): string {
    switch (warning.code) {
      case "empty":
        return t("warning.empty");
      case "common_password":
        return t("warning.commonPassword");
      case "common_word":
        return t("warning.commonWord", { word: warning.word });
      case "sequence":
        return t("warning.sequence");
      case "repeated_characters":
        return t("warning.repeatedCharacters");
      case "year":
        return t("warning.year");
      default:
        return "";
    }
  }

  function crackText(seconds: number): string {
    if (seconds < 1) return t("crack.instant");
    if (seconds < 60) return t("crack.seconds", { value: formatNumber(seconds) });
    const minutes = seconds / 60;
    if (minutes < 60) return t("crack.minutes", { value: formatNumber(minutes) });
    const hours = minutes / 60;
    if (hours < 24) return t("crack.hours", { value: formatNumber(hours) });
    const days = hours / 24;
    if (days < 365) return t("crack.days", { value: formatNumber(days) });
    const years = days / 365;
    if (years < 1e6) return t("crack.years", { value: formatNumber(years) });
    if (years < 1e9)
      return t("crack.millionYears", { value: formatNumber(years / 1e6) });
    return t("crack.universe");
  }

  let strength = $state<StrengthReport | null>(null);

  $effect(() => {
    const pw = accountOf()?.password ?? "";
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
    const acct = accountOf();
    if (!acct) return;
    const pw = await run(() =>
      invoke<string>("generate_password", {
        options: {
          length: 20,
          lowercase: true,
          uppercase: true,
          digits: true,
          symbols: true,
          exclude_ambiguous: false,
        },
      }),
    );
    if (pw) acct.password = pw;
  }

  async function genPassphrase() {
    const acct = accountOf();
    if (!acct) return;
    const pw = await run(() =>
      invoke<string>("generate_passphrase", { wordCount: 5, separator: "-" }),
    );
    if (pw) acct.password = pw;
  }

  async function importOtpauth() {
    const acct = accountOf();
    if (!acct || !otpauthInput.trim()) return;
    const parsed = await run(() =>
      invoke<{
        config: TotpConfig;
        account_name: string | null;
        label_issuer: string | null;
      }>("parse_otpauth", { uri: otpauthInput }),
    );
    if (parsed) {
      acct.totp = parsed.config;
      if (!acct.username && parsed.account_name) {
        acct.username = parsed.account_name;
      }
      otpauthInput = "";
    }
  }

  function enableTotp() {
    const acct = accountOf();
    if (!acct) return;
    acct.totp = {
      secret: "",
      issuer: null,
      account_name: null,
      digits: 6,
      period_secs: 30,
      algorithm: "SHA1",
    };
  }

  function setFirstUrl(value: string) {
    const acct = accountOf();
    if (!acct) return;
    if (acct.urls.length === 0) {
      acct.urls = [{ url: value, match_rule: "exact_host" }];
    } else {
      acct.urls[0].url = value;
    }
  }

  function setTags(value: string) {
    if (!selected) return;
    selected.tags = value
      .split(",")
      .map((tag) => tag.trim())
      .filter(Boolean);
  }

  // --- import / export ---
  interface PreviewItem {
    title: string;
    kind: string;
    has_username: boolean;
    has_password: boolean;
    has_totp: boolean;
    url_count: number;
    field_count: number;
  }
  let impFormat = $state("csv");
  let impText = $state("");
  let impPassword = $state("");
  let impPreview = $state<PreviewItem[] | null>(null);
  let expPassword = $state("");
  let expText = $state("");

  async function doPreview() {
    const items = await run(() =>
      invoke<PreviewItem[]>("import_preview", {
        format: impFormat,
        text: impText,
        exportPassword: impPassword || null,
      }),
    );
    if (items) impPreview = items;
  }

  async function doImport() {
    const n = await run(() =>
      invoke<number>("import_execute", {
        format: impFormat,
        text: impText,
        exportPassword: impPassword || null,
      }),
    );
    if (n !== undefined) {
      impPreview = null;
      impText = "";
      await refreshEntries();
      alert(t("import.done", { count: n }));
    }
  }

  async function doExport(kind: "csv" | "json" | "encrypted") {
    const text = await run(() => {
      if (kind === "csv") return invoke<string>("export_csv");
      if (kind === "json") return invoke<string>("export_json");
      return invoke<string>("export_encrypted", { password: expPassword });
    });
    if (text) expText = text;
  }

  // --- sync ---
  interface SyncStatusDto {
    configured: boolean;
    server_url: string | null;
    device_id: string | null;
    pending_ops: number;
  }
  interface DeviceDto {
    device_id: string;
    name: string;
    created_at_ms: number;
    last_seen_ms: number | null;
  }
  interface SyncReport {
    pushed: number;
    duplicates: number;
    pulled_new: number;
    pulled_updated: number;
    conflicts: number;
    conflict_copies: number;
    discarded: number;
  }
  let syncUrl = $state("");
  let syncStat = $state<SyncStatusDto | null>(null);
  let syncMsg = $state("");
  let devices = $state<DeviceDto[]>([]);
  let devicesMsg = $state("");

  async function refreshSyncStatus() {
    const s = await run(() => invoke<SyncStatusDto>("sync_status"));
    if (s) syncStat = s;
  }

  async function doSyncConfigure() {
    const s = await run(() =>
      invoke<SyncStatusDto>("sync_configure", { serverUrl: syncUrl }),
    );
    if (s) {
      syncStat = s;
      syncMsg = t("sync.registered");
      await refreshDevices();
    }
  }

  async function refreshDevices() {
    const list = await run(() => invoke<DeviceDto[]>("sync_devices"));
    if (list) devices = list;
    devicesMsg = "";
  }

  async function revokeDevice(device: DeviceDto) {
    const label = device.name || device.device_id.slice(0, 8);
    if (!confirm(t("sync.revokeConfirm", { name: label }))) return;
    const ok = await run(() =>
      invoke("sync_revoke_device", { deviceId: device.device_id }),
    );
    if (ok !== undefined) {
      devicesMsg = t("sync.revoked");
      await refreshDevices();
      await refreshSyncStatus();
    }
  }

  function formatTime(ms: number | null): string {
    if (!ms) return t("sync.never");
    return new Intl.DateTimeFormat(getLocale(), {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(ms));
  }

  async function doSyncNow() {
    const r = await run(() => invoke<SyncReport>("sync_now"));
    if (r) {
      syncMsg = t("sync.done", {
        pushed: r.pushed,
        new: r.pulled_new,
        updated: r.pulled_updated,
        conflicts: r.conflicts,
        copies: r.conflict_copies,
        discarded: r.discarded,
      });
      await refreshEntries();
      await refreshSyncStatus();
    }
  }

  // --- change master password ---
  let oldPw = $state("");
  let newPw = $state("");
  let showChangePw = $state(false);
  async function changePassword() {
    const ok = await run(() =>
      invoke("change_master_password", {
        oldPassword: oldPw,
        newPassword: newPw,
        secretKey: secretKeyInput,
      }),
    );
    if (ok !== undefined) {
      oldPw = "";
      newPw = "";
      showChangePw = false;
      alert(t("changePassword.done"));
    }
  }

  refreshStatus();
</script>

<main>
  <div class="topbar">
    <h1>{t("app.title")} <small>{t("app.subtitle")}</small></h1>
    <label class="language">
      {t("app.language")}
      <select
        value={getLocale()}
        onchange={(e) => setLocale((e.target as HTMLSelectElement).value as Locale)}
      >
        {#each SUPPORTED_LOCALES as loc}
          <option value={loc}>{loc === "en" ? "English" : "简体中文"}</option>
        {/each}
      </select>
    </label>
  </div>

  {#if error}<p class="error">{error}</p>{/if}

  {#if status === null}
    <p>{t("app.loading")}</p>
  {:else if generatedSecretKey}
    <section>
      <h2>{t("vault.created.title")}</h2>
      <p>{t("vault.created.body")}</p>
      <code class="secret">{generatedSecretKey}</code>
      {#if generatedAddress}
        <p>{t("vault.created.addressLabel")}:</p>
        <code class="secret">{generatedAddress}</code>
      {/if}
      <button
        onclick={() => {
          generatedSecretKey = null;
          generatedAddress = null;
        }}
      >
        {t("vault.created.saved")}
      </button>
    </section>
  {:else if !status.exists}
    {#if showJoin}
      <section>
        <h2>{t("join.title")}</h2>
        <p class="warn">{t("join.hint")}</p>
        <input
          type="text"
          placeholder={t("join.serverUrl")}
          bind:value={joinServer}
        />
        <input
          type="text"
          placeholder={t("join.address")}
          bind:value={joinAddress}
        />
        <input
          type="password"
          placeholder={t("join.password")}
          bind:value={joinPassword}
        />
        <input
          type="text"
          placeholder={t("join.secretKey")}
          bind:value={joinSecretKey}
        />
        <div class="row">
          <button
            disabled={busy ||
              !joinServer ||
              !joinAddress ||
              !joinPassword ||
              !joinSecretKey}
            onclick={joinVault}
          >
            {t("join.submit")}
          </button>
          <button onclick={() => (showJoin = false)}>
            {t("join.switchToCreate")}
          </button>
        </div>
      </section>
    {:else}
      <section>
        <h2>{t("vault.create.title")}</h2>
        <input
          type="password"
          placeholder={t("vault.create.password")}
          bind:value={password}
        />
        <input
          type="password"
          placeholder={t("vault.create.confirm")}
          bind:value={password2}
        />
        <p class="warn">{t("vault.create.warning")}</p>
        <div class="row">
          <button disabled={busy || !password} onclick={createVault}>
            {t("vault.create.submit")}
          </button>
          <button onclick={() => (showJoin = true)}>
            {t("join.switchToJoin")}
          </button>
        </div>
      </section>
    {/if}
  {:else if !status.unlocked}
    <section>
      <h2>{t("vault.unlock.title")}</h2>
      {#if biometric?.state === "available" && biometric.enrolled}
        <button disabled={busy} onclick={unlockBiometric}>
          {t("biometric.unlock.button")}
        </button>
      {/if}
      <input
        type="password"
        placeholder={t("vault.unlock.password")}
        bind:value={password}
      />
      <input
        type="text"
        placeholder={t("vault.unlock.secretKey")}
        bind:value={secretKeyInput}
      />
      {#if !status.password_only_available}
        <p>{t("vault.unlock.needSecretKeyOnce")}</p>
      {/if}
      <button disabled={busy || !password} onclick={unlock}>
        {t("vault.unlock.submit")}
      </button>
    </section>
  {:else}
    <section>
      <div class="row">
        <span>{t("vault.info", { id: status.vault_id?.slice(0, 8) ?? "" })}</span>
        {#if biometric?.state === "available"}
          {#if biometric.enrolled}
            <button onclick={disableBiometric}>{t("biometric.disable")}</button>
          {:else}
            <button onclick={enableBiometric}>{t("biometric.enable")}</button>
          {/if}
        {/if}
        <button onclick={() => (showChangePw = !showChangePw)}>
          {t("vault.changePassword")}
        </button>
        <button onclick={lock}>{t("vault.lock")}</button>
      </div>
      {#if showChangePw}
        <div class="row">
          <input
            type="password"
            placeholder={t("changePassword.current")}
            bind:value={oldPw}
          />
          <input
            type="password"
            placeholder={t("changePassword.new")}
            bind:value={newPw}
          />
          <input
            type="text"
            placeholder={t("changePassword.secretKey")}
            bind:value={secretKeyInput}
          />
          <button
            disabled={!oldPw || !newPw || !secretKeyInput}
            onclick={changePassword}
          >
            {t("changePassword.confirm")}
          </button>
        </div>
      {/if}

      <div class="row">
        <input
          type="search"
          placeholder={t("search.placeholder")}
          bind:value={query}
          oninput={refreshEntries}
        />
        <label>
          <input
            type="checkbox"
            bind:checked={showTrash}
            onchange={refreshEntries}
          />
          {t("search.trash")}
        </label>
      </div>
      <div class="row">
        <input
          type="text"
          placeholder={t("newEntry.title")}
          bind:value={newTitle}
        />
        <select bind:value={newKind}>
          <option value="account">{t("kind.account")}</option>
          <option value="card">{t("kind.card")}</option>
          <option value="identity">{t("kind.identity")}</option>
          <option value="note">{t("kind.note")}</option>
        </select>
        <button disabled={!newTitle.trim()} onclick={createEntry}>
          {t("newEntry.submit")}
        </button>
      </div>

      <ul class="list">
        {#each entries as entry (entry.id)}
          <li class:deleted={entry.deleted}>
            <button class="title" onclick={() => select(entry)}>
              {entry.favorite ? "★ " : ""}{entry.title}
              <small>· {kindLabel(entry.kind)}</small>
              {#if entry.conflict_copy_of}
                <span class="badge">{t("list.conflictCopy")}</span>
              {/if}
            </button>
            <button onclick={() => toggleFavorite(entry)}>
              {entry.favorite ? t("list.unfavorite") : t("list.favorite")}
            </button>
            {#if entry.deleted}
              <button onclick={() => restoreEntry(entry)}>
                {t("list.restore")}
              </button>
            {:else}
              <button onclick={() => trashEntry(entry)}>
                {t("list.delete")}
              </button>
            {/if}
          </li>
        {/each}
        {#if entries.length === 0}<li>{t("list.empty")}</li>{/if}
      </ul>

      {#if selected}
        <section class="editor">
          <h2>{t("editor.title")}</h2>
          <label>
            {t("editor.title")}
            <input type="text" bind:value={selected.title} />
          </label>

          {#if selected.payload.type === "account"}
            {@const acct = selected.payload as AccountPayload}
            <label>
              {t("editor.username")}
              <input type="text" bind:value={acct.username} />
            </label>
            <label>
              {t("editor.password")}
              <input
                type="text"
                value={acct.password ?? ""}
                oninput={(e) =>
                  (acct.password = (e.target as HTMLInputElement).value || null)}
              />
            </label>
            <div class="row">
              <button onclick={genPassword}>{t("editor.generatePassword")}</button>
              <button onclick={genPassphrase}>{t("editor.generatePhrase")}</button>
            </div>
            {#if strength}
              <p class="strength">
                {t("editor.strength", {
                  score: t(SCORE_KEYS[strength.score]),
                  bits: formatNumber(strength.entropy_bits),
                  time: crackText(strength.offline_crack_seconds),
                })}
                {#if strength.warnings.length}
                  <br />⚠ {strength.warnings.map(warningText).join("; ")}
                {/if}
              </p>
            {/if}
            <label>
              {t("editor.url")}
              <input
                type="text"
                value={acct.urls[0]?.url ?? ""}
                oninput={(e) => setFirstUrl((e.target as HTMLInputElement).value)}
              />
            </label>
            {#if acct.totp}
              <label>
                {t("editor.totpSecret")}
                <input type="text" bind:value={acct.totp.secret} />
              </label>
              {#if liveCode}
                <div class="row">
                  <span class="totp-code">{liveCode}</span>
                  <span>{t("editor.secondsLeft", { seconds: liveRemaining })}</span>
                </div>
              {/if}
              <label>
                {t("editor.issuer")}
                <input type="text" bind:value={acct.totp.issuer} />
              </label>
              <div class="row">
                <input
                  type="text"
                  placeholder={t("editor.otpauthPlaceholder")}
                  bind:value={otpauthInput}
                />
                <button disabled={!otpauthInput.trim()} onclick={importOtpauth}>
                  {t("editor.import")}
                </button>
              </div>
            {:else}
              <button onclick={enableTotp}>{t("editor.addTotp")}</button>
            {/if}
            <h3>{t("editor.passkeys")}</h3>
            {#each acct.passkeys as pk}
              <p>
                🔑 {pk.rp_id} · {t("editor.signCount", { count: pk.sign_count })}
              </p>
            {/each}
            <!-- Passkeys are only created when a site initiates registration
                 (AGENTS.md, ADR-0004); the editor never creates one. -->
          {:else if selected.payload.type === "card"}
            {@const card = selected.payload as CardPayload}
            <label>
              {t("editor.cardholder")}
              <input type="text" bind:value={card.cardholder_name} />
            </label>
            <label>
              {t("editor.number")}
              <input type="text" bind:value={card.number} />
            </label>
            <div class="row">
              <label>
                {t("editor.expMonth")}
                <input type="number" bind:value={card.expiry_month} />
              </label>
              <label>
                {t("editor.expYear")}
                <input type="number" bind:value={card.expiry_year} />
              </label>
              <label>
                {t("editor.cvc")}
                <input type="text" bind:value={card.cvc} />
              </label>
              <label>
                {t("editor.pin")}
                <input type="text" bind:value={card.pin} />
              </label>
            </div>
          {:else if selected.payload.type === "identity"}
            {@const identity = selected.payload as IdentityPayload}
            <label>
              {t("editor.fullName")}
              <input type="text" bind:value={identity.full_name} />
            </label>
            <div class="row">
              <label>
                {t("editor.firstName")}
                <input type="text" bind:value={identity.first_name} />
              </label>
              <label>
                {t("editor.lastName")}
                <input type="text" bind:value={identity.last_name} />
              </label>
            </div>
            <label>
              {t("editor.email")}
              <input
                type="text"
                value={identity.emails[0] ?? ""}
                oninput={(e) =>
                  (identity.emails = [(e.target as HTMLInputElement).value])}
              />
            </label>
            <label>
              {t("editor.phone")}
              <input
                type="text"
                value={identity.phones[0] ?? ""}
                oninput={(e) =>
                  (identity.phones = [(e.target as HTMLInputElement).value])}
              />
            </label>
          {:else}
            {@const note = selected.payload as NotePayload}
            <label>
              {t("editor.content")}
              <textarea bind:value={note.content} rows="8"></textarea>
            </label>
          {/if}

          <label>
            {t("editor.tags")}
            <input
              type="text"
              value={selected.tags.join(", ")}
              oninput={(e) => setTags((e.target as HTMLInputElement).value)}
            />
          </label>
          <label>
            {t("editor.notes")}
            <textarea bind:value={selected.notes} rows="3"></textarea>
          </label>

          <div class="row">
            <button disabled={busy} onclick={saveSelected}>
              {t("editor.save")}
            </button>
            <button onclick={() => (selected = null)}>
              {t("editor.close")}
            </button>
          </div>
        </section>
      {/if}

      <section class="editor">
        <h2>{t("import.title")}</h2>
        <div class="row">
          <select bind:value={impFormat}>
            <option value="csv">{t("import.formatCsv")}</option>
            <option value="bitwarden_json">{t("import.formatBitwardenJson")}</option>
            <option value="keepass_xml">{t("import.formatKeepass")}</option>
            <option value="yobei_json">{t("import.formatYobeiJson")}</option>
            <option value="yobei_encrypted">
              {t("import.formatYobeiEncrypted")}
            </option>
          </select>
          {#if impFormat === "yobei_encrypted"}
            <input
              type="password"
              placeholder={t("import.exportPassword")}
              bind:value={impPassword}
            />
          {/if}
        </div>
        <textarea
          rows="5"
          placeholder={t("import.paste")}
          bind:value={impText}
        ></textarea>
        <div class="row">
          <button disabled={!impText.trim()} onclick={doPreview}>
            {t("import.preview")}
          </button>
          <button disabled={!impText.trim()} onclick={doImport}>
            {t("import.submit")}
          </button>
        </div>
        {#if impPreview}
          <ul class="list">
            {#each impPreview as p}
              {@const flags = [
                p.has_username ? t("import.flagUsername") : "",
                p.has_password ? t("import.flagPassword") : "",
                p.has_totp ? t("import.flagTotp") : "",
              ]
                .filter(Boolean)
                .join(" ")}
              <li>
                {p.title}
                <small>
                  {t("import.previewLine", {
                    kind: kindLabel(p.kind),
                    flags: flags ? `${flags} · ` : "",
                    urls: p.url_count,
                    fields: p.field_count,
                  })}
                </small>
              </li>
            {/each}
          </ul>
          <button onclick={doImport}>
            {t("import.commit", { count: impPreview.length })}
          </button>
        {/if}

        <h2>{t("export.title")}</h2>
        <div class="row">
          <button onclick={() => doExport("csv")}>{t("export.csv")}</button>
          <button onclick={() => doExport("json")}>{t("export.json")}</button>
          <input
            type="password"
            placeholder={t("export.password")}
            bind:value={expPassword}
          />
          <button disabled={!expPassword} onclick={() => doExport("encrypted")}>
            {t("export.encrypted")}
          </button>
        </div>
        <p class="warn">{t("export.plaintextWarning")}</p>
        {#if expText}
          <textarea rows="8" readonly value={expText}></textarea>
        {/if}
      </section>

      <section class="editor">
        <h2>{t("sync.title")}</h2>
        {#if syncStat?.configured}
          <p>
            {t("sync.server", { url: syncStat.server_url ?? "" })}<br />
            {t("sync.device", {
              id: syncStat.device_id?.slice(0, 8) ?? "",
              pending: syncStat.pending_ops,
            })}
          </p>
          <div class="row">
            <button disabled={busy} onclick={doSyncNow}>{t("sync.now")}</button>
            <button onclick={refreshSyncStatus}>{t("sync.refresh")}</button>
            <button onclick={refreshDevices}>{t("sync.devices")}</button>
          </div>
          {#if devices.length}
            <ul class="list">
              {#each devices as device (device.device_id)}
                <li>
                  <span class="title">
                    {device.name || device.device_id.slice(0, 8)}
                    {#if device.device_id === syncStat?.device_id}
                      <small>· {t("sync.currentDevice")}</small>
                    {/if}
                    <small>
                      · {t("sync.lastSeen", {
                        time: formatTime(device.last_seen_ms),
                      })}
                    </small>
                  </span>
                  <button onclick={() => revokeDevice(device)}>
                    {t("sync.revoke")}
                  </button>
                </li>
              {/each}
            </ul>
          {/if}
          {#if devicesMsg}<p>{devicesMsg}</p>{/if}
        {:else}
          <div class="row">
            <input
              type="text"
              placeholder={t("sync.urlPlaceholder")}
              bind:value={syncUrl}
            />
            <button disabled={!syncUrl.trim()} onclick={doSyncConfigure}>
              {t("sync.register")}
            </button>
          </div>
          <p class="warn">{t("sync.deployWarning")}</p>
        {/if}
        {#if syncMsg}<p>{syncMsg}</p>{/if}
      </section>
    </section>
  {/if}
</main>

<style>
  :root {
    font-family: system-ui, sans-serif;
  }
  main {
    max-width: 760px;
    margin: 0 auto;
    padding: 16px;
  }
  section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 12px;
  }
  .topbar {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .language {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
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
  .badge {
    margin-left: 6px;
    padding: 1px 6px;
    border: 1px solid #b26a00;
    border-radius: 999px;
    color: #b26a00;
    font-size: 11px;
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
  .warn {
    color: #b26a00;
    font-size: 13px;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
  }
  input,
  select,
  textarea,
  button {
    padding: 6px 8px;
    font-size: 14px;
  }
</style>
