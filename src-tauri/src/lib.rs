//! yobei app shell: Tauri commands over yobei-core.
//!
//! The shell owns no business logic — it resolves the vault file path,
//! holds the unlocked `Service` in app state, and forwards calls. All
//! crypto and storage live in yobei-core (see docs/adr/).

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_yobei_biometric::BiometricExt;
use yobei_core::crypto::CryptoProfile;
use yobei_core::entry::{Entry, EntryKind, EntryPayload};
use yobei_core::secretkey;
use yobei_core::service::Service;
use yobei_core::vault::Vault;

#[derive(Default)]
struct AppState {
    service: Mutex<Option<Service>>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create app data dir: {e}"))?;
    Ok(dir.join("vault.yobei.db"))
}

fn parse_secret_key(text: &str) -> Result<Vec<u8>, String> {
    secretkey::parse_secret_key(text)
}

/// Normalize a sync address typed by the user: strip spaces and dashes,
/// uppercase (base32 canonical form).
fn normalize_address(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The sync credential travels in the Authorization header; refuse plain
/// HTTP except for local development.
fn validate_server_url(url: &str) -> Result<String, String> {
    let base = url.trim_end_matches('/').to_string();
    if base.starts_with("https://")
        || base.starts_with("http://localhost")
        || base.starts_with("http://127.0.0.1")
    {
        Ok(base)
    } else {
        Err("sync server URL must use https (http is allowed only for localhost)".to_string())
    }
}

fn with_service<T>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&mut Service) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    let service = guard
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(service)
}

#[derive(Serialize)]
struct VaultStatus {
    exists: bool,
    unlocked: bool,
    /// Secret Key is mandatory (ADR-0001); kept in the payload so the UI can
    /// explain the recovery-kit requirement.
    secret_key_enabled: bool,
    vault_id: Option<String>,
    sync_address: Option<String>,
}

#[tauri::command]
fn vault_status(app: AppHandle, state: State<'_, AppState>) -> Result<VaultStatus, String> {
    let path = vault_path(&app)?;
    let header = Vault::peek_header(&path);
    let guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    Ok(VaultStatus {
        exists: header.is_some(),
        unlocked: guard.is_some(),
        secret_key_enabled: header
            .as_ref()
            .map(|h| h.profile.secret_key_enabled)
            .unwrap_or(true),
        vault_id: guard
            .as_ref()
            .map(|s| s.vault_id().to_string())
            .or_else(|| header.as_ref().map(|h| h.vault_id.clone())),
        sync_address: guard
            .as_ref()
            .and_then(|s| s.sync_address().ok().map(|a| a.to_string()))
            .or_else(|| header.as_ref().and_then(|h| h.sync_address.clone())),
    })
}

#[derive(Serialize)]
struct CreateVaultResult {
    vault_id: String,
    /// Sync address (ADR-0002): part of the recovery kit, needed to join
    /// from a new device.
    sync_address: String,
    /// Shown to the user exactly once; required (with the password) to
    /// unlock on any device that does not hold it locally.
    secret_key: String,
}

#[tauri::command]
fn create_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
) -> Result<CreateVaultResult, String> {
    let path = vault_path(&app)?;
    // Secret Key is mandatory (ADR-0001).
    let secret_key_text = secretkey::generate_secret_key();
    let secret_key_bytes = parse_secret_key(&secret_key_text)?;
    let profile = CryptoProfile {
        secret_key_enabled: true,
        ..CryptoProfile::default()
    };
    let vault = Vault::create(&path, &password, Some(&secret_key_bytes), profile, now_ms())?;
    let service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let sync_address = service.sync_address()?.to_string();
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
    Ok(CreateVaultResult {
        vault_id,
        sync_address,
        secret_key: secret_key_text,
    })
}

#[tauri::command]
fn unlock_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    secret_key: String,
) -> Result<String, String> {
    let path = vault_path(&app)?;
    Vault::peek_header(&path).ok_or_else(|| "no vault found".to_string())?;
    if secret_key.trim().is_empty() {
        return Err("this vault requires its Secret Key".to_string());
    }
    let secret_key_bytes = parse_secret_key(&secret_key)?;
    let vault = Vault::open(&path, &password, Some(&secret_key_bytes))?;
    let service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
    Ok(vault_id)
}

/// Join an existing vault on this device using only the recovery kit
/// (sync address + Secret Key) and the master password (ADR-0002). Fetches
/// the encrypted bootstrap package, adopts the vault locally, registers
/// this device, and pulls existing entries.
#[tauri::command]
fn join_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    server_url: String,
    address: String,
    password: String,
    secret_key: String,
) -> Result<String, String> {
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("a local vault already exists".to_string());
    }
    let secret_key_bytes = parse_secret_key(&secret_key)?;
    let base = validate_server_url(&server_url)?;
    let address = normalize_address(&address);
    let resp = ureq::get(&format!("{base}/v1/vaults/{address}/bootstrap"))
        .call()
        .map_err(|e| format!("fetch bootstrap failed: {e}"))?;
    let body: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("bootstrap: bad response: {e}"))?;
    let package_b64 = body["bootstrap_b64"]
        .as_str()
        .ok_or("bootstrap response missing bootstrap_b64")?;
    let package = BASE64
        .decode(package_b64.as_bytes())
        .map_err(|_| "corrupt bootstrap package".to_string())?;

    let vault = Vault::adopt(&path, &password, &secret_key_bytes, &package, &address)?;
    let mut service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let (device_id, token) = register_device(&base, &service)?;
    {
        let vault = service.vault_mut();
        vault.set_sync_state("sync_server_url", &base)?;
        vault.set_sync_state("sync_device_id", &device_id)?;
        vault.set_sync_state("sync_token", &token)?;
    }
    let sync_result = sync_once(&mut service, now_ms());
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
    // The vault is usable even if the first pull failed; surface the error
    // so the UI can offer a retry.
    sync_result?;
    Ok(vault_id)
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = None; // dropping the Service drops (and zeroizes) the vault key
    Ok(())
}

// ------------------------------------------------------- biometric unlock ---

/// Biometric unlock state (ADR-0009). `state` is "available" |
/// "no_hardware" | "not_enrolled" | "no_device_credential" | "unavailable"
/// | "unsupported" (non-Android); `enrolled` says whether this device
/// already holds a wrapped vault key.
#[derive(Serialize)]
struct BiometricStatus {
    state: String,
    enrolled: bool,
}

#[tauri::command]
async fn biometric_status(app: AppHandle) -> Result<BiometricStatus, String> {
    match app.biometric().status().await {
        Ok(s) => Ok(BiometricStatus {
            state: s.state,
            enrolled: s.enrolled,
        }),
        Err(tauri_plugin_yobei_biometric::Error::UnsupportedPlatform) => Ok(BiometricStatus {
            state: "unsupported".to_string(),
            enrolled: false,
        }),
        Err(e) => Err(e.to_string()),
    }
}

/// Enroll this device for biometric unlock. Requires the vault to be
/// unlocked; takes the vault key out of memory (never the password or the
/// Secret Key) and hands it to the platform adapter, which wraps it under
/// the device keystore key after one biometric authentication.
#[tauri::command]
async fn biometric_enable(
    app: AppHandle,
    state: State<'_, AppState>,
    title: String,
    subtitle: String,
) -> Result<(), String> {
    let (vault_key, key_check) = {
        let mut guard = state
            .service
            .lock()
            .map_err(|_| "app state poisoned".to_string())?;
        let service = guard
            .as_mut()
            .ok_or_else(|| "vault is locked".to_string())?;
        let vault = service.vault_mut();
        let key = *vault.vault_key();
        let check = Vault::vault_key_check(&key)?;
        (key, check)
    };
    let vault_key_b64 = BASE64.encode(&vault_key);
    let key_check_b64 = BASE64.encode(&key_check);
    app.biometric()
        .enroll(&vault_key_b64, &key_check_b64, &title, &subtitle)
        .await
        .map_err(|e| e.to_string())
}

/// Unlock with the device keystore key after one biometric authentication.
/// The vault key travels only between the platform adapter and core; it
/// never enters the webview.
#[tauri::command]
async fn biometric_unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    title: String,
    subtitle: String,
) -> Result<String, String> {
    let path = vault_path(&app)?;
    Vault::peek_header(&path).ok_or_else(|| "no vault found".to_string())?;
    let resp = app
        .biometric()
        .unlock(&title, &subtitle)
        .await
        .map_err(|e| e.to_string())?;
    let vault_key = BASE64
        .decode(resp.vault_key_b64.as_bytes())
        .map_err(|_| "bad biometric key".to_string())?;
    let key_check = BASE64
        .decode(resp.key_check_b64.as_bytes())
        .map_err(|_| "bad biometric key".to_string())?;
    let vault_key: [u8; 32] = vault_key
        .try_into()
        .map_err(|_| "bad biometric key".to_string())?;
    let key_check: [u8; 32] = key_check
        .try_into()
        .map_err(|_| "bad biometric key".to_string())?;
    let vault = match Vault::open_with_key(&path, &vault_key, &key_check) {
        Ok(v) => v,
        Err(e) if e == "biometric key does not match this vault" => {
            // Stale blob (the vault was recreated after enrollment): drop
            // it so the user can re-enable, and fall back to the password.
            let _ = app.biometric().remove().await;
            return Err("biometric_key_invalidated".to_string());
        }
        Err(e) => return Err(e),
    };
    let service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
    Ok(vault_id)
}

/// Forget the wrapped vault key on this device (and its keystore key).
/// The vault itself is untouched; unlocking falls back to the password.
#[tauri::command]
async fn biometric_disable(app: AppHandle) -> Result<(), String> {
    app.biometric().remove().await.map_err(|e| e.to_string())
}

#[tauri::command]
fn change_master_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
    secret_key: String,
) -> Result<(), String> {
    let secret_key_bytes = parse_secret_key(&secret_key)?;
    with_service(&state, |service| {
        service.vault_mut().change_password(
            &old_password,
            &new_password,
            Some(&secret_key_bytes),
        )?;
        // The salt and wrapped key changed, so the bootstrap package a new
        // device would fetch must be refreshed (ADR-0002).
        if let Some(base) = service.vault_mut().get_sync_state("sync_server_url") {
            upload_bootstrap(&base, service).map_err(|e| {
                format!("password changed, but the sync server could not be updated: {e}")
            })?;
        }
        Ok(())
    })
}

#[tauri::command]
fn create_entry(state: State<'_, AppState>, kind: String, title: String) -> Result<Entry, String> {
    let kind = EntryKind::parse(&kind)?;
    with_service(&state, |service| {
        service.create_entry(kind, title, now_ms())
    })
}

#[tauri::command]
fn save_entry(state: State<'_, AppState>, entry: Entry) -> Result<Entry, String> {
    with_service(&state, |service| {
        // The webview edits content only. Identity, version, timestamps,
        // tombstone state and the conflict marker come from the store, so a
        // compromised frontend cannot forge sync metadata (ADR-0003/0007).
        let mut current = service
            .get_entry(&entry.id)?
            .ok_or_else(|| "entry not found".to_string())?;
        current.title = entry.title;
        current.favorite = entry.favorite;
        current.tags = entry.tags;
        current.notes = entry.notes;
        current.payload = entry.payload;
        service.save_entry(&mut current, now_ms())
    })
}

#[tauri::command]
fn get_entry(state: State<'_, AppState>, id: String) -> Result<Option<Entry>, String> {
    with_service(&state, |service| service.get_entry(&id))
}

#[tauri::command]
fn list_entries(
    state: State<'_, AppState>,
    query: Option<String>,
    include_deleted: Option<bool>,
) -> Result<Vec<Entry>, String> {
    with_service(&state, |service| {
        service.search(
            query.as_deref().unwrap_or(""),
            include_deleted.unwrap_or(false),
        )
    })
}

#[tauri::command]
fn set_favorite(state: State<'_, AppState>, id: String, favorite: bool) -> Result<(), String> {
    with_service(&state, |service| {
        service.set_favorite(&id, favorite, now_ms())
    })
}

#[tauri::command]
fn delete_entry(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_service(&state, |service| service.trash(&id, now_ms()))
}

#[tauri::command]
fn restore_entry(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_service(&state, |service| service.restore(&id, now_ms()))
}

#[derive(Serialize)]
struct TotpNow {
    code: String,
    remaining_secs: u32,
    period_secs: u32,
}

/// Live TOTP code for a config (saved or still being edited — the UI
/// passes the editor's current config, so codes preview before saving).
#[tauri::command]
fn totp_preview(config: yobei_core::entry::TotpConfig) -> Result<TotpNow, String> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(TotpNow {
        code: yobei_core::totp::totp_code(&config, now_secs)?,
        remaining_secs: yobei_core::totp::remaining_secs(&config, now_secs),
        period_secs: config.period_secs,
    })
}

#[tauri::command]
fn generate_totp_secret() -> String {
    yobei_core::totp::generate_secret()
}

#[derive(Serialize)]
struct ParsedOtpauthDto {
    config: yobei_core::entry::TotpConfig,
    account_name: Option<String>,
    label_issuer: Option<String>,
}

#[tauri::command]
fn parse_otpauth(uri: String) -> Result<ParsedOtpauthDto, String> {
    let parsed = yobei_core::totp::parse_otpauth_uri(&uri)?;
    Ok(ParsedOtpauthDto {
        config: parsed.config,
        account_name: parsed.account_name,
        label_issuer: parsed.label_issuer,
    })
}

#[tauri::command]
fn generate_password(options: yobei_core::passwords::GeneratorOptions) -> Result<String, String> {
    yobei_core::passwords::generate_password(&options)
}

#[tauri::command]
fn generate_passphrase(word_count: usize, separator: String) -> Result<String, String> {
    yobei_core::passwords::generate_passphrase(word_count, &separator)
}

#[tauri::command]
fn password_strength(password: String) -> yobei_core::passwords::StrengthReport {
    yobei_core::passwords::password_strength(&password)
}

#[tauri::command]
fn import_preview(
    format: String,
    text: String,
    export_password: Option<String>,
) -> Result<Vec<yobei_core::transfer::ImportPreviewItem>, String> {
    let entries = yobei_core::transfer::parse_import(&format, &text, export_password.as_deref())?;
    Ok(yobei_core::transfer::preview(&entries))
}

#[tauri::command]
fn import_execute(
    state: State<'_, AppState>,
    format: String,
    text: String,
    export_password: Option<String>,
) -> Result<usize, String> {
    let entries = yobei_core::transfer::parse_import(&format, &text, export_password.as_deref())?;
    with_service(&state, |service| service.import_entries(entries, now_ms()))
}

#[tauri::command]
fn export_csv(state: State<'_, AppState>) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_csv(&service.all_entries()?)
    })
}

#[tauri::command]
fn export_json(state: State<'_, AppState>) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_json(&service.all_entries()?)
    })
}

#[tauri::command]
fn export_encrypted(state: State<'_, AppState>, password: String) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_encrypted(&service.all_entries()?, &password)
    })
}

// ---------------------------------------------------------------- sync ---

/// HTTP adapter for the sync worker (workers/sync). Holds only the
/// server URL and this device's token; all protocol decisions live in
/// yobei-core's sync engine.
struct HttpTransport {
    base_url: String,
    token: String,
}

impl HttpTransport {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }
    fn auth(&self, req: ureq::Request) -> ureq::Request {
        req.set("Authorization", &format!("Bearer {}", self.token))
    }
}

impl yobei_core::ports::SyncTransportPort for HttpTransport {
    fn push_ops(&self, vault_id: &str, ops_json: &str) -> Result<String, String> {
        let resp = self
            .auth(ureq::post(&self.url(&format!("/v1/vaults/{vault_id}/ops"))))
            .set("Content-Type", "application/json")
            .send_string(ops_json)
            .map_err(|e| format!("sync push failed: {e}"))?;
        resp.into_string()
            .map_err(|e| format!("sync push: bad response: {e}"))
    }

    fn fetch_manifest(&self, vault_id: &str) -> Result<String, String> {
        let resp = self
            .auth(ureq::get(
                &self.url(&format!("/v1/vaults/{vault_id}/manifest")),
            ))
            .call()
            .map_err(|e| format!("sync manifest failed: {e}"))?;
        resp.into_string()
            .map_err(|e| format!("sync manifest: bad response: {e}"))
    }

    fn fetch_entry(&self, vault_id: &str, entry_id: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .auth(ureq::get(
                &self.url(&format!("/v1/vaults/{vault_id}/entries/{entry_id}")),
            ))
            .call()
            .map_err(|e| format!("sync fetch entry failed: {e}"))?;
        let mut buf = Vec::new();
        use std::io::Read;
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| format!("sync fetch entry: read failed: {e}"))?;
        Ok(buf)
    }
}

#[derive(Serialize)]
struct SyncStatusDto {
    configured: bool,
    server_url: Option<String>,
    device_id: Option<String>,
    pending_ops: usize,
}

fn read_sync_status(service: &mut Service) -> SyncStatusDto {
    let vault = service.vault_mut();
    SyncStatusDto {
        configured: vault.get_sync_state("sync_token").is_some(),
        server_url: vault.get_sync_state("sync_server_url"),
        device_id: vault.get_sync_state("sync_device_id"),
        pending_ops: vault.outbox_ops().map(|ops| ops.len()).unwrap_or(0),
    }
}

#[tauri::command]
fn sync_status(state: State<'_, AppState>) -> Result<SyncStatusDto, String> {
    with_service(&state, |service| Ok(read_sync_status(service)))
}

#[derive(Serialize, serde::Deserialize)]
struct DeviceDto {
    device_id: String,
    #[serde(default)]
    name: String,
    created_at_ms: i64,
    #[serde(default)]
    last_seen_ms: Option<i64>,
}

/// List the devices enrolled for this vault (owner auth).
#[tauri::command]
fn sync_devices(state: State<'_, AppState>) -> Result<Vec<DeviceDto>, String> {
    with_service(&state, |service| {
        let base = service
            .vault_mut()
            .get_sync_state("sync_server_url")
            .ok_or("sync is not configured yet")?;
        let address = service.sync_address()?.to_string();
        let auth = service.auth_key_b64()?;
        let resp = ureq::get(&format!("{base}/v1/vaults/{address}/devices"))
            .set("Authorization", &format!("Bearer {auth}"))
            .call()
            .map_err(|e| format!("list devices failed: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("devices: bad response: {e}"))?;
        let devices: Vec<DeviceDto> = serde_json::from_value(body["devices"].clone())
            .map_err(|e| format!("devices: bad payload: {e}"))?;
        Ok(devices)
    })
}

/// Revoke one device. If it is this device, forget the local token; the
/// local vault stays usable and sync can be configured again.
#[tauri::command]
fn sync_revoke_device(state: State<'_, AppState>, device_id: String) -> Result<(), String> {
    with_service(&state, |service| {
        let base = service
            .vault_mut()
            .get_sync_state("sync_server_url")
            .ok_or("sync is not configured yet")?;
        let address = service.sync_address()?.to_string();
        let auth = service.auth_key_b64()?;
        ureq::delete(&format!("{base}/v1/vaults/{address}/devices/{device_id}"))
            .set("Authorization", &format!("Bearer {auth}"))
            .call()
            .map_err(|e| format!("revoke device failed: {e}"))?;
        let current = service.vault_mut().get_sync_state("sync_device_id");
        if current.as_deref() == Some(device_id.as_str()) {
            let vault = service.vault_mut();
            vault.clear_sync_state("sync_device_id")?;
            vault.clear_sync_state("sync_token")?;
        }
        Ok(())
    })
}

/// Upload the bootstrap package and register this device with the user's
/// sync server. The auth key proves knowledge of the vault key (ADR-0002);
/// the server stores only its hash and its own revocable device token.
#[tauri::command]
fn sync_configure(state: State<'_, AppState>, server_url: String) -> Result<SyncStatusDto, String> {
    with_service(&state, |service| {
        let base = validate_server_url(&server_url)?;
        let (device_id, token) = register_device(&base, service)?;
        {
            let vault = service.vault_mut();
            vault.set_sync_state("sync_server_url", &base)?;
            vault.set_sync_state("sync_device_id", &device_id)?;
            vault.set_sync_state("sync_token", &token)?;
        }
        Ok(read_sync_status(service))
    })
}

/// PUT the sealed bootstrap package, then obtain a revocable device token.
fn register_device(base: &str, service: &Service) -> Result<(String, String), String> {
    upload_bootstrap(base, service)?;
    let address = service.sync_address()?.to_string();
    let auth_key = service.auth_key_b64()?;

    let resp = ureq::post(&format!("{base}/v1/vaults/{address}/devices"))
        .set("Authorization", &format!("Bearer {auth_key}"))
        .send_json(serde_json::json!({ "name": device_name() }))
        .map_err(|e| format!("device registration failed: {e}"))?;
    let body: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("registration: bad response: {e}"))?;
    let device_id = body["device_id"]
        .as_str()
        .ok_or("registration response missing device_id")?;
    let token = body["token"]
        .as_str()
        .ok_or("registration response missing token")?;
    Ok((device_id.to_string(), token.to_string()))
}

/// Upload (or refresh) the sealed bootstrap package. On the first upload the
/// server binds the address to the auth hash (TOFU); later uploads must carry
/// the auth key.
fn upload_bootstrap(base: &str, service: &Service) -> Result<(), String> {
    let address = service.sync_address()?.to_string();
    let package = BASE64.encode(service.bootstrap_package()?);
    let auth_key = service.auth_key_b64()?;
    let auth_hash = service.auth_hash_b64()?;
    ureq::put(&format!("{base}/v1/vaults/{address}/bootstrap"))
        .set("Authorization", &format!("Bearer {auth_key}"))
        .send_json(serde_json::json!({
            "bootstrap_b64": package,
            "auth_hash_b64": auth_hash,
        }))
        .map_err(|e| format!("bootstrap upload failed: {e}"))?;
    Ok(())
}

fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "device".to_string())
}

/// Create a passkey for an account entry and store it inside the entry
/// (encrypted like everything else). Passkeys are only created when a
/// website initiates registration (ADR-0004); this command is the bridge
/// used by the platform adapter once it has a real request.
#[tauri::command]
fn passkey_create(
    state: State<'_, AppState>,
    entry_id: String,
    rp_id: String,
    user_name: String,
) -> Result<Entry, String> {
    with_service(&state, |service| {
        let mut entry = service
            .get_entry(&entry_id)?
            .ok_or_else(|| "entry not found".to_string())?;
        let user_handle = user_name.clone().into_bytes();
        let (credential, _attestation) = yobei_core::webauthn::create_credential(
            yobei_core::webauthn::CreateCredentialParams {
                rp_id,
                rp_name: None,
                user_name: Some(user_name),
                user_display_name: None,
                user_handle,
                discoverable: true,
                // The placeholder bridge has not performed a platform user
                // verification, so it must not claim UV.
                user_verified: false,
                now_ms: now_ms(),
            },
        )?;
        match &mut entry.payload {
            EntryPayload::Account(account) => account.passkeys.push(credential),
            _ => return Err("passkeys can only be added to account entries".to_string()),
        }
        service.save_entry(&mut entry, now_ms())
    })
}

fn sync_once(
    service: &mut Service,
    now_ms: i64,
) -> Result<yobei_core::syncengine::SyncReport, String> {
    let (server_url, token) = {
        let vault = service.vault_mut();
        (
            vault.get_sync_state("sync_server_url"),
            vault.get_sync_state("sync_token"),
        )
    };
    let (server_url, token) = match (server_url, token) {
        (Some(u), Some(t)) => (u, t),
        _ => return Err("sync is not configured yet".to_string()),
    };
    let transport = HttpTransport {
        base_url: server_url,
        token,
    };
    yobei_core::syncengine::sync_now(service, &transport, now_ms)
}

#[tauri::command]
fn sync_now(state: State<'_, AppState>) -> Result<yobei_core::syncengine::SyncReport, String> {
    with_service(&state, |service| sync_once(service, now_ms()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_yobei_biometric::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            unlock_vault,
            join_vault,
            lock_vault,
            biometric_status,
            biometric_enable,
            biometric_unlock,
            biometric_disable,
            change_master_password,
            create_entry,
            save_entry,
            get_entry,
            list_entries,
            set_favorite,
            delete_entry,
            restore_entry,
            totp_preview,
            generate_totp_secret,
            parse_otpauth,
            generate_password,
            generate_passphrase,
            password_strength,
            import_preview,
            import_execute,
            export_csv,
            export_json,
            export_encrypted,
            sync_status,
            sync_devices,
            sync_revoke_device,
            sync_configure,
            sync_now,
            passkey_create
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
