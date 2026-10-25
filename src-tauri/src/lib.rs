//! yobei app shell: Tauri commands over yobei-core.
//!
//! The shell owns no business logic — it resolves the vault file path,
//! holds the unlocked `Service` in app state, and forwards calls. All
//! crypto and storage live in yobei-core (see docs/DESIGN.md).

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use yobei_core::crypto::CryptoProfile;
use yobei_core::record::{Record, RecordKind};
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

fn parse_secret_key(provided: &Option<String>) -> Result<Option<Vec<u8>>, String> {
    match provided {
        Some(text) if !text.trim().is_empty() => Ok(Some(secretkey::parse_secret_key(text)?)),
        _ => Ok(None),
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
    secret_key_enabled: bool,
    vault_id: Option<String>,
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
            .unwrap_or(false),
        vault_id: guard
            .as_ref()
            .map(|s| s.vault_id().to_string())
            .or_else(|| header.map(|h| h.vault_id)),
    })
}

#[derive(Serialize)]
struct CreateVaultResult {
    vault_id: String,
    /// Shown to the user exactly once; required (with the password) to
    /// unlock on any device that does not hold it locally.
    secret_key: Option<String>,
}

#[tauri::command]
fn create_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    use_secret_key: bool,
) -> Result<CreateVaultResult, String> {
    let path = vault_path(&app)?;
    let (secret_key_text, secret_key_bytes) = if use_secret_key {
        let text = secretkey::generate_secret_key();
        let bytes = secretkey::parse_secret_key(&text)?;
        (Some(text), Some(bytes))
    } else {
        (None, None)
    };
    let mut profile = CryptoProfile::default();
    profile.secret_key_enabled = use_secret_key;
    let vault = Vault::create(
        &path,
        &password,
        secret_key_bytes.as_deref(),
        profile,
        now_ms(),
    )?;
    let service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
    Ok(CreateVaultResult {
        vault_id,
        secret_key: secret_key_text,
    })
}

#[tauri::command]
fn unlock_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    secret_key: Option<String>,
) -> Result<String, String> {
    let path = vault_path(&app)?;
    let header = Vault::peek_header(&path).ok_or_else(|| "no vault found".to_string())?;
    let secret_key_bytes = parse_secret_key(&secret_key)?;
    if header.profile.secret_key_enabled && secret_key_bytes.is_none() {
        return Err("此保险库启用了 Secret Key，请提供 Secret Key".to_string());
    }
    let vault = Vault::open(&path, &password, secret_key_bytes.as_deref())?;
    let service = Service::new(vault);
    let vault_id = service.vault_id().to_string();
    let mut guard = state
        .service
        .lock()
        .map_err(|_| "app state poisoned".to_string())?;
    *guard = Some(service);
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

#[tauri::command]
fn change_master_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
    secret_key: Option<String>,
) -> Result<(), String> {
    let secret_key_bytes = parse_secret_key(&secret_key)?;
    with_service(&state, |service| {
        service
            .vault_mut()
            .change_password(&old_password, &new_password, secret_key_bytes.as_deref())
    })
}

fn parse_kind(kind: &str) -> Result<RecordKind, String> {
    match kind {
        "account" => Ok(RecordKind::Account),
        "api_key" => Ok(RecordKind::ApiKey),
        "card" => Ok(RecordKind::Card),
        "identity" => Ok(RecordKind::Identity),
        "note" => Ok(RecordKind::Note),
        "ssh_key" => Ok(RecordKind::SshKey),
        "custom" => Ok(RecordKind::Custom),
        other => Err(format!("unknown record kind: {other}")),
    }
}

#[tauri::command]
fn create_record(
    state: State<'_, AppState>,
    kind: String,
    title: String,
) -> Result<Record, String> {
    let kind = parse_kind(&kind)?;
    with_service(&state, |service| service.create_record(kind, title, now_ms()))
}

#[tauri::command]
fn save_record(state: State<'_, AppState>, mut record: Record) -> Result<Record, String> {
    with_service(&state, |service| {
        service.save_record(&mut record, now_ms())?;
        Ok(record)
    })
}

#[tauri::command]
fn get_record(state: State<'_, AppState>, id: String) -> Result<Option<Record>, String> {
    with_service(&state, |service| service.get_record(&id))
}

#[tauri::command]
fn list_records(
    state: State<'_, AppState>,
    query: Option<String>,
    include_deleted: Option<bool>,
) -> Result<Vec<Record>, String> {
    with_service(&state, |service| {
        service.search(query.as_deref().unwrap_or(""), include_deleted.unwrap_or(false))
    })
}

#[tauri::command]
fn set_favorite(state: State<'_, AppState>, id: String, favorite: bool) -> Result<(), String> {
    with_service(&state, |service| service.set_favorite(&id, favorite, now_ms()))
}

#[tauri::command]
fn delete_record(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_service(&state, |service| service.trash(&id, now_ms()))
}

#[tauri::command]
fn restore_record(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_service(&state, |service| service.restore(&id, now_ms()))
}

#[tauri::command]
fn purge_record(state: State<'_, AppState>, id: String) -> Result<(), String> {
    with_service(&state, |service| service.purge(&id))
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
fn totp_preview(config: yobei_core::record::TotpConfig) -> Result<TotpNow, String> {
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
    config: yobei_core::record::TotpConfig,
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
fn generate_password(
    options: yobei_core::passwords::GeneratorOptions,
) -> Result<String, String> {
    yobei_core::passwords::generate_password(&options)
}

#[tauri::command]
fn generate_passphrase(word_count: usize, separator: String) -> Result<String, String> {
    yobei_core::passwords::generate_passphrase(word_count, &separator)
}

#[tauri::command]
fn password_strength(
    password: String,
) -> yobei_core::passwords::StrengthReport {
    yobei_core::passwords::password_strength(&password)
}

#[tauri::command]
fn import_preview(
    format: String,
    text: String,
    export_password: Option<String>,
) -> Result<Vec<yobei_core::transfer::ImportPreviewItem>, String> {
    let records =
        yobei_core::transfer::parse_import(&format, &text, export_password.as_deref())?;
    Ok(yobei_core::transfer::preview(&records))
}

#[tauri::command]
fn import_execute(
    state: State<'_, AppState>,
    format: String,
    text: String,
    export_password: Option<String>,
) -> Result<usize, String> {
    let records =
        yobei_core::transfer::parse_import(&format, &text, export_password.as_deref())?;
    with_service(&state, |service| {
        service.import_records(records, now_ms())
    })
}

#[tauri::command]
fn export_csv(state: State<'_, AppState>) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_csv(&service.all_records()?)
    })
}

#[tauri::command]
fn export_json(state: State<'_, AppState>) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_json(&service.all_records()?)
    })
}

#[tauri::command]
fn export_encrypted(
    state: State<'_, AppState>,
    password: String,
) -> Result<String, String> {
    with_service(&state, |service| {
        yobei_core::transfer::export_encrypted(&service.all_records()?, &password)
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            unlock_vault,
            lock_vault,
            change_master_password,
            create_record,
            save_record,
            get_record,
            list_records,
            set_favorite,
            delete_record,
            restore_record,
            purge_record,
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
            export_encrypted
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
