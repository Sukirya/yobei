//! Import and export (ADR-0004 §5).
//!
//! Importers map foreign formats onto the unified [`Entry`] model without
//! losing a kind: a card stays a card, an identity stays an identity, a note
//! stays a note. Unknown columns are preserved as custom fields rather than
//! dropped.
//!
//! Import preview shows only presence flags ([`ImportPreviewItem`]) — never
//! secret values — before the user commits an import.
//!
//! Exports: Bitwarden-compatible CSV and plain JSON for interop, and the
//! recommended path — an encrypted `.yobei` export protected by its own
//! export password (Argon2id + XChaCha20-Poly1305, same primitives as the
//! vault itself).

use std::collections::HashMap;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::Argon2idParams;
use crate::entry::{
    CardPayload, CustomField, CustomFieldKind, Entry, EntryKind, EntryPayload, EntryUrl,
    IdentityPayload, TotpConfig, UrlMatch,
};
use crate::keys;
use crate::totp;

pub(crate) fn parse_totp_value(raw: &str) -> Option<TotpConfig> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("otpauth://") {
        totp::parse_otpauth_uri(raw).ok().map(|p| p.config)
    } else {
        // A bare base32 seed is accepted only if it actually decodes; storing
        // junk would fail later at display time (ADR-0004).
        totp::decode_secret(raw).ok().map(|_| TotpConfig {
            secret: raw.to_string(),
            ..TotpConfig::default()
        })
    }
}

fn blank_entry(kind: EntryKind, title: String) -> Entry {
    let id = String::new();
    let vault_id = String::new();
    let mut entry = match kind {
        EntryKind::Account => Entry::new_account(id, vault_id, title, 0),
        EntryKind::Card => Entry::new_card(id, vault_id, title, 0),
        EntryKind::Identity => Entry::new_identity(id, vault_id, title, 0),
        EntryKind::Note => Entry::new_note(id, vault_id, title, 0),
    };
    entry.created_at_ms = 0;
    entry.updated_at_ms = 0;
    entry
}

pub(crate) fn account_entry(
    title: String,
    username: &str,
    password: &str,
    urls: Vec<String>,
    totp: Option<TotpConfig>,
    notes: &str,
) -> Entry {
    let mut entry = blank_entry(EntryKind::Account, title);
    entry.notes = notes.to_string();
    if let EntryPayload::Account(account) = &mut entry.payload {
        account.username = username.to_string();
        account.password = if password.is_empty() {
            None
        } else {
            Some(password.to_string())
        };
        account.urls = urls
            .into_iter()
            .filter(|u| !u.trim().is_empty())
            .map(|u| EntryUrl {
                url: u.trim().to_string(),
                match_rule: UrlMatch::ExactHost,
            })
            .collect();
        account.totp = totp;
    }
    entry
}

// ---------------------------------------------------------------- CSV ---

type CsvRow = HashMap<String, String>;

fn read_csv(text: &str) -> Result<(Vec<String>, Vec<CsvRow>), String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("read CSV header: {e}"))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let mut rows = Vec::new();
    for result in reader.records() {
        let rec = result.map_err(|e| format!("read CSV row: {e}"))?;
        let mut row = HashMap::new();
        for (i, value) in rec.iter().enumerate() {
            if let Some(h) = headers.get(i) {
                row.insert(h.clone(), value.to_string());
            }
        }
        rows.push(row);
    }
    Ok((headers, rows))
}

fn cell<'a>(row: &'a CsvRow, keys: &[&str]) -> &'a str {
    for k in keys {
        if let Some(v) = row.get(*k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    ""
}

fn parse_csv(text: &str) -> Result<Vec<Entry>, String> {
    let (headers, rows) = read_csv(text)?;
    let is_bitwarden = headers.iter().any(|h| h.starts_with("login_"))
        || (headers.iter().any(|h| h == "type") && headers.iter().any(|h| h == "folder"));
    if is_bitwarden {
        parse_bitwarden_csv(&rows)
    } else {
        parse_generic_csv(&headers, &rows)
    }
}

fn parse_bitwarden_csv(rows: &[CsvRow]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for row in rows {
        let title = cell(row, &["name"]).to_string();
        if title.is_empty() {
            continue;
        }
        let kind = cell(row, &["type"]);
        let notes = cell(row, &["notes"]);
        let mut entry = match kind {
            "card" => {
                let mut entry = blank_entry(EntryKind::Card, title);
                entry.notes = notes.to_string();
                if let EntryPayload::Card(card) = &mut entry.payload {
                    fill_card_from_columns(row, card);
                }
                entry
            }
            "identity" => {
                let mut entry = blank_entry(EntryKind::Identity, title);
                entry.notes = notes.to_string();
                if let EntryPayload::Identity(identity) = &mut entry.payload {
                    fill_identity_from_columns(row, identity);
                }
                entry
            }
            "note" => {
                let mut entry = blank_entry(EntryKind::Note, title);
                if let EntryPayload::Note(note) = &mut entry.payload {
                    note.content = notes.to_string();
                }
                entry
            }
            "login" | "account" | "" => account_entry(
                title,
                cell(row, &["login_username"]),
                cell(row, &["login_password"]),
                cell(row, &["login_uri"])
                    .split(',')
                    .map(|s| s.to_string())
                    .collect(),
                parse_totp_value(cell(row, &["login_totp"])),
                notes,
            ),
            // Unknown types are preserved as notes rather than dropped
            // (ADR-0004 §5).
            other => {
                let mut entry = blank_entry(EntryKind::Note, title);
                if let EntryPayload::Note(note) = &mut entry.payload {
                    note.content = notes.to_string();
                    note.custom_fields.push(CustomField {
                        name: "original_type".to_string(),
                        kind: CustomFieldKind::Text,
                        value: other.to_string(),
                    });
                }
                entry
            }
        };
        entry.favorite = cell(row, &["favorite"]) == "1";
        let folder = cell(row, &["folder"]);
        if !folder.is_empty() {
            entry.tags.push(folder.to_string());
        }
        // Remaining custom fields are stored as "name: value" lines.
        for line in cell(row, &["fields"]).lines() {
            if let Some((name, value)) = line.split_once(':') {
                entry.payload_custom_fields_mut().push(CustomField {
                    name: name.trim().to_string(),
                    kind: CustomFieldKind::Text,
                    value: value.trim().to_string(),
                });
            }
        }
        out.push(entry);
    }
    if out.is_empty() {
        return Err("no importable rows found in Bitwarden CSV".to_string());
    }
    Ok(out)
}

fn fill_card_from_columns(row: &CsvRow, card: &mut CardPayload) {
    for (col, value) in row {
        let Some(name) = col.strip_prefix("card_") else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        match name {
            "cardholder_name" | "cardholdername" => card.cardholder_name = value.clone(),
            "number" => card.number = value.clone(),
            "exp_month" | "expmonth" => card.expiry_month = value.parse().ok(),
            "exp_year" | "expyear" => card.expiry_year = value.parse().ok(),
            "code" | "cvc" => card.cvc = Some(value.clone()),
            "pin" => card.pin = Some(value.clone()),
            other => card.custom_fields.push(CustomField {
                name: other.to_string(),
                kind: CustomFieldKind::Text,
                value: value.clone(),
            }),
        }
    }
}

fn fill_identity_from_columns(row: &CsvRow, identity: &mut IdentityPayload) {
    for (col, value) in row {
        let Some(name) = col.strip_prefix("identity_") else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        match name {
            "full_name" | "fullname" | "name" => identity.full_name = value.clone(),
            "first_name" | "firstname" => identity.first_name = value.clone(),
            "last_name" | "lastname" => identity.last_name = value.clone(),
            "email" => identity.emails.push(value.clone()),
            "phone" => identity.phones.push(value.clone()),
            other => identity.custom_fields.push(CustomField {
                name: other.to_string(),
                kind: CustomFieldKind::Text,
                value: value.clone(),
            }),
        }
    }
}

fn parse_generic_csv(headers: &[String], rows: &[CsvRow]) -> Result<Vec<Entry>, String> {
    // Chrome export (name,url,username,password,note) lands here too.
    let has_password = headers
        .iter()
        .any(|h| ["password", "pass"].contains(&h.as_str()));
    let has_username = headers
        .iter()
        .any(|h| ["username", "user", "login", "account"].contains(&h.as_str()));
    if !has_password && !has_username {
        return Err(
            "unrecognized CSV layout: need at least username/password columns \
             (supported: Bitwarden, Chrome, generic with name/url/username/password headers)"
                .to_string(),
        );
    }
    let mut out = Vec::new();
    for row in rows {
        let title = cell(row, &["name", "title"]);
        let url = cell(row, &["url", "website", "site", "login_uri"]);
        let username = cell(row, &["username", "user", "login", "account"]);
        let password = cell(row, &["password", "pass"]);
        if title.is_empty() && username.is_empty() && password.is_empty() {
            continue;
        }
        let title = if title.is_empty() {
            url.to_string()
        } else {
            title.to_string()
        };
        out.push(account_entry(
            title,
            username,
            password,
            vec![url.to_string()],
            parse_totp_value(cell(row, &["totp", "otp"])),
            cell(row, &["note", "notes", "comment"]),
        ));
    }
    if out.is_empty() {
        return Err("no importable rows found in CSV".to_string());
    }
    Ok(out)
}

// ------------------------------------------------------- Bitwarden JSON ---

#[derive(Deserialize)]
struct BwJson {
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    card: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    identity: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
}

#[derive(Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

fn json_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn parse_bitwarden_json(text: &str) -> Result<Vec<Entry>, String> {
    let parsed: BwJson =
        serde_json::from_str(text).map_err(|e| format!("parse Bitwarden JSON: {e}"))?;
    let mut out = Vec::new();
    for item in parsed.items {
        if item.name.is_empty() {
            continue;
        }
        let mut entry = match item.kind {
            1 => {
                let login = item.login.unwrap_or(BwLogin {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                });
                account_entry(
                    item.name.clone(),
                    login.username.as_deref().unwrap_or(""),
                    login.password.as_deref().unwrap_or(""),
                    login
                        .uris
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|u| u.uri.clone())
                        .collect(),
                    login.totp.as_deref().and_then(parse_totp_value),
                    item.notes.as_deref().unwrap_or(""),
                )
            }
            2 => {
                let mut entry = blank_entry(EntryKind::Note, item.name.clone());
                if let EntryPayload::Note(note) = &mut entry.payload {
                    note.content = item.notes.clone().unwrap_or_default();
                }
                entry
            }
            3 => {
                let mut entry = blank_entry(EntryKind::Card, item.name.clone());
                entry.notes = item.notes.clone().unwrap_or_default();
                if let (EntryPayload::Card(card), Some(map)) = (&mut entry.payload, item.card) {
                    fill_card_from_json(&map, card);
                }
                entry
            }
            4 => {
                let mut entry = blank_entry(EntryKind::Identity, item.name.clone());
                entry.notes = item.notes.clone().unwrap_or_default();
                if let (EntryPayload::Identity(identity), Some(map)) =
                    (&mut entry.payload, item.identity)
                {
                    fill_identity_from_json(&map, identity);
                }
                entry
            }
            _ => {
                // Unknown Bitwarden types are preserved as notes instead of
                // being silently dropped.
                let mut entry = blank_entry(EntryKind::Note, item.name.clone());
                if let EntryPayload::Note(note) = &mut entry.payload {
                    note.content = item.notes.clone().unwrap_or_default();
                    note.custom_fields.push(CustomField {
                        name: "original_type".to_string(),
                        kind: CustomFieldKind::Text,
                        value: item.kind.to_string(),
                    });
                    if let Some(map) = item.card {
                        for (key, value) in map {
                            if let Some(text) = json_text(&value) {
                                note.custom_fields.push(CustomField {
                                    name: key,
                                    kind: CustomFieldKind::Text,
                                    value: text,
                                });
                            }
                        }
                    }
                    if let Some(map) = item.identity {
                        for (key, value) in map {
                            if let Some(text) = json_text(&value) {
                                note.custom_fields.push(CustomField {
                                    name: key,
                                    kind: CustomFieldKind::Text,
                                    value: text,
                                });
                            }
                        }
                    }
                }
                entry
            }
        };
        entry.favorite = item.favorite;
        if let Some(fields) = item.fields {
            for f in fields {
                entry.payload_custom_fields_mut().push(CustomField {
                    name: f.name.unwrap_or_default(),
                    kind: CustomFieldKind::Text,
                    value: f.value.unwrap_or_default(),
                });
            }
        }
        out.push(entry);
    }
    if out.is_empty() {
        return Err("no importable items found in Bitwarden JSON".to_string());
    }
    Ok(out)
}

fn fill_card_from_json(map: &serde_json::Map<String, serde_json::Value>, card: &mut CardPayload) {
    for (key, value) in map {
        let Some(text) = json_text(value) else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "cardholdername" | "cardholder_name" => card.cardholder_name = text,
            "number" => card.number = text,
            "expmonth" => card.expiry_month = text.parse().ok(),
            "expyear" => card.expiry_year = text.parse().ok(),
            "code" | "cvc" => card.cvc = Some(text),
            "pin" => card.pin = Some(text),
            other => card.custom_fields.push(CustomField {
                name: other.to_string(),
                kind: CustomFieldKind::Text,
                value: text,
            }),
        }
    }
}

fn fill_identity_from_json(
    map: &serde_json::Map<String, serde_json::Value>,
    identity: &mut IdentityPayload,
) {
    for (key, value) in map {
        let Some(text) = json_text(value) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        match key.to_ascii_lowercase().as_str() {
            "fullname" | "full_name" => identity.full_name = text,
            "firstname" | "first_name" => identity.first_name = text,
            "lastname" | "last_name" => identity.last_name = text,
            "email" => identity.emails.push(text),
            "phone" => identity.phones.push(text),
            other => identity.custom_fields.push(CustomField {
                name: other.to_string(),
                kind: CustomFieldKind::Text,
                value: text,
            }),
        }
    }
}

// ------------------------------------------------------------- exports ---

fn custom_fields_text(entry: &Entry) -> String {
    entry
        .payload
        .custom_fields()
        .iter()
        .map(|f| format!("{}: {}", f.name, f.value))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn export_csv(entries: &[Entry]) -> Result<String, String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "fields",
            "reprompt",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
            "card_cardholder_name",
            "card_number",
            "card_exp_month",
            "card_exp_year",
            "card_code",
            "card_pin",
            "identity_full_name",
            "identity_first_name",
            "identity_last_name",
            "identity_email",
            "identity_phone",
        ])
        .map_err(|e| format!("CSV write: {e}"))?;
    for entry in entries {
        if entry.deleted {
            continue;
        }
        let folder = entry.tags.first().cloned().unwrap_or_default();
        let fields = custom_fields_text(entry);
        let mut row = vec![
            folder,
            if entry.favorite {
                "1".into()
            } else {
                "0".into()
            },
            // Bitwarden calls accounts "login"; keep the export importable.
            if entry.kind == EntryKind::Account {
                "login".to_string()
            } else {
                entry.kind.as_str().to_string()
            },
            entry.title.clone(),
            entry.notes.clone(),
            fields,
            "0".into(),
        ];
        // Seven fixed columns are always present; each kind fills its own.
        let mut login = vec![String::new(); 4];
        let mut card = vec![String::new(); 6];
        let mut identity = vec![String::new(); 5];
        match &entry.payload {
            EntryPayload::Account(account) => {
                login[0] = account
                    .urls
                    .iter()
                    .map(|u| u.url.clone())
                    .collect::<Vec<_>>()
                    .join(",");
                login[1] = account.username.clone();
                login[2] = account.password.clone().unwrap_or_default();
                login[3] = account
                    .totp
                    .as_ref()
                    .map(|t| t.secret.clone())
                    .unwrap_or_default();
            }
            EntryPayload::Card(card_payload) => {
                card[0] = card_payload.cardholder_name.clone();
                card[1] = card_payload.number.clone();
                card[2] = card_payload
                    .expiry_month
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                card[3] = card_payload
                    .expiry_year
                    .map(|y| y.to_string())
                    .unwrap_or_default();
                card[4] = card_payload.cvc.clone().unwrap_or_default();
                card[5] = card_payload.pin.clone().unwrap_or_default();
            }
            EntryPayload::Identity(identity_payload) => {
                identity[0] = identity_payload.full_name.clone();
                identity[1] = identity_payload.first_name.clone();
                identity[2] = identity_payload.last_name.clone();
                identity[3] = identity_payload.emails.first().cloned().unwrap_or_default();
                identity[4] = identity_payload.phones.first().cloned().unwrap_or_default();
            }
            EntryPayload::Note(note) => {
                row[4] = note.content.clone();
            }
        }
        row.extend(login);
        row.extend(card);
        row.extend(identity);
        writer
            .write_record(row.iter().map(|s| s.as_str()))
            .map_err(|e| format!("CSV write: {e}"))?;
    }
    let bytes = writer.into_inner().map_err(|e| format!("CSV write: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "CSV is not valid UTF-8".to_string())
}

pub fn export_json(entries: &[Entry]) -> Result<String, String> {
    let live: Vec<&Entry> = entries.iter().filter(|e| !e.deleted).collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "yobei-entries-1",
        "entries": live,
    }))
    .map_err(|e| format!("serialize export: {e}"))
}

fn parse_yobei_json(text: &str) -> Result<Vec<Entry>, String> {
    #[derive(Deserialize)]
    struct YobeiExport {
        entries: Vec<Entry>,
    }
    let parsed: YobeiExport =
        serde_json::from_str(text).map_err(|e| format!("parse yobei JSON: {e}"))?;
    Ok(parsed.entries)
}

#[derive(Serialize, Deserialize)]
struct EncryptedExport {
    format: String,
    kdf_params: Argon2idParams,
    salt_b64: String,
    ciphertext_b64: String,
}

pub fn export_encrypted(entries: &[Entry], export_password: &str) -> Result<String, String> {
    if export_password.is_empty() {
        return Err("export password must not be empty".to_string());
    }
    let params = Argon2idParams::DEFAULT;
    let salt = keys::random_bytes(keys::KDF_SALT_LEN);
    let key = keys::derive_kek(export_password, &salt, params, None)?;
    let live: Vec<&Entry> = entries.iter().filter(|e| !e.deleted).collect();
    let plaintext = serde_json::to_vec(&live).map_err(|e| format!("serialize export: {e}"))?;
    let ciphertext = keys::encrypt_blob(&key, &plaintext)?;
    let file = EncryptedExport {
        format: "yobei-encrypted-export-1".to_string(),
        kdf_params: params,
        salt_b64: BASE64.encode(&salt),
        ciphertext_b64: BASE64.encode(&ciphertext),
    };
    serde_json::to_string_pretty(&file).map_err(|e| format!("serialize export file: {e}"))
}

fn import_encrypted(text: &str, export_password: Option<&str>) -> Result<Vec<Entry>, String> {
    let password = export_password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "this is an encrypted export; an export password is required".to_string())?;
    let file: EncryptedExport =
        serde_json::from_str(text).map_err(|e| format!("parse encrypted export: {e}"))?;
    if file.format != "yobei-encrypted-export-1" {
        return Err(format!("unsupported export format: {}", file.format));
    }
    // Never feed untrusted KDF parameters straight into Argon2 (ADR-0001 §4).
    crate::bootstrap::validate_kdf_params(&file.kdf_params)?;
    let salt = BASE64
        .decode(file.salt_b64.as_bytes())
        .map_err(|_| "corrupt export (salt)".to_string())?;
    let ciphertext = BASE64
        .decode(file.ciphertext_b64.as_bytes())
        .map_err(|_| "corrupt export (ciphertext)".to_string())?;
    let key = keys::derive_kek(password, &salt, file.kdf_params, None)?;
    let plaintext = keys::decrypt_blob(&key, &ciphertext)
        .map_err(|_| "wrong export password or corrupt export".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("parse exported entries: {e}"))
}

// ------------------------------------------------------------- preview ---

/// Presence-flags-only preview of a pending import (never secret values).
#[derive(Debug, Clone, Serialize)]
pub struct ImportPreviewItem {
    pub title: String,
    pub kind: String,
    pub has_username: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub url_count: usize,
    pub field_count: usize,
}

pub fn preview(entries: &[Entry]) -> Vec<ImportPreviewItem> {
    entries
        .iter()
        .map(|entry| {
            let account = match &entry.payload {
                EntryPayload::Account(account) => Some(account),
                _ => None,
            };
            ImportPreviewItem {
                title: entry.title.clone(),
                kind: entry.kind.as_str().to_string(),
                has_username: account.is_some_and(|a| !a.username.is_empty()),
                has_password: account.is_some_and(|a| a.password.is_some()),
                has_totp: account.is_some_and(|a| a.totp.is_some()),
                url_count: account.map(|a| a.urls.len()).unwrap_or(0),
                field_count: entry.payload.custom_fields().len(),
            }
        })
        .collect()
}

/// Parse any supported import format into entries (ids/timestamps are
/// placeholders; the service assigns real ones on commit).
pub fn parse_import(
    format: &str,
    text: &str,
    export_password: Option<&str>,
) -> Result<Vec<Entry>, String> {
    match format {
        "csv" => parse_csv(text),
        "bitwarden_json" => parse_bitwarden_json(text),
        "keepass_xml" => crate::keepass::parse_keepass_xml(text),
        "yobei_json" => parse_yobei_json(text),
        "yobei_encrypted" => import_encrypted(text, export_password),
        other => Err(format!("unknown import format: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BW_CSV: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp,card_cardholder_name,card_number,card_exp_month,card_exp_year,card_code\n\
        Work,1,login,GitHub,main account,,0,https://github.com,octocat,hunter2,JBSWY3DPEHPK3PXP,,,,\n\
        ,0,card,Visa Card,,,,,,,,A Person,4111111111111111,12,2030,123\n\
        ,0,note,Shopping list,eggs and milk,,0,,,,\n";

    #[test]
    fn bitwarden_csv_preserves_kinds() {
        let entries = parse_csv(BW_CSV).unwrap();
        assert_eq!(entries.len(), 3);
        let gh = &entries[0];
        assert_eq!(gh.kind, EntryKind::Account);
        assert!(gh.favorite);
        assert_eq!(gh.tags, vec!["Work"]);
        if let EntryPayload::Account(account) = &gh.payload {
            assert_eq!(account.username, "octocat");
            assert_eq!(account.password.as_deref(), Some("hunter2"));
            assert_eq!(account.urls.len(), 1);
            assert!(account.totp.is_some());
        } else {
            panic!("expected account");
        }
        assert_eq!(entries[1].kind, EntryKind::Card);
        if let EntryPayload::Card(card) = &entries[1].payload {
            assert_eq!(card.number, "4111111111111111");
            assert_eq!(card.cardholder_name, "A Person");
            assert_eq!(card.expiry_month, Some(12));
        } else {
            panic!("expected card");
        }
        assert_eq!(entries[2].kind, EntryKind::Note);
    }

    const CHROME_CSV: &str = "name,url,username,password,note\n\
        Example,https://example.com,alice,pw123,hello\n\
        Bank,https://bank.example,bob,secret,\n";

    #[test]
    fn chrome_csv_imports_as_accounts() {
        let entries = parse_csv(CHROME_CSV).unwrap();
        assert_eq!(entries.len(), 2);
        if let EntryPayload::Account(account) = &entries[0].payload {
            assert_eq!(account.username, "alice");
        }
        assert_eq!(entries[1].title, "Bank");
    }

    const BW_JSON: &str = r#"{"items":[
        {"type":1,"name":"GitHub","favorite":true,
         "login":{"username":"octocat","password":"hunter2","totp":"otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                  "uris":[{"uri":"https://github.com"}]}},
        {"type":3,"name":"Visa","card":{"cardholderName":"A Person","number":"4111111111111111","expYear":"2030"}},
        {"type":4,"name":"Me","identity":{"firstName":"Ada","lastName":"Lovelace","email":"ada@example.com"}},
        {"type":2,"name":"Note1","notes":"hello note"}
    ]}"#;

    #[test]
    fn bitwarden_json_preserves_kinds_and_totp_uri() {
        let entries = parse_bitwarden_json(BW_JSON).unwrap();
        assert_eq!(entries.len(), 4);
        if let EntryPayload::Account(account) = &entries[0].payload {
            assert_eq!(
                account.totp.as_ref().unwrap().issuer.as_deref(),
                Some("GitHub")
            );
        } else {
            panic!("expected account");
        }
        assert_eq!(entries[1].kind, EntryKind::Card);
        if let EntryPayload::Card(card) = &entries[1].payload {
            assert_eq!(card.number, "4111111111111111");
        }
        assert_eq!(entries[2].kind, EntryKind::Identity);
        if let EntryPayload::Identity(identity) = &entries[2].payload {
            assert_eq!(identity.first_name, "Ada");
            assert_eq!(identity.emails, vec!["ada@example.com"]);
        }
        assert_eq!(entries[3].kind, EntryKind::Note);
    }

    #[test]
    fn preview_shows_presence_not_secrets() {
        let entries = parse_csv(BW_CSV).unwrap();
        let items = preview(&entries);
        assert_eq!(items.len(), 3);
        assert!(items[0].has_password && items[0].has_totp && items[0].has_username);
        let rendered = serde_json::to_string(&items).unwrap();
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn encrypted_export_roundtrip() {
        let entries = parse_csv(CHROME_CSV).unwrap();
        let text = export_encrypted(&entries, "export-pw").unwrap();
        let back = parse_import("yobei_encrypted", &text, Some("export-pw")).unwrap();
        assert_eq!(back.len(), 2);
        if let EntryPayload::Account(account) = &back[0].payload {
            assert_eq!(account.password.as_deref(), Some("pw123"));
        }
        assert!(parse_import("yobei_encrypted", &text, Some("wrong")).is_err());
        assert!(parse_import("yobei_encrypted", &text, None).is_err());
    }

    #[test]
    fn encrypted_export_rejects_absurd_kdf_parameters() {
        let entries = parse_csv(CHROME_CSV).unwrap();
        let text = export_encrypted(&entries, "export-pw").unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&text).unwrap();
        file["kdf_params"]["memory_kib"] = serde_json::json!(u32::MAX);
        let hostile = file.to_string();
        assert!(parse_import("yobei_encrypted", &hostile, Some("export-pw")).is_err());
    }

    #[test]
    fn csv_export_roundtrip_keeps_accounts() {
        let entries = parse_csv(BW_CSV).unwrap();
        let text = export_csv(&entries).unwrap();
        let back = parse_csv(&text).unwrap();
        assert_eq!(back.len(), 3);
        if let EntryPayload::Account(account) = &back[0].payload {
            assert_eq!(account.password.as_deref(), Some("hunter2"));
        }
        assert_eq!(back[1].kind, EntryKind::Card);
    }
}
