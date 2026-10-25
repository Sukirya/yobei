//! Import and export.
//!
//! Importers map foreign formats onto the unified [`Record`] model
//! *without type loss*: a card stays a card (as fields on a card-kind
//! record), an identity stays an identity. The reference project's
//! importer coerced everything to "login" and destroyed the rest — the
//! tests here pin the opposite behavior.
//!
//! Import preview (DESIGN.md §6 borrow): the UI previews presence flags
//! only ([`ImportPreviewItem`]) — never secret values — before the user
//! commits an import.
//!
//! Exports: Bitwarden-compatible CSV and a plain JSON for interop, and
//! the recommended path — an encrypted `.yobei` export protected by its
//! own export password (Argon2id + XChaCha20-Poly1305, same primitives
//! as the vault itself).

use std::collections::HashMap;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use crate::crypto::{Argon2idParams, CryptoProfile};
use crate::keys;
use crate::record::{AccountData, Field, FieldKind, Record, RecordKind, RecordUrl, TotpConfig, UrlMatch};
use crate::totp;

pub fn kind_str(kind: &RecordKind) -> &'static str {
    match kind {
        RecordKind::Account => "account",
        RecordKind::ApiKey => "api_key",
        RecordKind::Card => "card",
        RecordKind::Identity => "identity",
        RecordKind::Note => "note",
        RecordKind::SshKey => "ssh_key",
        RecordKind::Custom => "custom",
    }
}

fn blank_record(kind: RecordKind, title: String) -> Record {
    Record {
        id: String::new(), // assigned by Service::import_records
        vault_id: String::new(),
        kind,
        title,
        favorite: false,
        tags: Vec::new(),
        fields: Vec::new(),
        account: None,
        notes: String::new(),
        created_at_ms: 0,
        updated_at_ms: 0,
        version: 1,
        hlc: 0,
        deleted: false,
    }
}

/// A TOTP cell from another manager: either an otpauth:// URI or a bare
/// base32 secret.
pub(crate) fn parse_totp_value(raw: &str) -> Option<TotpConfig> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("otpauth://") {
        totp::parse_otpauth_uri(raw).ok().map(|p| p.config)
    } else {
        Some(TotpConfig {
            secret: raw.to_string(),
            ..TotpConfig::default()
        })
    }
}

pub(crate) fn account_record(
    title: String,
    username: &str,
    password: &str,
    urls: Vec<String>,
    totp: Option<TotpConfig>,
    notes: &str,
) -> Record {
    let mut record = blank_record(RecordKind::Account, title);
    record.notes = notes.to_string();
    record.account = Some(AccountData {
        username: username.to_string(),
        password: password.to_string(),
        urls: urls
            .into_iter()
            .filter(|u| !u.trim().is_empty())
            .map(|u| RecordUrl {
                url: u.trim().to_string(),
                match_rule: UrlMatch::ExactDomain,
            })
            .collect(),
        totp,
        ..AccountData::default()
    });
    record
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

fn parse_csv(text: &str) -> Result<Vec<Record>, String> {
    let (headers, rows) = read_csv(text)?;
    let is_bitwarden = headers.iter().any(|h| h.starts_with("login_"))
        || (headers.iter().any(|h| h == "type") && headers.iter().any(|h| h == "folder"));
    if is_bitwarden {
        parse_bitwarden_csv(&rows)
    } else {
        parse_generic_csv(&headers, &rows)
    }
}

fn parse_bitwarden_csv(rows: &[CsvRow]) -> Result<Vec<Record>, String> {
    let mut out = Vec::new();
    for row in rows {
        let title = cell(row, &["name"]).to_string();
        if title.is_empty() {
            continue;
        }
        let kind = cell(row, &["type"]);
        let notes = cell(row, &["notes"]);
        let mut record = match kind {
            "login" => account_record(
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
            "card" | "identity" => {
                let record_kind = if kind == "card" {
                    RecordKind::Card
                } else {
                    RecordKind::Identity
                };
                let mut r = blank_record(record_kind, title);
                r.notes = notes.to_string();
                // Card/identity data lives in extra columns; preserve
                // every populated one as a field (no type loss).
                let prefix = format!("{kind}_");
                for (col, value) in row.iter() {
                    if let Some(name) = col.strip_prefix(&prefix) {
                        if !value.is_empty() {
                            r.fields.push(Field {
                                name: name.to_string(),
                                kind: FieldKind::Text,
                                value: value.clone(),
                            });
                        }
                    }
                }
                r
            }
            "note" => {
                let mut r = blank_record(RecordKind::Note, title);
                r.fields.push(Field {
                    name: "content".to_string(),
                    kind: FieldKind::Text,
                    value: notes.to_string(),
                });
                r
            }
            _ => continue,
        };
        record.favorite = cell(row, &["favorite"]) == "1";
        let folder = cell(row, &["folder"]);
        if !folder.is_empty() {
            record.tags.push(folder.to_string());
        }
        // Custom fields are stored as "name: value" lines in `fields`.
        for line in cell(row, &["fields"]).lines() {
            if let Some((name, value)) = line.split_once(':') {
                record.fields.push(Field {
                    name: name.trim().to_string(),
                    kind: FieldKind::Text,
                    value: value.trim().to_string(),
                });
            }
        }
        out.push(record);
    }
    if out.is_empty() {
        return Err("no importable rows found in Bitwarden CSV".to_string());
    }
    Ok(out)
}

fn parse_generic_csv(headers: &[String], rows: &[CsvRow]) -> Result<Vec<Record>, String> {
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
        out.push(account_record(
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

fn json_map_to_fields(map: &serde_json::Map<String, serde_json::Value>) -> Vec<Field> {
    map.iter()
        .filter_map(|(k, v)| {
            v.as_str().map(|s| Field {
                name: k.clone(),
                kind: FieldKind::Text,
                value: s.to_string(),
            })
        })
        .collect()
}

fn parse_bitwarden_json(text: &str) -> Result<Vec<Record>, String> {
    let parsed: BwJson =
        serde_json::from_str(text).map_err(|e| format!("parse Bitwarden JSON: {e}"))?;
    let mut out = Vec::new();
    for item in parsed.items {
        if item.name.is_empty() {
            continue;
        }
        let mut record = match item.kind {
            1 => {
                let login = item.login.unwrap_or(BwLogin {
                    username: None,
                    password: None,
                    totp: None,
                    uris: None,
                });
                account_record(
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
            3 | 4 => {
                let mut r = blank_record(
                    if item.kind == 3 {
                        RecordKind::Card
                    } else {
                        RecordKind::Identity
                    },
                    item.name.clone(),
                );
                r.notes = item.notes.clone().unwrap_or_default();
                let map = if item.kind == 3 { item.card } else { item.identity };
                if let Some(map) = map {
                    r.fields = json_map_to_fields(&map);
                }
                r
            }
            2 => {
                let mut r = blank_record(RecordKind::Note, item.name.clone());
                r.fields.push(Field {
                    name: "content".to_string(),
                    kind: FieldKind::Text,
                    value: item.notes.clone().unwrap_or_default(),
                });
                r
            }
            _ => continue,
        };
        record.favorite = item.favorite;
        if let Some(fields) = item.fields {
            for f in fields {
                record.fields.push(Field {
                    name: f.name.unwrap_or_default(),
                    kind: FieldKind::Text,
                    value: f.value.unwrap_or_default(),
                });
            }
        }
        out.push(record);
    }
    if out.is_empty() {
        return Err("no importable items found in Bitwarden JSON".to_string());
    }
    Ok(out)
}

// ------------------------------------------------------------- exports ---

fn totp_export_value(totp: &Option<TotpConfig>) -> String {
    totp.as_ref().map(|t| t.secret.clone()).unwrap_or_default()
}

pub fn export_csv(records: &[Record]) -> Result<String, String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "folder", "favorite", "type", "name", "notes", "fields", "reprompt",
            "login_uri", "login_username", "login_password", "login_totp",
        ])
        .map_err(|e| format!("CSV write: {e}"))?;
    for r in records {
        if r.deleted {
            continue;
        }
        let fields_text = r
            .fields
            .iter()
            .map(|f| format!("{}: {}", f.name, f.value))
            .collect::<Vec<_>>()
            .join("\n");
        let (kind, uri, username, password, totp) = match (&r.kind, &r.account) {
            (RecordKind::Account, Some(a)) => (
                "login",
                a.urls
                    .iter()
                    .map(|u| u.url.clone())
                    .collect::<Vec<_>>()
                    .join(","),
                a.username.clone(),
                a.password.clone(),
                totp_export_value(&a.totp),
            ),
            (RecordKind::Card, _) => ("card", String::new(), String::new(), String::new(), String::new()),
            (RecordKind::Identity, _) => {
                ("identity", String::new(), String::new(), String::new(), String::new())
            }
            (RecordKind::Note, _) => ("note", String::new(), String::new(), String::new(), String::new()),
            _ => ("login", String::new(), String::new(), String::new(), String::new()),
        };
        writer
            .write_record([
                "",
                if r.favorite { "1" } else { "0" },
                kind,
                &r.title,
                &r.notes,
                &fields_text,
                "0",
                &uri,
                &username,
                &password,
                &totp,
            ])
            .map_err(|e| format!("CSV write: {e}"))?;
    }
    let bytes = writer.into_inner().map_err(|e| format!("CSV write: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "CSV is not valid UTF-8".to_string())
}

pub fn export_json(records: &[Record]) -> Result<String, String> {
    let live: Vec<&Record> = records.iter().filter(|r| !r.deleted).collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "format": "yobei-records-1",
        "records": live,
    }))
    .map_err(|e| format!("serialize export: {e}"))
}

fn parse_yobei_json(text: &str) -> Result<Vec<Record>, String> {
    #[derive(Deserialize)]
    struct YobeiExport {
        records: Vec<Record>,
    }
    let parsed: YobeiExport =
        serde_json::from_str(text).map_err(|e| format!("parse yobei JSON: {e}"))?;
    Ok(parsed.records)
}

#[derive(Serialize, Deserialize)]
struct EncryptedExport {
    format: String,
    kdf_params: Argon2idParams,
    salt_b64: String,
    ciphertext_b64: String,
}

pub fn export_encrypted(records: &[Record], export_password: &str) -> Result<String, String> {
    if export_password.is_empty() {
        return Err("export password must not be empty".to_string());
    }
    let profile = CryptoProfile::default();
    let salt = keys::random_bytes(keys::KDF_SALT_LEN);
    let key = keys::derive_kek(export_password, &salt, profile.kdf_params, None)?;
    let live: Vec<&Record> = records.iter().filter(|r| !r.deleted).collect();
    let plaintext =
        serde_json::to_vec(&live).map_err(|e| format!("serialize export: {e}"))?;
    let ciphertext = keys::encrypt_blob(&key, &plaintext)?;
    let file = EncryptedExport {
        format: "yobei-encrypted-export-1".to_string(),
        kdf_params: profile.kdf_params,
        salt_b64: BASE64.encode(&salt),
        ciphertext_b64: BASE64.encode(&ciphertext),
    };
    serde_json::to_string_pretty(&file).map_err(|e| format!("serialize export file: {e}"))
}

fn import_encrypted(text: &str, export_password: Option<&str>) -> Result<Vec<Record>, String> {
    let password = export_password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "this is an encrypted export; an export password is required".to_string())?;
    let file: EncryptedExport =
        serde_json::from_str(text).map_err(|e| format!("parse encrypted export: {e}"))?;
    if file.format != "yobei-encrypted-export-1" {
        return Err(format!("unsupported export format: {}", file.format));
    }
    let salt = BASE64
        .decode(file.salt_b64.as_bytes())
        .map_err(|_| "corrupt export (salt)".to_string())?;
    let ciphertext = BASE64
        .decode(file.ciphertext_b64.as_bytes())
        .map_err(|_| "corrupt export (ciphertext)".to_string())?;
    let key = keys::derive_kek(password, &salt, file.kdf_params, None)?;
    let plaintext = keys::decrypt_blob(&key, &ciphertext)
        .map_err(|_| "wrong export password or corrupt export".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("parse exported records: {e}"))
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

pub fn preview(records: &[Record]) -> Vec<ImportPreviewItem> {
    records
        .iter()
        .map(|r| ImportPreviewItem {
            title: r.title.clone(),
            kind: kind_str(&r.kind).to_string(),
            has_username: r
                .account
                .as_ref()
                .map(|a| !a.username.is_empty())
                .unwrap_or(false),
            has_password: r
                .account
                .as_ref()
                .map(|a| !a.password.is_empty())
                .unwrap_or(false),
            has_totp: r
                .account
                .as_ref()
                .map(|a| a.totp.is_some())
                .unwrap_or(false),
            url_count: r.account.as_ref().map(|a| a.urls.len()).unwrap_or(0),
            field_count: r.fields.len(),
        })
        .collect()
}

/// Parse any supported import format into records (ids/timestamps are
/// placeholders; the service assigns real ones on commit).
pub fn parse_import(
    format: &str,
    text: &str,
    export_password: Option<&str>,
) -> Result<Vec<Record>, String> {
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

    const BW_CSV: &str = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        Work,1,login,GitHub,main account,,0,https://github.com,octocat,hunter2,JBSWY3DPEHPK3PXP\n\
        ,0,card,Visa Card,,,,,,,,\n\
        ,0,note,Shopping list,eggs and milk,,0,,,,\n";

    #[test]
    fn bitwarden_csv_preserves_types() {
        let records = parse_csv(BW_CSV).unwrap();
        assert_eq!(records.len(), 3);
        let gh = &records[0];
        assert_eq!(gh.kind, RecordKind::Account);
        assert!(gh.favorite);
        assert_eq!(gh.tags, vec!["Work"]);
        let acct = gh.account.as_ref().unwrap();
        assert_eq!(acct.username, "octocat");
        assert_eq!(acct.password, "hunter2");
        assert_eq!(acct.urls.len(), 1);
        assert!(acct.totp.is_some());
        // The card must stay a card, not be coerced into a login.
        assert_eq!(records[1].kind, RecordKind::Card);
        assert_eq!(records[2].kind, RecordKind::Note);
    }

    const CHROME_CSV: &str = "name,url,username,password,note\n\
        Example,https://example.com,alice,pw123,hello\n\
        Bank,https://bank.example,bob,secret,\n";

    #[test]
    fn chrome_csv_imports_as_accounts() {
        let records = parse_csv(CHROME_CSV).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].account.as_ref().unwrap().username, "alice");
        assert_eq!(records[1].title, "Bank");
    }

    const BW_JSON: &str = r#"{"items":[
        {"type":1,"name":"GitHub","favorite":true,
         "login":{"username":"octocat","password":"hunter2","totp":"otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                  "uris":[{"uri":"https://github.com"}]}},
        {"type":3,"name":"Visa","card":{"cardholderName":"A Person","number":"4111111111111111","expYear":"2030"}},
        {"type":2,"name":"Note1","notes":"hello note"}
    ]}"#;

    #[test]
    fn bitwarden_json_preserves_types_and_totp_uri() {
        let records = parse_bitwarden_json(BW_JSON).unwrap();
        assert_eq!(records.len(), 3);
        let acct = records[0].account.as_ref().unwrap();
        assert_eq!(acct.totp.as_ref().unwrap().issuer.as_deref(), Some("GitHub"));
        assert_eq!(records[1].kind, RecordKind::Card);
        assert!(records[1]
            .fields
            .iter()
            .any(|f| f.name == "number" && f.value == "4111111111111111"));
        assert_eq!(records[2].kind, RecordKind::Note);
    }

    #[test]
    fn preview_shows_presence_not_secrets() {
        let records = parse_csv(BW_CSV).unwrap();
        let items = preview(&records);
        assert_eq!(items.len(), 3);
        assert!(items[0].has_password && items[0].has_totp && items[0].has_username);
        let rendered = serde_json::to_string(&items).unwrap();
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn encrypted_export_roundtrip() {
        let records = parse_csv(CHROME_CSV).unwrap();
        let text = export_encrypted(&records, "export-pw").unwrap();
        let back = parse_import("yobei_encrypted", &text, Some("export-pw")).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(
            back[0].account.as_ref().unwrap().password,
            records[0].account.as_ref().unwrap().password
        );
        assert!(parse_import("yobei_encrypted", &text, Some("wrong")).is_err());
        assert!(parse_import("yobei_encrypted", &text, None).is_err());
    }

    #[test]
    fn csv_export_roundtrip_keeps_accounts() {
        let records = parse_csv(BW_CSV).unwrap();
        let text = export_csv(&records).unwrap();
        let back = parse_csv(&text).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].account.as_ref().unwrap().password, "hunter2");
    }
}
