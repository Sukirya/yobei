//! Local HTTP API for the browser extension (ADR-0011).
//!
//! Desktop only. The server binds 127.0.0.1 (port 19445, falling forward
//! to 19455) and serves a tiny JSON API on a single background thread.
//! Everything except `GET /v1/ping` requires
//! `Authorization: Bearer <token>`; the token is a 32-byte random value
//! stored in `extension-token` under the app data dir (never in the vault,
//! never synced). No request or response is logged: plaintext must never
//! reach logs (AGENTS.md §1).

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::{AppState, now_ms, vault_path};
use yobei_core::entry::EntryKind;
use yobei_core::entry::{EntryPayload, EntryUrl, UrlMatch};

/// Default loopback port; the server falls forward if it is taken.
const DEFAULT_PORT: u16 = 19445;
const MAX_PORT: u16 = 19455;

/// Shared extension-API state, managed by the app.
pub struct ExtensionApi {
    port: Mutex<Option<u16>>,
    token: Mutex<String>,
}

#[derive(Serialize)]
pub struct ExtensionStatus {
    pub running: bool,
    pub port: Option<u16>,
}

fn lock<'a, T>(m: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Constant-time equality, so token guesses cannot be timed.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("cannot generate token: {e}"))?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

fn token_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(vault_path(app)?.with_file_name("extension-token"))
}

fn write_token_file(path: &PathBuf, token: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, token.as_bytes()))
            .map_err(|e| format!("cannot write extension token: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, token).map_err(|e| format!("cannot write extension token: {e}"))?;
    }
    Ok(())
}

/// Load the pairing token, generating and storing one on first run.
/// On non-desktop platforms the API does not exist; return an empty token.
pub fn load_or_create(app: &AppHandle) -> ExtensionApi {
    #[cfg(desktop)]
    {
        let token = token_path(app)
            .and_then(|p| match std::fs::read_to_string(&p) {
                Ok(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
                _ => {
                    let t = generate_token()?;
                    write_token_file(&p, &t)?;
                    Ok(t)
                }
            })
            .unwrap_or_else(|_| String::new());
        ExtensionApi {
            port: Mutex::new(None),
            token: Mutex::new(token),
        }
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        ExtensionApi {
            port: Mutex::new(None),
            token: Mutex::new(String::new()),
        }
    }
}

/// Start the loopback server on a background thread. Desktop only.
pub fn start_server(app: AppHandle) {
    #[cfg(desktop)]
    {
        std::thread::Builder::new()
            .name("yobei-extension-api".into())
            .spawn(move || {
                let server = (DEFAULT_PORT..=MAX_PORT).find_map(|port| {
                    tiny_http::Server::http(format!("127.0.0.1:{port}"))
                        .ok()
                        .map(|s| (port, s))
                });
                let Some((port, server)) = server else {
                    // No free port in range: the API stays down and the UI
                    // reports it as not running.
                    return;
                };
                if let Some(api) = app.try_state::<ExtensionApi>() {
                    *lock(&api.port) = Some(port);
                }
                for req in server.incoming_requests() {
                    handle(req, &app);
                }
            })
            .ok();
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
    }
}

pub fn status(app: &AppHandle) -> ExtensionStatus {
    match app.try_state::<ExtensionApi>() {
        Some(api) => {
            let port = *lock(&api.port);
            ExtensionStatus {
                running: port.is_some(),
                port,
            }
        }
        None => ExtensionStatus {
            running: false,
            port: None,
        },
    }
}

pub fn token(app: &AppHandle) -> Result<String, String> {
    #[cfg(desktop)]
    {
        let api = app
            .try_state::<ExtensionApi>()
            .ok_or("extension API is not available")?;
        Ok(lock(&api.token).clone())
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        Err("the browser extension API is only available on desktop".to_string())
    }
}

pub fn regenerate_token(app: &AppHandle) -> Result<String, String> {
    #[cfg(desktop)]
    {
        let new_token = generate_token()?;
        write_token_file(&token_path(app)?, &new_token)?;
        let api = app
            .try_state::<ExtensionApi>()
            .ok_or("extension API is not available")?;
        *lock(&api.token) = new_token.clone();
        Ok(new_token)
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        Err("the browser extension API is only available on desktop".to_string())
    }
}

// ------------------------------------------------------------- HTTP ---

#[cfg(desktop)]
fn json(req: tiny_http::Request, status: u16, value: serde_json::Value) {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    let _ = req.respond(
        tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            ),
    );
}

#[cfg(desktop)]
fn err(req: tiny_http::Request, status: u16, message: &str) {
    json(req, status, serde_json::json!({ "error": message }));
}

/// Case-insensitive header lookup (header names are ASCII).
#[cfg(desktop)]
fn header<'a>(req: &'a tiny_http::Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Only extension pages (or no Origin, e.g. curl) may call the API. A
/// random website must never be able to probe it, even though it would
/// still fail the token check.
#[cfg(desktop)]
fn origin_allowed(req: &tiny_http::Request) -> bool {
    let Some(value) = header(req, "Origin") else {
        return true;
    };
    value.starts_with("chrome-extension://")
        || value.starts_with("moz-extension://")
        || value.starts_with("safari-web-extension://")
}

#[cfg(desktop)]
fn read_json(req: &mut tiny_http::Request) -> Result<serde_json::Value, String> {
    let mut buf = Vec::new();
    req.as_reader()
        .read_to_end(&mut buf)
        .map_err(|_| "cannot read request body".to_string())?;
    if buf.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(&buf).map_err(|_| "invalid JSON body".to_string())
}

#[cfg(desktop)]
fn handle(mut req: tiny_http::Request, app: &AppHandle) {
    let method = req.method().clone();
    // CORS preflight from an extension page: echo its origin back.
    if method == tiny_http::Method::Options {
        let origin = header(&req, "Origin").map(|s| s.to_string()).filter(|o| {
            o.starts_with("chrome-extension://")
                || o.starts_with("moz-extension://")
                || o.starts_with("safari-web-extension://")
        });
        let mut resp = tiny_http::Response::empty(204);
        if let Some(o) = origin {
            for (name, value) in [
                ("Access-Control-Allow-Origin", o.as_str()),
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                (
                    "Access-Control-Allow-Headers",
                    "authorization, content-type",
                ),
            ] {
                resp = resp.with_header(
                    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap(),
                );
            }
        }
        let _ = req.respond(resp);
        return;
    }
    if !origin_allowed(&req) {
        err(req, 403, "forbidden origin");
        return;
    }
    let url = req.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url, String::new()),
    };
    let is_ping = method == tiny_http::Method::Get && path == "/v1/ping";
    if !is_ping {
        let authorized = header(&req, "Authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|presented| {
                app.try_state::<ExtensionApi>()
                    .map(|api| {
                        let stored = lock(&api.token);
                        !stored.is_empty() && ct_eq(presented, &stored)
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !authorized {
            err(req, 401, "unauthorized");
            return;
        }
    }
    match (method, path.as_str()) {
        (tiny_http::Method::Get, "/v1/ping") => {
            json(
                req,
                200,
                serde_json::json!({ "ok": true, "app": "yobei", "version": 1 }),
            );
        }
        (tiny_http::Method::Get, "/v1/status") => {
            let state = app.state::<AppState>();
            let locked = lock(&state.service).is_none();
            let exists = crate::vault_path(app)
                .map(|p| yobei_core::vault::Vault::peek_header(&p).is_some())
                .unwrap_or(false);
            json(
                req,
                200,
                serde_json::json!({ "locked": locked, "vault_exists": exists }),
            );
        }
        (tiny_http::Method::Post, "/v1/unlock") => match read_json(&mut req) {
            Ok(body) => {
                let password = body["password"].as_str().unwrap_or("").to_string();
                let secret_key = body["secret_key"].as_str().unwrap_or("").to_string();
                match crate::unlock_vault_inner(app, &password, &secret_key) {
                    Ok(vault_id) => json(req, 200, serde_json::json!({ "vault_id": vault_id })),
                    Err(e) => err(req, 400, &e),
                }
            }
            Err(e) => err(req, 400, &e),
        },
        (tiny_http::Method::Post, "/v1/lock") => match crate::lock_vault_inner(app) {
            Ok(()) => json(req, 200, serde_json::json!({ "ok": true })),
            Err(e) => err(req, 400, &e),
        },
        (tiny_http::Method::Get, "/v1/entries") => {
            let page_url = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("url="))
                .and_then(url_decode);
            let Some(page_url) = page_url else {
                err(req, 400, "missing url parameter");
                return;
            };
            match list_entries_for_url(app, &page_url) {
                Ok(entries) => json(req, 200, serde_json::json!({ "entries": entries })),
                Err(e) => err(req, e.0, &e.1),
            }
        }
        (tiny_http::Method::Get, p) if p.starts_with("/v1/entries/") => {
            let id = &p["/v1/entries/".len()..];
            match entry_credentials(app, id) {
                Ok(value) => json(req, 200, value),
                Err(e) => err(req, e.0, &e.1),
            }
        }
        (tiny_http::Method::Post, "/v1/entries") => match read_json(&mut req) {
            Ok(body) => {
                let url = body["url"].as_str().unwrap_or("").to_string();
                let username = body["username"].as_str().unwrap_or("").to_string();
                let password = body["password"].as_str().unwrap_or("").to_string();
                let title = body["title"].as_str().map(|s| s.to_string());
                match save_login(app, &url, &username, &password, title) {
                    Ok((id, title, updated)) => json(
                        req,
                        200,
                        serde_json::json!({ "id": id, "title": title, "updated": updated }),
                    ),
                    Err(e) => err(req, e.0, &e.1),
                }
            }
            Err(e) => err(req, 400, &e),
        },
        (tiny_http::Method::Post, "/v1/generate-password") => {
            let opts = match read_json(&mut req) {
                Ok(body) => {
                    let mut o = yobei_core::passwords::GeneratorOptions::default();
                    if let Some(n) = body["length"].as_u64() {
                        o.length = (n as usize).clamp(8, 128);
                    }
                    if let Some(s) = body["symbols"].as_bool() {
                        o.symbols = s;
                    }
                    o
                }
                Err(_) => yobei_core::passwords::GeneratorOptions::default(),
            };
            match yobei_core::passwords::generate_password(&opts) {
                Ok(pw) => json(req, 200, serde_json::json!({ "password": pw })),
                Err(e) => err(req, 400, &e),
            }
        }
        _ => err(req, 404, "not found"),
    }
}

#[cfg(desktop)]
fn url_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Host of a URL or bare domain, lowercased, without port or trailing dot.
#[cfg(desktop)]
fn host_of(raw: &str) -> Option<String> {
    let s = raw.trim().to_lowercase();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(&s);
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or("");
    let host = match s.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => s.split(':').next().unwrap_or(""),
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Domain matching (ADR-0004): exact host, or — only when the saved rule
/// says so — a subdomain of the saved host. `github.com.evil.net` never
/// matches `github.com`.
#[cfg(desktop)]
fn url_matches(saved: &EntryUrl, host: &str) -> bool {
    let Some(saved_host) = host_of(&saved.url) else {
        return false;
    };
    match saved.match_rule {
        UrlMatch::ExactHost => host == saved_host,
        UrlMatch::HostAndSubdomains => {
            host == saved_host || host.ends_with(&format!(".{saved_host}"))
        }
    }
}

#[derive(Serialize)]
#[cfg(desktop)]
struct EntrySummary {
    id: String,
    title: String,
    username: String,
    has_totp: bool,
}

/// Locked vaults report 409 with a stable message; other failures are
/// (status, message) pairs.
#[cfg(desktop)]
type ApiResult<T> = Result<T, (u16, String)>;

#[cfg(desktop)]
fn require_unlocked(app: &AppHandle) -> ApiResult<()> {
    let state = app.state::<AppState>();
    if lock(&state.service).is_none() {
        return Err((409, "vault is locked".to_string()));
    }
    Ok(())
}

#[cfg(desktop)]
fn list_entries_for_url(app: &AppHandle, page_url: &str) -> ApiResult<Vec<EntrySummary>> {
    require_unlocked(app)?;
    let Some(host) = host_of(page_url) else {
        return Err((400, "bad url".to_string()));
    };
    let state = app.state::<AppState>();
    let mut guard = lock(&state.service);
    let service = guard.as_mut().ok_or((409, "vault is locked".to_string()))?;
    let all = service.search("", false).map_err(|e| (400, e))?;
    Ok(all
        .into_iter()
        .filter_map(|e| {
            let EntryPayload::Account(a) = &e.payload else {
                return None;
            };
            if e.deleted || !a.urls.iter().any(|u| url_matches(u, &host)) {
                return None;
            }
            Some(EntrySummary {
                id: e.id.clone(),
                title: e.title.clone(),
                username: a.username.clone(),
                has_totp: a.totp.is_some(),
            })
        })
        .collect())
}

#[cfg(desktop)]
fn entry_credentials(app: &AppHandle, id: &str) -> ApiResult<serde_json::Value> {
    require_unlocked(app)?;
    let state = app.state::<AppState>();
    let mut guard = lock(&state.service);
    let service = guard.as_mut().ok_or((409, "vault is locked".to_string()))?;
    let entry = service
        .get_entry(id)
        .map_err(|e| (400, e))?
        .ok_or((404, "entry not found".to_string()))?;
    let EntryPayload::Account(a) = &entry.payload else {
        return Err((400, "not an account entry".to_string()));
    };
    let (totp_code, totp_remaining_secs) = match &a.totp {
        Some(config) => {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let code = yobei_core::totp::totp_code(config, now_secs).map_err(|e| (400, e))?;
            (
                Some(code),
                Some(yobei_core::totp::remaining_secs(config, now_secs)),
            )
        }
        None => (None, None),
    };
    Ok(serde_json::json!({
        "id": entry.id,
        "title": entry.title,
        "username": a.username,
        "password": a.password,
        "totp_code": totp_code,
        "totp_remaining_secs": totp_remaining_secs,
    }))
}

/// Save a login captured by the extension. Same host + username already
/// exists: only the password is updated, through the same save path the
/// desktop UI uses. Otherwise a new account entry is created.
#[cfg(desktop)]
fn save_login(
    app: &AppHandle,
    url: &str,
    username: &str,
    password: &str,
    title: Option<String>,
) -> ApiResult<(String, String, bool)> {
    require_unlocked(app)?;
    let Some(host) = host_of(url) else {
        return Err((400, "bad url".to_string()));
    };
    if username.is_empty() || password.is_empty() {
        return Err((400, "username and password are required".to_string()));
    }
    let state = app.state::<AppState>();
    let mut guard = lock(&state.service);
    let service = guard.as_mut().ok_or((409, "vault is locked".to_string()))?;
    let all = service.search("", false).map_err(|e| (400, e))?;
    for e in &all {
        let EntryPayload::Account(a) = &e.payload else {
            continue;
        };
        if e.deleted
            || a.username != username
            || !a
                .urls
                .iter()
                .any(|u| host_of(&u.url).as_deref() == Some(host.as_str()))
        {
            continue;
        }
        let mut current = service
            .get_entry(&e.id)
            .map_err(|e| (400, e))?
            .ok_or((404, "entry not found".to_string()))?;
        if let EntryPayload::Account(a2) = &mut current.payload {
            a2.password = Some(password.to_string());
        }
        let saved = service
            .save_entry(&mut current, now_ms())
            .map_err(|e| (400, e))?;
        return Ok((saved.id, saved.title, true));
    }
    let mut entry = service
        .create_entry(
            EntryKind::Account,
            title.unwrap_or_else(|| host.clone()),
            now_ms(),
        )
        .map_err(|e| (400, e))?;
    if let EntryPayload::Account(a) = &mut entry.payload {
        a.username = username.to_string();
        a.password = Some(password.to_string());
        a.urls = vec![EntryUrl {
            url: url.to_string(),
            match_rule: UrlMatch::ExactHost,
        }];
    }
    let saved = service
        .save_entry(&mut entry, now_ms())
        .map_err(|e| (400, e))?;
    Ok((saved.id, saved.title, false))
}
