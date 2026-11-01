//! Unified entry model (ADR-0004).
//!
//! Four kinds only: account / card / identity / note. Every kind shares one
//! envelope and one encryption/sync/conflict/delete path; only the payload
//! differs. API keys, SSH keys and other credentials live in notes as custom
//! fields — they are not entry kinds.
//!
//! This is the only entry model in the core: storage, crypto, sync and
//! transfer all work with these types.

use serde::{Deserialize, Serialize};

/// The only four entry kinds. Adding a fifth requires a new ADR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Account,
    Card,
    Identity,
    Note,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Account => "account",
            EntryKind::Card => "card",
            EntryKind::Identity => "identity",
            EntryKind::Note => "note",
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "account" => Ok(EntryKind::Account),
            "card" => Ok(EntryKind::Card),
            "identity" => Ok(EntryKind::Identity),
            "note" => Ok(EntryKind::Note),
            other => Err(format!("unknown entry kind: {other}")),
        }
    }
}

/// One stored entry. Exists only inside the encryption boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// UUIDv7 string (time-ordered, globally unique).
    pub id: String,
    pub vault_id: String,
    pub kind: EntryKind,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// Free-form notes attached to any kind.
    #[serde(default)]
    pub notes: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Version, incremented by exactly one on every local mutation
    /// (ADR-0003: version is the only conflict resolver).
    pub version: u64,
    /// Hybrid logical clock value, kept as metadata only (ADR-0003).
    pub hlc: u64,
    /// Tombstone flag. Deletion is a state, not a separate op shape.
    pub deleted: bool,
    /// Set when the entry enters the trash; used for the 30-day window.
    #[serde(default)]
    pub deleted_at_ms: Option<i64>,
    /// Set when this entry is a conflict copy of another entry (ADR-0003).
    /// The UI renders a localized badge; the data carries no user text.
    #[serde(default)]
    pub conflict_copy_of: Option<String>,
    pub payload: EntryPayload,
}

/// Type-specific payload. Internally tagged so the on-disk/sync JSON stays
/// self-describing and one envelope can carry every kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntryPayload {
    Account(AccountPayload),
    Card(CardPayload),
    Identity(IdentityPayload),
    Note(NotePayload),
}

impl EntryPayload {
    pub fn kind(&self) -> EntryKind {
        match self {
            EntryPayload::Account(_) => EntryKind::Account,
            EntryPayload::Card(_) => EntryKind::Card,
            EntryPayload::Identity(_) => EntryKind::Identity,
            EntryPayload::Note(_) => EntryKind::Note,
        }
    }

    /// Custom fields are allowed on every kind, so callers (search, export)
    /// do not need to match on the payload.
    pub fn custom_fields(&self) -> &[CustomField] {
        match self {
            EntryPayload::Account(payload) => &payload.custom_fields,
            EntryPayload::Card(payload) => &payload.custom_fields,
            EntryPayload::Identity(payload) => &payload.custom_fields,
            EntryPayload::Note(payload) => &payload.custom_fields,
        }
    }
}

// ------------------------------------------------------------------ account ---

/// Everything one account needs, in one entry: password, TOTP, passkeys and
/// recovery codes together (the user's core model).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPayload {
    #[serde(default)]
    pub username: String,
    /// `None` means "no password stored" (e.g. passkey-only account).
    #[serde(default)]
    pub password: Option<String>,
    /// Previous passwords, newest first.
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Saved sites. Empty means this account never participates in login
    /// autofill.
    #[serde(default)]
    pub urls: Vec<EntryUrl>,
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyCredential>,
    #[serde(default)]
    pub recovery_codes: Vec<RecoveryCode>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryUrl {
    pub url: String,
    pub match_rule: UrlMatch,
}

/// How a saved URL may be used for autofill matching (ADR-0004).
///
/// Only exact hosts and explicitly saved subdomain rules are allowed. There is
/// deliberately no "contains/suffix" rule: `github.com.evil.net` must never
/// match `github.com`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMatch {
    /// Host must equal this URL's host exactly.
    ExactHost,
    /// Host equals this URL's host or is one of its subdomains.
    HostAndSubdomains,
}

/// TOTP parameters (RFC 6238), stored on the account entry itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32 secret.
    pub secret: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub account_name: Option<String>,
    pub digits: u8,
    pub period_secs: u32,
    /// "SHA1" | "SHA256" | "SHA512".
    pub algorithm: String,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: None,
            account_name: None,
            digits: 6,
            period_secs: 30,
            algorithm: "SHA1".to_string(),
        }
    }
}

/// A real WebAuthn passkey credential. Created only when a website initiates
/// registration; the `rp_id` is the only trusted attribution anchor
/// (ADR-0004, ADR-0005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: Option<String>,
    #[serde(default)]
    pub user_name: Option<String>,
    #[serde(default)]
    pub user_display_name: Option<String>,
    pub user_handle: Vec<u8>,
    /// PKCS#8 DER private key (ES256), encrypted with the entry.
    pub private_key_pkcs8: Vec<u8>,
    /// COSE_Key public key (CBOR).
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub discoverable: bool,
    pub backup_eligible: bool,
    pub backed_up: bool,
    #[serde(default)]
    pub transports: Vec<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub code: String,
    #[serde(default)]
    pub used: bool,
    #[serde(default)]
    pub used_at_ms: Option<i64>,
}

// --------------------------------------------------------------------- card ---

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardPayload {
    #[serde(default)]
    pub cardholder_name: String,
    #[serde(default)]
    pub number: String,
    #[serde(default)]
    pub expiry_month: Option<u8>,
    #[serde(default)]
    pub expiry_year: Option<u16>,
    #[serde(default)]
    pub cvc: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub billing_address: Option<PostalAddress>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

// ----------------------------------------------------------------- identity ---

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPayload {
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub phones: Vec<String>,
    #[serde(default)]
    pub addresses: Vec<PostalAddress>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostalAddress {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub line1: String,
    #[serde(default)]
    pub line2: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub postal_code: String,
    #[serde(default)]
    pub country: String,
}

// --------------------------------------------------------------------- note ---

/// Notes (and therefore API keys / SSH keys / anything else) never participate
/// in autofill (ADR-0004).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotePayload {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
}

// ------------------------------------------------------------------ custom ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub kind: CustomFieldKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldKind {
    Text,
    Secret,
    Multiline,
    Url,
    Email,
    Phone,
    Number,
    Date,
}

// ---------------------------------------------------------------- constructors ---

impl Entry {
    fn new_with_payload(
        id: String,
        vault_id: String,
        title: String,
        now_ms: i64,
        payload: EntryPayload,
    ) -> Self {
        Self {
            id,
            vault_id,
            kind: payload.kind(),
            title,
            favorite: false,
            tags: Vec::new(),
            notes: String::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            version: 1,
            hlc: now_ms.max(0) as u64,
            deleted: false,
            deleted_at_ms: None,
            conflict_copy_of: None,
            payload,
        }
    }

    pub fn new_account(id: String, vault_id: String, title: String, now_ms: i64) -> Self {
        Self::new_with_payload(
            id,
            vault_id,
            title,
            now_ms,
            EntryPayload::Account(AccountPayload::default()),
        )
    }

    pub fn new_card(id: String, vault_id: String, title: String, now_ms: i64) -> Self {
        Self::new_with_payload(
            id,
            vault_id,
            title,
            now_ms,
            EntryPayload::Card(CardPayload::default()),
        )
    }

    pub fn new_identity(id: String, vault_id: String, title: String, now_ms: i64) -> Self {
        Self::new_with_payload(
            id,
            vault_id,
            title,
            now_ms,
            EntryPayload::Identity(IdentityPayload::default()),
        )
    }

    pub fn new_note(id: String, vault_id: String, title: String, now_ms: i64) -> Self {
        Self::new_with_payload(
            id,
            vault_id,
            title,
            now_ms,
            EntryPayload::Note(NotePayload::default()),
        )
    }

    /// Structural check run before encrypting or after decrypting. Catches a
    /// payload/kind mismatch that would otherwise silently mis-route autofill.
    pub fn validate(&self) -> Result<(), String> {
        if self.kind != self.payload.kind() {
            return Err(format!(
                "entry {} has kind {} but payload type {}",
                self.id,
                self.kind.as_str(),
                self.payload.kind().as_str()
            ));
        }
        if self.deleted && self.deleted_at_ms.is_none() {
            return Err(format!(
                "deleted entry {} has no deletion timestamp",
                self.id
            ));
        }
        if !self.deleted && self.deleted_at_ms.is_some() {
            return Err(format!(
                "live entry {} carries a deletion timestamp",
                self.id
            ));
        }
        Ok(())
    }

    /// Whether this entry may ever be offered to an autofill surface.
    /// Notes never are, regardless of their content (ADR-0004).
    pub fn may_participate_in_autofill(&self) -> bool {
        !self.deleted
            && matches!(
                self.kind,
                EntryKind::Account | EntryKind::Card | EntryKind::Identity
            )
    }

    /// Mutable access to the payload's custom fields, for importers that
    /// preserve unknown columns instead of dropping them.
    pub fn payload_custom_fields_mut(&mut self) -> &mut Vec<CustomField> {
        match &mut self.payload {
            EntryPayload::Account(payload) => &mut payload.custom_fields,
            EntryPayload::Card(payload) => &mut payload.custom_fields,
            EntryPayload::Identity(payload) => &mut payload.custom_fields,
            EntryPayload::Note(payload) => &mut payload.custom_fields,
        }
    }

    /// Login autofill candidate: an account with at least one saved URL and
    /// something to fill. Selecting candidates by URL is done by the caller.
    pub fn may_participate_in_login_autofill(&self) -> bool {
        if self.deleted || self.kind != EntryKind::Account {
            return false;
        }
        match &self.payload {
            EntryPayload::Account(account) => {
                !account.urls.is_empty()
                    && (account.password.is_some() || !account.passkeys.is_empty())
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_kinds_roundtrip() {
        let entries = [
            Entry::new_account("a".into(), "v".into(), "GitHub".into(), 1),
            Entry::new_card("c".into(), "v".into(), "Visa".into(), 1),
            Entry::new_identity("i".into(), "v".into(), "Me".into(), 1),
            Entry::new_note("n".into(), "v".into(), "Recovery".into(), 1),
        ];
        for entry in entries {
            entry.validate().unwrap();
            let json = serde_json::to_string(&entry).unwrap();
            let back: Entry = serde_json::from_str(&json).unwrap();
            assert_eq!(entry, back);
        }
    }

    #[test]
    fn account_payload_carries_everything_together() {
        let mut entry = Entry::new_account("a".into(), "v".into(), "GitHub".into(), 1);
        if let EntryPayload::Account(account) = &mut entry.payload {
            account.username = "octocat".into();
            account.password = Some("s3cret".into());
            account.urls.push(EntryUrl {
                url: "https://github.com".into(),
                match_rule: UrlMatch::ExactHost,
            });
            account.totp = Some(TotpConfig::default());
        }
        entry.validate().unwrap();
        assert!(entry.may_participate_in_login_autofill());
    }

    #[test]
    fn kind_and_payload_must_agree() {
        let mut entry = Entry::new_account("a".into(), "v".into(), "GitHub".into(), 1);
        entry.kind = EntryKind::Note;
        assert!(entry.validate().is_err());
    }

    #[test]
    fn notes_never_participate_in_autofill() {
        let mut note = Entry::new_note("n".into(), "v".into(), "API key".into(), 1);
        if let EntryPayload::Note(payload) = &mut note.payload {
            payload.content = "url: https://github.com\npassword: s3cret".into();
        }
        assert!(!note.may_participate_in_autofill());
        assert!(!note.may_participate_in_login_autofill());
    }

    #[test]
    fn account_without_url_never_offers_login_autofill() {
        let mut entry = Entry::new_account("a".into(), "v".into(), "API key".into(), 1);
        if let EntryPayload::Account(account) = &mut entry.payload {
            account.password = Some("secret".into());
        }
        assert!(!entry.may_participate_in_login_autofill());
    }

    #[test]
    fn deleted_entry_requires_timestamp() {
        let mut entry = Entry::new_note("n".into(), "v".into(), "X".into(), 1);
        entry.deleted = true;
        assert!(entry.validate().is_err());
        entry.deleted_at_ms = Some(2);
        entry.validate().unwrap();
        assert!(!entry.may_participate_in_autofill());
    }
}
