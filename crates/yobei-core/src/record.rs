//! Unified record model.
//!
//! Cards, identities and secure notes are not separate silos: every record
//! shares one structure and one encryption/sync path. A record "kind" is
//! only a template (preset fields, icon, validation) for UI and checks.
//! See docs/DESIGN.md §2.

use serde::{Deserialize, Serialize};

/// Record template kind. Storage, crypto and sync treat all kinds alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Account,
    ApiKey,
    Card,
    Identity,
    Note,
    SshKey,
    Custom,
}

/// Semantic type of a single field, for UI rendering and masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Password,
    Url,
    Email,
    Phone,
    TotpSecret,
    Date,
    Number,
}

/// One named field. Template kinds preset these; users can add their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub value: String,
}

/// How a saved URL may be used for autofill matching (anti-phishing:
/// exact-domain is the safe default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMatch {
    ExactDomain,
    Prefix,
    Regex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordUrl {
    pub url: String,
    pub match_rule: UrlMatch,
}

/// TOTP parameters (RFC 6238), stored on the account record itself.
/// Note for docs/UI: storing password + TOTP in one vault weakens the
/// separation that "two factors" implies; that is the user's informed
/// choice, surfaced honestly in the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32 secret.
    pub secret: String,
    pub issuer: Option<String>,
    pub digits: u8,       // typically 6
    pub period_secs: u32, // typically 30
    pub algorithm: String, // "SHA1" | "SHA256" | "SHA512"
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: None,
            digits: 6,
            period_secs: 30,
            algorithm: "SHA1".to_string(),
        }
    }
}

/// A real WebAuthn passkey credential, structured per the spec (this
/// replaces the reference project's placeholder string list — DESIGN.md
/// §6). Everything a software authenticator needs lives here; the whole
/// struct sits inside the record's encryption boundary, so the private
/// key is never stored or synced in plaintext. Platform adapters
/// (Android Credential Manager, Windows Hello) transport requests; the
/// cryptography lives in `webauthn.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// Raw credential ID bytes (also the record's lookup key at the RP).
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// The RP's opaque user id this credential was created for.
    pub user_handle: Vec<u8>,
    /// PKCS#8 DER private key (ES256). Encrypted at rest by the record
    /// encryption; never leaves the core.
    pub private_key_pkcs8: Vec<u8>,
    /// COSE_Key public key (CBOR), as embedded in attestation/authData.
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    /// Authenticator AAGUID (16 bytes).
    pub aaguid: Vec<u8>,
    pub discoverable: bool,
    pub backup_eligible: bool,
    pub backed_up: bool,
    /// Authenticator transports, e.g. ["internal"], ["internal","hybrid"].
    pub transports: Vec<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub code: String,
    pub used: bool,
}

/// Everything one account needs, in one record (the user's core model):
/// password, TOTP, passkeys and recovery codes live together.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountData {
    pub username: String,
    pub password: String,
    /// Previous passwords, newest first, so an old password can be
    /// recovered after a failed change on a site.
    pub password_history: Vec<String>,
    pub urls: Vec<RecordUrl>,
    pub totp: Option<TotpConfig>,
    pub passkeys: Vec<PasskeyCredential>,
    pub recovery_codes: Vec<RecoveryCode>,
}

/// A single vault record (plaintext domain model; exists only inside the
/// encryption boundary, never on the wire or on disk in this form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// UUIDv7 string (time-ordered, globally unique).
    pub id: String,
    pub vault_id: String,
    pub kind: RecordKind,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// Free-form / template fields for non-account kinds
    /// (api_key, card, identity, note uses a single `content` field, ...).
    pub fields: Vec<Field>,
    /// Present iff kind == Account.
    pub account: Option<AccountData>,
    pub notes: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// Per-record version, incremented on every local mutation.
    pub version: u64,
    /// Hybrid logical clock value for sync conflict detection.
    pub hlc: u64,
    /// Tombstone for sync delete semantics.
    pub deleted: bool,
}

impl Record {
    pub fn new_account(id: String, vault_id: String, title: String, now_ms: i64) -> Self {
        Self {
            id,
            vault_id,
            kind: RecordKind::Account,
            title,
            favorite: false,
            tags: Vec::new(),
            fields: Vec::new(),
            account: Some(AccountData::default()),
            notes: String::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            version: 1,
            hlc: 0,
            deleted: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_record_holds_everything_together() {
        let mut r = Record::new_account(
            "0199test-id".to_string(),
            "default".to_string(),
            "GitHub".to_string(),
            1_000,
        );
        let acct = r.account.as_mut().unwrap();
        acct.username = "octocat".to_string();
        acct.password = "s3cret".to_string();
        acct.totp = Some(TotpConfig {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            issuer: Some("GitHub".to_string()),
            ..TotpConfig::default()
        });
        acct.passkeys.push(PasskeyCredential {
            credential_id: vec![1, 2, 3],
            rp_id: "github.com".to_string(),
            rp_name: Some("GitHub".to_string()),
            user_name: Some("octocat".to_string()),
            user_display_name: None,
            user_handle: vec![42],
            private_key_pkcs8: vec![9, 9, 9],
            public_key_cose: vec![8, 8, 8],
            sign_count: 0,
            aaguid: vec![0; 16],
            discoverable: true,
            backup_eligible: true,
            backed_up: false,
            transports: vec!["internal".to_string()],
            created_at_ms: 1_000,
        });
        acct.recovery_codes.push(RecoveryCode {
            code: "abcd-1234".to_string(),
            used: false,
        });

        let json = serde_json::to_string(&r).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        let back_acct = back.account.unwrap();
        assert!(back_acct.totp.is_some());
        assert_eq!(back_acct.passkeys.len(), 1);
        assert_eq!(back_acct.recovery_codes.len(), 1);
    }

    #[test]
    fn card_is_just_a_template_over_fields() {
        let r = Record {
            id: "id-2".to_string(),
            vault_id: "default".to_string(),
            kind: RecordKind::Card,
            title: "Visa".to_string(),
            favorite: false,
            tags: vec![],
            fields: vec![Field {
                name: "number".to_string(),
                kind: FieldKind::Number,
                value: "4111".to_string(),
            }],
            account: None,
            notes: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            version: 1,
            hlc: 0,
            deleted: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(r, serde_json::from_str(&json).unwrap());
    }
}
