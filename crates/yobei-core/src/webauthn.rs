//! WebAuthn software authenticator (passkeys), ES256 only for v0.1.
//!
//! This is the real protocol machinery the reference project faked with
//! opaque strings: credential creation produces a proper attestation
//! object (fmt = "none"), and assertions are genuine ECDSA signatures
//! over `authData ‖ SHA-256(clientDataJSON)` that any RP — or the test
//! suite — can verify against the COSE public key.
//!
//! Platform adapters (Android Credential Manager, Windows) transport
//! the platform's create/get requests into these calls and persist the
//! returned credential inside the account record; the private key never
//! leaves the encrypted record.

use ciborium::Value;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::keys;
use crate::record::PasskeyCredential;

/// yobei's authenticator AAGUID ("yobei-passkey-01" as bytes). Identifies
/// the authenticator model in attested credential data.
pub const YOBEI_AAGUID: [u8; 16] = *b"yobei-passkey-01";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

fn flags(attested: bool, backup_eligible: bool, backed_up: bool) -> u8 {
    let mut f = FLAG_UP | FLAG_UV;
    if attested {
        f |= FLAG_AT;
    }
    if backup_eligible {
        f |= FLAG_BE;
    }
    if backed_up {
        f |= FLAG_BS;
    }
    f
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(rp_id.as_bytes());
    h.finalize().into()
}

fn cose_public_key(signing_key: &SigningKey) -> Result<Vec<u8>, String> {
    let point = signing_key
        .verifying_key()
        .to_encoded_point(false);
    let x = point.x().ok_or("missing x coordinate")?;
    let y = point.y().ok_or("missing y coordinate")?;
    let cose = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
        (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
        (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
        (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&cose, &mut out).map_err(|e| format!("COSE encode: {e}"))?;
    Ok(out)
}

fn authenticator_data(
    rp_id: &str,
    flag_byte: u8,
    sign_count: u32,
    attested: Option<(&PasskeyCredential, &[u8])>,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&rp_id_hash(rp_id));
    data.push(flag_byte);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((cred, cose)) = attested {
        data.extend_from_slice(&cred.aaguid);
        data.extend_from_slice(&(cred.credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(&cred.credential_id);
        data.extend_from_slice(cose);
    }
    data
}

/// Create a new passkey credential. Returns the credential (to store in
/// the account record) and the attestation object for the RP.
pub fn create_credential(
    rp_id: &str,
    rp_name: Option<String>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    user_handle: Vec<u8>,
    discoverable: bool,
    now_ms: i64,
) -> Result<(PasskeyCredential, Vec<u8>), String> {
    let signing_key = SigningKey::random(&mut OsRng);
    let private_key_pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| format!("encode private key: {e}"))?
        .as_bytes()
        .to_vec();
    let public_key_cose = cose_public_key(&signing_key)?;
    let credential = PasskeyCredential {
        credential_id: keys::random_bytes(32),
        rp_id: rp_id.to_string(),
        rp_name,
        user_name,
        user_display_name,
        user_handle,
        private_key_pkcs8,
        public_key_cose: public_key_cose.clone(),
        sign_count: 0,
        aaguid: YOBEI_AAGUID.to_vec(),
        discoverable,
        backup_eligible: true, // vault-synced passkeys are multi-device
        backed_up: false,      // flips true after the first sync push
        transports: vec!["internal".to_string(), "hybrid".to_string()],
        created_at_ms: now_ms,
    };
    let auth_data = authenticator_data(
        rp_id,
        flags(true, credential.backup_eligible, credential.backed_up),
        0,
        Some((&credential, &public_key_cose)),
    );
    let attestation = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut object = Vec::new();
    ciborium::ser::into_writer(&attestation, &mut object)
        .map_err(|e| format!("attestation encode: {e}"))?;
    Ok((credential, object))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature over authenticator_data ‖ hash.
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub sign_count: u32,
}

/// Produce an assertion for a stored credential. Increments the
/// credential's sign counter (the caller persists the record).
pub fn create_assertion(
    credential: &mut PasskeyCredential,
    rp_id: &str,
    client_data_json: &[u8],
) -> Result<Assertion, String> {
    if credential.rp_id != rp_id {
        return Err(format!(
            "credential is for {}, not {rp_id}",
            credential.rp_id
        ));
    }
    credential.sign_count = credential.sign_count.saturating_add(1);
    let auth_data = authenticator_data(
        rp_id,
        flags(false, credential.backup_eligible, credential.backed_up),
        credential.sign_count,
        None,
    );
    let mut client_hash = Sha256::new();
    client_hash.update(client_data_json);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_hash.finalize());
    let signing_key = SigningKey::from_pkcs8_der(&credential.private_key_pkcs8)
        .map_err(|e| format!("decode private key: {e}"))?;
    let signature: Signature = signing_key.sign(&signed);
    Ok(Assertion {
        credential_id: credential.credential_id.clone(),
        authenticator_data: auth_data,
        signature: signature.to_der().as_bytes().to_vec(),
        user_handle: credential.user_handle.clone(),
        sign_count: credential.sign_count,
    })
}

/// Verify an assertion against a COSE public key (RP-side check; used by
/// tests and available to any future verification tooling).
pub fn verify_assertion(
    public_key_cose: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_der: &[u8],
) -> Result<bool, String> {
    let cose: Value = ciborium::de::from_reader(public_key_cose)
        .map_err(|e| format!("COSE decode: {e}"))?;
    let map = cose.as_map().ok_or("COSE key is not a map")?;
    let get_bytes = |key: i64| -> Result<Vec<u8>, String> {
        map.iter()
            .find(|(k, _)| k.as_integer() == Some(key.into()))
            .and_then(|(_, v)| v.as_bytes().cloned())
            .ok_or_else(|| format!("COSE key missing component {key}"))
    };
    let x = get_bytes(-2)?;
    let y = get_bytes(-3)?;
    let point = p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| format!("invalid public key point: {e}"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    let mut client_hash = Sha256::new();
    client_hash.update(client_data_json);
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&client_hash.finalize());
    Ok(verifying_key.verify(&signed, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_data(challenge: &str, origin: &str) -> Vec<u8> {
        format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
        )
        .into_bytes()
    }

    #[test]
    fn created_credential_has_valid_attestation_structure() {
        let (cred, attestation) = create_credential(
            "github.com",
            Some("GitHub".into()),
            Some("octocat".into()),
            None,
            vec![1, 2, 3],
            true,
            1_000,
        )
        .unwrap();
        let parsed: Value = ciborium::de::from_reader(attestation.as_slice()).unwrap();
        let map = parsed.as_map().unwrap();
        let get = |k: &str| {
            map.iter()
                .find(|(key, _)| key.as_text() == Some(k))
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(get("fmt").as_text(), Some("none"));
        let auth_data = get("authData").as_bytes().unwrap().clone();
        // authData layout: rpIdHash(32) | flags(1) | signCount(4) |
        // aaguid(16) | credIdLen(2) | credId | COSE key.
        assert_eq!(&auth_data[..32], &rp_id_hash("github.com")[..]);
        assert_eq!(auth_data[32] & FLAG_AT, FLAG_AT);
        assert_eq!(&auth_data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&auth_data[37..53], &YOBEI_AAGUID[..]);
        let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert_eq!(cred_len, cred.credential_id.len());
        assert_eq!(&auth_data[55..55 + cred_len], &cred.credential_id[..]);
        assert_eq!(&auth_data[55 + cred_len..], &cred.public_key_cose[..]);
    }

    #[test]
    fn assertion_signature_verifies_and_counter_advances() {
        let (mut cred, _) = create_credential(
            "example.com",
            None,
            Some("alice".into()),
            None,
            vec![7],
            true,
            0,
        )
        .unwrap();
        let cd = client_data("abc123", "https://example.com");
        let first = create_assertion(&mut cred, "example.com", &cd).unwrap();
        assert_eq!(first.sign_count, 1);
        assert!(verify_assertion(
            &cred.public_key_cose,
            &first.authenticator_data,
            &cd,
            &first.signature,
        )
        .unwrap());

        // Tampered client data must not verify.
        let tampered = client_data("xyz999", "https://example.com");
        assert!(!verify_assertion(
            &cred.public_key_cose,
            &first.authenticator_data,
            &tampered,
            &first.signature,
        )
        .unwrap());

        let second = create_assertion(&mut cred, "example.com", &cd).unwrap();
        assert_eq!(second.sign_count, 2);
        // Wrong rp is refused before signing anything.
        assert!(create_assertion(&mut cred, "evil.com", &cd).is_err());
    }
}
