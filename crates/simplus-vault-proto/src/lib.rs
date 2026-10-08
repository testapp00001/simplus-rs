//! JSON wire types for the Simplus vault sync API (`/v1`).
//!
//! The server is zero-knowledge: every secret in these messages is either already encrypted
//! by the client (item blobs, key slots) or a key derived for authentication only.
//! Binary fields travel as standard base64 strings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped on incompatible protocol changes.
pub const API_VERSION: u32 = 1;

/// Header carrying the session token: `Authorization: Bearer <token>`.
pub const AUTH_HEADER: &str = "authorization";

/// Canonical form of an account email (trimmed, lower-case).
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Minimal sanity check; real verification would need e-mail delivery.
pub fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && email.len() <= 254
                && !email.contains(char::is_whitespace)
        }
        None => false,
    }
}

/// Serde helper: `Vec<u8>` as base64.
pub mod b64 {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        BASE64.decode(text.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Serde helper: `Option<Vec<u8>>` as base64 or `null`.
pub mod b64_opt {
    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&BASE64.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|t| BASE64.decode(t.as_bytes()).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Argon2id parameters and salt of the master password, needed before logging in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfInfo {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

/// The vault's wrapped keys. Every slot is opaque ciphertext to the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundle {
    pub vault_id: Uuid,
    #[serde(with = "b64")]
    pub master_slot: Vec<u8>,
    #[serde(with = "b64")]
    pub notes_slot: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_vault_slot: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_notes_slot: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    Open,
    Invite,
    Closed,
}

/// `GET /v1/info`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub registration: Registration,
}

/// `POST /v1/prelogin`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginResponse {
    pub kdf: KdfInfo,
}

/// `POST /v1/accounts`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
    pub kdf: KdfInfo,
    pub keys: KeyBundle,
    pub device: DeviceInfo,
    #[serde(default)]
    pub invite_code: Option<String>,
}

/// `POST /v1/sessions`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
    pub device: DeviceInfo,
}

/// `POST /v1/recover`: resets the login with a recovery-key proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub email: String,
    #[serde(with = "b64")]
    pub recovery_auth_key: Vec<u8>,
    #[serde(with = "b64")]
    pub new_auth_key: Vec<u8>,
    pub kdf: KdfInfo,
    pub keys: KeyBundle,
    pub device: DeviceInfo,
}

/// Returned by register, login and recover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    pub account_id: Uuid,
    pub keys: KeyBundle,
    pub keys_version: i64,
    pub kdf: KdfInfo,
}

/// `GET /v1/keys`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keys: KeyBundle,
    pub keys_version: i64,
    pub kdf: KdfInfo,
}

/// `PUT /v1/keys`: publish a changed key bundle.
///
/// * Master password change: `current_auth_key`, `new_auth_key` and `new_kdf` are required.
/// * Recovery-key rotation: `new_recovery_auth_key` is required.
/// * Notes password change: only the bundle changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateKeysRequest {
    pub expected_version: i64,
    pub keys: Option<KeyBundle>,
    #[serde(default, with = "b64_opt")]
    pub current_auth_key: Option<Vec<u8>>,
    #[serde(default, with = "b64_opt")]
    pub new_auth_key: Option<Vec<u8>>,
    #[serde(default)]
    pub new_kdf: Option<KdfInfo>,
    #[serde(default, with = "b64_opt")]
    pub new_recovery_auth_key: Option<Vec<u8>>,
    /// Sign out every other device (default after a master password change).
    #[serde(default)]
    pub revoke_other_sessions: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateKeysResponse {
    pub keys_version: i64,
}

/// `GET /v1/devices`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSession {
    pub id: Uuid,
    pub name: String,
    /// Unix seconds.
    pub created_at: i64,
    pub last_seen: i64,
    /// The session making this request.
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceSession>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Record,
    Note,
}

/// An item as stored on the server, returned by `GET /v1/items?since=<seq>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteItem {
    pub id: Uuid,
    pub kind: ItemKind,
    pub parent_id: Option<Uuid>,
    pub seq: i64,
    pub deleted: bool,
    /// Client-supplied modification time, Unix milliseconds.
    pub updated_at: i64,
    /// Sealed item; `None` for tombstones.
    #[serde(default, with = "b64_opt")]
    pub blob: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub items: Vec<RemoteItem>,
    /// More items are available; request again with `since` = the last item's `seq`.
    pub has_more: bool,
    /// The account's current sequence number.
    pub latest_seq: i64,
    pub keys_version: i64,
}

/// One change sent by a client. `base_seq` is the server seq the client last saw for this
/// item (0 for new items); the server rejects the change if the item has moved on since.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushItem {
    pub id: Uuid,
    pub kind: ItemKind,
    pub parent_id: Option<Uuid>,
    pub base_seq: i64,
    pub deleted: bool,
    pub updated_at: i64,
    #[serde(default, with = "b64_opt")]
    pub blob: Option<Vec<u8>>,
}

/// `POST /v1/items`
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub items: Vec<PushItem>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushStatus {
    Accepted,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    pub id: Uuid,
    pub status: PushStatus,
    /// New seq when accepted; the server's current seq for the item on conflict.
    pub seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    pub results: Vec<PushResult>,
    pub latest_seq: i64,
}

/// `DELETE /v1/account`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    #[serde(with = "b64")]
    pub auth_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    /// Missing, expired or revoked session token.
    Unauthorized,
    InvalidCredentials,
    /// Too many failed logins; try again later.
    Locked,
    RateLimited,
    AccountDisabled,
    RegistrationClosed,
    InviteRequired,
    InvalidInvite,
    EmailTaken,
    NotFound,
    /// `expected_version` did not match the server's key bundle version.
    VersionConflict,
    TooLarge,
    QuotaExceeded,
    Internal,
}

/// Body of every non-2xx response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_base64_and_round_trip() {
        let item = RemoteItem {
            id: Uuid::nil(),
            kind: ItemKind::Note,
            parent_id: None,
            seq: 7,
            deleted: false,
            updated_at: 1,
            blob: Some(vec![0, 1, 2, 255]),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""blob":"AAEC/w==""#), "{json}");
        assert!(json.contains(r#""kind":"note""#));
        assert_eq!(serde_json::from_str::<RemoteItem>(&json).unwrap(), item);

        let tombstone = RemoteItem { blob: None, deleted: true, ..item };
        let json = serde_json::to_string(&tombstone).unwrap();
        assert!(json.contains(r#""blob":null"#));
        assert_eq!(serde_json::from_str::<RemoteItem>(&json).unwrap(), tombstone);
    }

    #[test]
    fn optional_fields_default() {
        let req: UpdateKeysRequest = serde_json::from_str(r#"{"expected_version":3,"keys":null}"#).unwrap();
        assert_eq!(req.expected_version, 3);
        assert!(req.current_auth_key.is_none() && !req.revoke_other_sessions);
    }

    #[test]
    fn error_codes_are_snake_case() {
        let body = ErrorBody { code: ErrorCode::InvalidCredentials, message: "x".into() };
        assert!(serde_json::to_string(&body).unwrap().contains("invalid_credentials"));
    }

    #[test]
    fn email_helpers() {
        assert_eq!(normalize_email("  Bob@Example.COM "), "bob@example.com");
        for ok in ["a@b.co", "first.last+tag@sub.example.org"] {
            assert!(is_valid_email(ok), "{ok}");
        }
        for bad in ["", "no-at", "@b.co", "a@b", "a@.co", "a b@c.de"] {
            assert!(!is_valid_email(bad), "{bad}");
        }
    }
}
