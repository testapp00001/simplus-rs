//! HTTP handlers for `/v1`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use simplus_core::db::rusqlite::{Connection, OptionalExtension as _, Row};
use simplus_crypto::{KdfParams, hkdf_expand};
use simplus_vault_proto::{
    ChangesResponse, DeleteAccountRequest, DeviceInfo, DeviceSession, DevicesResponse, ErrorCode, ItemKind,
    KdfInfo, KeyBundle, KeysResponse, LoginRequest, PreloginRequest, PreloginResponse, PushRequest,
    PushResponse, PushResult, PushStatus, RecoverRequest, RegisterRequest, Registration, RemoteItem,
    ServerInfo, SessionResponse, UpdateKeysRequest, UpdateKeysResponse, is_valid_email, normalize_email,
};
use uuid::Uuid;

use crate::auth::{RateLimiter, client_ip, hash_secret, hash_token, new_token, verify_secret};
use crate::config::Config;
use crate::db::{Db, now, params, server_secret};
use crate::error::{ApiError, ApiResult};

const KEY_LEN: usize = 32;
const MAX_SLOT_BYTES: usize = 1024;
const MAX_DEVICE_NAME: usize = 100;
const MAX_ITEMS_PER_PUSH: usize = 1000;
const MAX_ITEMS_PER_PULL: u32 = 1000;

/// Everything a request handler needs.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    secret: Arc<[u8; 32]>,
    limiter: Arc<RateLimiter>,
    /// Verified against when an email is unknown, so timing does not reveal accounts.
    dummy_verifier: Arc<Vec<u8>>,
}

impl AppState {
    pub fn open(config: Config) -> anyhow::Result<Self> {
        let db = Db::open(&config.database)?;
        let secret = db.blocking(|conn| server_secret(conn))?;
        Ok(Self {
            db,
            limiter: Arc::new(RateLimiter::new(config.auth_requests_per_minute)),
            config: Arc::new(config),
            secret: Arc::new(secret),
            dummy_verifier: Arc::new(hash_secret(b"simplus-dummy-verifier")?),
        })
    }

    fn rate_limit(&self, headers: &HeaderMap, peer: SocketAddr) -> ApiResult<()> {
        let ip = client_ip(headers, peer, self.config.trust_proxy);
        if self.limiter.check(ip, now()) { Ok(()) } else { Err(ApiError::rate_limited()) }
    }

    /// Plausible, stable KDF parameters for an email with no account.
    fn fake_kdf(&self, email: &str) -> KdfInfo {
        let mut salt = [0u8; 16];
        let info = format!("simplus/server/fake-salt/{email}");
        hkdf_expand(&self.secret[..], None, info.as_bytes(), &mut salt)
            .expect("16 bytes is a valid HKDF length");
        let p = KdfParams::RECOMMENDED;
        KdfInfo { m_cost_kib: p.m_cost_kib, t_cost: p.t_cost, p_cost: p.p_cost, salt: salt.to_vec() }
    }
}

pub fn router(state: AppState) -> Router {
    let body_limit = state.config.max_body_bytes;
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/v1/info", get(info))
        .route("/v1/prelogin", post(prelogin))
        .route("/v1/accounts", post(register))
        .route("/v1/account", delete(delete_account))
        .route("/v1/sessions", post(login))
        .route("/v1/sessions/current", delete(logout))
        .route("/v1/recover", post(recover))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{id}", delete(revoke_device))
        .route("/v1/keys", get(get_keys).put(put_keys))
        .route("/v1/items", get(get_items).post(push_items))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

// ---------------------------------------------------------------------------------------------
// Validation and helpers
// ---------------------------------------------------------------------------------------------

fn check_key(bytes: &[u8], what: &str) -> ApiResult<()> {
    if bytes.len() == KEY_LEN {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("{what} must be 32 bytes")))
    }
}

fn check_kdf(kdf: &KdfInfo) -> ApiResult<()> {
    let params = KdfParams { m_cost_kib: kdf.m_cost_kib, t_cost: kdf.t_cost, p_cost: kdf.p_cost };
    params.validate().map_err(|e| ApiError::bad_request(e.to_string()))?;
    if kdf.salt.len() != 16 {
        return Err(ApiError::bad_request("salt must be 16 bytes"));
    }
    Ok(())
}

fn check_bundle(keys: &KeyBundle) -> ApiResult<()> {
    for slot in [&keys.master_slot, &keys.notes_slot, &keys.recovery_vault_slot, &keys.recovery_notes_slot] {
        if slot.is_empty() || slot.len() > MAX_SLOT_BYTES {
            return Err(ApiError::bad_request("invalid key slot"));
        }
    }
    Ok(())
}

fn check_device(device: &DeviceInfo) -> ApiResult<()> {
    let name = device.name.trim();
    if name.is_empty() || name.chars().count() > MAX_DEVICE_NAME {
        return Err(ApiError::bad_request("device name must have 1-100 characters"));
    }
    Ok(())
}

fn to_json<T: serde::Serialize>(value: &T) -> ApiResult<String> {
    serde_json::to_string(value).map_err(ApiError::internal)
}

fn from_json<T: serde::de::DeserializeOwned>(text: &str) -> ApiResult<T> {
    serde_json::from_str(text).map_err(ApiError::internal)
}

async fn hash_blocking(secret: Vec<u8>) -> ApiResult<Vec<u8>> {
    tokio::task::spawn_blocking(move || hash_secret(&secret)).await?.map_err(ApiError::internal)
}

async fn verify_blocking(stored: Vec<u8>, candidate: Vec<u8>) -> ApiResult<bool> {
    Ok(tokio::task::spawn_blocking(move || verify_secret(&stored, &candidate)).await?)
}

struct Account {
    id: String,
    auth_verifier: Vec<u8>,
    proof_verifier: Vec<u8>,
    kdf: KdfInfo,
    keys: KeyBundle,
    keys_version: i64,
    disabled: bool,
    locked_until: i64,
}

const ACCOUNT_COLUMNS: &str =
    "id, auth_verifier, proof_verifier, kdf, keys, keys_version, disabled, locked_until";

type AccountColumns = (String, Vec<u8>, Vec<u8>, String, String, i64, bool, i64);

fn account_columns(r: &Row<'_>) -> simplus_core::db::rusqlite::Result<AccountColumns> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
}

fn load_account(conn: &Connection, column: &str, value: &str) -> ApiResult<Option<Account>> {
    let row = conn
        .query_row(
            &format!("SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE {column} = ?1"),
            [value],
            account_columns,
        )
        .optional()?;
    row.map(|(id, auth_verifier, proof_verifier, kdf, keys, keys_version, disabled, locked_until)| {
        Ok(Account {
            id,
            auth_verifier,
            proof_verifier,
            kdf: from_json(&kdf)?,
            keys: from_json(&keys)?,
            keys_version,
            disabled,
            locked_until,
        })
    })
    .transpose()
}

fn session_response(account: &Account, token: String) -> ApiResult<SessionResponse> {
    Ok(SessionResponse {
        token,
        account_id: Uuid::parse_str(&account.id).map_err(ApiError::internal)?,
        keys: account.keys.clone(),
        keys_version: account.keys_version,
        kdf: account.kdf.clone(),
    })
}

/// Creates a session for `device`, replacing an older one from the same device.
fn create_session(conn: &Connection, account_id: &str, device: &DeviceInfo) -> ApiResult<String> {
    let (token, hash) = new_token().map_err(ApiError::internal)?;
    let device_id = device.id.to_string();
    let now = now();
    conn.execute(
        "DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2",
        params![account_id, device_id],
    )?;
    conn.execute(
        "INSERT INTO sessions (token_hash, account_id, device_id, device_name, created_at, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![&hash[..], account_id, device_id, device.name.trim(), now],
    )?;
    Ok(token)
}

impl AppState {
    async fn record_failure(&self, account_id: String) -> ApiResult<()> {
        let threshold = i64::from(self.config.lockout_threshold.max(1));
        let until = now() + i64::from(self.config.lockout_minutes) * 60;
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE accounts SET
                         locked_until = CASE WHEN failed_logins + 1 >= ?2 THEN ?3 ELSE locked_until END,
                         failed_logins = CASE WHEN failed_logins + 1 >= ?2 THEN 0 ELSE failed_logins + 1 END
                     WHERE id = ?1",
                    params![account_id, threshold, until],
                )?;
                Ok(())
            })
            .await
    }

    /// Looks up `email` and checks `secret` against the chosen verifier, counting failures
    /// towards the lockout. Unknown emails cost the same as wrong passwords.
    async fn authenticate(
        &self,
        email: &str,
        secret: &[u8],
        verifier: fn(&Account) -> &Vec<u8>,
    ) -> ApiResult<Account> {
        let email = email.to_owned();
        let account = self.db.call(move |conn| load_account(conn, "email", &email)).await?;
        if account.as_ref().is_some_and(|a| a.locked_until > now()) {
            return Err(ApiError::locked());
        }
        let stored = account.as_ref().map_or_else(|| self.dummy_verifier.to_vec(), |a| verifier(a).clone());
        let ok = verify_blocking(stored, secret.to_vec()).await?;
        match account {
            Some(account) if ok => {
                if account.disabled {
                    return Err(ApiError::disabled());
                }
                Ok(account)
            }
            Some(account) => {
                self.record_failure(account.id).await?;
                Err(ApiError::invalid_credentials())
            }
            None => Err(ApiError::invalid_credentials()),
        }
    }
}

/// An authenticated request (`Authorization: Bearer <token>`).
pub struct Session {
    account_id: String,
    token_hash: [u8; 32],
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(ApiError::unauthorized)?;
        let token_hash = hash_token(token.trim());
        let ttl = i64::from(state.config.session_ttl_days) * 86_400;
        state
            .db
            .call(move |conn| {
                let now = now();
                let row: Option<(String, i64, bool)> = conn
                    .query_row(
                        "SELECT s.account_id, s.last_seen, a.disabled
                         FROM sessions s JOIN accounts a ON a.id = s.account_id
                         WHERE s.token_hash = ?1",
                        [&token_hash[..]],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((account_id, last_seen, disabled)) = row else {
                    return Err(ApiError::unauthorized());
                };
                if now - last_seen > ttl {
                    conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [&token_hash[..]])?;
                    return Err(ApiError::unauthorized());
                }
                if disabled {
                    return Err(ApiError::disabled());
                }
                if now - last_seen > 300 {
                    conn.execute(
                        "UPDATE sessions SET last_seen = ?2 WHERE token_hash = ?1",
                        params![&token_hash[..], now],
                    )?;
                }
                Ok(Session { account_id, token_hash })
            })
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------------------------

async fn info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "simplus-sync-server".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        api_version: simplus_vault_proto::API_VERSION,
        registration: state.config.registration,
    })
}

async fn prelogin(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    state.rate_limit(&headers, peer)?;
    let email = normalize_email(&req.email);
    let lookup = email.clone();
    let kdf: Option<String> = state
        .db
        .call(move |conn| {
            Ok(conn
                .query_row("SELECT kdf FROM accounts WHERE email = ?1", [lookup], |r| r.get(0))
                .optional()?)
        })
        .await?;
    let kdf = match kdf {
        Some(json) => from_json(&json)?,
        None => state.fake_kdf(&email),
    };
    Ok(Json(PreloginResponse { kdf }))
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<SessionResponse>> {
    state.rate_limit(&headers, peer)?;
    let email = normalize_email(&req.email);
    if !is_valid_email(&email) {
        return Err(ApiError::bad_request("invalid email address"));
    }
    check_key(&req.auth_key, "auth_key")?;
    check_key(&req.key_proof, "key_proof")?;
    check_kdf(&req.kdf)?;
    check_bundle(&req.keys)?;
    check_device(&req.device)?;
    let invite = match state.config.registration {
        Registration::Open => None,
        Registration::Closed => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                ErrorCode::RegistrationClosed,
                "registration is closed",
            ));
        }
        Registration::Invite => {
            Some(req.invite_code.clone().filter(|c| !c.trim().is_empty()).ok_or_else(|| {
                ApiError::new(StatusCode::FORBIDDEN, ErrorCode::InviteRequired, "an invite code is required")
            })?)
        }
    };

    let auth_verifier = hash_blocking(req.auth_key.clone()).await?;
    let proof_verifier = hash_blocking(req.key_proof.clone()).await?;
    let account = Account {
        id: Uuid::now_v7().to_string(),
        auth_verifier,
        proof_verifier,
        kdf: req.kdf,
        keys: req.keys,
        keys_version: 1,
        disabled: false,
        locked_until: 0,
    };
    let kdf_json = to_json(&account.kdf)?;
    let keys_json = to_json(&account.keys)?;
    let device = req.device;
    let (account, token) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            if let Some(code) = invite {
                let used = tx.execute(
                    "UPDATE invites SET uses_left = uses_left - 1
                     WHERE code_hash = ?1 AND uses_left > 0 AND expires_at > ?2",
                    params![&hash_token(code.trim())[..], now()],
                )?;
                if used == 0 {
                    return Err(ApiError::new(StatusCode::FORBIDDEN, ErrorCode::InvalidInvite, "invalid or expired invite"));
                }
                tx.execute("DELETE FROM invites WHERE uses_left <= 0", [])?;
            }
            let taken: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM accounts WHERE email = ?1)", [&email], |r| r.get(0))?;
            if taken {
                return Err(ApiError::new(StatusCode::CONFLICT, ErrorCode::EmailTaken, "an account with this email exists"));
            }
            tx.execute(
                "INSERT INTO accounts (id, email, auth_verifier, proof_verifier, kdf, keys, keys_version, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
                params![account.id, email, account.auth_verifier, account.proof_verifier, kdf_json, keys_json, now()],
            )?;
            let token = create_session(&tx, &account.id, &device)?;
            tx.commit()?;
            Ok((account, token))
        })
        .await?;
    tracing::info!(account = %account.id, "account created");
    Ok(Json(session_response(&account, token)?))
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<SessionResponse>> {
    state.rate_limit(&headers, peer)?;
    check_key(&req.auth_key, "auth_key")?;
    check_device(&req.device)?;
    let account =
        state.authenticate(&normalize_email(&req.email), &req.auth_key, |a| &a.auth_verifier).await?;
    let account_id = account.id.clone();
    let device = req.device;
    let token = state
        .db
        .call(move |conn| {
            conn.execute("UPDATE accounts SET failed_logins = 0 WHERE id = ?1", [&account_id])?;
            create_session(conn, &account_id, &device)
        })
        .await?;
    Ok(Json(session_response(&account, token)?))
}

async fn recover(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RecoverRequest>,
) -> ApiResult<Json<SessionResponse>> {
    state.rate_limit(&headers, peer)?;
    check_key(&req.key_proof, "key_proof")?;
    check_key(&req.new_auth_key, "new_auth_key")?;
    check_kdf(&req.kdf)?;
    check_bundle(&req.keys)?;
    check_device(&req.device)?;
    let mut account =
        state.authenticate(&normalize_email(&req.email), &req.key_proof, |a| &a.proof_verifier).await?;
    if req.keys.vault_id != account.keys.vault_id {
        return Err(ApiError::bad_request("the key bundle belongs to a different vault"));
    }
    account.auth_verifier = hash_blocking(req.new_auth_key.clone()).await?;
    account.kdf = req.kdf;
    account.keys = req.keys;
    account.keys_version += 1;
    let kdf_json = to_json(&account.kdf)?;
    let keys_json = to_json(&account.keys)?;
    let device = req.device;
    let (account, token) = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE accounts SET auth_verifier = ?2, kdf = ?3, keys = ?4, keys_version = ?5, failed_logins = 0
                 WHERE id = ?1",
                params![account.id, account.auth_verifier, kdf_json, keys_json, account.keys_version],
            )?;
            // Every existing session belonged to someone who knew the old password.
            tx.execute("DELETE FROM sessions WHERE account_id = ?1", [&account.id])?;
            let token = create_session(&tx, &account.id, &device)?;
            tx.commit()?;
            Ok((account, token))
        })
        .await?;
    tracing::info!(account = %account.id, "account recovered with recovery key");
    Ok(Json(session_response(&account, token)?))
}

// ---------------------------------------------------------------------------------------------
// Authenticated endpoints
// ---------------------------------------------------------------------------------------------

async fn logout(State(state): State<AppState>, session: Session) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |conn| {
            conn.execute("DELETE FROM sessions WHERE token_hash = ?1", [&session.token_hash[..]])?;
            Ok(StatusCode::NO_CONTENT)
        })
        .await
}

async fn delete_account(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<DeleteAccountRequest>,
) -> ApiResult<StatusCode> {
    let id = session.account_id.clone();
    let account =
        state.db.call(move |conn| load_account(conn, "id", &id)).await?.ok_or_else(ApiError::unauthorized)?;
    if !verify_blocking(account.auth_verifier, req.auth_key).await? {
        return Err(ApiError::invalid_credentials());
    }
    state
        .db
        .call(move |conn| {
            conn.execute("DELETE FROM accounts WHERE id = ?1", [&session.account_id])?;
            Ok(())
        })
        .await?;
    tracing::info!(account = %account.id, "account deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(State(state): State<AppState>, session: Session) -> ApiResult<Json<DevicesResponse>> {
    state
        .db
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT device_id, device_name, created_at, last_seen, token_hash = ?2
                 FROM sessions WHERE account_id = ?1 ORDER BY created_at",
            )?;
            let rows = stmt.query_map(params![session.account_id, &session.token_hash[..]], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            let mut devices = Vec::new();
            for row in rows {
                let (id, name, created_at, last_seen, current) = row?;
                if let Ok(id) = Uuid::parse_str(&id) {
                    devices.push(DeviceSession { id, name, created_at, last_seen, current });
                }
            }
            Ok(Json(DevicesResponse { devices }))
        })
        .await
}

async fn revoke_device(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    state
        .db
        .call(move |conn| {
            let removed = conn.execute(
                "DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2",
                params![session.account_id, id.to_string()],
            )?;
            if removed == 0 { Err(ApiError::not_found("no such device")) } else { Ok(StatusCode::NO_CONTENT) }
        })
        .await
}

async fn get_keys(State(state): State<AppState>, session: Session) -> ApiResult<Json<KeysResponse>> {
    let account = state
        .db
        .call(move |conn| load_account(conn, "id", &session.account_id))
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(KeysResponse { keys: account.keys, keys_version: account.keys_version, kdf: account.kdf }))
}

async fn put_keys(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<UpdateKeysRequest>,
) -> ApiResult<Json<UpdateKeysResponse>> {
    let id = session.account_id.clone();
    let mut account =
        state.db.call(move |conn| load_account(conn, "id", &id)).await?.ok_or_else(ApiError::unauthorized)?;
    if req.expected_version != account.keys_version {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::VersionConflict,
            "the keys changed on another device",
        ));
    }
    let changes_login = req.current_auth_key.is_some() || req.new_auth_key.is_some() || req.new_kdf.is_some();
    if req.keys.is_none() && !changes_login {
        return Err(ApiError::bad_request("nothing to update"));
    }
    if let Some(keys) = &req.keys {
        check_bundle(keys)?;
        if keys.vault_id != account.keys.vault_id {
            return Err(ApiError::bad_request("the key bundle belongs to a different vault"));
        }
    }
    if changes_login {
        let (Some(current), Some(new), Some(kdf)) = (&req.current_auth_key, &req.new_auth_key, &req.new_kdf)
        else {
            return Err(ApiError::bad_request(
                "a login change needs current_auth_key, new_auth_key and new_kdf",
            ));
        };
        check_key(new, "new_auth_key")?;
        check_kdf(kdf)?;
        if !verify_blocking(account.auth_verifier.clone(), current.clone()).await? {
            state.record_failure(account.id.clone()).await?;
            return Err(ApiError::invalid_credentials());
        }
        account.auth_verifier = hash_blocking(new.clone()).await?;
        account.kdf = kdf.clone();
    }
    if let Some(keys) = req.keys {
        account.keys = keys;
    }
    let expected = account.keys_version;
    let kdf_json = to_json(&account.kdf)?;
    let keys_json = to_json(&account.keys)?;
    let revoke_others = req.revoke_other_sessions;
    state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            let updated = tx.execute(
                "UPDATE accounts SET auth_verifier = ?3, kdf = ?4, keys = ?5, keys_version = keys_version + 1
                 WHERE id = ?1 AND keys_version = ?2",
                params![account.id, expected, account.auth_verifier, kdf_json, keys_json],
            )?;
            if updated == 0 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::VersionConflict,
                    "the keys changed on another device",
                ));
            }
            if revoke_others {
                tx.execute(
                    "DELETE FROM sessions WHERE account_id = ?1 AND token_hash != ?2",
                    params![account.id, &session.token_hash[..]],
                )?;
            }
            tx.commit()?;
            Ok(Json(UpdateKeysResponse { keys_version: expected + 1 }))
        })
        .await
}

#[derive(Deserialize)]
struct ItemsQuery {
    #[serde(default)]
    since: i64,
    limit: Option<u32>,
}

fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Record => "record",
        ItemKind::Note => "note",
    }
}

fn parse_kind(name: &str) -> Option<ItemKind> {
    match name {
        "record" => Some(ItemKind::Record),
        "note" => Some(ItemKind::Note),
        _ => None,
    }
}

async fn get_items(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<ItemsQuery>,
) -> ApiResult<Json<ChangesResponse>> {
    let limit = query.limit.unwrap_or(500).clamp(1, MAX_ITEMS_PER_PULL);
    state
        .db
        .call(move |conn| {
            let (latest_seq, keys_version): (i64, i64) = conn.query_row(
                "SELECT seq, keys_version FROM accounts WHERE id = ?1",
                [&session.account_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut stmt = conn.prepare(
                "SELECT id, kind, parent_id, seq, deleted, updated_at, blob FROM items
                 WHERE account_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
            )?;
            let rows =
                stmt.query_map(params![session.account_id, query.since, i64::from(limit) + 1], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?;
            let mut items = Vec::new();
            for row in rows {
                let (id, kind, parent_id, seq, deleted, updated_at, blob) = row?;
                let parse = |s: &str| Uuid::parse_str(s).map_err(ApiError::internal);
                items.push(RemoteItem {
                    id: parse(&id)?,
                    kind: parse_kind(&kind).ok_or_else(|| ApiError::internal("bad item kind"))?,
                    parent_id: parent_id.as_deref().map(parse).transpose()?,
                    seq,
                    deleted,
                    updated_at,
                    blob,
                });
            }
            let has_more = items.len() > limit as usize;
            items.truncate(limit as usize);
            Ok(Json(ChangesResponse { items, has_more, latest_seq, keys_version }))
        })
        .await
}

async fn push_items(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    if req.items.len() > MAX_ITEMS_PER_PUSH {
        return Err(ApiError::bad_request(format!("at most {MAX_ITEMS_PER_PUSH} items per request")));
    }
    let mut seen = HashSet::new();
    for item in &req.items {
        if !seen.insert(item.id) {
            return Err(ApiError::bad_request("duplicate item in request"));
        }
        let shape_ok =
            matches!((item.kind, item.parent_id), (ItemKind::Record, None) | (ItemKind::Note, Some(_)))
                && item.deleted == item.blob.is_none();
        if !shape_ok {
            return Err(ApiError::bad_request("malformed item"));
        }
        if item.blob.as_ref().is_some_and(|b| b.len() > state.config.max_blob_bytes) {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge, "item too large"));
        }
    }
    let max_items = i64::from(state.config.max_items_per_account);
    state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            let mut seq: i64 = tx.query_row("SELECT seq FROM accounts WHERE id = ?1", [&session.account_id], |r| r.get(0))?;
            let mut live: i64 = tx.query_row(
                "SELECT COUNT(*) FROM items WHERE account_id = ?1 AND deleted = 0",
                [&session.account_id],
                |r| r.get(0),
            )?;
            let mut results = Vec::with_capacity(req.items.len());
            for item in req.items {
                let current: Option<(i64, String, bool)> = tx
                    .query_row(
                        "SELECT seq, kind, deleted FROM items WHERE account_id = ?1 AND id = ?2",
                        params![session.account_id, item.id.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let current_seq = current.as_ref().map_or(0, |c| c.0);
                if current_seq != item.base_seq {
                    results.push(PushResult { id: item.id, status: PushStatus::Conflict, seq: current_seq });
                    continue;
                }
                if current.as_ref().is_some_and(|c| c.1 != kind_name(item.kind)) {
                    return Err(ApiError::bad_request("an item cannot change kind"));
                }
                let was_live = current.as_ref().is_some_and(|c| !c.2);
                match (was_live, !item.deleted) {
                    (false, true) if live >= max_items => {
                        return Err(ApiError::new(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            ErrorCode::QuotaExceeded,
                            "item limit reached for this account",
                        ));
                    }
                    (false, true) => live += 1,
                    (true, false) => live -= 1,
                    _ => {}
                }
                seq += 1;
                tx.execute(
                    "INSERT INTO items (account_id, id, kind, parent_id, seq, deleted, updated_at, blob)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(account_id, id) DO UPDATE SET parent_id = excluded.parent_id, seq = excluded.seq,
                         deleted = excluded.deleted, updated_at = excluded.updated_at, blob = excluded.blob",
                    params![
                        session.account_id,
                        item.id.to_string(),
                        kind_name(item.kind),
                        item.parent_id.map(|p| p.to_string()),
                        seq,
                        item.deleted,
                        item.updated_at,
                        item.blob,
                    ],
                )?;
                results.push(PushResult { id: item.id, status: PushStatus::Accepted, seq });
            }
            tx.execute("UPDATE accounts SET seq = ?2 WHERE id = ?1", params![session.account_id, seq])?;
            tx.commit()?;
            Ok(Json(PushResponse { results, latest_seq: seq }))
        })
        .await
}
