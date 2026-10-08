//! Client side of Simplus vault sync.
//!
//! * [`create_account`] uploads an existing vault to a new server account.
//! * [`download_vault`] creates the vault on a new device from an existing account.
//! * [`sign_in`] reconnects a device that already has the vault.
//! * [`sync`] exchanges item changes; [`publish_keys`] pushes password or recovery-key changes.
//!
//! Everything blocks; call it from a background thread. Functions take a [`VaultAccess`] so
//! the vault lock is held only for local steps, never while waiting on the network.

mod client;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;
use simplus_vault_core::sync::{SyncSettings, auth_key_from_kdf};
use simplus_vault_core::{Vault, VaultError};
use simplus_vault_proto::{
    API_VERSION, DeviceInfo, DeviceSession, ErrorCode, LoginRequest, PushStatus, RecoverRequest,
    RegisterRequest, UpdateKeysRequest, normalize_email,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use client::{SyncClient, normalize_server_url};

/// Items requested per pull page and sent per push request.
const BATCH: usize = 500;
/// Pull/push rounds per sync before giving up on a busy item.
const MAX_ROUNDS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{message}")]
    Server { status: u16, code: ErrorCode, message: String },
    #[error("cannot reach the sync server: {0}")]
    Network(String),
    #[error("use an https:// address (http:// is only allowed for this computer)")]
    InsecureUrl,
    #[error("that is not a valid server address")]
    InvalidUrl,
    #[error("unexpected response from the sync server: {0}")]
    Protocol(String),
    #[error("this server speaks sync protocol {0}, which this app does not support")]
    Incompatible(u32),
    #[error("this account syncs a different vault")]
    DifferentVault,
    #[error("sync is not set up on this device")]
    NotSignedIn,
    #[error(transparent)]
    Vault(#[from] VaultError),
}

impl SyncError {
    fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// The session is no longer valid (signed out remotely, password changed elsewhere).
    pub fn is_unauthorized(&self) -> bool {
        matches!(self.code(), Some(ErrorCode::Unauthorized | ErrorCode::AccountDisabled))
    }

    /// Wrong email or password.
    pub fn is_invalid_credentials(&self) -> bool {
        self.code() == Some(ErrorCode::InvalidCredentials)
    }
}

/// Short-lived access to the vault for one local step of a sync.
pub trait VaultAccess {
    fn with_vault<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R, SyncError>) -> Result<R, SyncError>;
}

impl VaultAccess for Mutex<Vault> {
    fn with_vault<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R, SyncError>) -> Result<R, SyncError> {
        f(&mut self.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl VaultAccess for Mutex<Option<Vault>> {
    fn with_vault<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R, SyncError>) -> Result<R, SyncError> {
        match self.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            Some(vault) => f(vault),
            None => Err(VaultError::NotFound.into()),
        }
    }
}

/// Who is signing in, and from which device.
#[derive(Clone, Debug)]
pub struct Account<'a> {
    pub server_url: &'a str,
    pub email: &'a str,
    pub device_name: &'a str,
}

fn connect(server_url: &str) -> Result<SyncClient, SyncError> {
    let client = SyncClient::new(server_url)?;
    let info = client.info()?;
    if info.api_version != API_VERSION {
        return Err(SyncError::Incompatible(info.api_version));
    }
    Ok(client)
}

fn settings_for(account: &Account<'_>, client: &SyncClient, previous: Option<SyncSettings>) -> SyncSettings {
    let email = normalize_email(account.email);
    // Keep the device id when reconnecting the same account, so the server replaces the old
    // session instead of listing the device twice.
    let device_id = previous
        .filter(|p| p.server_url == client.base_url() && p.email == email)
        .map_or_else(Uuid::now_v7, |p| p.device_id);
    SyncSettings {
        server_url: client.base_url().to_owned(),
        email,
        device_id,
        device_name: account.device_name.trim().to_owned(),
    }
}

fn device(settings: &SyncSettings) -> DeviceInfo {
    DeviceInfo { id: settings.device_id, name: settings.device_name.clone() }
}

/// Creates a server account for an unlocked local vault and turns sync on.
pub fn create_account(
    vault: &impl VaultAccess,
    account: &Account<'_>,
    master_password: &str,
    invite_code: Option<&str>,
) -> Result<(), SyncError> {
    let client = connect(account.server_url)?;
    let (request, settings) = vault.with_vault(|v| {
        let settings = settings_for(account, &client, v.sync_settings()?);
        let request = RegisterRequest {
            email: settings.email.clone(),
            auth_key: v.auth_key(master_password)?.expose().to_vec(),
            key_proof: v.key_proof()?.expose().to_vec(),
            kdf: v.kdf_info()?,
            keys: v.key_bundle()?,
            device: device(&settings),
            invite_code: invite_code.map(str::trim).filter(|c| !c.is_empty()).map(str::to_owned),
        };
        Ok((request, settings))
    })?;
    let session = client.register(&request)?;
    vault.with_vault(|v| Ok(v.enable_sync(&settings, &session.token, session.keys_version)?))
}

fn login(
    client: &SyncClient,
    settings: &SyncSettings,
    master_password: &str,
) -> Result<simplus_vault_proto::SessionResponse, SyncError> {
    let kdf = client.prelogin(&settings.email)?;
    let auth_key = auth_key_from_kdf(master_password, &kdf)?;
    client.login(&LoginRequest {
        email: settings.email.clone(),
        auth_key: auth_key.expose().to_vec(),
        device: device(settings),
    })
}

/// Creates the local vault at `path` from an existing account (new device) and turns sync
/// on. Run [`sync`] afterwards to download the items.
pub fn download_vault(path: &Path, account: &Account<'_>, master_password: &str) -> Result<Vault, SyncError> {
    let client = connect(account.server_url)?;
    let settings = settings_for(account, &client, None);
    let session = login(&client, &settings, master_password)?;
    let mut vault = Vault::create_from_bundle(path, &session.keys, master_password)?;
    vault.enable_sync(&settings, &session.token, session.keys_version)?;
    Ok(vault)
}

/// Signs a device that already has this vault back in (after signing out, or after the
/// password was changed on another device). The vault must be unlocked.
pub fn sign_in(
    vault: &impl VaultAccess,
    account: &Account<'_>,
    master_password: &str,
) -> Result<(), SyncError> {
    let client = connect(account.server_url)?;
    let settings = vault.with_vault(|v| Ok(settings_for(account, &client, v.sync_settings()?)))?;
    let session = login(&client, &settings, master_password)?;
    vault.with_vault(|v| {
        if session.keys.vault_id != v.id() {
            return Err(SyncError::DifferentVault);
        }
        v.apply_key_bundle(&session.keys)?;
        Ok(v.enable_sync(&settings, &session.token, session.keys_version)?)
    })
}

/// Signs this device out on the server (best effort) and locally.
pub fn sign_out(vault: &impl VaultAccess) -> Result<(), SyncError> {
    if let Ok(client) = signed_in_client(vault) {
        let _ = client.logout();
    }
    vault.with_vault(|v| Ok(v.disable_sync()?))
}

fn signed_in_client(vault: &impl VaultAccess) -> Result<SyncClient, SyncError> {
    let (settings, token) = vault.with_vault(|v| {
        let settings = v.sync_settings()?.ok_or(SyncError::NotSignedIn)?;
        let token = v.sync_token()?.ok_or(SyncError::NotSignedIn)?;
        Ok((settings, token))
    })?;
    Ok(SyncClient::new(&settings.server_url)?.with_token(token))
}

pub fn devices(vault: &impl VaultAccess) -> Result<Vec<DeviceSession>, SyncError> {
    Ok(signed_in_client(vault)?.devices()?.devices)
}

pub fn revoke_device(vault: &impl VaultAccess, device_id: Uuid) -> Result<(), SyncError> {
    signed_in_client(vault)?.revoke_device(device_id)
}

/// A master password change to publish: the login keys before and after.
pub struct LoginChange {
    pub current_auth_key: Zeroizing<Vec<u8>>,
    pub new_auth_key: Zeroizing<Vec<u8>>,
}

/// Publishes the vault's current key bundle after a local password change or recovery-key
/// rotation. With `login`, the server login changes too and other devices are signed out.
pub fn publish_keys(vault: &impl VaultAccess, login: Option<LoginChange>) -> Result<(), SyncError> {
    let client = signed_in_client(vault)?;
    let request = vault.with_vault(|v| {
        let mut request = UpdateKeysRequest {
            expected_version: v.synced_keys_version()?,
            keys: Some(v.key_bundle()?),
            ..Default::default()
        };
        if let Some(login) = &login {
            request.current_auth_key = Some(login.current_auth_key.to_vec());
            request.new_auth_key = Some(login.new_auth_key.to_vec());
            request.new_kdf = Some(v.kdf_info()?);
            request.revoke_other_sessions = true;
        }
        Ok(request)
    })?;
    let response = client.update_keys(&request)?;
    vault.with_vault(|v| Ok(v.set_synced_keys_version(response.keys_version)?))
}

/// After [`Vault::recover`] reset both passwords locally, resets the server login too (using
/// the vault-key proof) and signs every other device out.
pub fn recover_account(vault: &impl VaultAccess, new_master_password: &str) -> Result<(), SyncError> {
    let (settings, request) = vault.with_vault(|v| {
        let settings = v.sync_settings()?.ok_or(SyncError::NotSignedIn)?;
        let request = RecoverRequest {
            email: settings.email.clone(),
            key_proof: v.key_proof()?.expose().to_vec(),
            new_auth_key: v.auth_key(new_master_password)?.expose().to_vec(),
            kdf: v.kdf_info()?,
            keys: v.key_bundle()?,
            device: device(&settings),
        };
        Ok((settings, request))
    })?;
    let session = connect(&settings.server_url)?.recover(&request)?;
    vault.with_vault(|v| Ok(v.enable_sync(&settings, &session.token, session.keys_version)?))
}

/// What a sync did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    pub conflicts: usize,
    pub rejected: usize,
    /// Another device changed a password or the recovery key; the new key bundle was adopted.
    pub keys_updated: bool,
}

/// Pulls remote changes, merges them, and pushes local changes, repeating while pushes
/// conflict. The vault must be unlocked.
pub fn sync(vault: &impl VaultAccess) -> Result<SyncReport, SyncError> {
    let client = signed_in_client(vault)?;
    let mut report = SyncReport::default();

    for _ in 0..MAX_ROUNDS {
        // Pull everything after the cursor, page by page.
        loop {
            let cursor = vault.with_vault(|v| Ok(v.sync_cursor()?))?;
            let page = client.changes(cursor, BATCH as u32)?;
            let local_keys_version = vault.with_vault(|v| Ok(v.synced_keys_version()?))?;
            if page.keys_version != local_keys_version {
                let keys = client.keys()?;
                vault.with_vault(|v| {
                    v.apply_key_bundle(&keys.keys)?;
                    Ok(v.set_synced_keys_version(keys.keys_version)?)
                })?;
                report.keys_updated = true;
            }
            let next_cursor = page.items.last().map_or(cursor, |item| item.seq);
            let applied = vault.with_vault(|v| {
                let applied = v.apply_remote(&page.items)?;
                v.set_sync_cursor(next_cursor)?;
                Ok(applied)
            })?;
            report.pulled += applied.applied;
            report.conflicts += applied.conflicts;
            report.rejected += applied.rejected;
            if !page.has_more {
                break;
            }
        }

        // Push local changes.
        let pending = vault.with_vault(|v| Ok(v.pending_changes()?))?;
        if pending.is_empty() {
            break;
        }
        let mut rejected = 0;
        for chunk in pending.chunks(BATCH) {
            let response = client.push(chunk.iter().map(|c| c.item.clone()).collect())?;
            let revisions: HashMap<Uuid, i64> = chunk.iter().map(|c| (c.item.id, c.revision)).collect();
            vault.with_vault(|v| {
                for result in &response.results {
                    match (result.status, revisions.get(&result.id)) {
                        (PushStatus::Accepted, Some(revision)) => {
                            v.mark_pushed(result.id, *revision, result.seq)?;
                            report.pushed += 1;
                        }
                        _ => rejected += 1,
                    }
                }
                Ok(())
            })?;
        }
        if rejected == 0 {
            break;
        }
        // Someone else changed those items first: pull their versions and try again.
    }

    vault.with_vault(|v| Ok(v.set_last_sync(Utc::now())?))?;
    Ok(report)
}
