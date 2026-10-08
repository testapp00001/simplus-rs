//! Local half of vault sync: key bundles, server credentials, change tracking and merging.
//!
//! This module never talks to the network. The sync client (`simplus-vault-sync`) moves
//! [`PendingChange`]s to the server and feeds the server's changes to [`Vault::apply_remote`].
//!
//! Conflict rules, chosen so that no data is ever lost:
//! * Both sides edited an item: the server's version is kept in place, and the local version
//!   becomes a new "(conflict copy)" item (unless both versions are identical).
//! * Local edit vs. remote delete: the edit wins and is pushed again.
//! * Local delete vs. remote edit: the remote version comes back.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use simplus_crypto::{
    KdfParams, KeySlot, SALT_LEN, Salt, SecretKey, SlotKind, derive_key, hkdf_subkey, open, seal,
};
use simplus_vault_proto::{ItemKind as WireKind, KdfInfo, KeyBundle, PushItem, RemoteItem};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::store::{self, FullRow, ItemKind, ItemRow};
use crate::vault::{
    CTX_VAULT_KEY, FORMAT_VERSION, META_FORMAT, META_MASTER_SLOT, META_NOTES_SLOT, META_RECOVERY_NOTES_SLOT,
    META_RECOVERY_VAULT_SLOT, META_VAULT_ID, PREVIOUS_SUFFIX, SLOT_KEYS, data_error, decrypt_note,
    decrypt_record, encrypt_item, load_slot, verify_vault_key, wrong,
};
use crate::{Record, Result, SecureNote, Vault, VaultError};

/// HKDF info for the key that logs in to the sync server.
const AUTH_KEY_INFO: &[u8] = b"simplus/vault/auth/v1";
/// HKDF info for the proof of holding the vault key (authorises recovery-key resets).
const KEY_PROOF_INFO: &[u8] = b"simplus/vault/key-proof/v1";
const TOKEN_AAD: &[u8] = b"simplus/vault/sync-token/v1";
const CONFLICT_SUFFIX: &str = " (conflict copy)";

const META_SETTINGS: &str = "sync.settings";
const META_TOKEN: &str = "sync.token";
const META_CURSOR: &str = "sync.cursor";
const META_KEYS_VERSION: &str = "sync.keys_version";
const META_LAST_SYNC: &str = "sync.last_sync";
const META_RECOVERY_PENDING: &str = "sync.recovery_pending";

/// Where and as whom this vault syncs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSettings {
    pub server_url: String,
    pub email: String,
    pub device_id: Uuid,
    pub device_name: String,
}

/// A local change waiting to be pushed. `revision` lets [`Vault::mark_pushed`] notice edits
/// made while the push was in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingChange {
    pub item: PushItem,
    pub revision: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Remote changes stored locally.
    pub applied: usize,
    /// Items edited on both sides (a conflict copy was kept, or a local edit won).
    pub conflicts: usize,
    /// Remote items ignored because they failed to decrypt or were inconsistent.
    pub rejected: usize,
}

impl From<WireKind> for ItemKind {
    fn from(kind: WireKind) -> Self {
        match kind {
            WireKind::Record => Self::Record,
            WireKind::Note => Self::Note,
        }
    }
}

impl From<ItemKind> for WireKind {
    fn from(kind: ItemKind) -> Self {
        match kind {
            ItemKind::Record => Self::Record,
            ItemKind::Note => Self::Note,
        }
    }
}

fn kdf_from_info(kdf: &KdfInfo) -> Result<(KdfParams, Salt)> {
    let params = KdfParams { m_cost_kib: kdf.m_cost_kib, t_cost: kdf.t_cost, p_cost: kdf.p_cost };
    params.validate().map_err(data_error)?;
    let salt: [u8; SALT_LEN] = kdf.salt.as_slice().try_into().map_err(|_| VaultError::Corrupted)?;
    Ok((params, Salt(salt)))
}

/// Server login key for `password`, computed from the account's KDF info. Used on a new
/// device, before any local vault exists.
pub fn auth_key_from_kdf(password: &str, kdf: &KdfInfo) -> Result<SecretKey> {
    let (params, salt) = kdf_from_info(kdf)?;
    let master = derive_key(password.as_bytes(), &salt, &params).map_err(VaultError::Crypto)?;
    Ok(hkdf_subkey(&master, AUTH_KEY_INFO))
}

fn meta_i64(vault: &Vault, key: &str) -> Result<i64> {
    match store::get_meta(&vault.conn, key)? {
        Some(bytes) => Ok(i64::from_le_bytes(bytes.try_into().map_err(|_| VaultError::Corrupted)?)),
        None => Ok(0),
    }
}

fn row_from_full(row: &FullRow) -> ItemRow {
    ItemRow { id: row.id, parent_id: row.parent_id, blob: row.blob.clone() }
}

fn remote_row(remote: &RemoteItem) -> ItemRow {
    ItemRow { id: remote.id, parent_id: remote.parent_id, blob: remote.blob.clone() }
}

/// Records compare equal regardless of when each copy was saved.
fn same_record(a: &Record, b: &Record) -> bool {
    let mut b = b.clone();
    b.updated_at = a.updated_at;
    b.password_history.clone_from(&a.password_history);
    *a == b
}

fn same_note(a: &SecureNote, b: &SecureNote) -> bool {
    a.title == b.title && a.body == b.body && a.record_id == b.record_id
}

impl Vault {
    // -------------------------------------------------------------------------------------
    // Keys and credentials
    // -------------------------------------------------------------------------------------

    /// Argon2id parameters and salt of the master password, published to the server so other
    /// devices can derive the same login key.
    pub fn kdf_info(&self) -> Result<KdfInfo> {
        match load_slot(&self.conn, META_MASTER_SLOT)?.kind() {
            SlotKind::Password { params, salt } => Ok(KdfInfo {
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt: salt.0.to_vec(),
            }),
            SlotKind::Key => Err(VaultError::Corrupted),
        }
    }

    /// Server login key. Fails with [`VaultError::WrongPassword`] for a wrong password.
    pub fn auth_key(&self, master_password: &str) -> Result<SecretKey> {
        let slot = load_slot(&self.conn, META_MASTER_SLOT)?;
        let master = slot.derive_master(master_password.as_bytes()).map_err(data_error)?;
        slot.open_with_master(&master, CTX_VAULT_KEY).map_err(wrong(VaultError::WrongPassword))?;
        Ok(hkdf_subkey(&master, AUTH_KEY_INFO))
    }

    /// Proof of holding the vault key; requires the vault to be unlocked.
    pub fn key_proof(&self) -> Result<SecretKey> {
        Ok(hkdf_subkey(self.require_vault_key()?, KEY_PROOF_INFO))
    }

    /// The wrapped keys, as uploaded to the sync server.
    pub fn key_bundle(&self) -> Result<KeyBundle> {
        let slot = |key| store::require_meta(&self.conn, key);
        Ok(KeyBundle {
            vault_id: self.id,
            master_slot: slot(META_MASTER_SLOT)?,
            notes_slot: slot(META_NOTES_SLOT)?,
            recovery_vault_slot: slot(META_RECOVERY_VAULT_SLOT)?,
            recovery_notes_slot: slot(META_RECOVERY_NOTES_SLOT)?,
        })
    }

    /// Creates a local vault on a new device from the bundle stored on the server and unlocks
    /// it. Fails with [`VaultError::WrongPassword`] before touching the disk if the master
    /// password does not open the bundle.
    pub fn create_from_bundle(path: &Path, bundle: &KeyBundle, master_password: &str) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        let master = KeySlot::from_bytes(&bundle.master_slot).map_err(data_error)?;
        for slot in [&bundle.notes_slot, &bundle.recovery_vault_slot, &bundle.recovery_notes_slot] {
            KeySlot::from_bytes(slot).map_err(data_error)?;
        }
        let vault_key = master
            .open_password(master_password.as_bytes(), CTX_VAULT_KEY)
            .map_err(wrong(VaultError::WrongPassword))?;
        let SlotKind::Password { params, .. } = *master.kind() else {
            return Err(VaultError::Corrupted);
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        let mut conn = store::open(path)?;
        let tx = conn.transaction()?;
        store::set_meta(&tx, META_FORMAT, &FORMAT_VERSION.to_le_bytes())?;
        store::set_meta(&tx, META_VAULT_ID, bundle.vault_id.as_bytes())?;
        store::set_meta(&tx, META_MASTER_SLOT, &bundle.master_slot)?;
        store::set_meta(&tx, META_NOTES_SLOT, &bundle.notes_slot)?;
        store::set_meta(&tx, META_RECOVERY_VAULT_SLOT, &bundle.recovery_vault_slot)?;
        store::set_meta(&tx, META_RECOVERY_NOTES_SLOT, &bundle.recovery_notes_slot)?;
        verify_vault_key(&tx, &vault_key)?;
        tx.commit()?;
        Ok(Self {
            conn,
            id: bundle.vault_id,
            kdf_params: params,
            vault_key: Some(vault_key),
            notes_key: None,
        })
    }

    /// Adopts a key bundle published by another device (after a password change or a
    /// recovery-key rotation). The previous slots are kept until the next successful unlock
    /// proves the new ones wrap the same keys; otherwise they are restored.
    pub fn apply_key_bundle(&mut self, bundle: &KeyBundle) -> Result<()> {
        if bundle.vault_id != self.id {
            return Err(VaultError::KeyMismatch);
        }
        let new = [
            &bundle.master_slot,
            &bundle.notes_slot,
            &bundle.recovery_vault_slot,
            &bundle.recovery_notes_slot,
        ];
        for slot in new {
            KeySlot::from_bytes(slot).map_err(data_error)?;
        }
        let tx = self.conn.transaction()?;
        for (key, value) in SLOT_KEYS.iter().zip(new) {
            let current = store::require_meta(&tx, key)?;
            if current == *value {
                continue;
            }
            let backup = format!("{key}{PREVIOUS_SUFFIX}");
            if store::get_meta(&tx, &backup)?.is_none() {
                store::set_meta(&tx, &backup, &current)?;
            }
            store::set_meta(&tx, key, value)?;
        }
        tx.commit()?;
        self.refresh_kdf_params()
    }

    // -------------------------------------------------------------------------------------
    // Sync settings and state
    // -------------------------------------------------------------------------------------

    /// The sync configuration, if sync has ever been set up.
    pub fn sync_settings(&self) -> Result<Option<SyncSettings>> {
        store::get_meta(&self.conn, META_SETTINGS)?
            .map(|json| serde_json::from_slice(&json).map_err(|_| VaultError::Corrupted))
            .transpose()
    }

    /// Whether this device holds a session token (i.e. is signed in).
    pub fn is_sync_enabled(&self) -> Result<bool> {
        Ok(store::get_meta(&self.conn, META_TOKEN)?.is_some())
    }

    /// Turns sync on for `settings` with a fresh session. Unless this vault was already synced
    /// with the same server and account, every item is scheduled for upload.
    pub fn enable_sync(&mut self, settings: &SyncSettings, token: &str, keys_version: i64) -> Result<()> {
        let resume = self
            .sync_settings()?
            .is_some_and(|old| old.server_url == settings.server_url && old.email == settings.email);
        let sealed_token =
            seal(self.require_vault_key()?, token.as_bytes(), TOKEN_AAD).map_err(VaultError::Crypto)?;
        let json = serde_json::to_vec(settings).map_err(|e| VaultError::Invalid(e.to_string()))?;
        let tx = self.conn.transaction()?;
        if !resume {
            store::reset_sync_state(&tx)?;
            store::set_meta(&tx, META_CURSOR, &0i64.to_le_bytes())?;
        }
        store::set_meta(&tx, META_SETTINGS, &json)?;
        store::set_meta(&tx, META_TOKEN, &sealed_token)?;
        store::set_meta(&tx, META_KEYS_VERSION, &keys_version.to_le_bytes())?;
        tx.commit()?;
        Ok(())
    }

    /// Signs this device out. Settings and per-item sync state are kept so signing in again
    /// to the same account resumes instead of re-uploading.
    pub fn disable_sync(&mut self) -> Result<()> {
        store::delete_meta(&self.conn, META_TOKEN)
    }

    /// The session token; requires the vault to be unlocked.
    pub fn sync_token(&self) -> Result<Option<Zeroizing<String>>> {
        let Some(sealed) = store::get_meta(&self.conn, META_TOKEN)? else { return Ok(None) };
        let plain = open(self.require_vault_key()?, &sealed, TOKEN_AAD).map_err(data_error)?;
        String::from_utf8(plain.to_vec()).map(|t| Some(Zeroizing::new(t))).map_err(|_| VaultError::Corrupted)
    }

    /// Highest server sequence number already pulled.
    pub fn sync_cursor(&self) -> Result<i64> {
        meta_i64(self, META_CURSOR)
    }

    pub fn set_sync_cursor(&mut self, cursor: i64) -> Result<()> {
        store::set_meta(&self.conn, META_CURSOR, &cursor.to_le_bytes())
    }

    /// Version of the server key bundle this vault last adopted or published.
    pub fn synced_keys_version(&self) -> Result<i64> {
        meta_i64(self, META_KEYS_VERSION)
    }

    pub fn set_synced_keys_version(&mut self, version: i64) -> Result<()> {
        store::set_meta(&self.conn, META_KEYS_VERSION, &version.to_le_bytes())
    }

    pub fn last_sync(&self) -> Result<Option<DateTime<Utc>>> {
        Ok(match meta_i64(self, META_LAST_SYNC)? {
            0 => None,
            ms => DateTime::from_timestamp_millis(ms),
        })
    }

    pub fn set_last_sync(&mut self, at: DateTime<Utc>) -> Result<()> {
        store::set_meta(&self.conn, META_LAST_SYNC, &at.timestamp_millis().to_le_bytes())
    }

    /// Passwords were reset with the recovery key while the server could not be told; the
    /// server login still has to be reset (see `simplus_vault_sync::recover_account`).
    pub fn recovery_pending(&self) -> Result<bool> {
        Ok(store::get_meta(&self.conn, META_RECOVERY_PENDING)?.is_some())
    }

    pub fn set_recovery_pending(&mut self, pending: bool) -> Result<()> {
        if pending {
            store::set_meta(&self.conn, META_RECOVERY_PENDING, &[1])
        } else {
            store::delete_meta(&self.conn, META_RECOVERY_PENDING)
        }
    }

    // -------------------------------------------------------------------------------------
    // Change exchange
    // -------------------------------------------------------------------------------------

    /// Local changes that still need to be pushed.
    pub fn pending_changes(&mut self) -> Result<Vec<PendingChange>> {
        store::clear_unpushed_tombstones(&self.conn)?;
        Ok(store::dirty_rows(&self.conn)?
            .into_iter()
            .map(|row| PendingChange {
                revision: row.revision,
                item: PushItem {
                    id: row.id,
                    kind: row.kind.into(),
                    parent_id: row.parent_id,
                    base_seq: row.server_seq,
                    deleted: row.deleted,
                    updated_at: row.updated_at,
                    blob: row.blob,
                },
            })
            .collect())
    }

    /// The server accepted `revision` of item `id` as `seq`.
    pub fn mark_pushed(&mut self, id: Uuid, revision: i64, seq: i64) -> Result<()> {
        store::mark_pushed(&self.conn, id, revision, seq)
    }

    /// Merges changes pulled from the server. Requires the vault to be unlocked so remote
    /// records can be verified and conflicts resolved; remote notes are verified too when the
    /// notes are unlocked.
    pub fn apply_remote(&mut self, items: &[RemoteItem]) -> Result<ApplyReport> {
        let vault_key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let notes_key = self.notes_key.as_ref();
        let now = Utc::now();
        let tx = self.conn.transaction()?;
        let mut report = ApplyReport::default();

        for remote in items {
            let kind = ItemKind::from(remote.kind);
            let row = remote_row(remote);
            let consistent =
                matches!((kind, remote.parent_id), (ItemKind::Record, None) | (ItemKind::Note, Some(_)));
            // Never store something we know is unreadable: it would break listing later.
            let valid = consistent
                && match (&remote.blob, remote.deleted) {
                    (_, true) => true,
                    (None, false) => false,
                    (Some(_), false) => match kind {
                        ItemKind::Record => decrypt_record(vault_key, &row).is_ok(),
                        ItemKind::Note => notes_key.is_none_or(|key| decrypt_note(key, &row).is_ok()),
                    },
                };
            if !valid {
                report.rejected += 1;
                continue;
            }
            let blob = if remote.deleted { None } else { remote.blob.as_deref() };
            let put = |tx: &simplus_core::db::rusqlite::Connection| {
                store::put_remote(
                    tx,
                    kind,
                    remote.id,
                    remote.parent_id,
                    remote.seq,
                    remote.deleted,
                    remote.updated_at,
                    blob,
                )
            };

            let Some(local) = store::get_full(&tx, remote.id)? else {
                if !remote.deleted {
                    put(&tx)?;
                    report.applied += 1;
                }
                continue;
            };
            if local.kind != kind || local.parent_id != remote.parent_id {
                report.rejected += 1;
                continue;
            }
            if local.server_seq >= remote.seq {
                continue; // Already have this version (typically our own push echoed back).
            }
            if !local.dirty {
                put(&tx)?;
                report.applied += 1;
                continue;
            }
            match (local.deleted, remote.deleted) {
                (true, true) | (true, false) => {
                    // Both deleted, or a remote edit beats a local delete.
                    put(&tx)?;
                    report.applied += 1;
                }
                (false, true) => {
                    // A local edit beats a remote delete: keep it and push it again.
                    store::set_server_seq(&tx, remote.id, remote.seq)?;
                    report.conflicts += 1;
                }
                (false, false) => {
                    let local_row = row_from_full(&local);
                    let differs = match kind {
                        ItemKind::Record => {
                            let mine = decrypt_record(vault_key, &local_row)?;
                            let theirs = decrypt_record(vault_key, &row)?;
                            let differs = !same_record(&mine, &theirs);
                            if differs {
                                let mut copy = mine.clone();
                                copy.id = Uuid::now_v7();
                                copy.title.push_str(CONFLICT_SUFFIX);
                                copy.updated_at = now;
                                let blob = encrypt_item(vault_key, ItemKind::Record, copy.id, None, &copy)?;
                                store::put_item(
                                    &tx,
                                    ItemKind::Record,
                                    copy.id,
                                    None,
                                    1,
                                    now.timestamp_millis(),
                                    &blob,
                                )?;
                            }
                            differs
                        }
                        ItemKind::Note => match notes_key {
                            Some(key) => {
                                let mine = decrypt_note(key, &local_row)?;
                                let theirs = decrypt_note(key, &row)?;
                                let differs = !same_note(&mine, &theirs);
                                if differs {
                                    copy_note(&tx, key, &mine, now)?;
                                }
                                differs
                            }
                            None => {
                                let blob = local.blob.as_deref().ok_or(VaultError::Corrupted)?;
                                store::stash_conflict(&tx, local.id, local.parent_id, blob)?;
                                true
                            }
                        },
                    };
                    put(&tx)?;
                    report.applied += 1;
                    if differs {
                        report.conflicts += 1;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(report)
    }

    /// Turns notes stashed during a locked-notes conflict into conflict copies (dropping the
    /// ones identical to the current note). Requires the notes to be unlocked.
    pub(crate) fn resolve_pending_conflicts(&mut self) -> Result<usize> {
        self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let key = self.notes_key.as_ref().ok_or(VaultError::NotesLocked)?;
        let now = Utc::now();
        let tx = self.conn.transaction()?;
        let mut created = 0;
        for stashed in store::stashed_conflicts(&tx)? {
            if let Ok(mine) = decrypt_note(key, &stashed) {
                let current = store::get_item(&tx, ItemKind::Note, stashed.id)?
                    .and_then(|row| decrypt_note(key, &row).ok());
                if !current.is_some_and(|theirs| same_note(&mine, &theirs)) {
                    copy_note(&tx, key, &mine, now)?;
                    created += 1;
                }
            }
            store::remove_stashed_conflict(&tx, stashed.id)?;
        }
        tx.commit()?;
        Ok(created)
    }
}

fn copy_note(
    conn: &simplus_core::db::rusqlite::Connection,
    key: &SecretKey,
    note: &SecureNote,
    now: DateTime<Utc>,
) -> Result<()> {
    let mut copy = note.clone();
    copy.id = Uuid::now_v7();
    copy.title.push_str(CONFLICT_SUFFIX);
    copy.updated_at = now;
    let blob = encrypt_item(key, ItemKind::Note, copy.id, Some(copy.record_id), &copy)?;
    store::put_item(conn, ItemKind::Note, copy.id, Some(copy.record_id), 1, now.timestamp_millis(), &blob)
}

#[cfg(test)]
mod tests;
