use std::path::Path;

use chrono::Utc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use simplus_core::db::rusqlite::Connection;
use simplus_crypto::{
    CryptoError, KdfParams, KeySlot, SecretKey, SlotKind, hkdf_subkey, open as open_sealed, seal,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::model::{MAX_PASSWORD_HISTORY, PasswordHistoryEntry, Record, SecureNote};
use crate::recovery::RecoveryKey;
use crate::store::{self, ItemKind, ItemRow};
use crate::{Result, VaultError};

pub(crate) const FORMAT_VERSION: u32 = 1;

pub(crate) const META_FORMAT: &str = "format_version";
pub(crate) const META_VAULT_ID: &str = "vault_id";
pub(crate) const META_MASTER_SLOT: &str = "slot.master";
pub(crate) const META_NOTES_SLOT: &str = "slot.notes";
pub(crate) const META_RECOVERY_VAULT_SLOT: &str = "slot.recovery.vault_key";
pub(crate) const META_RECOVERY_NOTES_SLOT: &str = "slot.recovery.notes_key";
pub(crate) const SLOT_KEYS: [&str; 4] =
    [META_MASTER_SLOT, META_NOTES_SLOT, META_RECOVERY_VAULT_SLOT, META_RECOVERY_NOTES_SLOT];
const META_KEY_CHECK_VAULT: &str = "key_check.vault";
const META_KEY_CHECK_NOTES: &str = "key_check.notes";
/// Suffix of the backup kept for each slot while a server-supplied key bundle is unverified.
pub(crate) const PREVIOUS_SUFFIX: &str = ".previous";

pub(crate) const CTX_VAULT_KEY: &[u8] = b"simplus/vault/vault-key";
pub(crate) const CTX_NOTES_KEY: &[u8] = b"simplus/vault/notes-key";
const CTX_RECOVERY_VAULT_KEY: &[u8] = b"simplus/vault/recovery/vault-key";
const CTX_RECOVERY_NOTES_KEY: &[u8] = b"simplus/vault/recovery/notes-key";
const ITEM_AAD_PREFIX: &[u8] = b"simplus/vault/item/v1";
const KEY_CHECK_INFO: &[u8] = b"simplus/vault/key-check/v1";

/// An open vault file. Starts locked; [`Vault::unlock`] makes records readable and
/// [`Vault::unlock_notes`] additionally makes secure notes readable.
pub struct Vault {
    pub(crate) conn: Connection,
    pub(crate) id: Uuid,
    pub(crate) kdf_params: KdfParams,
    pub(crate) vault_key: Option<SecretKey>,
    pub(crate) notes_key: Option<SecretKey>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("id", &self.id)
            .field("unlocked", &self.is_unlocked())
            .field("notes_unlocked", &self.notes_unlocked())
            .finish_non_exhaustive()
    }
}

/// Maps a crypto failure on stored data to "corrupted"; other crypto errors pass through.
pub(crate) fn data_error(e: CryptoError) -> VaultError {
    match e {
        CryptoError::Decrypt | CryptoError::Format | CryptoError::InvalidParams(_) => VaultError::Corrupted,
        other => VaultError::Crypto(other),
    }
}

pub(crate) fn wrong(password_error: VaultError) -> impl Fn(CryptoError) -> VaultError {
    move |e| match e {
        CryptoError::Decrypt => match &password_error {
            VaultError::WrongPassword => VaultError::WrongPassword,
            VaultError::WrongNotesPassword => VaultError::WrongNotesPassword,
            _ => VaultError::WrongRecoveryKey,
        },
        other => data_error(other),
    }
}

fn check_password(password: &str) -> Result<()> {
    if password.is_empty() { Err(VaultError::EmptyPassword) } else { Ok(()) }
}

pub(crate) fn item_aad(kind: ItemKind, id: Uuid, parent: Option<Uuid>) -> Vec<u8> {
    let mut aad = ITEM_AAD_PREFIX.to_vec();
    aad.push(kind as u8);
    aad.extend_from_slice(id.as_bytes());
    match parent {
        Some(p) => {
            aad.push(1);
            aad.extend_from_slice(p.as_bytes());
        }
        None => aad.push(0),
    }
    aad
}

pub(crate) fn encrypt_item<T: Serialize>(
    key: &SecretKey,
    kind: ItemKind,
    id: Uuid,
    parent: Option<Uuid>,
    value: &T,
) -> Result<Vec<u8>> {
    let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|e| VaultError::Invalid(e.to_string()))?);
    seal(key, &plain, &item_aad(kind, id, parent)).map_err(VaultError::Crypto)
}

pub(crate) fn decrypt_item<T: DeserializeOwned>(key: &SecretKey, kind: ItemKind, row: &ItemRow) -> Result<T> {
    let blob = row.blob.as_deref().ok_or(VaultError::Corrupted)?;
    let plain = open_sealed(key, blob, &item_aad(kind, row.id, row.parent_id)).map_err(data_error)?;
    serde_json::from_slice(&plain).map_err(|_| VaultError::Corrupted)
}

pub(crate) fn decrypt_record(key: &SecretKey, row: &ItemRow) -> Result<Record> {
    let record: Record = decrypt_item(key, ItemKind::Record, row)?;
    if record.id != row.id {
        return Err(VaultError::Corrupted);
    }
    Ok(record)
}

pub(crate) fn decrypt_note(key: &SecretKey, row: &ItemRow) -> Result<SecureNote> {
    let note: SecureNote = decrypt_item(key, ItemKind::Note, row)?;
    if note.id != row.id || Some(note.record_id) != row.parent_id {
        return Err(VaultError::Corrupted);
    }
    Ok(note)
}

pub(crate) fn load_slot(conn: &Connection, key: &str) -> Result<KeySlot> {
    KeySlot::from_bytes(&store::require_meta(conn, key)?).map_err(data_error)
}

fn write_slot(conn: &Connection, key: &str, slot: std::result::Result<KeySlot, CryptoError>) -> Result<()> {
    store::set_meta(conn, key, &slot.map_err(VaultError::Crypto)?.to_bytes())
}

/// Compares `key` with the fingerprint stored under `meta_key`, recording it if absent (vaults
/// created before fingerprints existed). A mismatch means a key slot was replaced by one that
/// wraps a different key, e.g. a tampered bundle from a sync server.
pub(crate) fn verify_key_check(conn: &Connection, meta_key: &str, key: &SecretKey) -> Result<()> {
    let expected = hkdf_subkey(key, KEY_CHECK_INFO);
    match store::get_meta(conn, meta_key)? {
        Some(stored) if stored.as_slice() == expected.expose() => Ok(()),
        Some(_) => Err(VaultError::KeyMismatch),
        None => store::set_meta(conn, meta_key, expected.expose()),
    }
}

pub(crate) fn verify_vault_key(conn: &Connection, key: &SecretKey) -> Result<()> {
    verify_key_check(conn, META_KEY_CHECK_VAULT, key)
}

pub(crate) fn verify_notes_key(conn: &Connection, key: &SecretKey) -> Result<()> {
    verify_key_check(conn, META_KEY_CHECK_NOTES, key)
}

/// Puts back the slots that a server-supplied bundle replaced (see `apply_key_bundle`).
fn restore_previous_slots(conn: &Connection) -> Result<()> {
    for key in SLOT_KEYS {
        let backup = format!("{key}{PREVIOUS_SUFFIX}");
        if let Some(previous) = store::get_meta(conn, &backup)? {
            store::set_meta(conn, key, &previous)?;
            store::delete_meta(conn, &backup)?;
        }
    }
    Ok(())
}

/// The new slots proved genuine; drop the backups.
fn forget_previous_slots(conn: &Connection) -> Result<()> {
    for key in SLOT_KEYS {
        store::delete_meta(conn, &format!("{key}{PREVIOUS_SUFFIX}"))?;
    }
    Ok(())
}

fn remove_db_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(p);
    }
}

impl Vault {
    /// Whether a vault file exists at `path`.
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Creates a new vault and returns it unlocked (notes locked) together with the recovery
    /// key, which must be shown to the user exactly once.
    pub fn create(
        path: &Path,
        master_password: &str,
        notes_password: &str,
        params: KdfParams,
    ) -> Result<(Self, RecoveryKey)> {
        check_password(master_password)?;
        check_password(notes_password)?;
        if master_password == notes_password {
            return Err(VaultError::PasswordsMustDiffer);
        }
        params.validate().map_err(VaultError::Crypto)?;
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let result = Self::create_inner(path, master_password, notes_password, params);
        if result.is_err() {
            remove_db_files(path);
        }
        result
    }

    fn create_inner(
        path: &Path,
        master_password: &str,
        notes_password: &str,
        params: KdfParams,
    ) -> Result<(Self, RecoveryKey)> {
        let mut conn = store::open(path)?;
        let vault_key = SecretKey::generate().map_err(VaultError::Crypto)?;
        let notes_key = SecretKey::generate().map_err(VaultError::Crypto)?;
        let recovery = RecoveryKey::generate()?;
        let id = Uuid::now_v7();

        let tx = conn.transaction()?;
        store::set_meta(&tx, META_FORMAT, &FORMAT_VERSION.to_le_bytes())?;
        store::set_meta(&tx, META_VAULT_ID, id.as_bytes())?;
        write_slot(
            &tx,
            META_MASTER_SLOT,
            KeySlot::seal_password(master_password.as_bytes(), params, &vault_key, CTX_VAULT_KEY),
        )?;
        write_slot(
            &tx,
            META_NOTES_SLOT,
            KeySlot::seal_password(notes_password.as_bytes(), params, &notes_key, CTX_NOTES_KEY),
        )?;
        write_slot(
            &tx,
            META_RECOVERY_VAULT_SLOT,
            KeySlot::seal_key(recovery.key(), &vault_key, CTX_RECOVERY_VAULT_KEY),
        )?;
        write_slot(
            &tx,
            META_RECOVERY_NOTES_SLOT,
            KeySlot::seal_key(recovery.key(), &notes_key, CTX_RECOVERY_NOTES_KEY),
        )?;
        verify_vault_key(&tx, &vault_key)?;
        verify_notes_key(&tx, &notes_key)?;
        tx.commit()?;

        Ok((Self { conn, id, kdf_params: params, vault_key: Some(vault_key), notes_key: None }, recovery))
    }

    /// Opens an existing vault in the locked state.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(VaultError::NotFound);
        }
        let conn = store::open(path)?;
        let version = store::require_meta(&conn, META_FORMAT)?;
        let version = u32::from_le_bytes(version.try_into().map_err(|_| VaultError::Corrupted)?);
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        let id = Uuid::from_slice(&store::require_meta(&conn, META_VAULT_ID)?)
            .map_err(|_| VaultError::Corrupted)?;
        let kdf_params = match load_slot(&conn, META_MASTER_SLOT)?.kind() {
            SlotKind::Password { params, .. } => *params,
            SlotKind::Key => return Err(VaultError::Corrupted),
        };
        Ok(Self { conn, id, kdf_params, vault_key: None, notes_key: None })
    }

    /// Resets both passwords with the recovery key and returns the vault unlocked.
    pub fn recover(
        path: &Path,
        recovery_key: &RecoveryKey,
        new_master_password: &str,
        new_notes_password: &str,
    ) -> Result<Self> {
        check_password(new_master_password)?;
        check_password(new_notes_password)?;
        if new_master_password == new_notes_password {
            return Err(VaultError::PasswordsMustDiffer);
        }
        let mut vault = Self::open(path)?;
        let vault_key = load_slot(&vault.conn, META_RECOVERY_VAULT_SLOT)?
            .open_key(recovery_key.key(), CTX_RECOVERY_VAULT_KEY)
            .map_err(wrong(VaultError::WrongRecoveryKey))?;
        let notes_key = load_slot(&vault.conn, META_RECOVERY_NOTES_SLOT)?
            .open_key(recovery_key.key(), CTX_RECOVERY_NOTES_KEY)
            .map_err(wrong(VaultError::WrongRecoveryKey))?;
        verify_vault_key(&vault.conn, &vault_key)?;
        verify_notes_key(&vault.conn, &notes_key)?;

        let params = vault.kdf_params;
        let tx = vault.conn.transaction()?;
        write_slot(
            &tx,
            META_MASTER_SLOT,
            KeySlot::seal_password(new_master_password.as_bytes(), params, &vault_key, CTX_VAULT_KEY),
        )?;
        write_slot(
            &tx,
            META_NOTES_SLOT,
            KeySlot::seal_password(new_notes_password.as_bytes(), params, &notes_key, CTX_NOTES_KEY),
        )?;
        tx.commit()?;
        vault.vault_key = Some(vault_key);
        Ok(vault)
    }

    /// Stable identifier of this vault (used later for sync).
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Argon2id parameters used when a password is (re)set.
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// Changes the Argon2id parameters used for future password changes.
    pub fn set_kdf_params(&mut self, params: KdfParams) -> Result<()> {
        params.validate().map_err(VaultError::Crypto)?;
        self.kdf_params = params;
        Ok(())
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        let key = load_slot(&self.conn, META_MASTER_SLOT)?
            .open_password(master_password.as_bytes(), CTX_VAULT_KEY)
            .map_err(wrong(VaultError::WrongPassword))?;
        if let Err(e) = verify_vault_key(&self.conn, &key) {
            // A key bundle received through sync wraps a different key: undo it.
            restore_previous_slots(&self.conn)?;
            self.refresh_kdf_params()?;
            return Err(e);
        }
        forget_previous_slots(&self.conn)?;
        self.vault_key = Some(key);
        Ok(())
    }

    pub(crate) fn refresh_kdf_params(&mut self) -> Result<()> {
        if let SlotKind::Password { params, .. } = load_slot(&self.conn, META_MASTER_SLOT)?.kind() {
            self.kdf_params = *params;
        }
        Ok(())
    }

    /// Forgets both keys; everything becomes unreadable until the next unlock.
    pub fn lock(&mut self) {
        self.vault_key = None;
        self.notes_key = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault_key.is_some()
    }

    /// Unlocks secure notes. The vault itself must already be unlocked.
    pub fn unlock_notes(&mut self, notes_password: &str) -> Result<()> {
        self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let key = load_slot(&self.conn, META_NOTES_SLOT)?
            .open_password(notes_password.as_bytes(), CTX_NOTES_KEY)
            .map_err(wrong(VaultError::WrongNotesPassword))?;
        verify_notes_key(&self.conn, &key)?;
        self.notes_key = Some(key);
        // Notes that lost a sync conflict while locked can now become conflict copies. Best
        // effort: anything left over is retried at the next unlock.
        let _ = self.resolve_pending_conflicts();
        Ok(())
    }

    pub fn lock_notes(&mut self) {
        self.notes_key = None;
    }

    pub fn notes_unlocked(&self) -> bool {
        self.vault_key.is_some() && self.notes_key.is_some()
    }

    pub(crate) fn require_vault_key(&self) -> Result<&SecretKey> {
        self.vault_key.as_ref().ok_or(VaultError::Locked)
    }

    pub(crate) fn require_notes_key(&self) -> Result<&SecretKey> {
        self.require_vault_key()?;
        self.notes_key.as_ref().ok_or(VaultError::NotesLocked)
    }

    /// All records, sorted by title.
    pub fn list_records(&self) -> Result<Vec<Record>> {
        let key = self.require_vault_key()?;
        let mut records = store::list_items(&self.conn, ItemKind::Record, None)?
            .iter()
            .map(|row| decrypt_record(key, row))
            .collect::<Result<Vec<_>>>()?;
        records.sort_by_cached_key(|r| (r.title.to_lowercase(), r.id));
        Ok(records)
    }

    pub fn get_record(&self, id: Uuid) -> Result<Record> {
        let key = self.require_vault_key()?;
        let row = store::get_item(&self.conn, ItemKind::Record, id)?.ok_or(VaultError::ItemNotFound(id))?;
        decrypt_record(key, &row)
    }

    /// Inserts or updates a record. The vault keeps `created_at` and the password history
    /// authoritative: a changed password is pushed onto the stored history.
    pub fn save_record(&mut self, record: &mut Record) -> Result<()> {
        let key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        if record.title.trim().is_empty() {
            return Err(VaultError::Invalid("a title is required".into()));
        }
        let now = Utc::now();
        let tx = self.conn.transaction()?;
        match store::get_item(&tx, ItemKind::Record, record.id)? {
            Some(row) => {
                let old = decrypt_record(key, &row)?;
                record.created_at = old.created_at;
                record.password_history = old.password_history.clone();
                if old.password != record.password && !old.password.is_empty() {
                    record
                        .password_history
                        .insert(0, PasswordHistoryEntry { password: old.password.clone(), changed_at: now });
                    record.password_history.truncate(MAX_PASSWORD_HISTORY);
                }
            }
            None if store::get_item(&tx, ItemKind::Note, record.id)?.is_some() => {
                return Err(VaultError::Invalid("id already used by a note".into()));
            }
            None => {}
        }
        record.updated_at = now;
        let revision = store::revision(&tx, record.id)? + 1;
        let blob = encrypt_item(key, ItemKind::Record, record.id, None, record)?;
        store::put_item(&tx, ItemKind::Record, record.id, None, revision, now.timestamp_millis(), &blob)?;
        tx.commit()?;
        Ok(())
    }

    /// Deletes a record and all of its secure notes (as tombstones, for sync).
    pub fn delete_record(&mut self, id: Uuid) -> Result<()> {
        self.require_vault_key()?;
        let now = Utc::now().timestamp_millis();
        let tx = self.conn.transaction()?;
        if store::get_item(&tx, ItemKind::Record, id)?.is_none() {
            return Err(VaultError::ItemNotFound(id));
        }
        for note in store::list_items(&tx, ItemKind::Note, Some(id))? {
            store::tombstone(&tx, note.id, now)?;
        }
        store::tombstone(&tx, id, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Number of secure notes on a record; available without the notes password.
    pub fn note_count(&self, record_id: Uuid) -> Result<usize> {
        self.require_vault_key()?;
        store::count_children(&self.conn, record_id)
    }

    /// Secure notes of a record, oldest first. Requires the notes password.
    pub fn list_notes(&self, record_id: Uuid) -> Result<Vec<SecureNote>> {
        let key = self.require_notes_key()?;
        let mut notes = store::list_items(&self.conn, ItemKind::Note, Some(record_id))?
            .iter()
            .map(|row| decrypt_note(key, row))
            .collect::<Result<Vec<_>>>()?;
        notes.sort_by_key(|n| (n.created_at, n.id));
        Ok(notes)
    }

    pub fn save_note(&mut self, note: &mut SecureNote) -> Result<()> {
        self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let key = self.notes_key.as_ref().ok_or(VaultError::NotesLocked)?;
        let now = Utc::now();
        let tx = self.conn.transaction()?;
        if store::get_item(&tx, ItemKind::Record, note.record_id)?.is_none() {
            return Err(VaultError::ItemNotFound(note.record_id));
        }
        match store::get_item(&tx, ItemKind::Note, note.id)? {
            Some(row) if row.parent_id != Some(note.record_id) => {
                return Err(VaultError::Invalid("a note cannot move to another record".into()));
            }
            Some(row) => note.created_at = decrypt_note(key, &row)?.created_at,
            None if store::get_item(&tx, ItemKind::Record, note.id)?.is_some() => {
                return Err(VaultError::Invalid("id already used by a record".into()));
            }
            None => {}
        }
        note.updated_at = now;
        let revision = store::revision(&tx, note.id)? + 1;
        let blob = encrypt_item(key, ItemKind::Note, note.id, Some(note.record_id), note)?;
        store::put_item(
            &tx,
            ItemKind::Note,
            note.id,
            Some(note.record_id),
            revision,
            now.timestamp_millis(),
            &blob,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_note(&mut self, id: Uuid) -> Result<()> {
        self.require_notes_key()?;
        if store::get_item(&self.conn, ItemKind::Note, id)?.is_none() {
            return Err(VaultError::ItemNotFound(id));
        }
        store::tombstone(&self.conn, id, Utc::now().timestamp_millis())?;
        Ok(())
    }

    /// Changes the master password. The new password must differ from the notes password.
    pub fn change_master_password(&mut self, current: &str, new: &str) -> Result<()> {
        check_password(new)?;
        let vault_key = load_slot(&self.conn, META_MASTER_SLOT)?
            .open_password(current.as_bytes(), CTX_VAULT_KEY)
            .map_err(wrong(VaultError::WrongPassword))?;
        if load_slot(&self.conn, META_NOTES_SLOT)?.open_password(new.as_bytes(), CTX_NOTES_KEY).is_ok() {
            return Err(VaultError::PasswordsMustDiffer);
        }
        let slot = KeySlot::seal_password(new.as_bytes(), self.kdf_params, &vault_key, CTX_VAULT_KEY);
        write_slot(&self.conn, META_MASTER_SLOT, slot)
    }

    /// Changes the notes password. The new password must differ from the master password.
    pub fn change_notes_password(&mut self, current: &str, new: &str) -> Result<()> {
        check_password(new)?;
        let notes_key = load_slot(&self.conn, META_NOTES_SLOT)?
            .open_password(current.as_bytes(), CTX_NOTES_KEY)
            .map_err(wrong(VaultError::WrongNotesPassword))?;
        if load_slot(&self.conn, META_MASTER_SLOT)?.open_password(new.as_bytes(), CTX_VAULT_KEY).is_ok() {
            return Err(VaultError::PasswordsMustDiffer);
        }
        let slot = KeySlot::seal_password(new.as_bytes(), self.kdf_params, &notes_key, CTX_NOTES_KEY);
        write_slot(&self.conn, META_NOTES_SLOT, slot)
    }

    /// Replaces the recovery key (e.g. after the old kit was lost or exposed). Requires both
    /// the vault and the notes to be unlocked. The old key stops working immediately.
    pub fn rotate_recovery_key(&mut self) -> Result<RecoveryKey> {
        let vault_key = self.vault_key.as_ref().ok_or(VaultError::Locked)?;
        let notes_key = self.notes_key.as_ref().ok_or(VaultError::NotesLocked)?;
        let recovery = RecoveryKey::generate()?;
        let tx = self.conn.transaction()?;
        write_slot(
            &tx,
            META_RECOVERY_VAULT_SLOT,
            KeySlot::seal_key(recovery.key(), vault_key, CTX_RECOVERY_VAULT_KEY),
        )?;
        write_slot(
            &tx,
            META_RECOVERY_NOTES_SLOT,
            KeySlot::seal_key(recovery.key(), notes_key, CTX_RECOVERY_NOTES_KEY),
        )?;
        tx.commit()?;
        Ok(recovery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CustomField;

    const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };
    const MP1: &str = "correct horse battery staple";
    const MP2: &str = "notes are extra secret";

    fn new_vault() -> (tempfile::TempDir, std::path::PathBuf, Vault, RecoveryKey) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let (vault, recovery) = Vault::create(&path, MP1, MP2, FAST).unwrap();
        (dir, path, vault, recovery)
    }

    fn sample_record() -> Record {
        let mut r = Record::new("GitHub");
        r.username = "octocat".into();
        r.password = "hunter2".into();
        r.urls = vec!["https://github.com".into()];
        r.custom_fields.push(CustomField { name: "PIN".into(), value: "1234".into(), hidden: true });
        r
    }

    #[test]
    fn create_rejects_bad_passwords_and_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        assert!(matches!(Vault::create(&path, "same", "same", FAST), Err(VaultError::PasswordsMustDiffer)));
        assert!(matches!(Vault::create(&path, "", MP2, FAST), Err(VaultError::EmptyPassword)));
        assert!(!path.exists(), "failed creation leaves nothing behind");
        Vault::create(&path, MP1, MP2, FAST).unwrap();
        assert!(matches!(Vault::create(&path, MP1, MP2, FAST), Err(VaultError::AlreadyExists)));
    }

    #[test]
    fn records_persist_and_need_unlock() {
        let (_dir, path, mut vault, _) = new_vault();
        let mut r = sample_record();
        vault.save_record(&mut r).unwrap();
        let id = vault.id();
        drop(vault);

        let mut vault = Vault::open(&path).unwrap();
        assert_eq!(vault.id(), id);
        assert_eq!(vault.kdf_params(), FAST);
        assert!(matches!(vault.list_records(), Err(VaultError::Locked)));
        assert!(matches!(vault.unlock("wrong"), Err(VaultError::WrongPassword)));
        vault.unlock(MP1).unwrap();
        let records = vault.list_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].password, "hunter2");
        assert_eq!(records[0].custom_fields[0].value, "1234");

        vault.lock();
        assert!(matches!(vault.get_record(r.id), Err(VaultError::Locked)));
    }

    #[test]
    fn save_tracks_history_and_keeps_created_at() {
        let (_dir, _path, mut vault, _) = new_vault();
        let mut r = sample_record();
        vault.save_record(&mut r).unwrap();
        let created = r.created_at;

        r.password = "hunter3".into();
        r.created_at = Utc::now() + chrono::Duration::days(1); // ignored by the vault
        r.password_history.clear(); // also ignored: history is authoritative in the vault
        vault.save_record(&mut r).unwrap();
        r.title = "GitHub (work)".into(); // no password change -> no history entry
        vault.save_record(&mut r).unwrap();

        let stored = vault.get_record(r.id).unwrap();
        assert_eq!(stored.created_at, created);
        assert_eq!(stored.title, "GitHub (work)");
        assert_eq!(stored.password_history.len(), 1);
        assert_eq!(stored.password_history[0].password, "hunter2");
        assert_eq!(store::revision(&vault.conn, r.id).unwrap(), 3);
    }

    #[test]
    fn history_is_capped() {
        let (_dir, _path, mut vault, _) = new_vault();
        let mut r = sample_record();
        for i in 0..(MAX_PASSWORD_HISTORY + 5) {
            r.password = format!("pw{i}");
            vault.save_record(&mut r).unwrap();
        }
        assert_eq!(vault.get_record(r.id).unwrap().password_history.len(), MAX_PASSWORD_HISTORY);
    }

    #[test]
    fn title_is_required() {
        let (_dir, _path, mut vault, _) = new_vault();
        let mut r = Record::new("  ");
        assert!(matches!(vault.save_record(&mut r), Err(VaultError::Invalid(_))));
    }

    #[test]
    fn notes_need_the_second_password() {
        let (_dir, _path, mut vault, _) = new_vault();
        let mut r = sample_record();
        vault.save_record(&mut r).unwrap();

        let mut note = SecureNote::new(r.id, "Recovery codes", "1111-2222\n3333-4444");
        assert!(matches!(vault.save_note(&mut note), Err(VaultError::NotesLocked)));
        assert!(matches!(vault.unlock_notes(MP1), Err(VaultError::WrongNotesPassword)));
        vault.unlock_notes(MP2).unwrap();
        vault.save_note(&mut note).unwrap();
        vault.save_note(&mut SecureNote::new(r.id, "Second", "b")).unwrap();

        vault.lock_notes();
        assert_eq!(vault.note_count(r.id).unwrap(), 2, "count works without the notes password");
        assert!(matches!(vault.list_notes(r.id), Err(VaultError::NotesLocked)));

        vault.unlock_notes(MP2).unwrap();
        let notes = vault.list_notes(r.id).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].body, "1111-2222\n3333-4444");

        vault.delete_note(notes[1].id).unwrap();
        assert_eq!(vault.note_count(r.id).unwrap(), 1);

        vault.lock();
        assert!(!vault.notes_unlocked(), "locking the vault also locks notes");
        assert!(matches!(vault.unlock_notes(MP2), Err(VaultError::Locked)));
    }

    #[test]
    fn notes_cannot_move_between_records() {
        let (_dir, _path, mut vault, _) = new_vault();
        vault.unlock_notes(MP2).unwrap();
        let mut a = sample_record();
        let mut b = Record::new("Other");
        vault.save_record(&mut a).unwrap();
        vault.save_record(&mut b).unwrap();
        let mut note = SecureNote::new(a.id, "n", "body");
        vault.save_note(&mut note).unwrap();
        note.record_id = b.id;
        assert!(matches!(vault.save_note(&mut note), Err(VaultError::Invalid(_))));
        let mut orphan = SecureNote::new(Uuid::now_v7(), "n", "body");
        assert!(matches!(vault.save_note(&mut orphan), Err(VaultError::ItemNotFound(_))));
    }

    #[test]
    fn delete_record_tombstones_its_notes() {
        let (_dir, _path, mut vault, _) = new_vault();
        vault.unlock_notes(MP2).unwrap();
        let mut r = sample_record();
        vault.save_record(&mut r).unwrap();
        let mut note = SecureNote::new(r.id, "n", "body");
        vault.save_note(&mut note).unwrap();

        vault.delete_record(r.id).unwrap();
        assert!(vault.list_records().unwrap().is_empty());
        assert!(matches!(vault.get_record(r.id), Err(VaultError::ItemNotFound(_))));
        assert_eq!(vault.note_count(r.id).unwrap(), 0);
        let deleted: i64 = vault
            .conn
            .query_row("SELECT COUNT(*) FROM items WHERE deleted = 1 AND blob IS NULL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(deleted, 2, "tombstones keep no ciphertext");
        assert!(matches!(vault.delete_record(r.id), Err(VaultError::ItemNotFound(_))));
    }

    #[test]
    fn swapped_or_tampered_blobs_are_detected() {
        let (_dir, _path, mut vault, _) = new_vault();
        let mut a = sample_record();
        let mut b = Record::new("Bank");
        vault.save_record(&mut a).unwrap();
        vault.save_record(&mut b).unwrap();

        // Copy record A's ciphertext into record B's row.
        vault
            .conn
            .execute(
                "UPDATE items SET blob = (SELECT blob FROM items WHERE id = ?1) WHERE id = ?2",
                [a.id.to_string(), b.id.to_string()],
            )
            .unwrap();
        assert!(matches!(vault.get_record(b.id), Err(VaultError::Corrupted)));
        assert!(matches!(vault.list_records(), Err(VaultError::Corrupted)));

        let mut c = Record::new("Mail");
        vault.save_record(&mut c).unwrap();
        let mut blob: Vec<u8> = vault
            .conn
            .query_row("SELECT blob FROM items WHERE id = ?1", [c.id.to_string()], |r| r.get(0))
            .unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        vault.conn.execute("UPDATE items SET blob = ?2 WHERE id = ?1", (c.id.to_string(), blob)).unwrap();
        assert!(matches!(vault.get_record(c.id), Err(VaultError::Corrupted)));
    }

    #[test]
    fn change_passwords() {
        let (_dir, path, mut vault, _) = new_vault();
        assert!(matches!(vault.change_master_password("nope", "new master"), Err(VaultError::WrongPassword)));
        assert!(matches!(vault.change_master_password(MP1, MP2), Err(VaultError::PasswordsMustDiffer)));
        vault.change_master_password(MP1, "new master").unwrap();

        assert!(matches!(
            vault.change_notes_password(MP2, "new master"),
            Err(VaultError::PasswordsMustDiffer)
        ));
        vault.change_notes_password(MP2, "new notes").unwrap();
        drop(vault);

        let mut vault = Vault::open(&path).unwrap();
        assert!(matches!(vault.unlock(MP1), Err(VaultError::WrongPassword)));
        vault.unlock("new master").unwrap();
        assert!(matches!(vault.unlock_notes(MP2), Err(VaultError::WrongNotesPassword)));
        vault.unlock_notes("new notes").unwrap();
    }

    #[test]
    fn recovery_key_resets_both_passwords() {
        let (_dir, path, mut vault, recovery) = new_vault();
        vault.unlock_notes(MP2).unwrap();
        let mut r = sample_record();
        vault.save_record(&mut r).unwrap();
        vault.save_note(&mut SecureNote::new(r.id, "n", "kept")).unwrap();
        drop(vault);

        let wrong_key = RecoveryKey::generate().unwrap();
        assert!(matches!(Vault::recover(&path, &wrong_key, "a1", "b1"), Err(VaultError::WrongRecoveryKey)));
        let typed = RecoveryKey::parse(&recovery.display().to_lowercase()).unwrap();
        let mut vault = Vault::recover(&path, &typed, "fresh master", "fresh notes").unwrap();
        assert!(vault.is_unlocked());
        assert_eq!(vault.get_record(r.id).unwrap().password, "hunter2");
        vault.unlock_notes("fresh notes").unwrap();
        assert_eq!(vault.list_notes(r.id).unwrap()[0].body, "kept");

        // The recovery key keeps working until rotated.
        let rotated = vault.rotate_recovery_key().unwrap();
        drop(vault);
        assert!(matches!(Vault::recover(&path, &recovery, "x1", "y1"), Err(VaultError::WrongRecoveryKey)));
        Vault::recover(&path, &rotated, "x1", "y1").unwrap();
    }

    #[test]
    fn rotate_requires_notes_unlocked() {
        let (_dir, _path, mut vault, _) = new_vault();
        assert!(matches!(vault.rotate_recovery_key(), Err(VaultError::NotesLocked)));
    }

    #[test]
    fn open_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Vault::open(&dir.path().join("missing.db")), Err(VaultError::NotFound)));
        let junk = dir.path().join("junk.db");
        std::fs::write(&junk, b"").unwrap();
        assert!(matches!(Vault::open(&junk), Err(VaultError::Corrupted)));
    }
}
