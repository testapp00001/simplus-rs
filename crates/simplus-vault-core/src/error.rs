use thiserror::Error;
use uuid::Uuid;

use simplus_core::db::rusqlite;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("wrong master password")]
    WrongPassword,
    #[error("wrong notes password")]
    WrongNotesPassword,
    #[error("incorrect recovery key")]
    WrongRecoveryKey,
    #[error("the vault is locked")]
    Locked,
    #[error("secure notes are locked")]
    NotesLocked,
    #[error("a vault already exists at this location")]
    AlreadyExists,
    #[error("no vault exists at this location")]
    NotFound,
    #[error("the notes password must be different from the master password")]
    PasswordsMustDiffer,
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("item not found: {0}")]
    ItemNotFound(Uuid),
    #[error("vault data is corrupted or has been tampered with")]
    Corrupted,
    #[error("the vault keys do not match this vault; a key bundle may have been tampered with")]
    KeyMismatch,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u32),
    #[error("{0}")]
    Invalid(String),
    #[error("import failed: {0}")]
    Import(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("cryptography error: {0}")]
    Crypto(simplus_crypto::CryptoError),
}

pub type Result<T, E = VaultError> = std::result::Result<T, E>;
