//! The Simplus password vault, independent of any UI.
//!
//! # Key hierarchy
//!
//! * **Master password** → Argon2id → master key → wraps the random **vault key**, which
//!   encrypts records (titles, usernames, passwords, URLs, TOTP secrets, custom fields).
//! * **Notes password** (must differ from the master password) → Argon2id → wraps the random
//!   **notes key**, which encrypts secure notes. Notes stay sealed until it is entered.
//! * **Recovery key** (random, shown once as a printable kit) wraps both keys, so both
//!   passwords can be reset if forgotten.
//!
//! Every record and note is sealed individually with XChaCha20-Poly1305, bound to its id, kind
//! and parent so ciphertexts cannot be swapped. Changing a password only re-wraps a key.

mod error;
pub mod generator;
pub mod import_export;
mod model;
mod recovery;
mod store;
pub mod totp;
mod vault;

pub use error::{Result, VaultError};
pub use model::{CustomField, MAX_PASSWORD_HISTORY, PasswordHistoryEntry, Record, SecureNote};
pub use recovery::RecoveryKey;
pub use simplus_crypto::KdfParams;
pub use vault::Vault;
