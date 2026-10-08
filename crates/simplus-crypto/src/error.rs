use thiserror::Error;

/// Errors produced by this crate.
///
/// Decryption failures deliberately carry no detail: a wrong password, a wrong key, tampered
/// ciphertext and mismatched associated data are indistinguishable to the caller.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("decryption failed (wrong key or corrupted data)")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("invalid key-derivation parameters: {0}")]
    InvalidParams(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("unsupported or malformed ciphertext format")]
    Format,
    #[error("operating system random number generator failed")]
    Rng,
}

pub type Result<T, E = CryptoError> = std::result::Result<T, E>;
