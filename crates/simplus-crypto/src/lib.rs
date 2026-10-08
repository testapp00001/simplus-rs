//! Cryptographic building blocks shared by every Simplus component that stores secrets.
//!
//! The design is a classic envelope scheme:
//!
//! * a password is stretched with **Argon2id** ([`derive_key`]) into a key-encryption key (KEK),
//! * the KEK **wraps** a random data-encryption key (DEK) inside a [`KeySlot`],
//! * items are sealed with **XChaCha20-Poly1305** ([`seal`] / [`open`]) under the DEK,
//!   binding caller-supplied associated data so ciphertexts cannot be swapped between items.
//!
//! Changing a password therefore only re-wraps the DEK; the data itself is never re-encrypted.

mod aead;
mod error;
mod kdf;
mod key;
mod slot;

pub use aead::{NONCE_LEN, SEALED_OVERHEAD, TAG_LEN, open, seal};
pub use error::{CryptoError, Result};
pub use kdf::{KdfParams, SALT_LEN, Salt, derive_key, hkdf_expand, hkdf_subkey};
pub use key::{KEY_LEN, SecretKey, random_bytes};
pub use slot::{KeySlot, SlotKind};

/// Re-exported so callers can hold decrypted plaintext without an extra dependency.
pub use zeroize::{Zeroize, Zeroizing};
