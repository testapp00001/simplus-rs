use std::fmt;

use zeroize::Zeroize;

use crate::{CryptoError, Result};

/// Length in bytes of every symmetric key used by Simplus.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key that is wiped from memory when dropped.
///
/// The bytes live on the heap so moving the key around never leaves stray copies on the stack.
/// `Debug` output is redacted and the type intentionally does not implement `Clone`.
pub struct SecretKey(Box<[u8; KEY_LEN]>);

impl SecretKey {
    /// Generates a fresh random key from the operating system RNG.
    pub fn generate() -> Result<Self> {
        let mut key = Self(Box::new([0u8; KEY_LEN]));
        getrandom::fill(&mut key.0[..]).map_err(|_| CryptoError::Rng)?;
        Ok(key)
    }

    /// Builds a key from raw bytes, wiping the source array.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let key = Self(Box::new(bytes));
        bytes.zeroize();
        key
    }

    /// Builds a key from a slice, failing unless it is exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Format)?;
        Ok(Self::from_bytes(array))
    }

    /// Borrows the raw key bytes. Keep the borrow as short-lived as possible.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Returns an independent copy of this key. Deliberately explicit instead of `Clone`.
    pub fn duplicate(&self) -> Self {
        Self(Box::new(*self.0))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Returns `N` bytes from the operating system RNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| CryptoError::Rng)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_is_redacted() {
        let key = SecretKey::from_bytes([7u8; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "SecretKey(<redacted>)");
    }

    #[test]
    fn from_slice_checks_length() {
        assert_eq!(SecretKey::from_slice(&[0u8; 31]).unwrap_err(), CryptoError::Format);
        assert!(SecretKey::from_slice(&[0u8; 32]).is_ok());
    }
}
