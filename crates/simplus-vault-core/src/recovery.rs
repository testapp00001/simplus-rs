use std::fmt;

use data_encoding::BASE32_NOPAD;
use simplus_crypto::SecretKey;
use zeroize::Zeroizing;

use crate::{Result, VaultError};

const GROUP: usize = 4;

/// A 256-bit random key that can reset both vault passwords.
///
/// Shown once at vault creation as 13 groups of 4 base32 characters, e.g.
/// `ABCD-EFGH-…`. Parsing ignores case, spaces and dashes.
pub struct RecoveryKey(SecretKey);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        SecretKey::generate().map(Self).map_err(VaultError::Crypto)
    }

    /// Human-friendly grouped form, for the recovery kit.
    pub fn display(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(BASE32_NOPAD.encode(self.0.expose()));
        let groups: Vec<&str> = encoded
            .as_bytes()
            .chunks(GROUP)
            .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
            .collect();
        Zeroizing::new(groups.join("-"))
    }

    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let bytes = Zeroizing::new(
            BASE32_NOPAD.decode(cleaned.as_bytes()).map_err(|_| VaultError::WrongRecoveryKey)?,
        );
        SecretKey::from_slice(&bytes).map(Self).map_err(|_| VaultError::WrongRecoveryKey)
    }

    pub(crate) fn key(&self) -> &SecretKey {
        &self.0
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shape() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.display();
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups[..12].iter().all(|g| g.len() == 4));
    }

    #[test]
    fn parse_is_forgiving_about_formatting() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.display();
        let messy = format!("  {} ", shown.to_lowercase().replace('-', " - "));
        assert_eq!(RecoveryKey::parse(&messy).unwrap().key().expose(), key.key().expose());
    }

    #[test]
    fn parse_rejects_garbage() {
        for bad in ["", "ABCD", "0000-1111", &"A".repeat(60)] {
            assert!(matches!(RecoveryKey::parse(bad), Err(VaultError::WrongRecoveryKey)), "{bad}");
        }
    }
}
