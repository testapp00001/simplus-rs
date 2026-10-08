//! Key slots: a data-encryption key wrapped under a password or under another key.
//!
//! Several slots can wrap the same key (for example a vault key wrapped once by the master
//! password and once by the recovery key). Binary layout, version 1:
//!
//! ```text
//! 0x01 | kind | [m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt 16B]  (password kind only)
//!      | sealed(wrapped key)
//! ```
//!
//! The header bytes are bound into the associated data of the wrapped key, together with a
//! caller-chosen `context` string, so a slot cannot be replayed for a different purpose.

use crate::kdf::{SALT_LEN, Salt};
use crate::{CryptoError, KdfParams, Result, SecretKey, derive_key, hkdf_subkey, open, seal};

const SLOT_V1: u8 = 1;
const KIND_PASSWORD: u8 = 1;
const KIND_KEY: u8 = 2;
const SLOT_KEK_INFO: &[u8] = b"simplus/slot-kek/v1";

/// How the key-encryption key of a slot is obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// Argon2id(password, salt, params), then HKDF.
    Password { params: KdfParams, salt: Salt },
    /// HKDF of a high-entropy key (for example a recovery key).
    Key,
}

/// A data key wrapped by a password or by another key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    kind: SlotKind,
    wrapped: Vec<u8>,
}

impl KeySlot {
    /// Wraps `dek` under `password`, using a fresh random salt.
    pub fn seal_password(
        password: &[u8],
        params: KdfParams,
        dek: &SecretKey,
        context: &[u8],
    ) -> Result<Self> {
        let salt = Salt::generate()?;
        let master = derive_key(password, &salt, &params)?;
        Self::seal_with_master(&master, params, salt, dek, context)
    }

    /// Wraps `dek` using an already-derived password master key (see [`derive_key`]).
    ///
    /// Useful when the same master key must also produce other subkeys, e.g. a server auth key.
    pub fn seal_with_master(
        master: &SecretKey,
        params: KdfParams,
        salt: Salt,
        dek: &SecretKey,
        context: &[u8],
    ) -> Result<Self> {
        Self::seal_inner(SlotKind::Password { params, salt }, master, dek, context)
    }

    /// Wraps `dek` under another high-entropy key.
    pub fn seal_key(wrapping_key: &SecretKey, dek: &SecretKey, context: &[u8]) -> Result<Self> {
        Self::seal_inner(SlotKind::Key, wrapping_key, dek, context)
    }

    fn seal_inner(kind: SlotKind, ikm: &SecretKey, dek: &SecretKey, context: &[u8]) -> Result<Self> {
        let mut slot = Self { kind, wrapped: Vec::new() };
        let kek = hkdf_subkey(ikm, SLOT_KEK_INFO);
        slot.wrapped = seal(&kek, dek.expose(), &slot.aad(context))?;
        Ok(slot)
    }

    /// Recovers the data key with a password. Fails with [`CryptoError::Decrypt`] on a wrong
    /// password.
    pub fn open_password(&self, password: &[u8], context: &[u8]) -> Result<SecretKey> {
        let master = self.derive_master(password)?;
        self.open_with_master(&master, context)
    }

    /// Runs the slot's password KDF, returning the master key without unwrapping anything.
    pub fn derive_master(&self, password: &[u8]) -> Result<SecretKey> {
        match &self.kind {
            SlotKind::Password { params, salt } => derive_key(password, salt, params),
            SlotKind::Key => Err(CryptoError::Format),
        }
    }

    /// Recovers the data key from an already-derived password master key.
    pub fn open_with_master(&self, master: &SecretKey, context: &[u8]) -> Result<SecretKey> {
        match self.kind {
            SlotKind::Password { .. } => self.open_inner(master, context),
            SlotKind::Key => Err(CryptoError::Format),
        }
    }

    /// Recovers the data key with the wrapping key of a [`SlotKind::Key`] slot.
    pub fn open_key(&self, wrapping_key: &SecretKey, context: &[u8]) -> Result<SecretKey> {
        match self.kind {
            SlotKind::Key => self.open_inner(wrapping_key, context),
            SlotKind::Password { .. } => Err(CryptoError::Format),
        }
    }

    fn open_inner(&self, ikm: &SecretKey, context: &[u8]) -> Result<SecretKey> {
        let kek = hkdf_subkey(ikm, SLOT_KEK_INFO);
        let raw = open(&kek, &self.wrapped, &self.aad(context))?;
        SecretKey::from_slice(&raw)
    }

    pub fn kind(&self) -> &SlotKind {
        &self.kind
    }

    fn header(&self) -> Vec<u8> {
        let mut out = vec![SLOT_V1];
        match &self.kind {
            SlotKind::Password { params, salt } => {
                out.push(KIND_PASSWORD);
                out.extend_from_slice(&params.m_cost_kib.to_le_bytes());
                out.extend_from_slice(&params.t_cost.to_le_bytes());
                out.extend_from_slice(&params.p_cost.to_le_bytes());
                out.extend_from_slice(&salt.0);
            }
            SlotKind::Key => out.push(KIND_KEY),
        }
        out
    }

    fn aad(&self, context: &[u8]) -> Vec<u8> {
        let header = self.header();
        let mut aad = Vec::with_capacity(context.len() + header.len() + 4);
        // Length-prefix the context so (context, header) pairs cannot collide.
        aad.extend_from_slice(&(context.len() as u32).to_le_bytes());
        aad.extend_from_slice(context);
        aad.extend_from_slice(&header);
        aad
    }

    /// Serialises the slot for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header();
        out.extend_from_slice(&self.wrapped);
        out
    }

    /// Parses a slot produced by [`KeySlot::to_bytes`]. KDF parameters are validated so a
    /// hostile file cannot request absurd resources.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let [SLOT_V1, kind, rest @ ..] = bytes else {
            return Err(CryptoError::Format);
        };
        match *kind {
            KIND_PASSWORD => {
                const HDR: usize = 12 + SALT_LEN;
                if rest.len() < HDR {
                    return Err(CryptoError::Format);
                }
                let u32_at = |i: usize| u32::from_le_bytes(rest[i..i + 4].try_into().unwrap());
                let params = KdfParams { m_cost_kib: u32_at(0), t_cost: u32_at(4), p_cost: u32_at(8) };
                params.validate()?;
                let salt = Salt(rest[12..HDR].try_into().unwrap());
                Ok(Self { kind: SlotKind::Password { params, salt }, wrapped: rest[HDR..].to_vec() })
            }
            KIND_KEY => Ok(Self { kind: SlotKind::Key, wrapped: rest.to_vec() }),
            _ => Err(CryptoError::Format),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 };
    const CTX: &[u8] = b"simplus/test/dek";

    #[test]
    fn password_slot_round_trip() {
        let dek = SecretKey::generate().unwrap();
        let slot = KeySlot::seal_password(b"pw", FAST, &dek, CTX).unwrap();
        assert_eq!(slot.open_password(b"pw", CTX).unwrap().expose(), dek.expose());
    }

    #[test]
    fn wrong_password_or_context_fails() {
        let dek = SecretKey::generate().unwrap();
        let slot = KeySlot::seal_password(b"pw", FAST, &dek, CTX).unwrap();
        assert_eq!(slot.open_password(b"nope", CTX).unwrap_err(), CryptoError::Decrypt);
        assert_eq!(slot.open_password(b"pw", b"other").unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn key_slot_round_trip_and_kind_mismatch() {
        let dek = SecretKey::generate().unwrap();
        let recovery = SecretKey::generate().unwrap();
        let slot = KeySlot::seal_key(&recovery, &dek, CTX).unwrap();
        assert_eq!(slot.open_key(&recovery, CTX).unwrap().expose(), dek.expose());
        assert_eq!(slot.open_password(b"pw", CTX).unwrap_err(), CryptoError::Format);
    }

    #[test]
    fn serialisation_round_trip() {
        let dek = SecretKey::generate().unwrap();
        for slot in [
            KeySlot::seal_password(b"pw", FAST, &dek, CTX).unwrap(),
            KeySlot::seal_key(&SecretKey::generate().unwrap(), &dek, CTX).unwrap(),
        ] {
            assert_eq!(KeySlot::from_bytes(&slot.to_bytes()).unwrap(), slot);
        }
    }

    #[test]
    fn tampered_params_are_rejected() {
        let dek = SecretKey::generate().unwrap();
        let slot = KeySlot::seal_password(b"pw", FAST, &dek, CTX).unwrap();
        let mut bytes = slot.to_bytes();
        bytes[6] ^= 1; // t_cost: 1 -> 0, invalid
        assert!(matches!(KeySlot::from_bytes(&bytes), Err(CryptoError::InvalidParams(_))));

        let mut bytes = slot.to_bytes();
        bytes[2] ^= 0x80; // m_cost 64 -> 192 KiB: still valid, but a different KEK and AAD
        let tampered = KeySlot::from_bytes(&bytes).unwrap();
        assert_eq!(tampered.open_password(b"pw", CTX).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        for bad in [&[][..], &[SLOT_V1], &[2, KIND_KEY], &[SLOT_V1, 9], &[SLOT_V1, KIND_PASSWORD, 0]] {
            assert!(KeySlot::from_bytes(bad).is_err());
        }
    }
}
