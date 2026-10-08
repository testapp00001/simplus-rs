//! XChaCha20-Poly1305 sealing with a self-describing, versioned wire format.
//!
//! ```text
//! sealed = version (1 byte) || nonce (24 bytes) || ciphertext || tag (16 bytes)
//! ```
//!
//! The version byte is authenticated by prepending it to the caller's associated data.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, Key, KeyInit, Nonce, Payload};
use zeroize::Zeroizing;

use crate::{CryptoError, Result, SecretKey, random_bytes};

const FORMAT_V1: u8 = 1;

/// XChaCha20 nonce length. Nonces are random; 192 bits makes collisions a non-issue.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Bytes added by [`seal`] on top of the plaintext length.
pub const SEALED_OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

fn cipher(key: &SecretKey) -> XChaCha20Poly1305 {
    let key: &Key<XChaCha20Poly1305> = key.expose().into();
    XChaCha20Poly1305::new(key)
}

fn versioned_aad(aad: &[u8]) -> Vec<u8> {
    let mut full = Vec::with_capacity(aad.len() + 1);
    full.push(FORMAT_V1);
    full.extend_from_slice(aad);
    full
}

/// Encrypts and authenticates `plaintext`, binding `aad` (for example an item id and type).
///
/// The same `aad` must be supplied to [`open`].
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let nonce: &Nonce<XChaCha20Poly1305> = (&nonce_bytes).into();
    let aad = versioned_aad(aad);
    let ciphertext = cipher(key)
        .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_V1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifies and decrypts data produced by [`seal`]. The plaintext is wiped when dropped.
pub fn open(key: &SecretKey, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEALED_OVERHEAD {
        return Err(CryptoError::Format);
    }
    let (version, rest) = sealed.split_at(1);
    if version[0] != FORMAT_V1 {
        return Err(CryptoError::Format);
    }
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
    let nonce: &Nonce<XChaCha20Poly1305> = nonce_bytes.try_into().map_err(|_| CryptoError::Format)?;
    let aad = versioned_aad(aad);
    cipher(key)
        .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::generate().unwrap()
    }

    #[test]
    fn round_trip() {
        let k = key();
        let sealed = seal(&k, b"hunter2", b"item:1").unwrap();
        assert_eq!(sealed.len(), 7 + SEALED_OVERHEAD);
        assert_eq!(open(&k, &sealed, b"item:1").unwrap().as_slice(), b"hunter2");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = key();
        let sealed = seal(&k, b"", b"").unwrap();
        assert!(open(&k, &sealed, b"").unwrap().is_empty());
    }

    #[test]
    fn nonces_are_unique() {
        let k = key();
        assert_ne!(seal(&k, b"x", b"").unwrap(), seal(&k, b"x", b"").unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&key(), b"secret", b"").unwrap();
        assert_eq!(open(&key(), &sealed, b"").unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn swapped_aad_fails() {
        let k = key();
        let sealed = seal(&k, b"secret", b"item:1").unwrap();
        assert_eq!(open(&k, &sealed, b"item:2").unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn every_flipped_byte_is_detected() {
        let k = key();
        let sealed = seal(&k, b"secret", b"aad").unwrap();
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert!(open(&k, &tampered, b"aad").is_err(), "flip at byte {i} not detected");
        }
    }

    #[test]
    fn truncated_input_is_a_format_error() {
        let k = key();
        assert_eq!(open(&k, &[FORMAT_V1; 10], b"").unwrap_err(), CryptoError::Format);
    }

    /// Test vector from draft-irtf-cfrg-xchacha-03, appendix A.3.1, checked against the raw
    /// cipher so the primitive is pinned independently of our framing.
    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
tip for the future, sunscreen would be it.";
        let expected = hex(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49",
        ));
        let cipher = cipher(&SecretKey::from_bytes(key));
        let out = cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad: &aad }).unwrap();
        assert_eq!(out, expected);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
