use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{CryptoError, KEY_LEN, Result, SecretKey, random_bytes};

/// Salt length used for every Argon2id derivation.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters. They are stored next to every password-protected key so they can
/// be raised over time without breaking existing vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Baseline for new secrets: 64 MiB, 3 passes, 4 lanes.
    pub const RECOMMENDED: Self = Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 4 };

    /// Upper bound accepted when *reading* stored parameters, so a corrupted or hostile file
    /// cannot make us allocate unbounded memory.
    pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
    pub const MAX_T_COST: u32 = 64;
    pub const MAX_P_COST: u32 = 64;

    /// Checks that the parameters are structurally valid and within resource limits.
    pub fn validate(&self) -> Result<()> {
        let invalid = |msg: &str| Err(CryptoError::InvalidParams(msg.to_owned()));
        if !(1..=Self::MAX_P_COST).contains(&self.p_cost) {
            return invalid("parallelism out of range");
        }
        if !(1..=Self::MAX_T_COST).contains(&self.t_cost) {
            return invalid("iterations out of range");
        }
        if self.m_cost_kib < 8 * self.p_cost || self.m_cost_kib > Self::MAX_M_COST_KIB {
            return invalid("memory cost out of range");
        }
        Ok(())
    }

    /// Picks the strongest parameters (starting from [`Self::RECOMMENDED`]) whose derivation
    /// time on this machine stays around `target`. Memory is raised first (up to `max_m_kib`),
    /// then passes. Never returns anything weaker than the recommended baseline.
    pub fn calibrate(target: Duration, max_m_kib: u32) -> Result<Self> {
        let salt = Salt::generate()?;
        let time = |params: &Self| -> Result<Duration> {
            let start = Instant::now();
            derive_key(b"calibration", &salt, params)?;
            Ok(start.elapsed())
        };

        let mut best = Self::RECOMMENDED;
        let mut elapsed = time(&best)?;
        while elapsed * 2 <= target && best.m_cost_kib * 2 <= max_m_kib {
            best.m_cost_kib *= 2;
            elapsed = time(&best)?;
        }
        // Passes scale roughly linearly, so extrapolate instead of re-measuring each step.
        if elapsed < target && !elapsed.is_zero() {
            let factor = target.as_secs_f64() / elapsed.as_secs_f64();
            let t = (f64::from(best.t_cost) * factor).floor() as u32;
            best.t_cost = t.clamp(best.t_cost, Self::MAX_T_COST);
        }
        Ok(best)
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

/// A random per-secret salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Salt(pub [u8; SALT_LEN]);

impl Salt {
    pub fn generate() -> Result<Self> {
        random_bytes().map(Self)
    }
}

/// Stretches a password into a 256-bit master key with Argon2id (v1.3).
pub fn derive_key(password: &[u8], salt: &Salt, params: &KdfParams) -> Result<SecretKey> {
    params.validate()?;
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(password, &salt.0, out.as_mut()).map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(SecretKey::from_bytes(*out))
}

/// HKDF-SHA256 extract-and-expand into an arbitrary-length output buffer.
pub fn hkdf_expand(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| CryptoError::InvalidParams("HKDF output too long".into()))
}

/// Derives an independent 256-bit subkey for a specific purpose, identified by `info`
/// (for example `b"simplus/vault/auth"`).
pub fn hkdf_subkey(ikm: &SecretKey, info: &[u8]) -> SecretKey {
    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    hkdf_expand(ikm.expose(), None, info, out.as_mut()).expect("32 bytes is a valid HKDF length");
    SecretKey::from_bytes(*out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_cost_kib: 64, t_cost: 3, p_cost: 4 };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Cross-implementation vector generated with the reference C implementation
    /// (argon2-cffi `hash_secret_raw`, Type.ID, version 19).
    #[test]
    fn argon2id_matches_reference_implementation() {
        let salt = Salt(core::array::from_fn(|i| i as u8));
        let key = derive_key(b"correct horse battery staple", &salt, &FAST).unwrap();
        assert_eq!(hex(key.expose()), "fff8371f0247952ba584679977a86d3b7606eac6ee454ab3bbd8d1a550593c9a");
    }

    #[test]
    fn derivation_depends_on_password_salt_and_params() {
        let salt = Salt([1; SALT_LEN]);
        let base = derive_key(b"pw", &salt, &FAST).unwrap();
        assert_eq!(base.expose(), derive_key(b"pw", &salt, &FAST).unwrap().expose());
        assert_ne!(base.expose(), derive_key(b"pw2", &salt, &FAST).unwrap().expose());
        assert_ne!(base.expose(), derive_key(b"pw", &Salt([2; SALT_LEN]), &FAST).unwrap().expose());
        let more_passes = KdfParams { t_cost: 4, ..FAST };
        assert_ne!(base.expose(), derive_key(b"pw", &salt, &more_passes).unwrap().expose());
    }

    #[test]
    fn rejects_out_of_range_params() {
        let salt = Salt([0; SALT_LEN]);
        for bad in [
            KdfParams { p_cost: 0, ..FAST },
            KdfParams { t_cost: 0, ..FAST },
            KdfParams { m_cost_kib: 16, p_cost: 4, t_cost: 1 },
            KdfParams { m_cost_kib: KdfParams::MAX_M_COST_KIB + 1, ..FAST },
        ] {
            assert!(matches!(derive_key(b"pw", &salt, &bad), Err(CryptoError::InvalidParams(_))));
        }
    }

    #[test]
    fn recommended_params_are_valid() {
        KdfParams::RECOMMENDED.validate().unwrap();
    }

    /// RFC 5869 test case 3 (empty salt and info). HKDF output is prefix-consistent, so the
    /// first 32 bytes of the 42-byte OKM are checked.
    #[test]
    fn hkdf_rfc5869_case3() {
        let mut okm = [0u8; 42];
        hkdf_expand(&[0x0b; 22], None, b"", &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_subkeys_are_domain_separated() {
        let master = SecretKey::from_bytes([9; KEY_LEN]);
        let a = hkdf_subkey(&master, b"simplus/a");
        let b = hkdf_subkey(&master, b"simplus/b");
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose(), hkdf_subkey(&master, b"simplus/a").expose());
    }
}
