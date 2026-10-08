//! Time-based one-time passwords (RFC 6238) and `otpauth://` URIs.

use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::{BASE32_NOPAD, Encoding};
use hmac::{Hmac, Mac};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("invalid otpauth URI: {0}")]
    InvalidUri(String),
    #[error("the TOTP secret is not valid base32")]
    InvalidSecret,
    #[error("unsupported: {0}")]
    Unsupported(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Everything needed to compute codes for one account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totp {
    secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// A code together with how long it remains valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub remaining_secs: u64,
    pub period: u64,
}

impl Drop for Totp {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn lenient_base32() -> Encoding {
    let mut spec = BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    spec.encoding().expect("valid base32 specification")
}

fn decode_secret(s: &str) -> Result<Vec<u8>, TotpError> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    match lenient_base32().decode(cleaned.as_bytes()) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => Err(TotpError::InvalidSecret),
    }
}

fn percent_decode(s: &str) -> Result<String, TotpError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let byte = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| TotpError::InvalidUri("bad percent escape".into()))?;
                out.push(byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| TotpError::InvalidUri("not UTF-8".into()))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Totp {
    /// Builds a config from a raw secret with the common defaults (SHA-1, 6 digits, 30 s).
    pub fn from_secret(secret: Vec<u8>) -> Self {
        Self { secret, algorithm: Algorithm::Sha1, digits: 6, period: 30, issuer: None, account: None }
    }

    /// Accepts either an `otpauth://totp/...` URI or a bare base32 secret (spaces, lowercase
    /// and padding are tolerated).
    pub fn parse(input: &str) -> Result<Self, TotpError> {
        let input = input.trim();
        if input.len() >= 10 && input[..10].eq_ignore_ascii_case("otpauth://") {
            Self::parse_uri(input)
        } else {
            decode_secret(input).map(Self::from_secret)
        }
    }

    fn parse_uri(uri: &str) -> Result<Self, TotpError> {
        let rest = &uri[10..];
        let (kind, rest) =
            rest.split_once('/').ok_or_else(|| TotpError::InvalidUri("missing type".into()))?;
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::Unsupported(format!("{kind} codes (only TOTP is supported)")));
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label)?;
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };

        let mut totp = Self::from_secret(Vec::new());
        let mut has_secret = false;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = Zeroizing::new(percent_decode(value)?);
            match key.to_ascii_lowercase().as_str() {
                "secret" => {
                    totp.secret = decode_secret(&value)?;
                    has_secret = true;
                }
                "issuer" if !value.is_empty() => issuer = Some(value.to_string()),
                "algorithm" => {
                    totp.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => return Err(TotpError::Unsupported(format!("algorithm {other}"))),
                    }
                }
                "digits" => {
                    totp.digits = value
                        .parse()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or_else(|| TotpError::InvalidUri("digits must be 6-8".into()))?
                }
                "period" => {
                    totp.period = value
                        .parse()
                        .ok()
                        .filter(|p| (1..=3600).contains(p))
                        .ok_or_else(|| TotpError::InvalidUri("invalid period".into()))?
                }
                _ => {}
            }
        }
        if !has_secret {
            return Err(TotpError::InvalidUri("missing secret".into()));
        }
        totp.issuer = issuer.filter(|i| !i.is_empty());
        totp.account = Some(account).filter(|a| !a.is_empty());
        Ok(totp)
    }

    /// Canonical `otpauth://` URI for export or QR codes.
    pub fn to_uri(&self) -> Zeroizing<String> {
        let label = match (&self.issuer, &self.account) {
            (Some(i), Some(a)) => format!("{}:{}", percent_encode(i), percent_encode(a)),
            (Some(i), None) => percent_encode(i),
            (None, Some(a)) => percent_encode(a),
            (None, None) => String::new(),
        };
        let mut uri = format!(
            "otpauth://totp/{label}?secret={}&algorithm={}&digits={}&period={}",
            BASE32_NOPAD.encode(&self.secret),
            self.algorithm.name(),
            self.digits,
            self.period
        );
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        Zeroizing::new(uri)
    }

    /// The code for a given Unix time.
    pub fn code_at(&self, unix_secs: u64) -> String {
        let counter = (unix_secs / self.period).to_be_bytes();
        macro_rules! hmac {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as hmac::digest::KeyInit>::new_from_slice(&self.secret)
                    .expect("HMAC accepts keys of any length");
                mac.update(&counter);
                mac.finalize().into_bytes().to_vec()
            }};
        }
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac!(sha1::Sha1),
            Algorithm::Sha256 => hmac!(sha2_digest10::Sha256),
            Algorithm::Sha512 => hmac!(sha2_digest10::Sha512),
        };
        // RFC 4226 dynamic truncation.
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let binary =
            u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// The code valid right now.
    pub fn current(&self) -> TotpCode {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        TotpCode {
            code: self.code_at(now),
            remaining_secs: self.period - now % self.period,
            period: self.period,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B.
    #[test]
    fn rfc6238_vectors() {
        let sha1 = b"12345678901234567890".to_vec();
        let sha256 = b"12345678901234567890123456789012".to_vec();
        let sha512 = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let make = |secret: &Vec<u8>, algorithm| {
            let mut totp = Totp::from_secret(secret.clone());
            totp.digits = 8;
            totp.algorithm = algorithm;
            totp
        };
        for (t, c1, c256, c512) in cases {
            assert_eq!(make(&sha1, Algorithm::Sha1).code_at(t), c1, "sha1 @ {t}");
            assert_eq!(make(&sha256, Algorithm::Sha256).code_at(t), c256, "sha256 @ {t}");
            assert_eq!(make(&sha512, Algorithm::Sha512).code_at(t), c512, "sha512 @ {t}");
        }
    }

    #[test]
    fn bare_secret_tolerates_formatting() {
        let a = Totp::parse("JBSW Y3DP EHPK 3PXP").unwrap();
        let b = Totp::parse("jbswy3dpehpk3pxp====").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.digits, 6);
        assert_eq!(a.period, 30);
    }

    #[test]
    fn parses_full_uri() {
        let t = Totp::parse(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
             &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("john.doe@email.com"));
        assert_eq!((t.algorithm, t.digits, t.period), (Algorithm::Sha256, 8, 60));
        assert_eq!(Totp::parse(&t.to_uri()).unwrap(), t, "URI round trip");
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(Totp::parse("not base32!"), Err(TotpError::InvalidSecret));
        assert!(matches!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DP"), Err(TotpError::Unsupported(_))));
        assert!(matches!(Totp::parse("otpauth://totp/x?issuer=y"), Err(TotpError::InvalidUri(_))));
        assert!(matches!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DP&digits=12"),
            Err(TotpError::InvalidUri(_))
        ));
    }

    #[test]
    fn current_code_shape() {
        let code = Totp::parse("JBSWY3DPEHPK3PXP").unwrap().current();
        assert_eq!(code.code.len(), 6);
        assert!((1..=30).contains(&code.remaining_secs));
    }
}
