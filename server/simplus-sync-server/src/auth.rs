//! Credential verifiers, session tokens and request throttling.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use axum::http::HeaderMap;
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};
use simplus_crypto::{KdfParams, SALT_LEN, Salt, derive_key, random_bytes};

/// Server-side Argon2id cost for verifiers (OWASP baseline). The secrets being hashed are
/// already 256-bit keys derived client-side with a much higher cost.
const SERVER_KDF: KdfParams = KdfParams { m_cost_kib: 19 * 1024, t_cost: 2, p_cost: 1 };
const VERIFIER_V1: u8 = 1;
const VERIFIER_LEN: usize = 1 + 12 + SALT_LEN + 32;

/// Hashes a client-derived secret for storage: `v1 | m | t | p | salt | argon2id(secret)`.
pub fn hash_secret(secret: &[u8]) -> anyhow::Result<Vec<u8>> {
    let salt = Salt::generate()?;
    let hash = derive_key(secret, &salt, &SERVER_KDF)?;
    let mut out = Vec::with_capacity(VERIFIER_LEN);
    out.push(VERIFIER_V1);
    for n in [SERVER_KDF.m_cost_kib, SERVER_KDF.t_cost, SERVER_KDF.p_cost] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&salt.0);
    out.extend_from_slice(hash.expose());
    Ok(out)
}

/// Checks `candidate` against a stored verifier in constant time.
pub fn verify_secret(stored: &[u8], candidate: &[u8]) -> bool {
    if stored.len() != VERIFIER_LEN || stored[0] != VERIFIER_V1 {
        return false;
    }
    let u32_at = |i: usize| u32::from_le_bytes(stored[i..i + 4].try_into().expect("4 bytes"));
    let params = KdfParams { m_cost_kib: u32_at(1), t_cost: u32_at(5), p_cost: u32_at(9) };
    let salt = Salt(stored[13..13 + SALT_LEN].try_into().expect("salt length"));
    match derive_key(candidate, &salt, &params) {
        Ok(hash) => constant_time_eq(hash.expose(), &stored[13 + SALT_LEN..]),
        Err(_) => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A new random session token and the hash stored for it.
pub fn new_token() -> anyhow::Result<(String, [u8; 32])> {
    let token = BASE64URL_NOPAD.encode(&random_bytes::<32>()?);
    let hash = hash_token(&token);
    Ok((token, hash))
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Fixed-window request counter per client IP.
pub struct RateLimiter {
    per_minute: u32,
    windows: Mutex<HashMap<IpAddr, (i64, u32)>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self { per_minute, windows: Mutex::default() }
    }

    /// Records a request; `false` if the client is over its budget for the current minute.
    pub fn check(&self, ip: IpAddr, now: i64) -> bool {
        let window = now / 60;
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if windows.len() > 10_000 {
            windows.retain(|_, (w, _)| *w == window);
        }
        let entry = windows.entry(ip).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= self.per_minute
    }
}

/// The client address, from `X-Forwarded-For` only when the proxy is trusted.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_proxy: bool) -> IpAddr {
    if trust_proxy
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return ip;
    }
    peer.ip()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_round_trip() {
        let stored = hash_secret(b"client auth key").unwrap();
        assert_eq!(stored.len(), VERIFIER_LEN);
        assert!(verify_secret(&stored, b"client auth key"));
        assert!(!verify_secret(&stored, b"other key"));
        assert!(!verify_secret(&stored[1..], b"client auth key"));
        assert_ne!(hash_secret(b"client auth key").unwrap(), stored, "salted");
    }

    #[test]
    fn tokens_are_unique_and_hashed() {
        let (a, ha) = new_token().unwrap();
        let (b, _) = new_token().unwrap();
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), ha);
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn rate_limit_window() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(ip, 0) && limiter.check(ip, 1));
        assert!(!limiter.check(ip, 2));
        assert!(limiter.check("10.0.0.2".parse().unwrap(), 2), "per client");
        assert!(limiter.check(ip, 61), "new window");
    }

    #[test]
    fn forwarded_for_only_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        assert_eq!(client_ip(&headers, peer, false), peer.ip());
        assert_eq!(client_ip(&headers, peer, true).to_string(), "203.0.113.9");
    }
}
