//! Thin blocking HTTP client for the sync API.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use simplus_vault_proto::{
    ChangesResponse, DeleteAccountRequest, DevicesResponse, ErrorBody, KdfInfo, KeysResponse, LoginRequest,
    PreloginRequest, PreloginResponse, PushItem, PushRequest, PushResponse, RecoverRequest, RegisterRequest,
    ServerInfo, SessionResponse, UpdateKeysRequest, UpdateKeysResponse,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::SyncError;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Checks and normalises a server address. `https://` is required, except for `http://` to
/// the local machine (development and same-host setups).
pub fn normalize_server_url(url: &str) -> Result<String, SyncError> {
    let url = url.trim().trim_end_matches('/');
    let (scheme, rest) = url.split_once("://").ok_or(SyncError::InvalidUrl)?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if host.is_empty() || rest.contains(char::is_whitespace) {
        return Err(SyncError::InvalidUrl);
    }
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Ok(url.to_owned()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "::1") => Ok(url.to_owned()),
        "http" => Err(SyncError::InsecureUrl),
        _ => Err(SyncError::InvalidUrl),
    }
}

/// A connection to one sync server, optionally signed in.
pub struct SyncClient {
    base: String,
    agent: ureq::Agent,
    token: Option<Zeroizing<String>>,
}

impl SyncClient {
    pub fn new(server_url: &str) -> Result<Self, SyncError> {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(TIMEOUT))
            .user_agent(concat!("simplus/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self { base: normalize_server_url(server_url)?, agent, token: None })
    }

    pub fn with_token(mut self, token: Zeroizing<String>) -> Self {
        self.token = Some(token);
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn send<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, SyncError> {
        let mut builder = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("accept", "application/json");
        if let Some(token) = &self.token {
            builder = builder.header("authorization", format!("Bearer {}", token.as_str()));
        }
        let payload = match body {
            Some(body) => {
                builder = builder.header("content-type", "application/json");
                serde_json::to_vec(body).map_err(|e| SyncError::Protocol(e.to_string()))?
            }
            None => Vec::new(),
        };
        let request = builder.body(payload).map_err(|e| SyncError::Protocol(e.to_string()))?;
        let mut response = self.agent.run(request).map_err(|e| SyncError::Network(e.to_string()))?;
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(|e| SyncError::Network(e.to_string()))?;
        if (200..300).contains(&status) {
            let text = if text.is_empty() { "null" } else { text.as_str() };
            return serde_json::from_str(text).map_err(|e| SyncError::Protocol(e.to_string()));
        }
        match serde_json::from_str::<ErrorBody>(&text) {
            Ok(error) => Err(SyncError::Server { status, code: error.code, message: error.message }),
            Err(_) => Err(SyncError::Protocol(format!("HTTP {status}"))),
        }
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, SyncError> {
        self.send("GET", path, None::<&()>)
    }

    pub fn info(&self) -> Result<ServerInfo, SyncError> {
        self.get("/v1/info")
    }

    pub fn prelogin(&self, email: &str) -> Result<KdfInfo, SyncError> {
        let response: PreloginResponse =
            self.send("POST", "/v1/prelogin", Some(&PreloginRequest { email: email.to_owned() }))?;
        Ok(response.kdf)
    }

    pub fn register(&self, request: &RegisterRequest) -> Result<SessionResponse, SyncError> {
        self.send("POST", "/v1/accounts", Some(request))
    }

    pub fn login(&self, request: &LoginRequest) -> Result<SessionResponse, SyncError> {
        self.send("POST", "/v1/sessions", Some(request))
    }

    pub fn recover(&self, request: &RecoverRequest) -> Result<SessionResponse, SyncError> {
        self.send("POST", "/v1/recover", Some(request))
    }

    pub fn logout(&self) -> Result<(), SyncError> {
        self.send::<serde::de::IgnoredAny>("DELETE", "/v1/sessions/current", None::<&()>).map(drop)
    }

    pub fn delete_account(&self, auth_key: &[u8]) -> Result<(), SyncError> {
        let body = DeleteAccountRequest { auth_key: auth_key.to_vec() };
        self.send::<serde::de::IgnoredAny>("DELETE", "/v1/account", Some(&body)).map(drop)
    }

    pub fn devices(&self) -> Result<DevicesResponse, SyncError> {
        self.get("/v1/devices")
    }

    pub fn revoke_device(&self, id: Uuid) -> Result<(), SyncError> {
        self.send::<serde::de::IgnoredAny>("DELETE", &format!("/v1/devices/{id}"), None::<&()>).map(drop)
    }

    pub fn keys(&self) -> Result<KeysResponse, SyncError> {
        self.get("/v1/keys")
    }

    pub fn update_keys(&self, request: &UpdateKeysRequest) -> Result<UpdateKeysResponse, SyncError> {
        self.send("PUT", "/v1/keys", Some(request))
    }

    pub fn changes(&self, since: i64, limit: u32) -> Result<ChangesResponse, SyncError> {
        self.get(&format!("/v1/items?since={since}&limit={limit}"))
    }

    pub fn push(&self, items: Vec<PushItem>) -> Result<PushResponse, SyncError> {
        self.send("POST", "/v1/items", Some(&PushRequest { items }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert_eq!(normalize_server_url(" https://sync.example.com/ ").unwrap(), "https://sync.example.com");
        assert_eq!(
            normalize_server_url("https://example.com:8443/simplus").unwrap(),
            "https://example.com:8443/simplus"
        );
        for local in ["http://localhost:8080", "http://127.0.0.1:9", "http://[::1]:8080"] {
            assert!(normalize_server_url(local).is_ok(), "{local}");
        }
        assert!(matches!(normalize_server_url("http://sync.example.com"), Err(SyncError::InsecureUrl)));
        assert!(matches!(normalize_server_url("http://localhost.evil.com"), Err(SyncError::InsecureUrl)));
        for bad in ["sync.example.com", "ftp://x.y", "https://", "https://a b"] {
            assert!(matches!(normalize_server_url(bad), Err(SyncError::InvalidUrl)), "{bad}");
        }
    }
}
