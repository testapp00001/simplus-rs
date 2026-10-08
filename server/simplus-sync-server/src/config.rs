use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use simplus_vault_proto::Registration;

/// Server settings: a TOML file (optional) overridden by `SIMPLUS_*` environment variables.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address to listen on. Put a TLS-terminating reverse proxy in front of it.
    pub bind: SocketAddr,
    /// SQLite database file.
    pub database: PathBuf,
    /// Who may create accounts: `open`, `invite` (admin-issued codes) or `closed`.
    pub registration: Registration,
    /// Take the client address from `X-Forwarded-For` (only behind a trusted proxy).
    pub trust_proxy: bool,
    pub max_items_per_account: u32,
    /// Largest accepted encrypted item.
    pub max_blob_bytes: usize,
    /// Largest accepted request body.
    pub max_body_bytes: usize,
    /// Sessions expire after this many days without use.
    pub session_ttl_days: u32,
    /// Login/registration/recovery attempts allowed per client IP per minute.
    pub auth_requests_per_minute: u32,
    /// Failed logins before an account is temporarily locked.
    pub lockout_threshold: u32,
    pub lockout_minutes: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().expect("valid address"),
            database: PathBuf::from("data/simplus-sync.db"),
            registration: Registration::Open,
            trust_proxy: false,
            max_items_per_account: 50_000,
            max_blob_bytes: 256 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            session_ttl_days: 90,
            auth_requests_per_minute: 30,
            lockout_threshold: 10,
            lockout_minutes: 15,
        }
    }
}

fn parse_bool(name: &str, value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("{name}: expected true or false, got {other:?}"),
    }
}

impl Config {
    /// Loads `path` (if given) and applies environment overrides.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = match path {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))?
            }
            None => Self::default(),
        };
        config.apply_env(|name| std::env::var(name).ok())?;
        Ok(config)
    }

    fn apply_env(&mut self, get: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(v) = get("SIMPLUS_BIND") {
            self.bind = v.parse().with_context(|| format!("SIMPLUS_BIND: invalid address {v:?}"))?;
        }
        if let Some(v) = get("SIMPLUS_DATABASE") {
            self.database = PathBuf::from(v);
        }
        if let Some(v) = get("SIMPLUS_REGISTRATION") {
            self.registration = match v.trim().to_ascii_lowercase().as_str() {
                "open" => Registration::Open,
                "invite" => Registration::Invite,
                "closed" => Registration::Closed,
                other => bail!("SIMPLUS_REGISTRATION: expected open, invite or closed, got {other:?}"),
            };
        }
        if let Some(v) = get("SIMPLUS_TRUST_PROXY") {
            self.trust_proxy = parse_bool("SIMPLUS_TRUST_PROXY", &v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_and_env_overrides() {
        let config: Config =
            toml::from_str("registration = \"invite\"\nmax_items_per_account = 10\n").unwrap();
        assert_eq!(config.registration, Registration::Invite);
        assert_eq!(config.max_items_per_account, 10);
        assert_eq!(config.session_ttl_days, 90, "unspecified fields keep defaults");

        let mut config = Config::default();
        let env = |name: &str| match name {
            "SIMPLUS_BIND" => Some("127.0.0.1:9000".to_owned()),
            "SIMPLUS_REGISTRATION" => Some("closed".to_owned()),
            "SIMPLUS_TRUST_PROXY" => Some("yes".to_owned()),
            _ => None,
        };
        config.apply_env(env).unwrap();
        assert_eq!(config.bind.port(), 9000);
        assert_eq!(config.registration, Registration::Closed);
        assert!(config.trust_proxy);

        assert!(config.apply_env(|_| Some("bogus".to_owned())).is_err());
        assert!(toml::from_str::<Config>("unknown_key = 1").is_err(), "typos are rejected");
    }
}
