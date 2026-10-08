use std::path::Path;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// User-editable application settings, persisted as TOML.
///
/// Every section uses `#[serde(default)]` so older or partial files keep loading as new
/// settings are added.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub security: SecurityConfig,
    pub plugins: PluginsConfig,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub theme: Theme,
    /// Closing the main window hides it to the system tray instead of quitting.
    pub close_to_tray: bool,
    /// Launch automatically when the user logs in.
    pub start_with_system: bool,
    /// When auto-started, stay in the tray instead of showing the window.
    pub start_minimized: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self { theme: Theme::System, close_to_tray: true, start_with_system: false, start_minimized: true }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Lock the password vault after this many idle minutes (0 = never).
    pub vault_auto_lock_minutes: u32,
    /// Clear copied secrets from the clipboard after this many seconds (0 = never).
    pub clipboard_clear_seconds: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { vault_auto_lock_minutes: 5, clipboard_clear_seconds: 30 }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsConfig {
    /// Plugin ids the user has disabled.
    pub disabled: Vec<String>,
    /// Allows loading unpacked plugins from arbitrary folders.
    pub developer_mode: bool,
}

impl AppConfig {
    /// Loads the config file, returning defaults when it does not exist yet.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Writes the config atomically (temp file + rename) so a crash never leaves it truncated.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(self)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_gives_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(AppConfig::load(&tmp.path().join("nope.toml")).unwrap(), AppConfig::default());
    }

    #[test]
    fn save_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sub/config.toml");
        let mut cfg = AppConfig::default();
        cfg.general.theme = Theme::Dark;
        cfg.plugins.disabled.push("com.example.hello".into());
        cfg.save(&path).unwrap();
        assert_eq!(AppConfig::load(&path).unwrap(), cfg);
    }

    #[test]
    fn partial_file_fills_defaults() {
        let cfg: AppConfig = toml::from_str("[general]\nclose_to_tray = false\n").unwrap();
        assert!(!cfg.general.close_to_tray);
        assert_eq!(cfg.security, SecurityConfig::default());
    }
}
