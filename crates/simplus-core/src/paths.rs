use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Display name, also used for OS-level directory names.
pub const APP_NAME: &str = "Simplus";

/// If a file with this name sits next to the executable, all data is stored in a `data`
/// folder beside it instead of the user profile (portable / USB-stick mode).
pub const PORTABLE_MARKER: &str = "simplus.portable";

/// Filesystem locations used by the app.
///
/// On Windows the defaults are `%APPDATA%\Simplus\config` for settings and
/// `%LOCALAPPDATA%\Simplus\data` for databases, logs and plugins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub log_dir: PathBuf,
    pub plugins_dir: PathBuf,
}

impl AppPaths {
    /// Resolves the platform directories, honouring portable mode.
    pub fn discover() -> anyhow::Result<Self> {
        if let Some(root) = portable_root() {
            return Ok(Self::from_root(&root));
        }
        let dirs = directories::ProjectDirs::from("", "", APP_NAME)
            .context("could not determine the user's home directory")?;
        let data_dir = dirs.data_local_dir().to_path_buf();
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            cache_dir: dirs.cache_dir().to_path_buf(),
            log_dir: data_dir.join("logs"),
            plugins_dir: data_dir.join("plugins"),
            data_dir,
        })
    }

    /// Puts everything under a single root directory (portable mode and tests).
    pub fn from_root(root: &Path) -> Self {
        Self {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            cache_dir: root.join("cache"),
            log_dir: root.join("logs"),
            plugins_dir: root.join("plugins"),
        }
    }

    /// Creates every directory that does not exist yet.
    pub fn ensure_dirs(&self) -> io::Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.cache_dir, &self.log_dir, &self.plugins_dir] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Main application database (profiles, jobs, schedules, sync state).
    pub fn database_file(&self) -> PathBuf {
        self.data_dir.join("simplus.db")
    }

    /// Encrypted App credential store.
    pub fn secrets_file(&self) -> PathBuf {
        self.data_dir.join("secrets.db")
    }
}

fn portable_root() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    exe_dir.join(PORTABLE_MARKER).is_file().then(|| exe_dir.join("data"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_root_layout_and_ensure() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_root(tmp.path());
        paths.ensure_dirs().unwrap();
        assert!(paths.plugins_dir.is_dir());
        assert_eq!(paths.config_file(), tmp.path().join("config/config.toml"));
        assert_eq!(paths.secrets_file(), tmp.path().join("data/secrets.db"));
    }
}
