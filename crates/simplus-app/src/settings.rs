use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use simplus_core::AppConfig;
use simplus_core::config::Theme;
use slint::ComponentHandle as _;

use crate::{AppSettings, MainWindow};

/// Loads the config into the `AppSettings` global and persists it whenever the UI saves.
pub fn install(ui: &MainWindow, path: PathBuf) {
    let config = AppConfig::load(&path).unwrap_or_else(|e| {
        tracing::warn!("using default settings: {e:#}");
        AppConfig::default()
    });
    let settings = ui.global::<AppSettings<'_>>();
    settings.set_theme(match config.general.theme {
        Theme::System => 0,
        Theme::Light => 1,
        Theme::Dark => 2,
    });
    settings.set_auto_lock_minutes(config.security.vault_auto_lock_minutes as i32);
    settings.set_clipboard_clear_seconds(config.security.clipboard_clear_seconds as i32);
    ui.invoke_apply_theme();

    let config = Rc::new(RefCell::new(config));
    let weak = ui.as_weak();
    settings.on_save(move || {
        let Some(ui) = weak.upgrade() else { return };
        let settings = ui.global::<AppSettings<'_>>();
        let mut config = config.borrow_mut();
        config.general.theme = match settings.get_theme() {
            1 => Theme::Light,
            2 => Theme::Dark,
            _ => Theme::System,
        };
        config.security.vault_auto_lock_minutes = settings.get_auto_lock_minutes().max(0) as u32;
        config.security.clipboard_clear_seconds = settings.get_clipboard_clear_seconds().max(0) as u32;
        if let Err(e) = config.save(&path) {
            tracing::error!("cannot save settings: {e:#}");
        }
    });
}
