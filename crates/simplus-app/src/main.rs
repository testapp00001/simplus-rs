// Release builds on Windows are GUI apps without a console window.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

slint::include_modules!();

mod clipboard;
mod session;
mod settings;
mod vault_ui;

use anyhow::Context as _;
use slint::ComponentHandle as _;

/// Slint has no generic "monospace" family, so pick one that ships with each OS.
const MONO_FONT: &str = if cfg!(windows) {
    "Consolas"
} else if cfg!(target_os = "macos") {
    "Menlo"
} else {
    "DejaVu Sans Mono"
};

fn main() -> anyhow::Result<()> {
    let paths = simplus_core::AppPaths::discover()?;
    paths.ensure_dirs().context("cannot create the application directories")?;
    let _log_guard = simplus_core::logging::init(Some(&paths.log_dir))?;

    let Some(_instance) = acquire_single_instance()? else {
        return Ok(());
    };

    let ui = MainWindow::new()?;
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.global::<Theme<'_>>().set_mono_font(MONO_FONT.into());
    settings::install(&ui, paths.config_file());
    let _vault = vault_ui::VaultController::install(&ui, paths.data_dir.join("vault.db"));

    tracing::info!(data = %paths.data_dir.display(), "Simplus started");
    ui.run()?;
    Ok(())
}

/// Two processes writing the same vault would be unsafe, so only one instance may run.
fn acquire_single_instance() -> anyhow::Result<Option<single_instance::SingleInstance>> {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default();
    let name = format!("dev.simplus.app.{user}");
    let name = if cfg!(target_os = "macos") {
        std::env::temp_dir().join(format!("{name}.lock")).to_string_lossy().into_owned()
    } else {
        name
    };
    let instance = single_instance::SingleInstance::new(&name)
        .map_err(|e| anyhow::anyhow!("single-instance check failed: {e}"))?;
    if instance.is_single() {
        return Ok(Some(instance));
    }
    rfd::MessageDialog::new()
        .set_title("Simplus")
        .set_description("Simplus is already running.")
        .set_level(rfd::MessageLevel::Info)
        .show();
    Ok(None)
}
