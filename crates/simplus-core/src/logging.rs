use std::io::IsTerminal as _;
use std::path::Path;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, fmt};

/// Environment variable holding a `tracing` filter directive, e.g. `SIMPLUS_LOG=debug`.
pub const LOG_ENV: &str = "SIMPLUS_LOG";

/// Installs the global logger: human-readable output on stderr plus, when `log_dir` is given,
/// a daily-rotated `simplus.log` file. Keep the returned guard alive for the whole program so
/// buffered file output is flushed on exit.
pub fn init(log_dir: Option<&Path>) -> anyhow::Result<Option<WorkerGuard>> {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    // Colours only on an interactive terminal (not in Docker logs or log files).
    let stderr = fmt::layer().with_ansi(std::io::stderr().is_terminal()).with_writer(std::io::stderr);

    let (file_layer, guard) = match log_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let appender = tracing_appender::rolling::daily(dir, "simplus.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            (Some(fmt::layer().with_ansi(false).with_writer(writer)), Some(guard))
        }
        None => (None, None),
    };

    tracing_subscriber::registry().with(filter).with(stderr).with(file_layer).try_init()?;
    Ok(guard)
}
