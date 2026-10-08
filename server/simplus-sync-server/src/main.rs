use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use simplus_sync_server::{AppState, Config, admin, db::Db};

/// Self-hostable sync server for the Simplus password vault.
#[derive(Parser)]
#[command(name = "simplus-sync-server", version, about)]
struct Cli {
    /// TOML configuration file (environment variables SIMPLUS_* override it).
    #[arg(long, short, env = "SIMPLUS_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Manage invite codes (for `registration = "invite"`).
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// Manage accounts.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Show account, item and session counts.
    Stats,
    /// Write a consistent copy of the database to FILE.
    Backup { file: PathBuf },
    /// Print the effective configuration.
    Config,
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Create an invite code.
    Create {
        /// How many accounts the code may create.
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Days until the code expires.
        #[arg(long, default_value_t = 7)]
        days: u32,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    List,
    /// Block an account and sign out its devices.
    Disable {
        email: String,
    },
    Enable {
        email: String,
    },
    /// Permanently delete an account and its encrypted data.
    Delete {
        email: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

fn format_time(secs: i64) -> String {
    let days = secs / 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _log = simplus_core::logging::init(None)?;
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref())?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let bind = config.bind;
            let registration = config.registration;
            let state = AppState::open(config)?;
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("cannot listen on {bind}"))?;
            tracing::info!(%bind, ?registration, "simplus-sync-server {} listening", env!("CARGO_PKG_VERSION"));
            simplus_sync_server::serve(state, listener, shutdown_signal()).await?;
        }
        Command::Config => print!("{}", toml::to_string_pretty(&config)?),
        command => {
            let db = Db::open(&config.database)?;
            match command {
                Command::Invite { command: InviteCommand::Create { uses, days } } => {
                    let code = admin::create_invite(&db, uses, days)?;
                    println!("{code}\n(valid for {uses} account(s), expires in {days} day(s))");
                }
                Command::User { command } => match command {
                    UserCommand::List => {
                        println!("{:<40} {:<10} {:>7} {:>7}  status", "email", "created", "items", "devices");
                        for u in admin::list_users(&db)? {
                            let status = if u.disabled { "disabled" } else { "active" };
                            println!(
                                "{:<40} {:<10} {:>7} {:>7}  {status}",
                                u.email,
                                format_time(u.created_at),
                                u.items,
                                u.devices
                            );
                        }
                    }
                    UserCommand::Disable { email } | UserCommand::Enable { email }
                        if !admin::list_users(&db)?
                            .iter()
                            .any(|u| u.email == simplus_vault_proto::normalize_email(&email)) =>
                    {
                        anyhow::bail!("no account for {email}");
                    }
                    UserCommand::Disable { email } => {
                        admin::set_disabled(&db, &email, true)?;
                        println!("disabled {email} and signed out its devices");
                    }
                    UserCommand::Enable { email } => {
                        admin::set_disabled(&db, &email, false)?;
                        println!("enabled {email}");
                    }
                    UserCommand::Delete { email, yes } => {
                        anyhow::ensure!(yes, "this permanently deletes the account; re-run with --yes");
                        anyhow::ensure!(admin::delete_user(&db, &email)?, "no account for {email}");
                        println!("deleted {email}");
                    }
                },
                Command::Stats => {
                    let s = admin::stats(&db)?;
                    println!("accounts: {}\nitems:    {}\nsessions: {}", s.accounts, s.items, s.sessions);
                }
                Command::Backup { file } => {
                    admin::backup(&db, &file)?;
                    println!("backup written to {}", file.display());
                }
                Command::Serve | Command::Config => unreachable!("handled above"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::format_time(0), "1970-01-01");
        assert_eq!(super::format_time(1_790_000_000), "2026-09-21");
    }
}
