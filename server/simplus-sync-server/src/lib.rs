//! Simplus vault sync server.
//!
//! A zero-knowledge relay: it stores encrypted vault items and wrapped keys for each account
//! and hands out changes by sequence number. It never sees a password or a decryption key.

pub mod admin;
pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;

use std::future::Future;
use std::net::SocketAddr;

pub use api::{AppState, router};
pub use config::Config;

/// Serves the API on `listener` until `shutdown` resolves.
pub async fn serve(
    state: AppState,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).with_graceful_shutdown(shutdown).await?;
    Ok(())
}
