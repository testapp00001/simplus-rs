//! SQLite storage. Requests run their queries on a blocking thread while holding a single
//! connection, which is plenty for personal and small-team servers.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use simplus_core::db::rusqlite::{self, Connection, OptionalExtension as _};

use crate::error::ApiResult;

const MIGRATIONS: &[&str] = &["
    CREATE TABLE server_meta (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
    );
    CREATE TABLE accounts (
        id             TEXT PRIMARY KEY,
        email          TEXT NOT NULL UNIQUE,
        auth_verifier  BLOB NOT NULL,
        proof_verifier BLOB NOT NULL,
        kdf            TEXT NOT NULL,
        keys           TEXT NOT NULL,
        keys_version   INTEGER NOT NULL,
        seq            INTEGER NOT NULL DEFAULT 0,
        disabled       INTEGER NOT NULL DEFAULT 0,
        failed_logins  INTEGER NOT NULL DEFAULT 0,
        locked_until   INTEGER NOT NULL DEFAULT 0,
        created_at     INTEGER NOT NULL
    );
    CREATE TABLE sessions (
        token_hash  BLOB PRIMARY KEY,
        account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
        device_id   TEXT NOT NULL,
        device_name TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL
    );
    CREATE INDEX sessions_account ON sessions (account_id, device_id);
    CREATE TABLE items (
        account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
        id         TEXT NOT NULL,
        kind       TEXT NOT NULL,
        parent_id  TEXT,
        seq        INTEGER NOT NULL,
        deleted    INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        blob       BLOB,
        PRIMARY KEY (account_id, id)
    );
    CREATE INDEX items_seq ON items (account_id, seq);
    CREATE TABLE invites (
        code_hash  BLOB PRIMARY KEY,
        uses_left  INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );
"];

/// Shared handle to the server database.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        }
        let mut conn = simplus_core::db::open(path)
            .with_context(|| format!("cannot open database {}", path.display()))?;
        simplus_core::db::migrate(&mut conn, "sync-server", MIGRATIONS)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    /// Runs `f` with the connection on a blocking thread.
    pub async fn call<R, F>(&self, f: F) -> ApiResult<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Connection) -> ApiResult<R> + Send + 'static,
    {
        let db = self.0.clone();
        tokio::task::spawn_blocking(move || f(&mut db.lock().unwrap_or_else(|e| e.into_inner()))).await?
    }

    /// Runs `f` on the current thread (admin commands).
    pub fn blocking<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Random server secret, created on first start. Used to derive fake prelogin answers for
/// unknown accounts, so they stay stable across restarts.
pub fn server_secret(conn: &Connection) -> anyhow::Result<[u8; 32]> {
    let stored: Option<Vec<u8>> =
        conn.query_row("SELECT value FROM server_meta WHERE key = 'secret'", [], |r| r.get(0)).optional()?;
    if let Some(secret) = stored {
        return secret.try_into().map_err(|_| anyhow::anyhow!("corrupted server secret"));
    }
    let secret = simplus_crypto::random_bytes::<32>()?;
    conn.execute("INSERT INTO server_meta (key, value) VALUES ('secret', ?1)", [&secret[..]])?;
    Ok(secret)
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub use rusqlite::params;
