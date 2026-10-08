//! Operations behind the administrator CLI.

use std::path::Path;

use data_encoding::BASE32_NOPAD;
use simplus_core::db::rusqlite::OptionalExtension as _;

use crate::auth::hash_token;
use crate::db::{Db, now, params};

#[derive(Debug, PartialEq, Eq)]
pub struct UserSummary {
    pub email: String,
    pub created_at: i64,
    pub disabled: bool,
    pub items: i64,
    pub devices: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Stats {
    pub accounts: i64,
    pub items: i64,
    pub sessions: i64,
}

/// Creates an invite code valid for `uses` registrations within `days` days.
pub fn create_invite(db: &Db, uses: u32, days: u32) -> anyhow::Result<String> {
    let raw = simplus_crypto::random_bytes::<10>()?;
    let code = BASE32_NOPAD.encode(&raw);
    let now = now();
    db.blocking(|conn| {
        conn.execute(
            "INSERT INTO invites (code_hash, uses_left, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![&hash_token(&code)[..], uses.max(1), now + i64::from(days.max(1)) * 86_400, now],
        )
    })?;
    Ok(code)
}

pub fn list_users(db: &Db) -> anyhow::Result<Vec<UserSummary>> {
    db.blocking(|conn| {
        let mut stmt = conn.prepare(
            "SELECT a.email, a.created_at, a.disabled,
                    (SELECT COUNT(*) FROM items i WHERE i.account_id = a.id AND i.deleted = 0),
                    (SELECT COUNT(*) FROM sessions s WHERE s.account_id = a.id)
             FROM accounts a ORDER BY a.email",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(UserSummary {
                email: r.get(0)?,
                created_at: r.get(1)?,
                disabled: r.get(2)?,
                items: r.get(3)?,
                devices: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    })
}

/// Disables or re-enables an account. Disabling also signs out every device.
pub fn set_disabled(db: &Db, email: &str, disabled: bool) -> anyhow::Result<bool> {
    let email = simplus_vault_proto::normalize_email(email);
    db.blocking(|conn| {
        let id: Option<String> =
            conn.query_row("SELECT id FROM accounts WHERE email = ?1", [&email], |r| r.get(0)).optional()?;
        let Some(id) = id else { return Ok(false) };
        conn.execute("UPDATE accounts SET disabled = ?2 WHERE id = ?1", params![id, disabled])?;
        if disabled {
            conn.execute("DELETE FROM sessions WHERE account_id = ?1", [&id])?;
        }
        Ok(true)
    })
}

/// Permanently deletes an account and all of its data.
pub fn delete_user(db: &Db, email: &str) -> anyhow::Result<bool> {
    let email = simplus_vault_proto::normalize_email(email);
    Ok(db.blocking(|conn| conn.execute("DELETE FROM accounts WHERE email = ?1", [&email]))? > 0)
}

pub fn stats(db: &Db) -> anyhow::Result<Stats> {
    db.blocking(|conn| {
        let count = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
        Ok(Stats {
            accounts: count("SELECT COUNT(*) FROM accounts")?,
            items: count("SELECT COUNT(*) FROM items WHERE deleted = 0")?,
            sessions: count("SELECT COUNT(*) FROM sessions")?,
        })
    })
}

/// Writes a consistent copy of the database while the server keeps running.
pub fn backup(db: &Db, target: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!target.exists(), "{} already exists", target.display());
    let target =
        target.to_str().ok_or_else(|| anyhow::anyhow!("backup path must be valid UTF-8"))?.to_owned();
    db.blocking(|conn| conn.execute("VACUUM INTO ?1", [target]))?;
    Ok(())
}
