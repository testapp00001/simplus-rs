//! SQLite helpers: connection setup and namespaced, forward-only migrations.
//!
//! Each component (core, S3 module, a plugin, ...) owns a migration namespace, so modules can
//! evolve their tables independently inside the same database file.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};

pub use rusqlite;

/// Opens (or creates) a database with the pragmas every Simplus database uses.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    Ok(conn)
}

/// In-memory database, mainly for tests.
pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// Applies `migrations[current..]` for `namespace` inside one transaction and returns the new
/// schema version. Migrations are append-only: never edit one that has shipped.
pub fn migrate(conn: &mut Connection, namespace: &str, migrations: &[&str]) -> rusqlite::Result<u32> {
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
             namespace TEXT PRIMARY KEY,
             version   INTEGER NOT NULL
         );",
    )?;
    let current: u32 = tx
        .query_row("SELECT version FROM _migrations WHERE namespace = ?1", [namespace], |r| r.get(0))
        .optional()?
        .unwrap_or(0);
    for sql in migrations.iter().skip(current as usize) {
        tx.execute_batch(sql)?;
    }
    let target = migrations.len() as u32;
    if target > current {
        tx.execute(
            "INSERT INTO _migrations (namespace, version) VALUES (?1, ?2)
             ON CONFLICT(namespace) DO UPDATE SET version = excluded.version",
            params![namespace, target],
        )?;
    }
    tx.commit()?;
    Ok(target.max(current))
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "CREATE TABLE t (id INTEGER PRIMARY KEY);";
    const V2: &str = "ALTER TABLE t ADD COLUMN name TEXT;";

    #[test]
    fn applies_incrementally_and_is_idempotent() {
        let mut conn = open_in_memory().unwrap();
        assert_eq!(migrate(&mut conn, "test", &[V1]).unwrap(), 1);
        assert_eq!(migrate(&mut conn, "test", &[V1]).unwrap(), 1);
        assert_eq!(migrate(&mut conn, "test", &[V1, V2]).unwrap(), 2);
        conn.execute("INSERT INTO t (name) VALUES ('x')", []).unwrap();
    }

    #[test]
    fn namespaces_are_independent() {
        let mut conn = open_in_memory().unwrap();
        migrate(&mut conn, "a", &[V1]).unwrap();
        assert_eq!(migrate(&mut conn, "b", &["CREATE TABLE u (id INTEGER);"]).unwrap(), 1);
    }

    #[test]
    fn failed_migration_rolls_back() {
        let mut conn = open_in_memory().unwrap();
        assert!(migrate(&mut conn, "test", &[V1, "NOT SQL"]).is_err());
        assert_eq!(migrate(&mut conn, "test", &[]).unwrap(), 0);
        assert!(conn.execute("INSERT INTO t DEFAULT VALUES", []).is_err(), "V1 must be rolled back");
    }
}
