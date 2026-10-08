//! SQLite persistence for the vault: a key/value `meta` table and one encrypted row per item.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension as _, params};
use simplus_core::db::{self, rusqlite};
use uuid::Uuid;

use crate::{Result, VaultError};

const MIGRATIONS: &[&str] = &["
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value BLOB NOT NULL
    );
    CREATE TABLE items (
        id         TEXT PRIMARY KEY,
        kind       INTEGER NOT NULL,
        parent_id  TEXT,
        revision   INTEGER NOT NULL,
        deleted    INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        blob       BLOB
    );
    CREATE INDEX items_parent ON items (parent_id) WHERE parent_id IS NOT NULL;
"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ItemKind {
    Record = 1,
    Note = 2,
}

/// One row of the `items` table. `blob` is `None` for tombstones.
pub(crate) struct ItemRow {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub blob: Option<Vec<u8>>,
}

pub(crate) fn open(path: &Path) -> Result<Connection> {
    let mut conn = db::open(path)?;
    db::migrate(&mut conn, "vault", MIGRATIONS)?;
    Ok(conn)
}

pub(crate) fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
}

pub(crate) fn require_meta(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    get_meta(conn, key)?.ok_or(VaultError::Corrupted)
}

pub(crate) fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn parse_uuid(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    Ok(ItemRow {
        id: parse_uuid(row.get(0)?)?,
        parent_id: row.get::<_, Option<String>>(1)?.map(parse_uuid).transpose()?,
        blob: row.get(2)?,
    })
}

/// A live (non-deleted) item of the given kind.
pub(crate) fn get_item(conn: &Connection, kind: ItemKind, id: Uuid) -> Result<Option<ItemRow>> {
    Ok(conn
        .query_row(
            "SELECT id, parent_id, blob FROM items WHERE id = ?1 AND kind = ?2 AND deleted = 0",
            params![id.to_string(), kind as i64],
            row_to_item,
        )
        .optional()?)
}

/// Current revision of an item, including tombstones (0 if it never existed).
pub(crate) fn revision(conn: &Connection, id: Uuid) -> Result<i64> {
    Ok(conn
        .query_row("SELECT revision FROM items WHERE id = ?1", [id.to_string()], |r| r.get(0))
        .optional()?
        .unwrap_or(0))
}

pub(crate) fn list_items(conn: &Connection, kind: ItemKind, parent: Option<Uuid>) -> Result<Vec<ItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, parent_id, blob FROM items
         WHERE kind = ?1 AND deleted = 0 AND (?2 IS NULL OR parent_id = ?2)",
    )?;
    let rows = stmt.query_map(params![kind as i64, parent.map(|p| p.to_string())], row_to_item)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn count_children(conn: &Connection, parent: Uuid) -> Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM items WHERE parent_id = ?1 AND deleted = 0",
        [parent.to_string()],
        |r| r.get(0),
    )?;
    Ok(n as usize)
}

pub(crate) fn put_item(
    conn: &Connection,
    kind: ItemKind,
    id: Uuid,
    parent_id: Option<Uuid>,
    revision: i64,
    updated_at_ms: i64,
    blob: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT INTO items (id, kind, parent_id, revision, deleted, updated_at, blob)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, parent_id = excluded.parent_id,
             revision = excluded.revision, deleted = 0, updated_at = excluded.updated_at, blob = excluded.blob",
        params![id.to_string(), kind as i64, parent_id.map(|p| p.to_string()), revision, updated_at_ms, blob],
    )?;
    Ok(())
}

/// Replaces an item with a tombstone (kept so a future sync can propagate the deletion).
pub(crate) fn tombstone(conn: &Connection, id: Uuid, updated_at_ms: i64) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE items SET deleted = 1, blob = NULL, revision = revision + 1, updated_at = ?2
         WHERE id = ?1 AND deleted = 0",
        params![id.to_string(), updated_at_ms],
    )? > 0)
}
